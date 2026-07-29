import { randomBytes } from "node:crypto";
import { constants } from "node:fs";
import {
  lstat,
  mkdir,
  open,
  readdir,
  realpath,
  unlink,
} from "node:fs/promises";
import { dirname, resolve } from "node:path";

const NOFOLLOW = constants.O_NOFOLLOW ?? 0;
const DEFAULT_WAIT_MS = 10;
const DEFAULT_TIMEOUT_MS = 15_000;
const LOCK_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const CHOOSING_NAME =
  /^choosing-(?<pid>[1-9][0-9]*)-(?<nonce>[a-f0-9]{32})\.lock$/;
const TICKET_NAME =
  /^ticket-(?<number>[0-9]+)-(?<pid>[1-9][0-9]*)-(?<nonce>[a-f0-9]{32})\.lock$/;

export interface FileLockOptions {
  rootDir: string;
  name: string;
  error(message: string): Error;
  timeoutMs?: number;
  waitMs?: number;
}

export interface FileLockHandle {
  readonly directory: string;
  readonly ticketPath: string;
  readonly token: string;
  readonly error: (message: string) => Error;
}

interface ParsedEntry {
  kind: "choosing" | "ticket";
  name: string;
  path: string;
  pid: number;
  number?: bigint;
}

function isErrorCode(error: unknown, code: string): boolean {
  return (
    error instanceof Error &&
    "code" in error &&
    (error as NodeJS.ErrnoException).code === code
  );
}

function processIsAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if (isErrorCode(error, "ESRCH")) return false;
    if (isErrorCode(error, "EPERM")) return true;
    throw error;
  }
}

function finiteDuration(
  value: number | undefined,
  fallback: number,
  field: string,
  error: (message: string) => Error,
): number {
  const normalized = value ?? fallback;
  if (!Number.isFinite(normalized) || normalized <= 0) {
    throw error(`${field} must be a positive finite number`);
  }
  return normalized;
}

async function syncDirectory(directory: string): Promise<void> {
  const handle = await open(directory, constants.O_RDONLY);
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function createExclusiveFile(
  filePath: string,
  value: string,
): Promise<void> {
  const handle = await open(
    filePath,
    constants.O_WRONLY |
      constants.O_CREAT |
      constants.O_EXCL |
      NOFOLLOW,
    0o600,
  );
  try {
    await handle.writeFile(value, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function readSecureFile(
  filePath: string,
  error: (message: string) => Error,
): Promise<string> {
  const handle = await open(filePath, constants.O_RDONLY | NOFOLLOW);
  try {
    if (!(await handle.stat()).isFile()) {
      throw error("Writer-lock ticket must be a regular file");
    }
    return await handle.readFile("utf8");
  } finally {
    await handle.close();
  }
}

function parseEntry(
  directory: string,
  name: string,
  error: (message: string) => Error,
): ParsedEntry {
  const choosing = CHOOSING_NAME.exec(name);
  if (choosing?.groups) {
    const pid = Number(choosing.groups.pid);
    if (!Number.isSafeInteger(pid)) {
      throw error("Writer-lock chooser has an invalid PID");
    }
    return {
      kind: "choosing",
      name,
      path: resolve(directory, name),
      pid,
    };
  }
  const ticket = TICKET_NAME.exec(name);
  if (ticket?.groups) {
    const pid = Number(ticket.groups.pid);
    if (!Number.isSafeInteger(pid)) {
      throw error("Writer-lock ticket has an invalid PID");
    }
    const number = BigInt(ticket.groups.number);
    if (number <= 0n) {
      throw error("Writer-lock ticket has an invalid sequence");
    }
    return {
      kind: "ticket",
      name,
      path: resolve(directory, name),
      pid,
      number,
    };
  }
  throw error(`Writer-lock directory contains an invalid entry: ${name}`);
}

async function listEntries(
  directory: string,
  error: (message: string) => Error,
): Promise<ParsedEntry[]> {
  return (await readdir(directory)).map((name) =>
    parseEntry(directory, name, error),
  );
}

async function removeExactStaleEntry(entry: ParsedEntry): Promise<boolean> {
  if (processIsAlive(entry.pid)) return false;
  try {
    await unlink(entry.path);
  } catch (error) {
    if (!isErrorCode(error, "ENOENT")) throw error;
  }
  return true;
}

async function ensureLockDirectory(
  rootDir: string,
  name: string,
  error: (message: string) => Error,
): Promise<string> {
  if (!LOCK_NAME.test(name)) {
    throw error("Writer-lock name contains invalid characters");
  }
  const canonicalRoot = await realpath(rootDir);
  const directory = resolve(canonicalRoot, `.${name}.locks`);
  try {
    await mkdir(directory, { mode: 0o700 });
    await syncDirectory(canonicalRoot);
  } catch (mkdirError) {
    if (!isErrorCode(mkdirError, "EEXIST")) throw mkdirError;
  }
  const stats = await lstat(directory);
  if (stats.isSymbolicLink() || !stats.isDirectory()) {
    throw error("Writer-lock path must be a real directory");
  }
  if ((stats.mode & 0o077) !== 0) {
    throw error("Writer-lock directory permissions are too broad");
  }
  const canonicalDirectory = await realpath(directory);
  if (dirname(canonicalDirectory) !== canonicalRoot) {
    throw error("Writer-lock directory escaped its state root");
  }
  return canonicalDirectory;
}

async function cleanupOwnPath(filePath: string | null): Promise<void> {
  if (!filePath) return;
  try {
    await unlink(filePath);
  } catch (error) {
    if (!isErrorCode(error, "ENOENT")) throw error;
  }
}

/**
 * Acquires a filesystem lock using Lamport bakery tickets. Every chooser and
 * ticket has a unique, never-reused pathname, so stale-process recovery never
 * unlinks a pathname that a newer live owner could have replaced.
 */
export async function acquireFileLock(
  options: FileLockOptions,
): Promise<FileLockHandle> {
  const timeoutMs = finiteDuration(
    options.timeoutMs,
    DEFAULT_TIMEOUT_MS,
    "Writer-lock timeout",
    options.error,
  );
  const waitMs = finiteDuration(
    options.waitMs,
    DEFAULT_WAIT_MS,
    "Writer-lock wait interval",
    options.error,
  );
  const directory = await ensureLockDirectory(
    options.rootDir,
    options.name,
    options.error,
  );
  const nonce = randomBytes(16).toString("hex");
  const identity = `${process.pid}-${nonce}`;
  const token = JSON.stringify({ pid: process.pid, nonce });
  const choosingPath = resolve(directory, `choosing-${identity}.lock`);
  let ticketPath: string | null = null;
  let ticketName: string | null = null;
  const deadline = Date.now() + timeoutMs;

  try {
    await createExclusiveFile(choosingPath, token);
    await syncDirectory(directory);

    let maximum = 0n;
    for (const entry of await listEntries(directory, options.error)) {
      if (entry.kind === "ticket" && entry.number! > maximum) {
        maximum = entry.number!;
      }
    }
    const number = maximum + 1n;
    ticketName =
      `ticket-${number.toString().padStart(20, "0")}-${identity}.lock`;
    ticketPath = resolve(directory, ticketName);
    await createExclusiveFile(ticketPath, token);
    await cleanupOwnPath(choosingPath);
    await syncDirectory(directory);

    for (;;) {
      let retry = false;
      const entries = await listEntries(directory, options.error);
      if (!entries.some((entry) => entry.path === ticketPath)) {
        throw options.error("Writer-lock ticket disappeared");
      }

      for (const entry of entries) {
        if (entry.path === ticketPath) continue;
        if (await removeExactStaleEntry(entry)) {
          retry = true;
        }
      }
      if (retry) {
        await syncDirectory(directory);
        continue;
      }

      const liveEntries = await listEntries(directory, options.error);
      const chooserIsActive = liveEntries.some(
        (entry) => entry.kind === "choosing",
      );
      const earlierTicketExists = liveEntries.some((entry) => {
        if (entry.kind !== "ticket" || entry.path === ticketPath) return false;
        if (entry.number! < number) return true;
        return entry.number === number && entry.name < ticketName!;
      });
      if (!chooserIsActive && !earlierTicketExists) {
        return {
          directory,
          ticketPath,
          token,
          error: options.error,
        };
      }
      if (Date.now() >= deadline) {
        throw options.error("Timed out waiting for the writer lock");
      }
      await new Promise<void>((resolveDelay) => {
        setTimeout(resolveDelay, waitMs);
      });
    }
  } catch (error) {
    await cleanupOwnPath(ticketPath);
    await cleanupOwnPath(choosingPath);
    throw error;
  }
}

export async function releaseFileLock(
  handle: FileLockHandle,
): Promise<void> {
  let current: string;
  try {
    current = await readSecureFile(handle.ticketPath, handle.error);
  } catch (error) {
    if (isErrorCode(error, "ENOENT")) {
      throw handle.error("Writer-lock ticket disappeared");
    }
    throw error;
  }
  if (current !== handle.token) {
    throw handle.error("Writer-lock ownership changed");
  }
  await unlink(handle.ticketPath);
  await syncDirectory(handle.directory);
}
