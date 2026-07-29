import { constants } from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  open,
  realpath,
} from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve } from "node:path";

import {
  acquireFileLock,
  releaseFileLock,
} from "../internal/fileLock";
import {
  EscalationConflictError,
  EscalationNotFoundError,
  EscalationStoreCorruptionError,
  EscalationStoreNotInitializedError,
  EscalationValidationError,
} from "./errors";
import type {
  EscalationRequest,
  EscalationResolution,
  EscalationStore,
} from "./types";
import {
  canonicalJson,
  sameValue,
  sha256,
  timestampMs,
  validateEscalationRequest,
  validateEscalationResolution,
} from "./validation";

function clone<T>(value: T): T {
  return JSON.parse(canonicalJson(value)) as T;
}

function currentTime(now: () => number): number {
  const value = now();
  if (!Number.isFinite(value)) {
    throw new EscalationValidationError("Clock returned an invalid timestamp");
  }
  return value;
}

function assertResolutionMatchesRequest(
  request: EscalationRequest,
  resolution: EscalationResolution,
): void {
  if (resolution.escalationId !== request.id) {
    throw new EscalationConflictError(
      "Resolution does not belong to the escalation request",
      {
        escalationId: request.id,
        resolutionEscalationId: resolution.escalationId,
      },
    );
  }
  const createdAt = timestampMs(request.createdAt, "request.createdAt");
  const expiresAt = timestampMs(request.expiresAt, "request.expiresAt");
  const resolvedAt = timestampMs(resolution.resolvedAt, "resolution.resolvedAt");
  if (resolvedAt < createdAt || resolvedAt >= expiresAt) {
    throw new EscalationConflictError(
      "Resolution timestamp is outside the escalation approval window",
      { escalationId: request.id },
    );
  }
}

export class MemoryEscalationStore implements EscalationStore {
  private readonly requests = new Map<string, EscalationRequest>();
  private readonly resolutions = new Map<string, EscalationResolution>();

  constructor(private readonly now: () => number = () => Date.now()) {}

  initialize(): void {}

  putPending(request: EscalationRequest): EscalationRequest {
    validateEscalationRequest(request);
    const normalized = clone(request);
    const existing = this.requests.get(normalized.id);
    if (existing) {
      if (sameValue(existing, normalized)) return clone(existing);
      throw new EscalationConflictError(
        `Escalation "${normalized.id}" already exists with different content`,
        { escalationId: normalized.id },
      );
    }
    this.requests.set(normalized.id, normalized);
    return clone(normalized);
  }

  getPending(escalationId: string): EscalationRequest | null {
    const request = this.requests.get(escalationId);
    return request ? clone(request) : null;
  }

  listPending(): EscalationRequest[] {
    const now = currentTime(this.now);
    return [...this.requests.values()]
      .filter((request) => !this.resolutions.has(request.id))
      .filter((request) => timestampMs(request.expiresAt, "request.expiresAt") > now)
      .map(clone);
  }

  putResolution(resolution: EscalationResolution): EscalationResolution {
    validateEscalationResolution(resolution);
    const normalized = clone(resolution);
    const request = this.requests.get(normalized.escalationId);
    if (!request) {
      throw new EscalationNotFoundError(normalized.escalationId);
    }
    const existing = this.resolutions.get(normalized.escalationId);
    if (existing) {
      if (sameValue(existing, normalized)) return clone(existing);
      throw new EscalationConflictError(
        `Escalation "${normalized.escalationId}" is already resolved`,
        { escalationId: normalized.escalationId },
      );
    }
    const now = currentTime(this.now);
    if (now >= timestampMs(request.expiresAt, "request.expiresAt")) {
      throw new EscalationConflictError(
        `Escalation "${normalized.escalationId}" has expired`,
        { escalationId: normalized.escalationId },
      );
    }
    if (
      timestampMs(normalized.resolvedAt, "resolution.resolvedAt") > now
    ) {
      throw new EscalationConflictError(
        "Resolution timestamp must not be in the future",
        { escalationId: normalized.escalationId },
      );
    }
    assertResolutionMatchesRequest(request, normalized);
    this.resolutions.set(normalized.escalationId, normalized);
    return clone(normalized);
  }

  getResolution(escalationId: string): EscalationResolution | null {
    const resolution = this.resolutions.get(escalationId);
    return resolution ? clone(resolution) : null;
  }
}

type EscalationLogKind = "pending" | "resolution";

interface EscalationLogBody {
  format: "coreax-escalation-log";
  version: 1;
  kind: EscalationLogKind;
  value: EscalationRequest | EscalationResolution;
}

interface EscalationLogEnvelope extends EscalationLogBody {
  checksum: string;
}

function encodeLogRecord(
  kind: EscalationLogKind,
  value: EscalationRequest | EscalationResolution,
): string {
  const body: EscalationLogBody = {
    format: "coreax-escalation-log",
    version: 1,
    kind,
    value,
  };
  return `${canonicalJson({ ...body, checksum: sha256(canonicalJson(body)) })}\n`;
}

function decodeLogRecord<T extends EscalationRequest | EscalationResolution>(
  line: string,
  expectedKind: EscalationLogKind,
  filePath: string,
  lineNumber: number,
): T {
  try {
    const parsed = JSON.parse(line) as Partial<EscalationLogEnvelope>;
    if (
      parsed.format !== "coreax-escalation-log" ||
      parsed.version !== 1 ||
      parsed.kind !== expectedKind ||
      !parsed.value ||
      typeof parsed.checksum !== "string"
    ) {
      throw new EscalationValidationError("unsupported record envelope");
    }
    const body: EscalationLogBody = {
      format: parsed.format,
      version: parsed.version,
      kind: parsed.kind,
      value: parsed.value,
    };
    if (sha256(canonicalJson(body)) !== parsed.checksum) {
      throw new EscalationValidationError("checksum mismatch");
    }
    if (expectedKind === "pending") {
      validateEscalationRequest(parsed.value);
    } else {
      validateEscalationResolution(parsed.value);
    }
    return clone(parsed.value) as T;
  } catch (error) {
    if (error instanceof EscalationStoreCorruptionError) throw error;
    const message = error instanceof Error ? error.message : String(error);
    throw new EscalationStoreCorruptionError(filePath, lineNumber, message);
  }
}

async function readCompleteLog<T extends EscalationRequest | EscalationResolution>(
  filePath: string,
  kind: EscalationLogKind,
): Promise<T[]> {
  const handle = await open(
    filePath,
    constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
  );
  let content: string;
  try {
    content = await handle.readFile("utf8");
  } finally {
    await handle.close();
  }
  if (!content) return [];
  const lines = content.split("\n");
  if (lines.at(-1) !== "") {
    throw new EscalationStoreCorruptionError(
      filePath,
      0,
      "truncated log tail",
    );
  }
  lines.pop();
  return lines.map((line, index) =>
    decodeLogRecord<T>(line, kind, filePath, index + 1),
  );
}

async function recoverTruncatedTail(filePath: string): Promise<void> {
  const handle = await open(
    filePath,
    constants.O_RDWR | (constants.O_NOFOLLOW ?? 0),
  );
  try {
    const data = await handle.readFile();
    if (data.length === 0 || data[data.length - 1] === 0x0a) return;
    const lastNewline = data.lastIndexOf(0x0a);
    await handle.truncate(lastNewline < 0 ? 0 : lastNewline + 1);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

function isWithin(candidate: string, root: string): boolean {
  const relation = relative(root, candidate);
  return (
    relation === "" ||
    (!relation.startsWith("..") && !isAbsolute(relation))
  );
}

async function assertSafeParent(
  rootRealPath: string,
  filePath: string,
  create: boolean,
): Promise<void> {
  const parent = dirname(filePath);
  if (create) {
    await mkdir(parent, { recursive: true, mode: 0o700 });
  }
  const parentRealPath = await realpath(parent);
  if (!isWithin(parentRealPath, rootRealPath)) {
    throw new EscalationValidationError(
      `Escalation state path escapes rootDir through a symlink: ${filePath}`,
    );
  }
}

async function assertRegularFile(filePath: string): Promise<void> {
  const stats = await lstat(filePath);
  if (stats.isSymbolicLink() || !stats.isFile() || stats.nlink !== 1) {
    throw new EscalationValidationError(
      `Escalation state path must be a regular, non-linked file: ${filePath}`,
    );
  }
}

async function ensureFile(
  rootRealPath: string,
  filePath: string,
): Promise<void> {
  await assertSafeParent(rootRealPath, filePath, true);
  const handle = await open(
    filePath,
    constants.O_APPEND |
      constants.O_CREAT |
      constants.O_WRONLY |
      (constants.O_NOFOLLOW ?? 0),
    0o600,
  );
  try {
    await handle.chmod(0o600);
  } finally {
    await handle.close();
  }
  await assertRegularFile(filePath);
}

async function durableAppend(filePath: string, value: string): Promise<void> {
  const handle = await open(
    filePath,
    constants.O_APPEND |
      constants.O_WRONLY |
      (constants.O_NOFOLLOW ?? 0),
  );
  try {
    await handle.appendFile(value, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
}

export interface FileEscalationStorePaths {
  pending: string;
  resolutions: string;
}

export interface FileEscalationStoreConfig {
  rootDir?: string;
  paths?: Partial<FileEscalationStorePaths>;
  now?: () => number;
}

function resolveConfiguredPath(rootDir: string, value: string): string {
  const candidate = resolve(rootDir, value);
  if (candidate === rootDir || !isWithin(candidate, rootDir)) {
    throw new EscalationValidationError(
      `Escalation state path must stay within rootDir: ${value}`,
    );
  }
  return candidate;
}

const FILE_OPERATIONS = new Map<string, Promise<void>>();

function enqueueFileOperation<T>(
  key: string,
  operation: () => Promise<T>,
): Promise<T> {
  const previous = FILE_OPERATIONS.get(key) ?? Promise.resolve();
  const lockedOperation = () =>
    withEscalationLock(key, operation);
  const run = previous.then(lockedOperation, lockedOperation);
  const settled = run.then(
    () => undefined,
    () => undefined,
  );
  FILE_OPERATIONS.set(key, settled);
  void settled.then(() => {
    if (FILE_OPERATIONS.get(key) === settled) FILE_OPERATIONS.delete(key);
  });
  return run;
}

async function withEscalationLock<T>(
  rootDir: string,
  operation: () => Promise<T>,
): Promise<T> {
  await mkdir(rootDir, { recursive: true, mode: 0o700 });
  const rootStats = await lstat(rootDir);
  if (rootStats.isSymbolicLink() || !rootStats.isDirectory()) {
    throw new EscalationValidationError(
      "Escalation rootDir must be a real directory, not a symlink",
    );
  }
  await chmod(rootDir, 0o700);
  const lock = await acquireFileLock({
    rootDir,
    name: "escalation-writer",
    error: (message) => new EscalationValidationError(message),
  });
  try {
    return await operation();
  } finally {
    await releaseFileLock(lock);
  }
}

interface FileSnapshot {
  requests: Map<string, EscalationRequest>;
  resolutions: Map<string, EscalationResolution>;
}

export class FileEscalationStore implements EscalationStore {
  readonly rootDir: string;
  readonly paths: FileEscalationStorePaths;

  private initialized = false;
  private initialization: Promise<void> | null = null;
  private realRootPath: string | null = null;
  private readonly now: () => number;

  constructor(config: FileEscalationStoreConfig = {}) {
    this.rootDir = resolve(
      config.rootDir ?? resolve(process.cwd(), ".coreax", "escalation"),
    );
    this.paths = {
      pending: resolveConfiguredPath(
        this.rootDir,
        config.paths?.pending ?? "pending.ndjson",
      ),
      resolutions: resolveConfiguredPath(
        this.rootDir,
        config.paths?.resolutions ?? "resolutions.ndjson",
      ),
    };
    if (this.paths.pending === this.paths.resolutions) {
      throw new EscalationValidationError(
        "Pending and resolution logs must use different files",
      );
    }
    this.now = config.now ?? (() => Date.now());
  }

  initialize(): Promise<void> {
    if (this.initialized) return Promise.resolve();
    if (this.initialization) return this.initialization;
    this.initialization = enqueueFileOperation(this.rootDir, () =>
      this.initializeFiles(),
    ).finally(() => {
      this.initialization = null;
    });
    return this.initialization;
  }

  private async initializeFiles(): Promise<void> {
    await mkdir(this.rootDir, { recursive: true, mode: 0o700 });
    const rootStats = await lstat(this.rootDir);
    if (rootStats.isSymbolicLink() || !rootStats.isDirectory()) {
      throw new EscalationValidationError(
        "Escalation rootDir must be a real directory, not a symlink",
      );
    }
    this.realRootPath = await realpath(this.rootDir);
    await ensureFile(this.realRootPath, this.paths.pending);
    await ensureFile(this.realRootPath, this.paths.resolutions);
    await this.assertSafePaths();
    await recoverTruncatedTail(this.paths.pending);
    await recoverTruncatedTail(this.paths.resolutions);
    await this.loadSnapshot();
    this.initialized = true;
  }

  private async assertSafePaths(): Promise<void> {
    if (!this.realRootPath) {
      throw new EscalationStoreNotInitializedError();
    }
    const currentRootRealPath = await realpath(this.rootDir);
    if (currentRootRealPath !== this.realRootPath) {
      throw new EscalationValidationError(
        "Escalation rootDir changed after initialization",
      );
    }
    for (const filePath of [this.paths.pending, this.paths.resolutions]) {
      await assertSafeParent(this.realRootPath, filePath, false);
      await assertRegularFile(filePath);
    }
  }

  private assertInitialized(): void {
    if (!this.initialized) {
      throw new EscalationStoreNotInitializedError();
    }
  }

  private async loadSnapshot(): Promise<FileSnapshot> {
    await this.assertSafePaths();
    const requestRows = await readCompleteLog<EscalationRequest>(
      this.paths.pending,
      "pending",
    );
    const resolutionRows = await readCompleteLog<EscalationResolution>(
      this.paths.resolutions,
      "resolution",
    );
    const requests = new Map<string, EscalationRequest>();
    const resolutions = new Map<string, EscalationResolution>();

    for (const request of requestRows) {
      const existing = requests.get(request.id);
      if (existing && !sameValue(existing, request)) {
        throw new EscalationStoreCorruptionError(
          this.paths.pending,
          0,
          `conflicting duplicate request "${request.id}"`,
        );
      }
      requests.set(request.id, request);
    }

    for (const resolution of resolutionRows) {
      const request = requests.get(resolution.escalationId);
      if (!request) {
        throw new EscalationStoreCorruptionError(
          this.paths.resolutions,
          0,
          `orphan resolution "${resolution.id}"`,
        );
      }
      try {
        assertResolutionMatchesRequest(request, resolution);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        throw new EscalationStoreCorruptionError(
          this.paths.resolutions,
          0,
          message,
        );
      }
      const existing = resolutions.get(resolution.escalationId);
      if (existing && !sameValue(existing, resolution)) {
        throw new EscalationStoreCorruptionError(
          this.paths.resolutions,
          0,
          `conflicting resolutions for "${resolution.escalationId}"`,
        );
      }
      resolutions.set(resolution.escalationId, resolution);
    }

    return { requests, resolutions };
  }

  private async recoverLogs(): Promise<void> {
    await this.assertSafePaths();
    await recoverTruncatedTail(this.paths.pending);
    await recoverTruncatedTail(this.paths.resolutions);
  }

  private enqueueOperation<T>(operation: () => Promise<T>): Promise<T> {
    return enqueueFileOperation(this.rootDir, operation);
  }

  async putPending(request: EscalationRequest): Promise<EscalationRequest> {
    this.assertInitialized();
    validateEscalationRequest(request);
    const normalized = clone(request);
    return this.enqueueOperation(async () => {
      await this.recoverLogs();
      const snapshot = await this.loadSnapshot();
      const existing = snapshot.requests.get(normalized.id);
      if (existing) {
        if (sameValue(existing, normalized)) return clone(existing);
        throw new EscalationConflictError(
          `Escalation "${normalized.id}" already exists with different content`,
          { escalationId: normalized.id },
        );
      }
      await durableAppend(
        this.paths.pending,
        encodeLogRecord("pending", normalized),
      );
      return clone(normalized);
    });
  }

  async getPending(escalationId: string): Promise<EscalationRequest | null> {
    this.assertInitialized();
    return this.enqueueOperation(async () => {
      const request = (await this.loadSnapshot()).requests.get(escalationId);
      return request ? clone(request) : null;
    });
  }

  async listPending(): Promise<EscalationRequest[]> {
    this.assertInitialized();
    return this.enqueueOperation(async () => {
      const snapshot = await this.loadSnapshot();
      const now = currentTime(this.now);
      return [...snapshot.requests.values()]
        .filter((request) => !snapshot.resolutions.has(request.id))
        .filter(
          (request) =>
            timestampMs(request.expiresAt, "request.expiresAt") > now,
        )
        .map(clone);
    });
  }

  async putResolution(
    resolution: EscalationResolution,
  ): Promise<EscalationResolution> {
    this.assertInitialized();
    validateEscalationResolution(resolution);
    const normalized = clone(resolution);
    return this.enqueueOperation(async () => {
      await this.recoverLogs();
      const snapshot = await this.loadSnapshot();
      const request = snapshot.requests.get(normalized.escalationId);
      if (!request) {
        throw new EscalationNotFoundError(normalized.escalationId);
      }
      const existing = snapshot.resolutions.get(normalized.escalationId);
      if (existing) {
        if (sameValue(existing, normalized)) return clone(existing);
        throw new EscalationConflictError(
          `Escalation "${normalized.escalationId}" is already resolved`,
          { escalationId: normalized.escalationId },
        );
      }
      const now = currentTime(this.now);
      if (now >= timestampMs(request.expiresAt, "request.expiresAt")) {
        throw new EscalationConflictError(
          `Escalation "${normalized.escalationId}" has expired`,
          { escalationId: normalized.escalationId },
        );
      }
      if (
        timestampMs(normalized.resolvedAt, "resolution.resolvedAt") > now
      ) {
        throw new EscalationConflictError(
          "Resolution timestamp must not be in the future",
          { escalationId: normalized.escalationId },
        );
      }
      assertResolutionMatchesRequest(request, normalized);
      await durableAppend(
        this.paths.resolutions,
        encodeLogRecord("resolution", normalized),
      );
      return clone(normalized);
    });
  }

  async getResolution(
    escalationId: string,
  ): Promise<EscalationResolution | null> {
    this.assertInitialized();
    return this.enqueueOperation(async () => {
      const resolution = (await this.loadSnapshot()).resolutions.get(
        escalationId,
      );
      return resolution ? clone(resolution) : null;
    });
  }
}
