import {
  closeSync,
  chmodSync,
  constants,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { join, resolve } from "node:path";
import { randomUUID } from "node:crypto";
import {
  acquireFileLock,
  releaseFileLock,
} from "../internal/fileLock";
import { LOG_PREFIX } from "./constants";

const NOFOLLOW = constants.O_NOFOLLOW ?? 0;

/**
 * Manages append-only audit files. Each row is written with one synchronous append
 * so a process crash cannot leave an in-memory buffer that was reported as flushed.
 */
export class FileManager {
  private readonly requestedDirectory: string;
  private baseDir: string | null = null;
  private auditDate: string | null = null;

  constructor(baseDir: string) {
    if (!baseDir.trim()) {
      throw new Error(`${LOG_PREFIX} config.directory is required`);
    }
    this.requestedDirectory = resolve(baseDir);
  }

  initialize(): void {
    if (this.baseDir) return;
    if (!existsSync(this.requestedDirectory)) {
      mkdirSync(this.requestedDirectory, {
        recursive: true,
        mode: 0o700,
      });
    }
    const directoryStat = lstatSync(this.requestedDirectory);
    if (directoryStat.isSymbolicLink() || !directoryStat.isDirectory()) {
      throw new Error(
        `${LOG_PREFIX} config.directory must be a real directory, not a symlink`,
      );
    }
    chmodSync(this.requestedDirectory, 0o700);
    this.baseDir = realpathSync(this.requestedDirectory);
  }

  private requireBaseDir(): string {
    if (!this.baseDir) {
      throw new Error(
        `${LOG_PREFIX} audit state must be initialized before use`,
      );
    }
    return this.baseDir;
  }

  // Current audit stream date (if active).
  get currentAuditDate(): string | null {
    return this.auditDate;
  }

  auditFilePath(date: string): string {
    return join(this.requireBaseDir(), `audit-${date}.ndjson`);
  }

  auditHeadPath(date: string): string {
    return join(this.requireBaseDir(), `audit-${date}.head.json`);
  }

  readAuditTail(date: string): string | null {
    const filePath = this.auditFilePath(date);
    if (!existsSync(filePath)) return null;
    const content = readSecureFile(filePath);
    if (!content) return null;
    if (!content.endsWith("\n")) {
      throw new Error(`${LOG_PREFIX} cannot append to a truncated audit log`);
    }
    const lines = content.split("\n");
    for (let index = lines.length - 1; index >= 0; index -= 1) {
      const line = lines[index]?.trim();
      if (line) return line;
    }
    return null;
  }

  readAuditHead(date: string): string | null {
    const filePath = this.auditHeadPath(date);
    return existsSync(filePath) ? readSecureFile(filePath) : null;
  }

  /**
   * Serialize a read/sign/append/head transaction across SDK instances and local
   * processes. A lock left by a crashed process is recovered only after the
   * recorded PID is no longer alive.
   */
  async withAuditLock<T>(
    date: string,
    task: () => Promise<T>,
  ): Promise<T> {
    const baseDir = this.requireBaseDir();
    const lock = await acquireFileLock({
      rootDir: baseDir,
      name: `audit-${date}`,
      error: (message) => new Error(`${LOG_PREFIX} ${message}`),
    });
    try {
      return await task();
    } finally {
      await releaseFileLock(lock);
    }
  }

  // Ensure the audit stream targets the given date.
  // Returns the previous date if rotation occurred, or null otherwise.
  rotateAuditStream(date: string): string | null {
    if (this.auditDate === date) return null;
    const previousDate = this.auditDate;
    this.auditDate = date;
    return previousDate;
  }

  writeAuditLine(line: string): void {
    if (!this.auditDate) {
      throw new Error(`${LOG_PREFIX} audit stream is not initialized`);
    }
    appendAndSync(this.auditFilePath(this.auditDate), line);
  }

  writeAuditHead(date: string, line: string): void {
    const filePath = this.auditHeadPath(date);
    const temporaryPath = `${filePath}.${randomUUID()}.tmp`;
    try {
      const descriptor = openSync(
        temporaryPath,
        constants.O_WRONLY |
          constants.O_CREAT |
          constants.O_EXCL |
          NOFOLLOW,
        0o600,
      );
      try {
        writeAll(descriptor, line);
        fsyncSync(descriptor);
      } finally {
        closeSync(descriptor);
      }
      renameSync(temporaryPath, filePath);
      syncDirectory(this.requireBaseDir());
    } finally {
      if (existsSync(temporaryPath)) unlinkSync(temporaryPath);
    }
  }

  async drainAuditStream(): Promise<void> {
    this.requireBaseDir();
  }

  // Close all active streams and release resources.
  close(): void {
    this.auditDate = null;
  }
}

function appendAndSync(filePath: string, line: string): void {
  const descriptor = openSync(
    filePath,
    constants.O_WRONLY |
      constants.O_APPEND |
      constants.O_CREAT |
      NOFOLLOW,
    0o600,
  );
  try {
    if (!fstatSync(descriptor).isFile()) {
      throw new Error(`${LOG_PREFIX} audit target must be a regular file`);
    }
    writeAll(descriptor, line);
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function readSecureFile(filePath: string): string {
  const descriptor = openSync(
    filePath,
    constants.O_RDONLY | NOFOLLOW,
  );
  try {
    if (!fstatSync(descriptor).isFile()) {
      throw new Error(`${LOG_PREFIX} audit target must be a regular file`);
    }
    return readFileSync(descriptor, "utf8");
  } finally {
    closeSync(descriptor);
  }
}

function writeAll(descriptor: number, value: string): void {
  const bytes = Buffer.from(value);
  let offset = 0;
  while (offset < bytes.length) {
    offset += writeSync(
      descriptor,
      bytes,
      offset,
      bytes.length - offset,
    );
  }
}

function syncDirectory(directory: string): void {
  const descriptor = openSync(directory, "r");
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}
