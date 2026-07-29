import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  acquireFileLock,
  releaseFileLock,
} from "../src/internal/fileLock";

const temporaryDirectories: string[] = [];

function temporaryRoot(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "coreax-file-lock-"));
  temporaryDirectories.push(root);
  fs.chmodSync(root, 0o700);
  return root;
}

function unusedPid(): number {
  for (const candidate of [2_147_483_647, 1_073_741_823, 536_870_911]) {
    try {
      process.kill(candidate, 0);
    } catch (error) {
      if (
        error instanceof Error &&
        "code" in error &&
        (error as NodeJS.ErrnoException).code === "ESRCH"
      ) {
        return candidate;
      }
    }
  }
  throw new Error("could not find an unused PID for stale-lock testing");
}

afterEach(() => {
  while (temporaryDirectories.length > 0) {
    fs.rmSync(temporaryDirectories.pop()!, {
      force: true,
      recursive: true,
    });
  }
});

describe("cross-process file lock", () => {
  it("serializes live tickets and safely reclaims unique stale tickets", async () => {
    const rootDir = temporaryRoot();
    const lockDir = path.join(rootDir, ".writer.locks");
    fs.mkdirSync(lockDir, { mode: 0o700 });
    const stalePid = unusedPid();
    const staleChooser =
      `choosing-${stalePid}-${"a".repeat(32)}.lock`;
    const staleTicket =
      `ticket-${"1".padStart(20, "0")}-${stalePid}-${"b".repeat(32)}.lock`;
    fs.writeFileSync(path.join(lockDir, staleChooser), "stale", {
      mode: 0o600,
    });
    fs.writeFileSync(path.join(lockDir, staleTicket), "stale", {
      mode: 0o600,
    });

    const error = (message: string) => new Error(message);
    const first = await acquireFileLock({
      rootDir,
      name: "writer",
      error,
    });
    expect(fs.existsSync(path.join(lockDir, staleChooser))).toBe(false);
    expect(fs.existsSync(path.join(lockDir, staleTicket))).toBe(false);

    let secondSettled = false;
    const secondPromise = acquireFileLock({
      rootDir,
      name: "writer",
      error,
    }).then((handle) => {
      secondSettled = true;
      return handle;
    });
    await new Promise((resolve) => setTimeout(resolve, 25));
    expect(secondSettled).toBe(false);

    await releaseFileLock(first);
    const second = await secondPromise;
    await releaseFileLock(second);
    expect(fs.readdirSync(lockDir)).toEqual([]);
  });

  it("fails closed when the lock directory contains an unknown entry", async () => {
    const rootDir = temporaryRoot();
    const lockDir = path.join(rootDir, ".writer.locks");
    fs.mkdirSync(lockDir, { mode: 0o700 });
    fs.writeFileSync(path.join(lockDir, "unexpected"), "content", {
      mode: 0o600,
    });

    await expect(
      acquireFileLock({
        rootDir,
        name: "writer",
        error: (message) => new Error(message),
      }),
    ).rejects.toThrow(/invalid entry/);
  });
});
