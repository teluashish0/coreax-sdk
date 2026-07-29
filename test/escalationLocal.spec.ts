import { generateKeyPairSync } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import {
  ApprovalCapabilityIssueError,
  createLocalEscalationManager,
  EscalationApprovalRequiredError,
  EscalationConflictError,
  EscalationResolverError,
  EscalationStoreCorruptionError,
  EscalationStoreNotInitializedError,
  EscalationValidationError,
  FileApprovalNonceStore,
  FileEscalationStore,
  fingerprintApprovalKey,
  issueApprovalCapability,
  MemoryApprovalNonceStore,
  MemoryEscalationStore,
  StaticApprovalKeyring,
  verifyApprovalCapability,
  type EscalationResolution,
} from "../src/escalation";

const tempDirs: string[] = [];

function makeTempDir(): string {
  const directory = fs.mkdtempSync(
    path.join(os.tmpdir(), "coreax-escalation-"),
  );
  tempDirs.push(directory);
  return directory;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    fs.rmSync(tempDirs.pop()!, { force: true, recursive: true });
  }
});

function createClock(initial = Date.parse("2026-01-01T00:00:00.000Z")) {
  let current = initial;
  return {
    now: () => current,
    advance: (milliseconds: number) => {
      current += milliseconds;
    },
  };
}

describe("local escalation manager", () => {
  it("fails closed until an explicit, unexpired approval exists", async () => {
    const clock = createClock();
    let id = 0;
    const manager = createLocalEscalationManager({
      now: clock.now,
      idFactory: () => `generated-${++id}`,
    });
    await manager.initialize();

    const pending = await manager.create({
      id: "escalation-1",
      action: "filesystem.write",
      scope: { path: "/workspace/report.json", operation: "replace" },
      reason: "Side effect crosses the configured write boundary",
      requestedBy: "agent-1",
      ttlMs: 5_000,
    });

    expect(pending.status).toBe("pending");
    await expect(manager.requireApproved(pending.request.id)).rejects.toBeInstanceOf(
      EscalationApprovalRequiredError,
    );
    await expect(manager.requireApproved("missing")).rejects.toBeInstanceOf(
      EscalationApprovalRequiredError,
    );

    const approved = await manager.resolve({
      escalationId: pending.request.id,
      resolutionId: "approval-1",
      decision: "approve",
      resolvedBy: "reviewer@example.test",
    });
    expect(approved.status).toBe("approved");
    await expect(manager.requireApproved(pending.request.id)).resolves.toMatchObject({
      status: "approved",
      resolution: { id: "approval-1", decision: "approve" },
    });

    clock.advance(5_000);
    await expect(manager.requireApproved(pending.request.id)).rejects.toMatchObject({
      details: { status: "expired" },
    });
  });

  it("waits locally and validates caller-supplied resolutions before storing them", async () => {
    const clock = createClock();
    let polls = 0;
    const manager = createLocalEscalationManager({
      now: clock.now,
      sleep: async (milliseconds) => {
        clock.advance(milliseconds);
      },
      resolver: {
        getResolution: async (request): Promise<EscalationResolution | null> => {
          polls += 1;
          if (polls < 2) return null;
          return {
            id: "resolution-from-caller",
            escalationId: request.id,
            decision: "approve",
            resolvedBy: "local-reviewer",
            resolvedAt: new Date(clock.now()).toISOString(),
          };
        },
      },
    });
    await manager.initialize();
    await manager.create({
      id: "escalation-wait",
      action: "change.apply",
      scope: { changeId: "change-7" },
      reason: "Protected change",
      ttlMs: 5_000,
    });

    await expect(
      manager.waitForResolution("escalation-wait", {
        timeoutMs: 1_000,
        pollIntervalMs: 10,
      }),
    ).resolves.toMatchObject({
      status: "approved",
      resolution: { id: "resolution-from-caller" },
    });

    const invalidManager = createLocalEscalationManager({
      now: clock.now,
      resolver: {
        getResolution: async () => ({
          id: "wrong-resolution",
          escalationId: "another-escalation",
          decision: "approve",
          resolvedBy: "local-reviewer",
          resolvedAt: new Date(clock.now()).toISOString(),
        }),
      },
    });
    await invalidManager.initialize();
    await invalidManager.create({
      id: "escalation-invalid-resolution",
      action: "change.apply",
      scope: { changeId: "change-8" },
      reason: "Protected change",
    });
    await expect(
      invalidManager.requireApproved("escalation-invalid-resolution"),
    ).rejects.toBeInstanceOf(EscalationResolverError);
  });

  it("does not let a hostile resolver mutate the persisted approval scope", async () => {
    const clock = createClock();
    const store = new MemoryEscalationStore(clock.now);
    const manager = createLocalEscalationManager({
      now: clock.now,
      store,
      resolver: {
        getResolution: async (request) => {
          (request.scope as { path: string }).path = "/outside";
          request.expiresAt = "2099-01-01T00:00:00.000Z";
          return null;
        },
      },
    });
    await manager.initialize();
    await manager.create({
      id: "immutable-resolver-request",
      action: "filesystem.write",
      scope: { path: "/workspace/report.json" },
      reason: "Protected write",
    });

    await expect(
      manager.get("immutable-resolver-request"),
    ).rejects.toBeInstanceOf(EscalationResolverError);
    expect(store.getPending("immutable-resolver-request")).toMatchObject({
      scope: { path: "/workspace/report.json" },
      expiresAt: "2026-01-01T00:15:00.000Z",
    });
  });
});

describe("file escalation state", () => {
  it("is initialization-only, durable, serialized, and recovers a truncated tail", async () => {
    const clock = createClock();
    const rootDir = path.join(makeTempDir(), "state");
    const store = new FileEscalationStore({ rootDir, now: clock.now });
    expect(fs.existsSync(rootDir)).toBe(false);
    await expect(store.listPending()).rejects.toBeInstanceOf(
      EscalationStoreNotInitializedError,
    );
    await store.initialize();
    expect(fs.existsSync(rootDir)).toBe(true);

    const manager = createLocalEscalationManager({
      store,
      now: clock.now,
    });
    await manager.initialize();
    await Promise.all(
      Array.from({ length: 8 }, (_, index) =>
        manager.create({
          id: `file-escalation-${index}`,
          action: "tool.execute",
          scope: { tool: `tool-${index}` },
          reason: "Tool requires review",
        }),
      ),
    );
    await manager.resolve({
      escalationId: "file-escalation-3",
      resolutionId: "file-approval-3",
      decision: "approve",
      resolvedBy: "reviewer",
    });
    expect(await manager.listPending()).toHaveLength(7);

    fs.appendFileSync(store.paths.resolutions, '{"incomplete":', "utf8");
    const beforeRecovery = fs.statSync(store.paths.resolutions).size;
    await expect(
      store.getResolution("file-escalation-3"),
    ).rejects.toBeInstanceOf(EscalationStoreCorruptionError);
    const recoveredStore = new FileEscalationStore({ rootDir, now: clock.now });
    await recoveredStore.initialize();
    const afterRecovery = fs.statSync(store.paths.resolutions).size;
    expect(afterRecovery).toBeLessThan(beforeRecovery);

    const recoveredManager = createLocalEscalationManager({
      store: recoveredStore,
      now: clock.now,
    });
    await recoveredManager.initialize();
    await expect(
      recoveredManager.requireApproved("file-escalation-3"),
    ).resolves.toMatchObject({
      status: "approved",
      resolution: { id: "file-approval-3" },
    });
  });

  it("rejects a complete log record whose integrity envelope is invalid", async () => {
    const rootDir = path.join(makeTempDir(), "state");
    const store = new FileEscalationStore({ rootDir });
    await store.initialize();
    fs.appendFileSync(store.paths.pending, "{}\n", "utf8");

    const reopened = new FileEscalationStore({ rootDir });
    await expect(reopened.initialize()).rejects.toBeInstanceOf(
      EscalationStoreCorruptionError,
    );
  });

  it("serializes conflicting resolutions across store instances", async () => {
    const clock = createClock();
    const rootDir = path.join(makeTempDir(), "shared-state");
    const firstStore = new FileEscalationStore({ rootDir, now: clock.now });
    const secondStore = new FileEscalationStore({ rootDir, now: clock.now });
    await Promise.all([firstStore.initialize(), secondStore.initialize()]);
    const firstManager = createLocalEscalationManager({
      store: firstStore,
      now: clock.now,
    });
    const secondManager = createLocalEscalationManager({
      store: secondStore,
      now: clock.now,
    });
    await firstManager.create({
      id: "shared-resolution",
      action: "database.update",
      scope: { row: "record-1" },
      reason: "Protected mutation",
    });

    const results = await Promise.allSettled([
      firstManager.resolve({
        escalationId: "shared-resolution",
        resolutionId: "resolution-a",
        decision: "approve",
        resolvedBy: "reviewer-a",
      }),
      secondManager.resolve({
        escalationId: "shared-resolution",
        resolutionId: "resolution-b",
        decision: "reject",
        resolvedBy: "reviewer-b",
      }),
    ]);

    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(
      1,
    );
    const rejected = results.find(
      (result): result is PromiseRejectedResult =>
        result.status === "rejected",
    );
    expect(rejected?.reason).toBeInstanceOf(EscalationConflictError);
    const reopened = new FileEscalationStore({ rootDir, now: clock.now });
    await expect(reopened.initialize()).resolves.toBeUndefined();
    expect(await reopened.getResolution("shared-resolution")).not.toBeNull();
  });

  it("rejects configured paths outside the root and symlinked parents", async () => {
    const base = makeTempDir();
    const rootDir = path.join(base, "state");
    expect(
      () =>
        new FileEscalationStore({
          rootDir,
          paths: { pending: "../outside.ndjson" },
        }),
    ).toThrow(EscalationValidationError);
    expect(fs.existsSync(rootDir)).toBe(false);

    fs.mkdirSync(rootDir, { recursive: true });
    const outside = path.join(base, "outside");
    fs.mkdirSync(outside);
    fs.symlinkSync(outside, path.join(rootDir, "linked"));
    const linkedStore = new FileEscalationStore({
      rootDir,
      paths: { pending: "linked/pending.ndjson" },
    });
    await expect(linkedStore.initialize()).rejects.toBeInstanceOf(
      EscalationValidationError,
    );
    expect(fs.readdirSync(outside)).toEqual([]);
  });
});

describe("signed approval capabilities", () => {
  it("binds approval, escalation, action, scope, key, expiry, and nonce", async () => {
    const clock = createClock();
    const manager = createLocalEscalationManager({ now: clock.now });
    await manager.initialize();
    await manager.create({
      id: "capability-escalation",
      action: "database.update",
      scope: {
        table: "projects",
        row: "project-17",
        credential: "must-not-appear-in-capability",
      },
      reason: "Protected data mutation",
      ttlMs: 10_000,
    });
    const state = await manager.resolve({
      escalationId: "capability-escalation",
      resolutionId: "capability-approval",
      decision: "approve",
      resolvedBy: "reviewer",
    });
    const signingKeys = generateKeyPairSync("ed25519");
    const otherKeys = generateKeyPairSync("ed25519");
    const keyId = fingerprintApprovalKey(signingKeys.publicKey);
    const token = issueApprovalCapability({
      state,
      privateKey: signingKeys.privateKey,
      ttlMs: 1_000,
      nonce: "single-use-nonce",
      now: clock.now,
    });
    const expected = {
      escalationId: state.request.id,
      approvalId: state.resolution!.id,
      action: state.request.action,
      scope: state.request.scope,
    };

    const decodedClaims = JSON.parse(
      Buffer.from(token.split(".")[1]!, "base64url").toString("utf8"),
    ) as Record<string, unknown>;
    expect(decodedClaims).not.toHaveProperty("scope");
    expect(JSON.stringify(decodedClaims)).not.toContain(
      "must-not-appear-in-capability",
    );

    const valid = await verifyApprovalCapability({
      token,
      expected,
      keyResolver: new StaticApprovalKeyring({
        [keyId]: signingKeys.publicKey,
      }),
      expectedKeyId: keyId,
      nonceStore: new MemoryApprovalNonceStore(clock.now),
      now: clock.now,
    });
    expect(valid).toMatchObject({
      valid: true,
      keyId,
      claims: {
        escalationId: "capability-escalation",
        approvalId: "capability-approval",
        action: "database.update",
      },
    });

    const replayStore = new MemoryApprovalNonceStore(clock.now);
    await expect(
      verifyApprovalCapability({
        token,
        expected,
        publicKey: signingKeys.publicKey,
        nonceStore: replayStore,
        now: clock.now,
      }),
    ).resolves.toMatchObject({ valid: true });
    await expect(
      verifyApprovalCapability({
        token,
        expected,
        publicKey: signingKeys.publicKey,
        nonceStore: replayStore,
        now: clock.now,
      }),
    ).resolves.toEqual({ valid: false, reason: "replayed" });

    await expect(
      verifyApprovalCapability({
        token,
        expected: {
          ...expected,
          scope: { ...expected.scope, row: "project-18" },
        },
        publicKey: signingKeys.publicKey,
        nonceStore: new MemoryApprovalNonceStore(clock.now),
        now: clock.now,
      }),
    ).resolves.toEqual({ valid: false, reason: "scope_mismatch" });
    await expect(
      verifyApprovalCapability({
        token,
        expected,
        publicKey: otherKeys.publicKey,
        nonceStore: new MemoryApprovalNonceStore(clock.now),
        now: clock.now,
      }),
    ).resolves.toEqual({ valid: false, reason: "unknown_key" });
    await expect(
      verifyApprovalCapability({
        token,
        expected: { ...expected, escalationId: "another-escalation" },
        publicKey: signingKeys.publicKey,
        nonceStore: new MemoryApprovalNonceStore(clock.now),
        now: clock.now,
      }),
    ).resolves.toEqual({
      valid: false,
      reason: "escalation_mismatch",
    });
    await expect(
      verifyApprovalCapability({
        token,
        expected: Object.defineProperty(
          { ...expected },
          "escalationId",
          {
            get() {
              throw new Error("hostile expected scope");
            },
          },
        ),
        publicKey: signingKeys.publicKey,
        nonceStore: new MemoryApprovalNonceStore(clock.now),
        now: clock.now,
      }),
    ).resolves.toEqual({ valid: false, reason: "invalid_claims" });
    await expect(
      verifyApprovalCapability({
        token,
        expected,
        keyResolver: () => {
          throw new Error("resolver failed");
        },
        nonceStore: new MemoryApprovalNonceStore(clock.now),
        now: clock.now,
      }),
    ).resolves.toEqual({ valid: false, reason: "unknown_key" });

    clock.advance(1_000);
    await expect(
      verifyApprovalCapability({
        token,
        expected,
        publicKey: signingKeys.publicKey,
        nonceStore: new MemoryApprovalNonceStore(clock.now),
        now: clock.now,
      }),
    ).resolves.toEqual({ valid: false, reason: "expired" });

    expect(() =>
      issueApprovalCapability({
        state,
        privateKey: signingKeys.privateKey,
        keyId: "untrusted-alias",
        ttlMs: 1_000,
        nonce: "aliased-nonce",
        now: () => Date.parse("2026-01-01T00:00:00.000Z"),
      }),
    ).toThrow(ApprovalCapabilityIssueError);

    const claimsPart = token.split(".")[1]!;
    const ambiguousClaims = JSON.parse(
      Buffer.from(claimsPart, "base64url").toString("utf8"),
    ) as Record<string, unknown>;
    ambiguousClaims.issuedAt = "2026-01-01T00:00:00";
    const ambiguousToken = [
      token.split(".")[0]!,
      Buffer.from(JSON.stringify(ambiguousClaims), "utf8").toString(
        "base64url",
      ),
      token.split(".")[2]!,
    ].join(".");
    await expect(
      verifyApprovalCapability({
        token: ambiguousToken,
        expected,
        publicKey: signingKeys.publicKey,
        nonceStore: new MemoryApprovalNonceStore(clock.now),
        now: clock.now,
      }),
    ).resolves.toEqual({ valid: false, reason: "invalid_claims" });
  });

  it("rejects missing or non-approved resolutions and persists replay defense", async () => {
    const clock = createClock();
    const manager = createLocalEscalationManager({ now: clock.now });
    await manager.initialize();
    const pending = await manager.create({
      id: "pending-capability",
      action: "message.send",
      scope: { channel: "operations" },
      reason: "Outbound message",
    });
    const keys = generateKeyPairSync("ed25519");
    expect(() =>
      issueApprovalCapability({
        state: pending,
        privateKey: keys.privateKey,
        now: clock.now,
      }),
    ).toThrow(ApprovalCapabilityIssueError);
    expect(() =>
      issueApprovalCapability({
        state: null,
        privateKey: keys.privateKey,
        now: clock.now,
      }),
    ).toThrow(ApprovalCapabilityIssueError);
    const rejected = await manager.resolve({
      escalationId: pending.request.id,
      resolutionId: "rejected-resolution",
      decision: "reject",
      resolvedBy: "reviewer",
    });
    expect(() =>
      issueApprovalCapability({
        state: rejected,
        privateKey: keys.privateKey,
        now: clock.now,
      }),
    ).toThrow(ApprovalCapabilityIssueError);
    await expect(
      verifyApprovalCapability({
        token: null,
        expected: {
          escalationId: "pending-capability",
          approvalId: "missing",
          action: "message.send",
          scope: { channel: "operations" },
        },
        publicKey: keys.publicKey,
        nonceStore: new MemoryApprovalNonceStore(clock.now),
        now: clock.now,
      }),
    ).resolves.toEqual({ valid: false, reason: "missing" });

    const nonceRoot = path.join(makeTempDir(), "nonces");
    const firstStore = new FileApprovalNonceStore({
      rootDir: nonceRoot,
      now: clock.now,
    });
    const secondStore = new FileApprovalNonceStore({
      rootDir: nonceRoot,
      now: clock.now,
    });
    await Promise.all([firstStore.initialize(), secondStore.initialize()]);
    const results = await Promise.all([
      firstStore.consume(
        "cross-process-safe-nonce",
        "2026-01-01T00:01:00.000Z",
      ),
      secondStore.consume(
        "cross-process-safe-nonce",
        "2026-01-01T00:01:00.000Z",
      ),
    ]);
    expect(results.sort()).toEqual([false, true]);
    expect(
      fs.readdirSync(nonceRoot).every((name) =>
        /^[a-f0-9]{64}\.used$/.test(name),
      ),
    ).toBe(true);
  });

  it.skipIf(process.platform === "win32")(
    "rejects symlinked nonce roots and uses private directory permissions",
    async () => {
      const base = makeTempDir();
      const target = path.join(base, "target-nonces");
      const linked = path.join(base, "linked-nonces");
      fs.mkdirSync(target, { mode: 0o700 });
      fs.symlinkSync(target, linked, "dir");

      await expect(
        new FileApprovalNonceStore({ rootDir: linked }).initialize(),
      ).rejects.toThrow(/not a symlink/i);

      const privateRoot = path.join(base, "private-nonces");
      fs.mkdirSync(privateRoot, { mode: 0o777 });
      const store = new FileApprovalNonceStore({ rootDir: privateRoot });
      await store.initialize();
      expect(fs.statSync(privateRoot).mode & 0o077).toBe(0);
    },
  );
});
