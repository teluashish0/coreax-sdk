import { generateKeyPairSync, type KeyObject } from "node:crypto";

import { describe, expect, it, vi } from "vitest";

import {
  createLocalEscalationManager,
  issueApprovalCapability,
  MemoryApprovalNonceStore,
  type CreateEscalationInput,
  type EscalationState,
  type LocalEscalationManager,
} from "../src/escalation";
import {
  createCoreaxGuard,
  type GuardApprovalCapabilityConfig,
} from "../src/guard";
import type { CoreaxPolicy } from "../src/policy";

const APPROVAL_TIME = Date.parse("2026-01-01T00:00:00.000Z");
const ESCALATED_POLICY: CoreaxPolicy = {
  version: 1,
  tools: { allow: ["read@1.0"] },
  enforcement: {
    denyOn: [],
    escalateOn: ["tool_not_in_allowlist"],
  },
};
const GUARDED_INPUT = {
  kind: "tool_call" as const,
  target: "records.delete@1.0",
  content: { id: "record-7" },
};

function approvedManager(
  now: () => number,
  escalationId = "guard-approval-1",
) {
  return createLocalEscalationManager({
    now,
    idFactory: () => escalationId,
    resolver: {
      getResolution: (request) => ({
        id: "review-resolution-1",
        escalationId: request.id,
        decision: "approve" as const,
        resolvedBy: "local-reviewer",
        resolvedAt: new Date(now()).toISOString(),
      }),
    },
  });
}

function createEscalatingGuard(options: {
  now?: () => number;
  manager?: ReturnType<typeof approvedManager>;
  approvalCapability?: GuardApprovalCapabilityConfig;
}) {
  const now = options.now ?? (() => APPROVAL_TIME);
  return createCoreaxGuard({
    now,
    provider: { local: { policy: ESCALATED_POLICY } },
    escalation: {
      enabled: true,
      manager: options.manager ?? approvedManager(now),
      ...(options.approvalCapability
        ? { approvalCapability: options.approvalCapability }
        : {}),
    },
  });
}

function signedCapabilityConfig(options: {
  privateKey: KeyObject;
  publicKey: KeyObject;
  now?: () => number;
  transformState?: (state: EscalationState) => EscalationState;
  nonce?: string;
}): GuardApprovalCapabilityConfig {
  const now = options.now ?? (() => APPROVAL_TIME);
  return {
    publicKey: options.publicKey,
    nonceStore: new MemoryApprovalNonceStore(now),
    getCapability: ({ resolution }) =>
      issueApprovalCapability({
        state: options.transformState?.(resolution) ?? resolution,
        privateKey: options.privateKey,
        nonce: options.nonce,
        now,
      }),
  };
}

function adversarialManager(options: {
  now: () => number;
  mutateCreateInput?: (input: CreateEscalationInput) => void;
  transformWait?: (state: EscalationState) => EscalationState;
}): LocalEscalationManager {
  const base = approvedManager(options.now);
  return {
    initialize: () => base.initialize(),
    async create(input) {
      options.mutateCreateInput?.(input);
      return base.create(input);
    },
    get: (escalationId) => base.get(escalationId),
    listPending: () => base.listPending(),
    resolve: (input) => base.resolve(input),
    async waitForResolution(escalationId, waitOptions) {
      const state = await base.waitForResolution(
        escalationId,
        waitOptions,
      );
      return options.transformWait?.(structuredClone(state)) ?? state;
    },
    requireApproved: (escalationId) =>
      base.requireApproved(escalationId),
  };
}

describe("guard approval capability enforcement", () => {
  it("executes only after a signed, scoped, unexpired capability verifies", async () => {
    const keys = generateKeyPairSync("ed25519");
    const action = vi.fn(async () => "deleted");
    const guard = createEscalatingGuard({
      approvalCapability: signedCapabilityConfig({
        privateKey: keys.privateKey,
        publicKey: keys.publicKey,
      }),
    });

    await expect(guard.execute(GUARDED_INPUT, action)).resolves.toMatchObject({
      decision: { outcome: "escalate" },
      escalation: { status: "approved" },
      value: "deleted",
    });
    expect(action).toHaveBeenCalledTimes(1);
  });

  it("fails closed when an approved resolution has no capability verifier", async () => {
    const action = vi.fn(async () => "must-not-run");
    const guard = createEscalatingGuard({});

    await expect(guard.execute(GUARDED_INPUT, action)).rejects.toMatchObject({
      code: "COREAX_GUARD_BLOCKED",
      details: { reason: "missing" },
    });
    expect(action).not.toHaveBeenCalled();
  });

  it("rejects a capability signed by the wrong key", async () => {
    const signer = generateKeyPairSync("ed25519");
    const trusted = generateKeyPairSync("ed25519");
    const action = vi.fn(async () => "must-not-run");
    const guard = createEscalatingGuard({
      approvalCapability: signedCapabilityConfig({
        privateKey: signer.privateKey,
        publicKey: trusted.publicKey,
      }),
    });

    await expect(guard.execute(GUARDED_INPUT, action)).rejects.toMatchObject({
      code: "COREAX_GUARD_BLOCKED",
      details: { reason: "unknown_key" },
    });
    expect(action).not.toHaveBeenCalled();
  });

  it("rejects a valid signature whose scope does not match the guarded action", async () => {
    const keys = generateKeyPairSync("ed25519");
    const action = vi.fn(async () => "must-not-run");
    const guard = createEscalatingGuard({
      approvalCapability: signedCapabilityConfig({
        privateKey: keys.privateKey,
        publicKey: keys.publicKey,
        transformState: (state) => ({
          ...state,
          request: {
            ...state.request,
            scope: { ...state.request.scope, target: "records.read@1.0" },
          },
        }),
      }),
    });

    await expect(guard.execute(GUARDED_INPUT, action)).rejects.toMatchObject({
      code: "COREAX_GUARD_BLOCKED",
      details: { reason: "scope_mismatch" },
    });
    expect(action).not.toHaveBeenCalled();
  });

  it("consumes approval nonces and rejects replay before a second execution", async () => {
    const keys = generateKeyPairSync("ed25519");
    const now = () => APPROVAL_TIME;
    const manager = approvedManager(now, "stable-escalation");
    const nonceStore = new MemoryApprovalNonceStore(now);
    let token: string | undefined;
    const action = vi.fn(async () => "deleted");
    const guard = createEscalatingGuard({
      now,
      manager,
      approvalCapability: {
        publicKey: keys.publicKey,
        nonceStore,
        getCapability: ({ resolution }) => {
          token ??= issueApprovalCapability({
            state: resolution,
            privateKey: keys.privateKey,
            nonce: "single-use-approval",
            now,
          });
          return token;
        },
      },
    });

    await expect(guard.execute(GUARDED_INPUT, action)).resolves.toMatchObject({
      value: "deleted",
    });
    await expect(guard.execute(GUARDED_INPUT, action)).rejects.toMatchObject({
      code: "COREAX_GUARD_BLOCKED",
      details: { reason: "replayed" },
    });
    expect(action).toHaveBeenCalledTimes(1);
  });

  it("rejects a capability that expires before verification", async () => {
    const keys = generateKeyPairSync("ed25519");
    let current = APPROVAL_TIME;
    const now = () => current;
    const action = vi.fn(async () => "must-not-run");
    const guard = createEscalatingGuard({
      now,
      manager: approvedManager(now),
      approvalCapability: {
        publicKey: keys.publicKey,
        nonceStore: new MemoryApprovalNonceStore(now),
        getCapability: ({ resolution }) => {
          const capability = issueApprovalCapability({
            state: resolution,
            privateKey: keys.privateKey,
            ttlMs: 1,
            now,
          });
          current += 2;
          return capability;
        },
      },
    });

    await expect(guard.execute(GUARDED_INPUT, action)).rejects.toMatchObject({
      code: "COREAX_GUARD_BLOCKED",
      details: { reason: "expired" },
    });
    expect(action).not.toHaveBeenCalled();
  });

  it("rejects a manager that mutates the canonical request during creation", async () => {
    const keys = generateKeyPairSync("ed25519");
    const now = () => APPROVAL_TIME;
    const action = vi.fn(async () => "must-not-run");
    const getCapability = vi.fn(() => null);
    const manager = adversarialManager({
      now,
      mutateCreateInput(input) {
        input.action = "records.read@1.0";
        input.scope = {
          ...input.scope,
          target: "records.read@1.0",
          contentSha256: "0".repeat(64),
        };
      },
    });
    const guard = createEscalatingGuard({
      now,
      manager,
      approvalCapability: {
        publicKey: keys.publicKey,
        nonceStore: new MemoryApprovalNonceStore(now),
        getCapability,
      },
    });

    await expect(guard.execute(GUARDED_INPUT, action)).rejects.toMatchObject({
      code: "COREAX_GUARD_ESCALATION_FAILED",
      message: expect.stringContaining("substituted"),
    });
    expect(getCapability).not.toHaveBeenCalled();
    expect(action).not.toHaveBeenCalled();
  });

  it.each([
    {
      label: "request ID",
      transform(state: EscalationState): EscalationState {
        return {
          ...state,
          request: { ...state.request, id: "substituted-escalation" },
          resolution: state.resolution
            ? {
                ...state.resolution,
                escalationId: "substituted-escalation",
              }
            : null,
        };
      },
    },
    {
      label: "action",
      transform(state: EscalationState): EscalationState {
        return {
          ...state,
          request: {
            ...state.request,
            action: "records.read@1.0",
          },
        };
      },
    },
    {
      label: "scope",
      transform(state: EscalationState): EscalationState {
        return {
          ...state,
          request: {
            ...state.request,
            scope: {
              ...state.request.scope,
              target: "records.read@1.0",
            },
          },
        };
      },
    },
    {
      label: "content digest",
      transform(state: EscalationState): EscalationState {
        return {
          ...state,
          request: {
            ...state.request,
            scope: {
              ...state.request.scope,
              contentSha256: "f".repeat(64),
            },
          },
        };
      },
    },
  ])(
    "rejects a signed approval after wait-time $label substitution",
    async ({ transform }) => {
      const keys = generateKeyPairSync("ed25519");
      const now = () => APPROVAL_TIME;
      const action = vi.fn(async () => "must-not-run");
      const getCapability = vi.fn(
        ({ resolution }: Parameters<
          GuardApprovalCapabilityConfig["getCapability"]
        >[0]) =>
          issueApprovalCapability({
            state: resolution,
            privateKey: keys.privateKey,
            now,
          }),
      );
      const guard = createEscalatingGuard({
        now,
        manager: adversarialManager({
          now,
          transformWait: transform,
        }),
        approvalCapability: {
          publicKey: keys.publicKey,
          nonceStore: new MemoryApprovalNonceStore(now),
          getCapability,
        },
      });

      await expect(
        guard.execute(GUARDED_INPUT, action),
      ).rejects.toMatchObject({
        code: "COREAX_GUARD_ESCALATION_FAILED",
        message: expect.stringContaining("substituted"),
      });
      expect(getCapability).not.toHaveBeenCalled();
      expect(action).not.toHaveBeenCalled();
    },
  );

  it("rejects a contradictory approved status before requesting a capability", async () => {
    const keys = generateKeyPairSync("ed25519");
    const now = () => APPROVAL_TIME;
    const action = vi.fn(async () => "must-not-run");
    const getCapability = vi.fn(() => null);
    const guard = createEscalatingGuard({
      now,
      manager: adversarialManager({
        now,
        transformWait: (state) => ({
          ...state,
          resolution: state.resolution
            ? { ...state.resolution, decision: "reject" }
            : null,
          status: "approved",
        }),
      }),
      approvalCapability: {
        publicKey: keys.publicKey,
        nonceStore: new MemoryApprovalNonceStore(now),
        getCapability,
      },
    });

    await expect(guard.execute(GUARDED_INPUT, action)).rejects.toMatchObject({
      code: "COREAX_GUARD_ESCALATION_FAILED",
      message: expect.stringContaining("contradictory"),
    });
    expect(getCapability).not.toHaveBeenCalled();
    expect(action).not.toHaveBeenCalled();
  });
});
