import { generateKeyPairSync, type KeyObject } from "node:crypto";

import { describe, expect, it, vi } from "vitest";

import {
  AdaptivePolicyEngine,
  InMemoryAdaptivePolicyStore,
  PolicyLearningError,
  assessPolicyTransition,
  buildContextualBanditModel,
  buildFittedQModel,
  rankPolicyCandidates,
  signPolicyOperationAuthorization,
  simulatePolicyCandidate,
  stableDigest,
  verifyPolicyOperationAuthorization,
  type PolicyCandidate,
  type PolicyDocument,
  type PolicyLearningState,
  type PolicyOperationAuthorization,
  type PolicyRewardComponentKey,
  type RewardComponents,
  type UnsignedPolicyOperationAuthorization,
} from "../src/policy-learning";

type TestPolicy = PolicyDocument<{ label: string }>;

const FIXED_NOW = new Date("2026-07-29T18:00:00.000Z");

function rewards(
  values: Partial<RewardComponents<PolicyRewardComponentKey>> = {},
): RewardComponents<PolicyRewardComponentKey> {
  return {
    incident_reduction: 0,
    sensitive_exposure_prevention: 0,
    false_positive_reduction: 0,
    latency_reduction: 0,
    human_acceptance: 0,
    evaluator_score: 0,
    ...values,
  };
}

function basePolicy(): TestPolicy {
  return {
    permissions: [
      {
        id: "read-orders",
        actions: ["read"],
        resources: ["orders"],
      },
    ],
    denyRules: [
      {
        id: "deny-sensitive-export",
        actions: ["export"],
        resources: ["sensitive-records"],
        required: true,
      },
    ],
    data: { label: "baseline" },
  };
}

function tightenedPolicy(): TestPolicy {
  return {
    ...basePolicy(),
    denyRules: [
      ...basePolicy().denyRules,
      {
        id: "deny-unreviewed-write",
        actions: ["write"],
        resources: ["orders"],
      },
    ],
    data: { label: "tightened" },
  };
}

function state(risk = 1): PolicyLearningState {
  return {
    key: `risk-${risk}`,
    features: { risk, recent_denials: risk > 0.5 },
    severity: "high",
    baseline: {
      incidentCount: 20,
      sensitiveIncidentCount: 5,
      falsePositiveRatePct: 12,
      latencyMs: 100,
    },
  };
}

function candidates(): Array<PolicyCandidate<string, TestPolicy>> {
  return [
    {
      key: "observe",
      action: "observe",
      targetPolicy: basePolicy(),
      priority: 1,
      simulation: {
        incidentMultiplier: 1,
        evaluatorScore0to100: 50,
      },
    },
    {
      key: "tighten",
      action: "tighten",
      targetPolicy: tightenedPolicy(),
      priority: 2,
      simulation: {
        incidentMultiplier: 0.5,
        sensitiveIncidentMultiplier: 0.2,
        latencyMultiplier: 1.05,
        evaluatorScore0to100: 90,
      },
    },
  ];
}

function signedAuthorization(input: {
  operation: "promote" | "rollback";
  subject: string;
  targetVersion: string;
  expectedActiveVersion: string;
  policyDigest: string;
  nonce: string;
  keyId?: string;
  privateKey: KeyObject;
}): PolicyOperationAuthorization {
  const authorization: UnsignedPolicyOperationAuthorization = {
    format: "coreax_policy_operation_v1",
    operation: input.operation,
    subject: input.subject,
    targetVersion: input.targetVersion,
    policyDigest: input.policyDigest,
    expectedActiveVersion: input.expectedActiveVersion,
    nonce: input.nonce,
    keyId: input.keyId ?? "release-key",
    issuedAt: "2026-07-29T17:59:00.000Z",
    expiresAt: "2026-07-29T19:00:00.000Z",
  };
  return signPolicyOperationAuthorization({
    authorization,
    privateKey: input.privateKey,
  });
}

describe("policy-learning algorithms", () => {
  it("trains and ranks a contextual bandit deterministically", () => {
    const weights = {
      incident_reduction: 1,
      sensitive_exposure_prevention: 3,
      false_positive_reduction: 1,
      latency_reduction: 0.35,
      human_acceptance: 0.5,
      evaluator_score: 0.2,
    };
    const rows = [
      {
        x: [1, 1, 1],
        actionKey: "tighten",
        components: rewards({
          incident_reduction: 0.9,
          sensitive_exposure_prevention: 1,
        }),
      },
      {
        x: [1, 1, 1],
        actionKey: "tighten",
        components: rewards({
          incident_reduction: 0.8,
          sensitive_exposure_prevention: 0.9,
        }),
      },
      {
        x: [1, 1, 1],
        actionKey: "observe",
        components: rewards({
          incident_reduction: -0.2,
          sensitive_exposure_prevention: -0.2,
        }),
      },
    ];

    const modelA = buildContextualBanditModel({
      featureNames: ["bias", "recent_denials", "risk"],
      actionKeys: ["tighten", "observe"],
      rows,
      weights,
      lambda: 0.1,
    });
    const modelB = buildContextualBanditModel({
      featureNames: ["bias", "recent_denials", "risk"],
      actionKeys: ["observe", "tighten"],
      rows,
      weights,
      lambda: 0.1,
    });

    expect(modelA).toEqual(modelB);
    const inference = rankPolicyCandidates({
      state: state(1),
      candidates: candidates(),
      currentPolicy: basePolicy(),
      model: modelA,
      modelVersion: "model-1",
      weights,
    });

    expect(inference.chosenActionKey).toBe("tighten");
    expect(inference.rankedActions[0]).toMatchObject({
      actionKey: "tighten",
      source: "model",
      allowed: true,
    });
    expect(
      Object.values(inference.distribution).reduce(
        (total, probability) => total + probability,
        0,
      ),
    ).toBeCloseTo(1, 12);

    const explicitlyEmpty = rankPolicyCandidates({
      state: state(1),
      candidates: candidates(),
      currentPolicy: basePolicy(),
      model: modelA,
      modelVersion: "model-1",
      weights,
      chooseFromActionKeys: [],
    });
    expect(explicitlyEmpty.chosenActionKey).toBeNull();
    expect(Object.values(explicitlyEmpty.distribution)).toEqual(
      expect.arrayContaining([0]),
    );
    expect(
      Object.values(explicitlyEmpty.distribution).every(
        (probability) => probability === 0,
      ),
    ).toBe(true);
  });

  it("runs deterministic fitted Q iteration across replayed transitions", () => {
    const transitions = [
      {
        state: state(1),
        actionKey: "tighten",
        rewardComponents: rewards({ incident_reduction: 0.8 }),
        nextState: state(0.5),
        nextActionKeys: ["tighten", "observe"],
      },
      {
        state: state(0.5),
        actionKey: "observe",
        rewardComponents: rewards({ incident_reduction: -0.1 }),
        nextState: null,
      },
    ];
    const weights = {
      incident_reduction: 1,
      sensitive_exposure_prevention: 3,
      false_positive_reduction: 1,
      latency_reduction: 0.35,
      human_acceptance: 0.5,
      evaluator_score: 0.2,
    };

    const first = buildFittedQModel({
      transitions,
      actionKeys: ["tighten", "observe"],
      weights,
      gamma: 0.9,
      iterations: 4,
    });
    const replay = buildFittedQModel({
      transitions,
      actionKeys: ["observe", "tighten"],
      weights,
      gamma: 0.9,
      iterations: 4,
    });

    expect(first).toEqual(replay);
    expect(first.model).toMatchObject({
      algorithm: "coreax_fitted_q_v1",
      trainingRows: 2,
      iterations: 4,
    });
    expect(first.metrics.meanAbsoluteTdError).not.toBeNull();
  });

  it("simulates counterfactual rewards without time or random inputs", () => {
    const candidate = candidates()[1];
    const first = simulatePolicyCandidate(state(1), candidate);
    const second = simulatePolicyCandidate(state(1), candidate);

    expect(first).toEqual(second);
    expect(first.projected).toEqual({
      incidentCount: 10,
      sensitiveIncidentCount: 1,
      falsePositiveRatePct: 12,
      latencyMs: 105,
    });
    expect(first.components).toMatchObject({
      incident_reduction: 0.5,
      sensitive_exposure_prevention: 0.8,
      latency_reduction: -0.05,
      evaluator_score: 0.8,
    });
  });
});

describe("policy-learning hard safety constraints", () => {
  it("rejects wildcard and implicit exact permission expansion", () => {
    const wildcard = {
      ...basePolicy(),
      permissions: [
        ...basePolicy().permissions,
        { id: "everything", actions: ["*"], resources: ["*"] },
      ],
    };
    const exact = {
      ...basePolicy(),
      permissions: [
        ...basePolicy().permissions,
        { id: "write-orders", actions: ["write"], resources: ["orders"] },
      ],
    };

    expect(
      assessPolicyTransition({
        currentPolicy: basePolicy(),
        targetPolicy: wildcard,
      }).reasons.map((reason) => reason.code),
    ).toContain("wildcard_permission_expansion");
    expect(
      assessPolicyTransition({
        currentPolicy: basePolicy(),
        targetPolicy: exact,
      }).reasons.map((reason) => reason.code),
    ).toContain("permission_expansion");
    expect(
      assessPolicyTransition({
        currentPolicy: basePolicy(),
        targetPolicy: exact,
        constraints: { allowExactPermissionExpansion: true },
      }).allowed,
    ).toBe(true);
    expect(
      assessPolicyTransition({
        currentPolicy: basePolicy(),
        targetPolicy: wildcard,
        constraints: { allowExactPermissionExpansion: true },
      }).allowed,
    ).toBe(false);
  });

  it("rejects removal or modification of mandatory deny rules", () => {
    const removed: TestPolicy = {
      ...basePolicy(),
      denyRules: [],
    };
    const weakened: TestPolicy = {
      ...basePolicy(),
      denyRules: [
        {
          id: "deny-sensitive-export",
          actions: ["export"],
          resources: ["public-records"],
          required: true,
        },
      ],
    };

    expect(
      assessPolicyTransition({
        currentPolicy: basePolicy(),
        targetPolicy: removed,
      }).reasons.map((reason) => reason.code),
    ).toContain("required_deny_missing");
    expect(
      assessPolicyTransition({
        currentPolicy: basePolicy(),
        targetPolicy: weakened,
      }).reasons.map((reason) => reason.code),
    ).toContain("required_deny_weakened");
  });

  it("never assigns selection probability to an unsafe candidate", () => {
    const unsafe: PolicyCandidate<string, TestPolicy> = {
      key: "allow-everything",
      action: "expand",
      targetPolicy: {
        ...basePolicy(),
        permissions: [
          ...basePolicy().permissions,
          { actions: ["*"], resources: ["*"] },
        ],
      },
      priority: 1_000,
      simulation: {
        incidentMultiplier: 0,
        sensitiveIncidentMultiplier: 0,
        evaluatorScore0to100: 100,
      },
    };
    const inference = rankPolicyCandidates({
      state: state(),
      candidates: [unsafe, ...candidates()],
      currentPolicy: basePolicy(),
    });

    expect(inference.distribution["allow-everything"]).toBe(0);
    expect(inference.chosenActionKey).not.toBe("allow-everything");
    expect(
      inference.rankedActions.find(
        (action) => action.actionKey === "allow-everything",
      ),
    ).toMatchObject({
      allowed: false,
      safetyReasons: [
        expect.objectContaining({ code: "wildcard_permission_expansion" }),
      ],
    });
  });
});

describe("AdaptivePolicyEngine", () => {
  it("defaults to shadow proposals and promotes and rolls back only with signed operations", () => {
    const releaseKeys = generateKeyPairSync("ed25519");
    const engine = new AdaptivePolicyEngine<string, TestPolicy>({
      initialPolicy: basePolicy(),
      initialVersion: "v1",
      initialCreatedAt: "2026-07-29T17:00:00.000Z",
      trustedPublicKeys: { "release-key": releaseKeys.publicKey },
      clock: () => new Date(FIXED_NOW),
    });

    expect(engine.mode).toBe("shadow");
    const proposed = engine.propose({
      state: state(),
      candidates: candidates(),
      idempotencyKey: "run-1",
    });
    expect(proposed.proposal).toMatchObject({
      mode: "shadow",
      status: "shadow",
      baseVersion: "v1",
      candidateKey: "tighten",
    });
    expect(engine.getActiveVersion().version).toBe("v1");

    const revisionAfterProposal = engine.getSnapshot().revision;
    const replayedProposal = engine.propose({
      state: state(),
      candidates: candidates(),
      idempotencyKey: "run-1",
    });
    expect(replayedProposal.proposal).toEqual(proposed.proposal);
    expect(engine.getSnapshot().revision).toBe(revisionAfterProposal);

    const promoteAuthorization = signedAuthorization({
      operation: "promote",
      subject: proposed.proposal!.proposalId,
      targetVersion: "v2",
      expectedActiveVersion: "v1",
      policyDigest: proposed.proposal!.targetDigest,
      nonce: "promote-1",
      privateKey: releaseKeys.privateKey,
    });
    const promoted = engine.promote({
      proposalId: proposed.proposal!.proposalId,
      version: "v2",
      authorization: promoteAuthorization,
    });
    expect(promoted).toMatchObject({
      version: "v2",
      parentVersion: "v1",
      source: "promotion",
    });
    expect(engine.getActivePolicy().data?.label).toBe("tightened");

    const revisionAfterPromotion = engine.getSnapshot().revision;
    expect(
      engine.promote({
        proposalId: proposed.proposal!.proposalId,
        version: "v2",
        authorization: promoteAuthorization,
      }),
    ).toEqual(promoted);
    expect(engine.getSnapshot()).toMatchObject({
      revision: revisionAfterPromotion,
      activeVersion: "v2",
    });
    expect(engine.getSnapshot().operationReceipts).toHaveLength(1);

    const rollbackAuthorization = signedAuthorization({
      operation: "rollback",
      subject: "v1",
      targetVersion: "v1",
      expectedActiveVersion: "v2",
      policyDigest: stableDigest(basePolicy()),
      nonce: "rollback-1",
      privateKey: releaseKeys.privateKey,
    });
    expect(
      engine.rollback({
        targetVersion: "v1",
        authorization: rollbackAuthorization,
      }).version,
    ).toBe("v1");
    const revisionAfterRollback = engine.getSnapshot().revision;
    expect(
      engine.rollback({
        targetVersion: "v1",
        authorization: rollbackAuthorization,
      }).version,
    ).toBe("v1");
    expect(engine.getSnapshot()).toMatchObject({
      revision: revisionAfterRollback,
      activeVersion: "v1",
    });
    expect(() =>
      engine.promote({
        proposalId: proposed.proposal!.proposalId,
        version: "v2",
        authorization: promoteAuthorization,
      }),
    ).toThrow("authorization_replay:promote-1:state_changed");
  });

  it("binds idempotent replay to its subject and rechecks expiry", () => {
    const releaseKeys = generateKeyPairSync("ed25519");
    let currentTime = new Date(FIXED_NOW);
    const engine = new AdaptivePolicyEngine<string, TestPolicy>({
      initialPolicy: basePolicy(),
      initialVersion: "v1",
      trustedPublicKeys: { "release-key": releaseKeys.publicKey },
      authorizationClockSkewMs: 0,
      clock: () => new Date(currentTime),
    });
    const proposal = engine.propose({
      state: state(),
      candidates: candidates(),
      idempotencyKey: "replay-scope",
    }).proposal!;
    const authorization = signedAuthorization({
      operation: "promote",
      subject: proposal.proposalId,
      targetVersion: "v2",
      expectedActiveVersion: "v1",
      policyDigest: proposal.targetDigest,
      nonce: "replay-scope-promotion",
      privateKey: releaseKeys.privateKey,
    });
    engine.promote({
      proposalId: proposal.proposalId,
      version: "v2",
      authorization,
    });

    expect(() =>
      engine.promote({
        proposalId: "different-proposal",
        version: "v2",
        authorization,
      }),
    ).toThrow("authorization_replay:replay-scope-promotion");

    currentTime = new Date("2026-07-29T20:00:00.000Z");
    expect(() =>
      engine.promote({
        proposalId: proposal.proposalId,
        version: "v2",
        authorization,
      }),
    ).toThrow("authorization_invalid:expired");
  });

  it("rejects wrong signing keys, expired authorizations, and nonce reuse", () => {
    const trustedKeys = generateKeyPairSync("ed25519");
    const wrongKeys = generateKeyPairSync("ed25519");
    const engine = new AdaptivePolicyEngine<string, TestPolicy>({
      initialPolicy: basePolicy(),
      initialVersion: "v1",
      trustedPublicKeys: { "release-key": trustedKeys.publicKey },
      clock: () => new Date(FIXED_NOW),
    });
    const proposal = engine.propose({
      state: state(),
      candidates: candidates(),
      idempotencyKey: "signed-operation-test",
    }).proposal!;

    const wrongDigest = signedAuthorization({
      operation: "promote",
      subject: proposal.proposalId,
      targetVersion: "v2",
      expectedActiveVersion: "v1",
      policyDigest: stableDigest(basePolicy()),
      nonce: "wrong-digest",
      privateKey: trustedKeys.privateKey,
    });
    expect(() =>
      engine.promote({
        proposalId: proposal.proposalId,
        version: "v2",
        authorization: wrongDigest,
      }),
    ).toThrow("authorization_mismatch");

    const wrongSignature = signedAuthorization({
      operation: "promote",
      subject: proposal.proposalId,
      targetVersion: "v2",
      expectedActiveVersion: "v1",
      policyDigest: proposal.targetDigest,
      nonce: "wrong-signature",
      privateKey: wrongKeys.privateKey,
    });
    expect(() =>
      engine.promote({
        proposalId: proposal.proposalId,
        version: "v2",
        authorization: wrongSignature,
      }),
    ).toThrow("authorization_invalid:invalid_signature");

    const expiredUnsigned: UnsignedPolicyOperationAuthorization = {
      format: "coreax_policy_operation_v1",
      operation: "promote",
      subject: proposal.proposalId,
      targetVersion: "v2",
      expectedActiveVersion: "v1",
      policyDigest: proposal.targetDigest,
      nonce: "expired",
      keyId: "release-key",
      issuedAt: "2026-07-29T15:00:00.000Z",
      expiresAt: "2026-07-29T16:00:00.000Z",
    };
    const expired = signPolicyOperationAuthorization({
      authorization: expiredUnsigned,
      privateKey: trustedKeys.privateKey,
    });
    expect(
      verifyPolicyOperationAuthorization({
        authorization: expired,
        publicKeys: { "release-key": trustedKeys.publicKey },
        now: FIXED_NOW,
        maxClockSkewMs: 0,
      }),
    ).toMatchObject({ valid: false, reason: "expired" });

    const ambiguous = {
      ...expiredUnsigned,
      nonce: "ambiguous-time",
      issuedAt: "2026-07-29T15:00:00",
    };
    expect(() =>
      signPolicyOperationAuthorization({
        authorization: ambiguous,
        privateKey: trustedKeys.privateKey,
      }),
    ).toThrow("invalid_policy_authorization");
    expect(
      verifyPolicyOperationAuthorization({
        authorization: {
          ...expired,
          issuedAt: "2026-07-29T15:00:00",
        },
        publicKeys: { "release-key": trustedKeys.publicKey },
        now: FIXED_NOW,
      }),
    ).toMatchObject({ valid: false, reason: "invalid_time" });
    for (const maxClockSkewMs of [Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(
        verifyPolicyOperationAuthorization({
          authorization: expired,
          publicKeys: { "release-key": trustedKeys.publicKey },
          now: FIXED_NOW,
          maxClockSkewMs,
        }),
      ).toMatchObject({ valid: false, reason: "invalid_time" });
    }
    expect(
      verifyPolicyOperationAuthorization({
        authorization: expired,
        publicKeys: { "release-key": trustedKeys.publicKey },
        now: FIXED_NOW.getTime() as unknown as string,
      }),
    ).toMatchObject({ valid: false, reason: "invalid_time" });

    const valid = signedAuthorization({
      operation: "promote",
      subject: proposal.proposalId,
      targetVersion: "v2",
      expectedActiveVersion: "v1",
      policyDigest: proposal.targetDigest,
      nonce: "shared-nonce",
      privateKey: trustedKeys.privateKey,
    });
    engine.promote({
      proposalId: proposal.proposalId,
      version: "v2",
      authorization: valid,
    });

    const changedUse = signedAuthorization({
      operation: "rollback",
      subject: "v1",
      targetVersion: "v1",
      expectedActiveVersion: "v2",
      policyDigest: stableDigest(basePolicy()),
      nonce: "shared-nonce",
      privateKey: trustedKeys.privateKey,
    });
    expect(() =>
      engine.rollback({
        targetVersion: "v1",
        authorization: changedUse,
      }),
    ).toThrow("authorization_replay:shared-nonce");
  });

  it("rejects non-finite clock skew and malformed safety constraints", () => {
    for (const authorizationClockSkewMs of [
      Number.NaN,
      Number.POSITIVE_INFINITY,
      -1,
    ]) {
      expect(
        () =>
          new AdaptivePolicyEngine<string, TestPolicy>({
            initialPolicy: basePolicy(),
            initialVersion: "v1",
            authorizationClockSkewMs,
          }),
      ).toThrow("engine_state_invalid:authorization_clock_skew");
    }
    expect(
      () =>
        new AdaptivePolicyEngine<string, TestPolicy>({
          initialPolicy: basePolicy(),
          initialVersion: "v1",
          constraints: {
            allowExactPermissionExpansion:
              "false" as unknown as boolean,
          },
        }),
    ).toThrow("engine_state_invalid:safety_constraints");
    expect(() =>
      assessPolicyTransition({
        currentPolicy: basePolicy(),
        targetPolicy: {
          ...basePolicy(),
          permissions: [
            ...basePolicy().permissions,
            {
              id: "write-orders",
              actions: ["write"],
              resources: ["orders"],
            },
          ],
        },
        constraints: {
          allowExactPermissionExpansion: "false" as unknown as boolean,
        },
      }),
    ).toThrow("invalid_policy_safety_constraints");
  });

  it("deduplicates identical training replay and rejects conflicting observations", () => {
    const engine = new AdaptivePolicyEngine<string, TestPolicy>({
      initialPolicy: basePolicy(),
      initialVersion: "v1",
      clock: () => new Date(FIXED_NOW),
    });
    const observation = {
      id: "outcome-1",
      state: state(),
      actionKey: "tighten",
      rewardComponents: rewards({ incident_reduction: 0.75 }),
    };

    const trained = engine.train({
      observations: [observation],
      modelVersion: "model-1",
      actionKeys: ["observe", "tighten"],
    });
    const revisionAfterTraining = engine.getSnapshot().revision;
    expect(
      engine.train({
        observations: [observation],
        modelVersion: "model-1",
        actionKeys: ["observe", "tighten"],
      }),
    ).toEqual(trained);
    expect(engine.getSnapshot()).toMatchObject({
      revision: revisionAfterTraining,
      activeModelVersion: "model-1",
    });
    expect(engine.getSnapshot().observations).toHaveLength(1);

    expect(() =>
      engine.train({
        observations: [
          {
            ...observation,
            rewardComponents: rewards({ incident_reduction: -1 }),
          },
        ],
        modelVersion: "model-2",
        actionKeys: ["observe", "tighten"],
      }),
    ).toThrow("observation_id_conflict:outcome-1");
  });

  it("rejects corrupted stored digests, duplicate versions, and replay receipts", () => {
    const releaseKeys = generateKeyPairSync("ed25519");
    const engine = new AdaptivePolicyEngine<string, TestPolicy>({
      initialPolicy: basePolicy(),
      initialVersion: "v1",
      trustedPublicKeys: { "release-key": releaseKeys.publicKey },
      clock: () => new Date(FIXED_NOW),
    });
    const proposal = engine.propose({
      state: state(),
      candidates: candidates(),
      idempotencyKey: "integrity-proposal",
    }).proposal!;
    engine.promote({
      proposalId: proposal.proposalId,
      version: "v2",
      authorization: signedAuthorization({
        operation: "promote",
        subject: proposal.proposalId,
        targetVersion: "v2",
        expectedActiveVersion: "v1",
        policyDigest: proposal.targetDigest,
        nonce: "integrity-promotion",
        privateKey: releaseKeys.privateKey,
      }),
    });
    engine.train({
      observations: [
        {
          id: "integrity-observation",
          state: state(),
          actionKey: "tighten",
          rewardComponents: rewards({ incident_reduction: 0.5 }),
        },
      ],
      modelVersion: "integrity-model",
      actionKeys: ["observe", "tighten"],
    });
    const snapshot = engine.getSnapshot();
    const corruptedStates = [
      (() => {
        const corrupted = structuredClone(snapshot);
        corrupted.versions[1].policy.data!.label = "tampered";
        return corrupted;
      })(),
      (() => {
        const corrupted = structuredClone(snapshot);
        corrupted.models[0].model.alpha += 1;
        return corrupted;
      })(),
      (() => {
        const corrupted = structuredClone(snapshot);
        corrupted.observations[0].rewardComponents.incident_reduction = -1;
        return corrupted;
      })(),
      (() => {
        const corrupted = structuredClone(snapshot);
        corrupted.proposals[0].action = "tampered";
        return corrupted;
      })(),
      (() => {
        const corrupted = structuredClone(snapshot);
        corrupted.proposals[0].idempotencyKey = "tampered-idempotency";
        return corrupted;
      })(),
      (() => {
        const corrupted = structuredClone(snapshot);
        corrupted.versions[1].createdAt = "2026-07-29T18:00:01.000Z";
        return corrupted;
      })(),
      (() => {
        const corrupted = structuredClone(snapshot);
        corrupted.models[0].createdAt = "2026-07-29T18:00:01.000Z";
        return corrupted;
      })(),
      (() => {
        const corrupted = structuredClone(snapshot);
        corrupted.operationReceipts[0].appliedAt =
          "2026-07-29T18:00:01.000Z";
        return corrupted;
      })(),
      (() => {
        const corrupted = structuredClone(snapshot);
        corrupted.versions.push(structuredClone(corrupted.versions[0]));
        return corrupted;
      })(),
      (() => {
        const corrupted = structuredClone(snapshot);
        corrupted.operationReceipts.push(
          structuredClone(corrupted.operationReceipts[0]),
        );
        return corrupted;
      })(),
    ];

    for (const corrupted of corruptedStates) {
      expect(
        () =>
          new AdaptivePolicyEngine<string, TestPolicy>({
            initialPolicy: basePolicy(),
            initialVersion: "v1",
            trustedPublicKeys: { "release-key": releaseKeys.publicKey },
            store: new InMemoryAdaptivePolicyStore(corrupted),
            clock: () => new Date(FIXED_NOW),
          }),
      ).toThrow("engine_state_invalid");
    }
  });

  it("anchors a loaded store to the configured initial policy and version", () => {
    const original = new AdaptivePolicyEngine<string, TestPolicy>({
      initialPolicy: basePolicy(),
      initialVersion: "v1",
      initialCreatedAt: "2026-07-29T17:00:00.000Z",
      clock: () => new Date(FIXED_NOW),
    });
    const validSnapshot = original.getSnapshot();
    expect(
      () =>
        new AdaptivePolicyEngine<string, TestPolicy>({
          initialPolicy: basePolicy(),
          initialVersion: "v1",
          store: new InMemoryAdaptivePolicyStore(validSnapshot),
          clock: () => new Date(FIXED_NOW),
        }),
    ).not.toThrow();

    const replacement = structuredClone(validSnapshot);
    const replacementPolicy: TestPolicy = {
      permissions: [
        {
          id: "attacker-write",
          actions: ["write"],
          resources: ["orders"],
        },
      ],
      denyRules: [],
      data: { label: "replacement-root" },
    };
    replacement.activeVersion = "replacement-v1";
    replacement.versions[0].version = "replacement-v1";
    replacement.versions[0].policy = replacementPolicy;
    replacement.versions[0].digest = stableDigest(replacementPolicy);
    replacement.versions[0].recordDigest = stableDigest({
      version: "replacement-v1",
      parentVersion: null,
      policyDigest: replacement.versions[0].digest,
      source: "initial",
      proposalId: null,
      createdAt: replacement.versions[0].createdAt,
    });

    expect(
      () =>
        new AdaptivePolicyEngine<string, TestPolicy>({
          initialPolicy: basePolicy(),
          initialVersion: "v1",
          store: new InMemoryAdaptivePolicyStore(replacement),
          clock: () => new Date(FIXED_NOW),
        }),
    ).toThrow("engine_state_invalid:initial_policy_anchor");
  });

  it("does not make implicit network calls", () => {
    const fetchSpy = vi.fn(() => {
      throw new Error("network access attempted");
    });
    vi.stubGlobal("fetch", fetchSpy);
    try {
      const engine = new AdaptivePolicyEngine<string, TestPolicy>({
        initialPolicy: basePolicy(),
        initialVersion: "v1",
        clock: () => new Date(FIXED_NOW),
      });
      engine.rank({ state: state(), candidates: candidates() });
      engine.train({
        observations: [
          {
            id: "offline-outcome",
            state: state(),
            actionKey: "tighten",
            rewardComponents: rewards({ incident_reduction: 0.5 }),
          },
        ],
        modelVersion: "offline-model",
        actionKeys: ["observe", "tighten"],
      });
      expect(fetchSpy).not.toHaveBeenCalled();
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("surfaces typed policy-learning failures", () => {
    const error = new PolicyLearningError(
      "unsafe_policy_transition",
      "required_deny_missing",
    );
    expect(error).toMatchObject({
      name: "PolicyLearningError",
      code: "unsafe_policy_transition",
      message:
        "unsafe_policy_transition:required_deny_missing",
    });
  });
});
