import type { ContextualBanditModel } from "./bandit";
import type { PolicyOperationAuthorization } from "./authorization";
import type {
  PolicyDocument,
  PolicyJsonValue,
  PolicyLearningMode,
  PolicyLearningState,
  PolicyRewardComponentKey,
  RewardComponents,
} from "./types";
import type { PolicySafetyReason } from "./safety";

export interface StoredPolicyObservation {
  id: string;
  state: PolicyLearningState;
  actionKey: string;
  rewardComponents: RewardComponents<PolicyRewardComponentKey>;
  digest: string;
}

export interface PolicyModelVersion {
  version: string;
  model: ContextualBanditModel<PolicyRewardComponentKey>;
  digest: string;
  createdAt: string;
  recordDigest: string;
}

export interface AdaptivePolicyVersion<
  TPolicy extends PolicyDocument = PolicyDocument,
> {
  version: string;
  parentVersion: string | null;
  policy: TPolicy;
  digest: string;
  source: "initial" | "promotion";
  proposalId?: string;
  createdAt: string;
  recordDigest: string;
}

export interface AdaptivePolicyProposal<
  TAction extends PolicyJsonValue = PolicyJsonValue,
  TPolicy extends PolicyDocument = PolicyDocument,
> {
  proposalId: string;
  idempotencyKey: string;
  mode: PolicyLearningMode;
  status: "shadow" | "pending" | "promoted";
  baseVersion: string;
  candidateKey: string;
  action: TAction;
  targetPolicy: TPolicy;
  targetDigest: string;
  modelVersion: string | null;
  expectedReward: number;
  safetyReasons: PolicySafetyReason[];
  promotedVersion?: string;
  createdAt: string;
  recordDigest: string;
}

export interface PolicyOperationReceipt {
  nonce: string;
  authorizationFingerprint: string;
  operation: "promote" | "rollback";
  targetVersion: string;
  resultingActiveVersion: string;
  authorization: PolicyOperationAuthorization;
  appliedAt: string;
  recordDigest: string;
}

export interface AdaptivePolicyEngineState<
  TAction extends PolicyJsonValue = PolicyJsonValue,
  TPolicy extends PolicyDocument = PolicyDocument,
> {
  schemaVersion: 1;
  revision: number;
  activeVersion: string;
  versions: AdaptivePolicyVersion<TPolicy>[];
  proposals: AdaptivePolicyProposal<TAction, TPolicy>[];
  observations: StoredPolicyObservation[];
  models: PolicyModelVersion[];
  activeModelVersion: string | null;
  operationReceipts: PolicyOperationReceipt[];
}

export interface AdaptivePolicyStore<
  TAction extends PolicyJsonValue = PolicyJsonValue,
  TPolicy extends PolicyDocument = PolicyDocument,
> {
  load(): AdaptivePolicyEngineState<TAction, TPolicy> | null;
  commit(
    expectedRevision: number | null,
    next: AdaptivePolicyEngineState<TAction, TPolicy>,
  ): void;
}

function clone<T>(value: T): T {
  return structuredClone(value);
}

export class PolicyStoreConflictError extends Error {
  constructor() {
    super("policy_store_revision_conflict");
    this.name = "PolicyStoreConflictError";
  }
}

/**
 * Pure in-memory storage with compare-and-swap semantics. Callers can inject a
 * durable implementation without the SDK creating files or opening sockets.
 */
export class InMemoryAdaptivePolicyStore<
  TAction extends PolicyJsonValue = PolicyJsonValue,
  TPolicy extends PolicyDocument = PolicyDocument,
> implements AdaptivePolicyStore<TAction, TPolicy>
{
  private state: AdaptivePolicyEngineState<TAction, TPolicy> | null;

  constructor(initial?: AdaptivePolicyEngineState<TAction, TPolicy>) {
    this.state = initial ? clone(initial) : null;
  }

  load(): AdaptivePolicyEngineState<TAction, TPolicy> | null {
    return this.state ? clone(this.state) : null;
  }

  commit(
    expectedRevision: number | null,
    next: AdaptivePolicyEngineState<TAction, TPolicy>,
  ): void {
    const currentRevision = this.state?.revision ?? null;
    if (currentRevision !== expectedRevision) {
      throw new PolicyStoreConflictError();
    }
    if (expectedRevision !== null && next.revision !== expectedRevision + 1) {
      throw new PolicyStoreConflictError();
    }
    if (expectedRevision === null && next.revision !== 0) {
      throw new PolicyStoreConflictError();
    }
    this.state = clone(next);
  }
}
