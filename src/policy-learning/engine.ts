import type { KeyLike } from "node:crypto";

import {
  parsePolicyRfc3339Timestamp,
  policyAuthorizationFingerprint,
  verifyPolicyOperationAuthorization,
  type PolicyOperationAuthorization,
  type PolicyVersionOperation,
} from "./authorization";
import {
  buildContextualBanditModel,
  type ContextualBanditModel,
} from "./bandit";
import {
  collectFeatureNames,
  extractPolicyFeatureVector,
} from "./features";
import { rankPolicyCandidates, type PolicyInferenceResult } from "./inference";
import { stableDigest } from "./math";
import {
  DEFAULT_POLICY_REWARD_WEIGHTS,
} from "./reward";
import {
  assessPolicyTransition,
  type PolicySafetyConstraints,
} from "./safety";
import {
  InMemoryAdaptivePolicyStore,
  type AdaptivePolicyEngineState,
  type AdaptivePolicyProposal,
  type AdaptivePolicyStore,
  type AdaptivePolicyVersion,
  type PolicyModelVersion,
  type PolicyOperationReceipt,
  type StoredPolicyObservation,
} from "./store";
import type {
  PolicyCandidate,
  PolicyDocument,
  PolicyJsonValue,
  PolicyLearningMode,
  PolicyLearningState,
  PolicyObservation,
  PolicyRewardComponentKey,
  RewardWeights,
} from "./types";

export type PolicyLearningErrorCode =
  | "engine_state_missing"
  | "active_policy_missing"
  | "observation_id_conflict"
  | "model_version_conflict"
  | "proposal_idempotency_conflict"
  | "proposal_integrity_invalid"
  | "proposal_not_found"
  | "proposal_base_version_changed"
  | "policy_version_conflict"
  | "unsafe_policy_transition"
  | "authorization_replay"
  | "authorization_mismatch"
  | "authorization_invalid"
  | "rollback_version_not_found"
  | "engine_state_invalid";

export class PolicyLearningError extends Error {
  readonly code: PolicyLearningErrorCode;

  constructor(code: PolicyLearningErrorCode, detail?: string) {
    super(detail ? `${code}:${detail}` : code);
    this.name = "PolicyLearningError";
    this.code = code;
  }
}

export interface AdaptivePolicyEngineConfig<
  TAction extends PolicyJsonValue,
  TPolicy extends PolicyDocument,
> {
  initialPolicy: TPolicy;
  initialVersion: string;
  initialCreatedAt?: string;
  mode?: PolicyLearningMode;
  constraints?: PolicySafetyConstraints;
  weights?: Readonly<RewardWeights<PolicyRewardComponentKey>>;
  trustedPublicKeys?: Readonly<Record<string, KeyLike>>;
  authorizationClockSkewMs?: number;
  store?: AdaptivePolicyStore<TAction, TPolicy>;
  clock?: () => Date;
}

export interface AdaptivePolicyProposalResult<
  TAction extends PolicyJsonValue,
  TPolicy extends PolicyDocument,
> {
  inference: PolicyInferenceResult;
  proposal: AdaptivePolicyProposal<TAction, TPolicy> | null;
}

function strippedState(state: PolicyLearningState): PolicyLearningState {
  return {
    ...(state.key ? { key: state.key } : {}),
    features: { ...state.features },
    ...(state.severity ? { severity: state.severity } : {}),
    ...(state.baseline ? { baseline: { ...state.baseline } } : {}),
  };
}

function nonempty(value: string, error: string): string {
  const normalized = value.trim();
  if (!normalized) throw new Error(error);
  return normalized;
}

function validTimestamp(value: string): boolean {
  return parsePolicyRfc3339Timestamp(value) !== null;
}

function uniqueNonemptyStrings(values: readonly unknown[]): boolean {
  return (
    values.length > 0 &&
    values.every(
      (value) =>
        typeof value === "string" &&
        value.trim() === value &&
        value.length > 0,
    ) &&
    new Set(values).size === values.length
  );
}

function isPolicyJson(
  value: unknown,
  seen = new Set<object>(),
  depth = 0,
): boolean {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return true;
  }
  if (typeof value === "number") return Number.isFinite(value);
  if (typeof value !== "object" || depth > 32 || seen.has(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  if (
    !Array.isArray(value) &&
    prototype !== Object.prototype &&
    prototype !== null
  ) {
    return false;
  }
  seen.add(value);
  const entries = Array.isArray(value)
    ? value
    : Object.values(value as Record<string, unknown>);
  const valid = entries.every((entry) =>
    isPolicyJson(entry, seen, depth + 1),
  );
  seen.delete(value);
  return valid;
}

function validPolicyDocument(value: unknown): value is PolicyDocument {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const policy = value as PolicyDocument;
  if (!Array.isArray(policy.permissions) || !Array.isArray(policy.denyRules)) {
    return false;
  }
  const permissionIds = new Set<string>();
  for (const permission of policy.permissions) {
    if (
      !permission ||
      typeof permission !== "object" ||
      !Array.isArray(permission.actions) ||
      !uniqueNonemptyStrings(permission.actions) ||
      !Array.isArray(permission.resources) ||
      !uniqueNonemptyStrings(permission.resources) ||
      (permission.id !== undefined &&
        (typeof permission.id !== "string" ||
          permission.id.trim().length === 0 ||
          permissionIds.has(permission.id))) ||
      (permission.conditions !== undefined &&
        !isPolicyJson(permission.conditions))
    ) {
      return false;
    }
    if (permission.id !== undefined) permissionIds.add(permission.id);
  }
  const denyIds = new Set<string>();
  for (const rule of policy.denyRules) {
    if (
      !rule ||
      typeof rule !== "object" ||
      typeof rule.id !== "string" ||
      rule.id.trim().length === 0 ||
      denyIds.has(rule.id) ||
      (rule.actions !== undefined &&
        (!Array.isArray(rule.actions) ||
          !uniqueNonemptyStrings(rule.actions))) ||
      (rule.resources !== undefined &&
        (!Array.isArray(rule.resources) ||
          !uniqueNonemptyStrings(rule.resources))) ||
      (rule.required !== undefined && typeof rule.required !== "boolean") ||
      (rule.conditions !== undefined && !isPolicyJson(rule.conditions))
    ) {
      return false;
    }
    denyIds.add(rule.id);
  }
  return policy.data === undefined || isPolicyJson(policy.data);
}

function policyVersionRecordDigest(
  version: Omit<AdaptivePolicyVersion, "recordDigest">,
): string {
  return stableDigest({
    version: version.version,
    parentVersion: version.parentVersion,
    policyDigest: version.digest,
    source: version.source,
    proposalId: version.proposalId ?? null,
    createdAt: version.createdAt,
  });
}

function policyProposalRecordDigest(
  proposal: Omit<AdaptivePolicyProposal, "recordDigest">,
): string {
  return stableDigest({
    proposalId: proposal.proposalId,
    idempotencyKey: proposal.idempotencyKey,
    mode: proposal.mode,
    status: proposal.status,
    baseVersion: proposal.baseVersion,
    candidateKey: proposal.candidateKey,
    action: proposal.action,
    targetDigest: proposal.targetDigest,
    modelVersion: proposal.modelVersion,
    expectedReward: proposal.expectedReward,
    safetyReasons: proposal.safetyReasons,
    promotedVersion: proposal.promotedVersion ?? null,
    createdAt: proposal.createdAt,
  });
}

function policyModelRecordDigest(
  model: Omit<PolicyModelVersion, "recordDigest">,
): string {
  return stableDigest({
    version: model.version,
    modelDigest: model.digest,
    createdAt: model.createdAt,
  });
}

function policyReceiptRecordDigest(
  receipt: Omit<PolicyOperationReceipt, "recordDigest">,
): string {
  return stableDigest({
    nonce: receipt.nonce,
    authorizationFingerprint: receipt.authorizationFingerprint,
    operation: receipt.operation,
    targetVersion: receipt.targetVersion,
    resultingActiveVersion: receipt.resultingActiveVersion,
    authorization: policyAuthorizationFingerprint(receipt.authorization),
    appliedAt: receipt.appliedAt,
  });
}

export class AdaptivePolicyEngine<
  TAction extends PolicyJsonValue = PolicyJsonValue,
  TPolicy extends PolicyDocument = PolicyDocument,
> {
  readonly mode: PolicyLearningMode;

  private readonly store: AdaptivePolicyStore<TAction, TPolicy>;
  private readonly constraints: PolicySafetyConstraints;
  private readonly weights: RewardWeights<PolicyRewardComponentKey>;
  private readonly trustedPublicKeys: Readonly<Record<string, KeyLike>>;
  private readonly authorizationClockSkewMs: number;
  private readonly clock: () => Date;

  constructor(config: AdaptivePolicyEngineConfig<TAction, TPolicy>) {
    const initialVersion = nonempty(
      config.initialVersion,
      "initial_version_is_required",
    );
    if (!validPolicyDocument(config.initialPolicy)) {
      throw new PolicyLearningError(
        "engine_state_invalid",
        "initial_policy",
      );
    }
    const initialPolicyDigest = stableDigest(config.initialPolicy);
    const mode = config.mode ?? "shadow";
    if (mode !== "shadow" && mode !== "proposal") {
      throw new PolicyLearningError("engine_state_invalid", "mode");
    }
    this.mode = mode;
    const rawConstraints = config.constraints ?? {};
    if (
      !rawConstraints ||
      typeof rawConstraints !== "object" ||
      Array.isArray(rawConstraints) ||
      (rawConstraints.allowExactPermissionExpansion !== undefined &&
        typeof rawConstraints.allowExactPermissionExpansion !== "boolean") ||
      (rawConstraints.requiredDenyRuleIds !== undefined &&
        (!Array.isArray(rawConstraints.requiredDenyRuleIds) ||
          (rawConstraints.requiredDenyRuleIds.length > 0 &&
            !uniqueNonemptyStrings(rawConstraints.requiredDenyRuleIds))))
    ) {
      throw new PolicyLearningError(
        "engine_state_invalid",
        "safety_constraints",
      );
    }
    this.constraints = {
      ...(rawConstraints.allowExactPermissionExpansion !== undefined
        ? {
            allowExactPermissionExpansion:
              rawConstraints.allowExactPermissionExpansion,
          }
        : {}),
      ...(rawConstraints.requiredDenyRuleIds
        ? { requiredDenyRuleIds: [...rawConstraints.requiredDenyRuleIds] }
        : {}),
    };
    this.weights = {
      ...DEFAULT_POLICY_REWARD_WEIGHTS,
      ...(config.weights ?? {}),
    };
    this.trustedPublicKeys = config.trustedPublicKeys ?? {};
    const authorizationClockSkewMs =
      config.authorizationClockSkewMs ?? 30_000;
    if (
      !Number.isFinite(authorizationClockSkewMs) ||
      authorizationClockSkewMs < 0
    ) {
      throw new PolicyLearningError(
        "engine_state_invalid",
        "authorization_clock_skew",
      );
    }
    this.authorizationClockSkewMs = authorizationClockSkewMs;
    this.clock = config.clock ?? (() => new Date());
    this.store =
      config.store ?? new InMemoryAdaptivePolicyStore<TAction, TPolicy>();

    const existing = this.store.load();
    if (!existing) {
      const createdAt =
        config.initialCreatedAt ?? this.clock().toISOString();
      if (
        !validTimestamp(createdAt)
      ) {
        throw new PolicyLearningError(
          "engine_state_invalid",
          "initial_policy_or_timestamp",
        );
      }
      const version: AdaptivePolicyVersion<TPolicy> = {
        version: initialVersion,
        parentVersion: null,
        policy: structuredClone(config.initialPolicy),
        digest: initialPolicyDigest,
        source: "initial",
        createdAt,
        recordDigest: "",
      };
      version.recordDigest = policyVersionRecordDigest(version);
      const initialState: AdaptivePolicyEngineState<TAction, TPolicy> = {
        schemaVersion: 1,
        revision: 0,
        activeVersion: initialVersion,
        versions: [version],
        proposals: [],
        observations: [],
        models: [],
        activeModelVersion: null,
        operationReceipts: [],
      };
      this.validateState(initialState);
      this.store.commit(null, initialState);
    } else {
      this.validateState(existing);
      const storedInitial = existing.versions.find(
        (version) => version.source === "initial",
      );
      if (
        !storedInitial ||
        storedInitial.version !== initialVersion ||
        storedInitial.digest !== initialPolicyDigest
      ) {
        throw new PolicyLearningError(
          "engine_state_invalid",
          "initial_policy_anchor",
        );
      }
    }
  }

  getSnapshot(): AdaptivePolicyEngineState<TAction, TPolicy> {
    return this.load();
  }

  getActiveVersion(): AdaptivePolicyVersion<TPolicy> {
    const state = this.load();
    return structuredClone(this.activeVersion(state));
  }

  getActivePolicy(): TPolicy {
    return structuredClone(this.getActiveVersion().policy);
  }

  rank<TContext = unknown>(input: {
    state: PolicyLearningState<TContext>;
    candidates: readonly PolicyCandidate<TAction, TPolicy>[];
    chooseFromActionKeys?: readonly string[] | null;
    softmaxTemperature?: number;
  }): PolicyInferenceResult {
    const stored = this.load();
    const active = this.activeVersion(stored);
    const modelVersion = stored.activeModelVersion
      ? stored.models.find(
          (entry) => entry.version === stored.activeModelVersion,
        ) ?? null
      : null;

    return rankPolicyCandidates({
      ...input,
      currentPolicy: active.policy,
      model: modelVersion?.model ?? null,
      modelVersion: modelVersion?.version ?? null,
      weights: this.weights,
      constraints: this.constraints,
    });
  }

  train(input: {
    observations: readonly PolicyObservation<PolicyRewardComponentKey>[];
    modelVersion: string;
    actionKeys?: readonly string[];
    featureNames?: readonly string[];
    lambda?: number;
    alpha?: number;
  }): PolicyModelVersion {
    const modelVersion = nonempty(
      input.modelVersion,
      "model_version_is_required",
    );
    const state = this.load();
    const existingById = new Map(
      state.observations.map((observation) => [observation.id, observation]),
    );
    const appended: StoredPolicyObservation[] = [];

    for (const observation of input.observations) {
      const id = nonempty(observation.id, "observation_id_is_required");
      const normalized: StoredPolicyObservation = {
        id,
        state: strippedState(observation.state),
        actionKey: nonempty(
          observation.actionKey,
          "observation_action_is_required",
        ),
        rewardComponents: { ...observation.rewardComponents },
        digest: "",
      };
      normalized.digest = stableDigest({
        id: normalized.id,
        state: normalized.state,
        actionKey: normalized.actionKey,
        rewardComponents: normalized.rewardComponents,
      });

      const existing = existingById.get(id);
      if (existing) {
        if (existing.digest !== normalized.digest) {
          throw new PolicyLearningError("observation_id_conflict", id);
        }
        continue;
      }
      existingById.set(id, normalized);
      appended.push(normalized);
    }

    const observations = [...state.observations, ...appended];
    if (observations.length === 0) {
      throw new Error("training_observations_are_required");
    }

    const featureNames = input.featureNames
      ? [...input.featureNames]
      : collectFeatureNames(
          observations.map((observation) => observation.state),
        );
    const actionKeys = [
      ...new Set(
        (
          input.actionKeys ??
          observations.map((observation) => observation.actionKey)
        )
          .map((actionKey) => actionKey.trim())
          .filter(Boolean),
      ),
    ].sort((left, right) => left.localeCompare(right));

    const model = buildContextualBanditModel({
      featureNames,
      actionKeys,
      weights: this.weights,
      lambda: input.lambda,
      alpha: input.alpha,
      rows: observations.map((observation) => ({
        x: extractPolicyFeatureVector(
          observation.state,
          featureNames,
        ).values,
        actionKey: observation.actionKey,
        components: observation.rewardComponents,
      })),
    });
    const digest = stableDigest(model);
    const existingModel = state.models.find(
      (entry) => entry.version === modelVersion,
    );
    if (existingModel) {
      if (existingModel.digest !== digest) {
        throw new PolicyLearningError(
          "model_version_conflict",
          modelVersion,
        );
      }
      if (
        appended.length === 0 &&
        state.activeModelVersion === modelVersion
      ) {
        return structuredClone(existingModel);
      }
      const next = {
        ...state,
        revision: state.revision + 1,
        observations,
        activeModelVersion: modelVersion,
      };
      this.commit(state.revision, next);
      return structuredClone(existingModel);
    }

    const storedModel: PolicyModelVersion = {
      version: modelVersion,
      model,
      digest,
      createdAt: this.clock().toISOString(),
      recordDigest: "",
    };
    storedModel.recordDigest = policyModelRecordDigest(storedModel);
    this.commit(state.revision, {
      ...state,
      revision: state.revision + 1,
      observations,
      models: [...state.models, storedModel],
      activeModelVersion: modelVersion,
    });
    return structuredClone(storedModel);
  }

  propose<TContext = unknown>(input: {
    state: PolicyLearningState<TContext>;
    candidates: readonly PolicyCandidate<TAction, TPolicy>[];
    idempotencyKey: string;
    chooseFromActionKeys?: readonly string[] | null;
    softmaxTemperature?: number;
  }): AdaptivePolicyProposalResult<TAction, TPolicy> {
    const idempotencyKey = nonempty(
      input.idempotencyKey,
      "idempotency_key_is_required",
    );
    const stored = this.load();
    const inference = this.rank(input);
    const chosen = inference.chosenActionKey
      ? input.candidates.find(
          (candidate) => candidate.key === inference.chosenActionKey,
        ) ?? null
      : null;

    if (!chosen) return { inference, proposal: null };

    const targetDigest = stableDigest(chosen.targetPolicy);
    const existing = stored.proposals.find(
      (proposal) => proposal.idempotencyKey === idempotencyKey,
    );
    if (existing) {
      if (
        existing.candidateKey !== chosen.key ||
        existing.targetDigest !== targetDigest ||
        stableDigest(existing.action) !== stableDigest(chosen.action)
      ) {
        throw new PolicyLearningError(
          "proposal_idempotency_conflict",
          idempotencyKey,
        );
      }
      return { inference, proposal: structuredClone(existing) };
    }

    const ranked = inference.rankedActions.find(
      (action) => action.actionKey === chosen.key,
    );
    if (!ranked?.allowed) return { inference, proposal: null };

    const proposalId = `proposal_${stableDigest({
      idempotencyKey,
      baseVersion: stored.activeVersion,
      candidateKey: chosen.key,
      targetDigest,
      action: chosen.action,
    }).slice(0, 24)}`;
    const proposal: AdaptivePolicyProposal<TAction, TPolicy> = {
      proposalId,
      idempotencyKey,
      mode: this.mode,
      status: this.mode === "shadow" ? "shadow" : "pending",
      baseVersion: stored.activeVersion,
      candidateKey: chosen.key,
      action: structuredClone(chosen.action),
      targetPolicy: structuredClone(chosen.targetPolicy),
      targetDigest,
      modelVersion: inference.modelVersion,
      expectedReward: ranked.expectedReward,
      safetyReasons: ranked.safetyReasons,
      createdAt: this.clock().toISOString(),
      recordDigest: "",
    };
    proposal.recordDigest = policyProposalRecordDigest(proposal);
    this.commit(stored.revision, {
      ...stored,
      revision: stored.revision + 1,
      proposals: [...stored.proposals, proposal],
    });
    return { inference, proposal: structuredClone(proposal) };
  }

  promote(input: {
    proposalId: string;
    version: string;
    authorization: PolicyOperationAuthorization;
  }): AdaptivePolicyVersion<TPolicy> {
    const proposalId = nonempty(input.proposalId, "proposal_id_is_required");
    const version = nonempty(input.version, "policy_version_is_required");
    const state = this.load();
    const replay = this.findOperationReplay(
      state,
      input.authorization,
      "promote",
      version,
      proposalId,
    );
    if (replay) {
      const existingVersion = state.versions.find(
        (entry) => entry.version === replay.resultingActiveVersion,
      );
      if (!existingVersion) {
        throw new PolicyLearningError("active_policy_missing");
      }
      return structuredClone(existingVersion);
    }

    const proposal = state.proposals.find(
      (entry) => entry.proposalId === proposalId,
    );
    if (!proposal) {
      throw new PolicyLearningError("proposal_not_found", proposalId);
    }
    if (proposal.baseVersion !== state.activeVersion) {
      throw new PolicyLearningError(
        "proposal_base_version_changed",
        proposal.baseVersion,
      );
    }
    if (stableDigest(proposal.targetPolicy) !== proposal.targetDigest) {
      throw new PolicyLearningError(
        "proposal_integrity_invalid",
        proposalId,
      );
    }
    if (state.versions.some((entry) => entry.version === version)) {
      throw new PolicyLearningError("policy_version_conflict", version);
    }

    const fingerprint = this.authorize({
      authorization: input.authorization,
      operation: "promote",
      subject: proposalId,
      targetVersion: version,
      policyDigest: proposal.targetDigest,
      expectedActiveVersion: state.activeVersion,
    });
    const current = this.activeVersion(state);
    const safety = assessPolicyTransition({
      currentPolicy: current.policy,
      targetPolicy: proposal.targetPolicy,
      constraints: this.constraints,
    });
    if (!safety.allowed) {
      throw new PolicyLearningError(
        "unsafe_policy_transition",
        safety.reasons.map((reason) => reason.code).join(","),
      );
    }

    const promoted: AdaptivePolicyVersion<TPolicy> = {
      version,
      parentVersion: state.activeVersion,
      policy: structuredClone(proposal.targetPolicy),
      digest: proposal.targetDigest,
      source: "promotion",
      proposalId,
      createdAt: this.clock().toISOString(),
      recordDigest: "",
    };
    promoted.recordDigest = policyVersionRecordDigest(promoted);
    const receipt = this.operationReceipt({
      authorization: input.authorization,
      fingerprint,
      resultingActiveVersion: version,
    });
    const proposals = state.proposals.map((entry) => {
      if (entry.proposalId !== proposalId) return entry;
      const promotedProposal: AdaptivePolicyProposal<TAction, TPolicy> = {
        ...entry,
        status: "promoted",
        promotedVersion: version,
        recordDigest: "",
      };
      promotedProposal.recordDigest =
        policyProposalRecordDigest(promotedProposal);
      return promotedProposal;
    });
    this.commit(state.revision, {
      ...state,
      revision: state.revision + 1,
      activeVersion: version,
      versions: [...state.versions, promoted],
      proposals,
      operationReceipts: [...state.operationReceipts, receipt],
    });
    return structuredClone(promoted);
  }

  rollback(input: {
    targetVersion: string;
    authorization: PolicyOperationAuthorization;
  }): AdaptivePolicyVersion<TPolicy> {
    const targetVersion = nonempty(
      input.targetVersion,
      "rollback_version_is_required",
    );
    const state = this.load();
    const replay = this.findOperationReplay(
      state,
      input.authorization,
      "rollback",
      targetVersion,
      targetVersion,
    );
    if (replay) {
      const replayTarget = state.versions.find(
        (entry) => entry.version === replay.resultingActiveVersion,
      );
      if (!replayTarget) {
        throw new PolicyLearningError("active_policy_missing");
      }
      return structuredClone(replayTarget);
    }

    const target = state.versions.find(
      (entry) => entry.version === targetVersion,
    );
    if (!target) {
      throw new PolicyLearningError(
        "rollback_version_not_found",
        targetVersion,
      );
    }
    const fingerprint = this.authorize({
      authorization: input.authorization,
      operation: "rollback",
      subject: targetVersion,
      targetVersion,
      policyDigest: target.digest,
      expectedActiveVersion: state.activeVersion,
    });
    const current = this.activeVersion(state);
    const safety = assessPolicyTransition({
      currentPolicy: current.policy,
      targetPolicy: target.policy,
      constraints: {
        ...this.constraints,
        // A signed rollback is an explicit operator action. Exact additions
        // can therefore be restored, while wildcard additions remain blocked.
        allowExactPermissionExpansion: true,
      },
    });
    if (!safety.allowed) {
      throw new PolicyLearningError(
        "unsafe_policy_transition",
        safety.reasons.map((reason) => reason.code).join(","),
      );
    }

    const receipt = this.operationReceipt({
      authorization: input.authorization,
      fingerprint,
      resultingActiveVersion: targetVersion,
    });
    this.commit(state.revision, {
      ...state,
      revision: state.revision + 1,
      activeVersion: targetVersion,
      operationReceipts: [...state.operationReceipts, receipt],
    });
    return structuredClone(target);
  }

  private load(): AdaptivePolicyEngineState<TAction, TPolicy> {
    const state = this.store.load();
    if (!state) throw new PolicyLearningError("engine_state_missing");
    this.validateState(state);
    return state;
  }

  private commit(
    expectedRevision: number,
    next: AdaptivePolicyEngineState<TAction, TPolicy>,
  ): void {
    this.validateState(next);
    this.store.commit(expectedRevision, next);
  }

  private validateState(
    state: AdaptivePolicyEngineState<TAction, TPolicy>,
  ): void {
    const invalid = (detail: string): never => {
      throw new PolicyLearningError("engine_state_invalid", detail);
    };
    if (
      state.schemaVersion !== 1 ||
      !Number.isSafeInteger(state.revision) ||
      state.revision < 0 ||
      typeof state.activeVersion !== "string" ||
      state.activeVersion.trim() !== state.activeVersion ||
      state.activeVersion.length === 0 ||
      !Array.isArray(state.versions) ||
      !Array.isArray(state.proposals) ||
      !Array.isArray(state.observations) ||
      !Array.isArray(state.models) ||
      !Array.isArray(state.operationReceipts)
    ) {
      invalid("shape");
    }

    const versionIds = new Set<string>();
    const initialVersions: string[] = [];
    for (const version of state.versions) {
      if (
        !version ||
        typeof version !== "object" ||
        typeof version.version !== "string" ||
        version.version.trim() !== version.version ||
        version.version.length === 0 ||
        versionIds.has(version.version)
      ) {
        invalid("duplicate_or_invalid_version");
      }
      versionIds.add(version.version);
      if (
        !validPolicyDocument(version.policy) ||
        typeof version.digest !== "string" ||
        version.digest !== stableDigest(version.policy) ||
        typeof version.recordDigest !== "string" ||
        version.recordDigest !== policyVersionRecordDigest(version)
      ) {
        invalid(`version_digest:${version.version}`);
      }
      if (!validTimestamp(version.createdAt)) {
        invalid(`version_timestamp:${version.version}`);
      }
      if (version.source === "initial") {
        initialVersions.push(version.version);
        if (version.parentVersion !== null || version.proposalId !== undefined) {
          invalid(`initial_version_metadata:${version.version}`);
        }
      } else if (version.source === "promotion") {
        if (
          typeof version.parentVersion !== "string" ||
          version.parentVersion.trim().length === 0 ||
          typeof version.proposalId !== "string" ||
          version.proposalId.trim().length === 0
        ) {
          invalid(`promotion_version_metadata:${version.version}`);
        }
      } else {
        invalid(`version_source:${version.version}`);
      }
    }
    if (
      state.versions.length === 0 ||
      initialVersions.length !== 1 ||
      !versionIds.has(state.activeVersion)
    ) {
      invalid("active_or_initial_version");
    }
    for (const version of state.versions) {
      if (
        version.parentVersion !== null &&
        (!versionIds.has(version.parentVersion) ||
          version.parentVersion === version.version)
      ) {
        invalid(`version_parent:${version.version}`);
      }
      const visited = new Set<string>([version.version]);
      let parent = version.parentVersion;
      while (parent !== null) {
        if (visited.has(parent)) invalid(`version_cycle:${version.version}`);
        visited.add(parent);
        parent =
          state.versions.find((entry) => entry.version === parent)
            ?.parentVersion ?? null;
      }
    }

    const modelIds = new Set<string>();
    for (const modelVersion of state.models) {
      if (
        !modelVersion ||
        typeof modelVersion !== "object" ||
        typeof modelVersion.version !== "string" ||
        modelVersion.version.trim() !== modelVersion.version ||
        modelVersion.version.length === 0 ||
        modelIds.has(modelVersion.version)
      ) {
        invalid("duplicate_or_invalid_model_version");
      }
      modelIds.add(modelVersion.version);
      if (
        modelVersion.digest !== stableDigest(modelVersion.model) ||
        !validTimestamp(modelVersion.createdAt) ||
        typeof modelVersion.recordDigest !== "string" ||
        modelVersion.recordDigest !== policyModelRecordDigest(modelVersion)
      ) {
        invalid(`model_integrity:${modelVersion.version}`);
      }
      const model = modelVersion.model;
      if (
        !model ||
        typeof model !== "object" ||
        model.algorithm !== "coreax_contextual_bandit_v1" ||
        !Array.isArray(model.featureNames) ||
        !uniqueNonemptyStrings(model.featureNames) ||
        !Array.isArray(model.actionKeys) ||
        !uniqueNonemptyStrings(model.actionKeys) ||
        !Array.isArray(model.rewardKeys) ||
        !uniqueNonemptyStrings(model.rewardKeys) ||
        !model.weights ||
        typeof model.weights !== "object" ||
        !model.componentModels ||
        typeof model.componentModels !== "object" ||
        !Number.isFinite(model.lambda) ||
        model.lambda <= 0 ||
        !Number.isFinite(model.alpha) ||
        model.alpha < 0 ||
        !Number.isSafeInteger(model.trainingRows) ||
        model.trainingRows < 0
      ) {
        invalid(`model_shape:${modelVersion.version}`);
      }
      const dimension = model.featureNames.length;
      for (const rewardKey of model.rewardKeys) {
        if (
          !Number.isFinite(model.weights[rewardKey]) ||
          model.componentModels[rewardKey]?.component !== rewardKey
        ) {
          invalid(`model_reward:${modelVersion.version}`);
        }
        const actions = model.componentModels[rewardKey]?.actions;
        if (!actions) invalid(`model_actions:${modelVersion.version}`);
        for (const actionKey of model.actionKeys) {
          const statistics = actions[actionKey];
          if (
            !statistics ||
            statistics.actionKey !== actionKey ||
            statistics.weights.length !== dimension ||
            statistics.weights.some((value) => !Number.isFinite(value)) ||
            statistics.inverseCovariance.length !== dimension ||
            statistics.inverseCovariance.some(
              (row) =>
                row.length !== dimension ||
                row.some((value) => !Number.isFinite(value)),
            ) ||
            !Number.isSafeInteger(statistics.observationCount) ||
            statistics.observationCount < 0
          ) {
            invalid(`model_statistics:${modelVersion.version}`);
          }
        }
      }
    }
    if (
      state.activeModelVersion !== null &&
      (typeof state.activeModelVersion !== "string" ||
        !modelIds.has(state.activeModelVersion))
    ) {
      invalid("active_model_version");
    }

    const observationIds = new Set<string>();
    for (const observation of state.observations) {
      if (
        !observation ||
        typeof observation !== "object" ||
        typeof observation.id !== "string" ||
        observation.id.trim().length === 0 ||
        observationIds.has(observation.id) ||
        typeof observation.actionKey !== "string" ||
        observation.actionKey.trim().length === 0 ||
        !observation.rewardComponents ||
        typeof observation.rewardComponents !== "object" ||
        Array.isArray(observation.rewardComponents) ||
        !observation.state ||
        typeof observation.state !== "object" ||
        !observation.state.features ||
        typeof observation.state.features !== "object" ||
        Array.isArray(observation.state.features) ||
        Object.entries(observation.state.features).some(
          ([key, value]) =>
            key.trim().length === 0 ||
            (value !== undefined &&
              value !== null &&
              typeof value !== "boolean" &&
              (typeof value !== "number" || !Number.isFinite(value))),
        ) ||
        (observation.state.key !== undefined &&
          (typeof observation.state.key !== "string" ||
            observation.state.key.trim().length === 0)) ||
        (observation.state.severity !== undefined &&
          !["low", "medium", "high", "critical"].includes(
            observation.state.severity,
          )) ||
        (observation.state.baseline !== undefined &&
          (!Number.isFinite(observation.state.baseline.incidentCount) ||
            !Number.isFinite(
              observation.state.baseline.falsePositiveRatePct,
            ) ||
            !Number.isFinite(observation.state.baseline.latencyMs) ||
            (observation.state.baseline.sensitiveIncidentCount !==
              undefined &&
              !Number.isFinite(
                observation.state.baseline.sensitiveIncidentCount,
              )))) ||
        Object.prototype.hasOwnProperty.call(observation.state, "context")
      ) {
        invalid("duplicate_or_invalid_observation");
      }
      observationIds.add(observation.id);
      const digest = stableDigest({
        id: observation.id,
        state: observation.state,
        actionKey: observation.actionKey,
        rewardComponents: observation.rewardComponents,
      });
      if (
        observation.digest !== digest ||
        Object.values(observation.rewardComponents).some(
          (value) => !Number.isFinite(value),
        )
      ) {
        invalid(`observation_integrity:${observation.id}`);
      }
    }

    const proposalIds = new Set<string>();
    const idempotencyKeys = new Set<string>();
    for (const proposal of state.proposals) {
      if (
        !proposal ||
        typeof proposal !== "object" ||
        typeof proposal.proposalId !== "string" ||
        proposal.proposalId.trim().length === 0 ||
        proposalIds.has(proposal.proposalId) ||
        typeof proposal.idempotencyKey !== "string" ||
        proposal.idempotencyKey.trim().length === 0 ||
        idempotencyKeys.has(proposal.idempotencyKey) ||
        typeof proposal.candidateKey !== "string" ||
        proposal.candidateKey.trim().length === 0 ||
        !versionIds.has(proposal.baseVersion) ||
        !isPolicyJson(proposal.action) ||
        !validPolicyDocument(proposal.targetPolicy) ||
        !Array.isArray(proposal.safetyReasons) ||
        proposal.safetyReasons.some(
          (reason) =>
            !reason ||
            typeof reason !== "object" ||
            ![
              "wildcard_permission_expansion",
              "permission_expansion",
              "required_deny_missing",
              "required_deny_weakened",
            ].includes(reason.code) ||
            typeof reason.detail !== "string",
        ) ||
        proposal.targetDigest !== stableDigest(proposal.targetPolicy) ||
        !validTimestamp(proposal.createdAt) ||
        (proposal.mode !== "shadow" && proposal.mode !== "proposal") ||
        !Number.isFinite(proposal.expectedReward) ||
        typeof proposal.recordDigest !== "string" ||
        proposal.recordDigest !== policyProposalRecordDigest(proposal)
      ) {
        invalid("duplicate_or_invalid_proposal");
      }
      proposalIds.add(proposal.proposalId);
      idempotencyKeys.add(proposal.idempotencyKey);
      if (
        proposal.modelVersion !== null &&
        !modelIds.has(proposal.modelVersion)
      ) {
        invalid(`proposal_model:${proposal.proposalId}`);
      }
      if (proposal.status === "promoted") {
        const promoted = state.versions.find(
          (version) => version.version === proposal.promotedVersion,
        );
        if (
          !promoted ||
          promoted.source !== "promotion" ||
          promoted.proposalId !== proposal.proposalId ||
          promoted.digest !== proposal.targetDigest
        ) {
          invalid(`proposal_promotion:${proposal.proposalId}`);
        }
      } else if (
        (proposal.status !== "shadow" && proposal.status !== "pending") ||
        proposal.promotedVersion !== undefined
      ) {
        invalid(`proposal_status:${proposal.proposalId}`);
      }
    }
    for (const version of state.versions) {
      if (
        version.source === "promotion" &&
        !state.proposals.some(
          (proposal) =>
            proposal.proposalId === version.proposalId &&
            proposal.promotedVersion === version.version,
        )
      ) {
        invalid(`promotion_proposal:${version.version}`);
      }
    }

    const receiptNonces = new Set<string>();
    const receiptFingerprints = new Set<string>();
    let reconstructedActiveVersion = initialVersions[0];
    let previousAppliedAt = -Infinity;
    for (const receipt of state.operationReceipts) {
      if (
        !receipt ||
        typeof receipt !== "object" ||
        !receipt.authorization ||
        typeof receipt.authorization !== "object"
      ) {
        invalid("operation_receipt");
      }
      const authorization = receipt.authorization;
      const appliedAt = parsePolicyRfc3339Timestamp(receipt.appliedAt);
      if (
        appliedAt === null ||
        appliedAt < previousAppliedAt ||
        typeof receipt.nonce !== "string" ||
        receipt.nonce.trim().length === 0 ||
        receiptNonces.has(receipt.nonce) ||
        typeof receipt.authorizationFingerprint !== "string" ||
        receiptFingerprints.has(receipt.authorizationFingerprint) ||
        receipt.nonce !== authorization.nonce ||
        receipt.authorizationFingerprint !==
          policyAuthorizationFingerprint(authorization) ||
        receipt.operation !== authorization.operation ||
        receipt.targetVersion !== authorization.targetVersion ||
        receipt.resultingActiveVersion !== authorization.targetVersion ||
        !versionIds.has(receipt.resultingActiveVersion) ||
        authorization.expectedActiveVersion !== reconstructedActiveVersion ||
        typeof receipt.recordDigest !== "string" ||
        receipt.recordDigest !== policyReceiptRecordDigest(receipt)
      ) {
        invalid("operation_receipt");
      }
      const targetVersion = state.versions.find(
        (version) => version.version === receipt.resultingActiveVersion,
      );
      if (
        !targetVersion ||
        authorization.policyDigest !== targetVersion.digest ||
        (authorization.operation === "promote" &&
          (targetVersion.source !== "promotion" ||
            targetVersion.parentVersion !== reconstructedActiveVersion ||
            targetVersion.proposalId !== authorization.subject)) ||
        (authorization.operation === "rollback" &&
          authorization.subject !== authorization.targetVersion)
      ) {
        invalid(`operation_receipt_target:${receipt.nonce}`);
      }
      const verification = verifyPolicyOperationAuthorization({
        authorization,
        publicKeys: this.trustedPublicKeys,
        now: receipt.appliedAt,
        maxClockSkewMs: this.authorizationClockSkewMs,
      });
      if (
        !verification.valid ||
        verification.fingerprint !== receipt.authorizationFingerprint
      ) {
        invalid(`operation_receipt_signature:${receipt.nonce}`);
      }
      previousAppliedAt = appliedAt!;
      receiptNonces.add(receipt.nonce);
      receiptFingerprints.add(receipt.authorizationFingerprint);
      reconstructedActiveVersion = receipt.resultingActiveVersion;
    }
    if (reconstructedActiveVersion !== state.activeVersion) {
      invalid("operation_history");
    }
    for (const version of state.versions) {
      if (
        version.source === "promotion" &&
        !state.operationReceipts.some(
          (receipt) =>
            receipt.operation === "promote" &&
            receipt.resultingActiveVersion === version.version,
        )
      ) {
        invalid(`promotion_receipt:${version.version}`);
      }
    }
  }

  private activeVersion(
    state: AdaptivePolicyEngineState<TAction, TPolicy>,
  ): AdaptivePolicyVersion<TPolicy> {
    const active = state.versions.find(
      (version) => version.version === state.activeVersion,
    );
    if (!active) throw new PolicyLearningError("active_policy_missing");
    return active;
  }

  private findOperationReplay(
    state: AdaptivePolicyEngineState<TAction, TPolicy>,
    authorization: PolicyOperationAuthorization,
    operation: PolicyVersionOperation,
    targetVersion: string,
    subject: string,
  ): PolicyOperationReceipt | null {
    const existing = state.operationReceipts.find(
      (receipt) => receipt.nonce === authorization.nonce,
    );
    if (!existing) return null;
    const fingerprint = policyAuthorizationFingerprint(authorization);
    if (
      existing.authorizationFingerprint !== fingerprint ||
      existing.operation !== operation ||
      existing.targetVersion !== targetVersion ||
      existing.authorization.subject !== subject ||
      authorization.subject !== subject
    ) {
      throw new PolicyLearningError(
        "authorization_replay",
        authorization.nonce,
      );
    }
    const verification = verifyPolicyOperationAuthorization({
      authorization,
      publicKeys: this.trustedPublicKeys,
      now: this.clock(),
      maxClockSkewMs: this.authorizationClockSkewMs,
    });
    if (!verification.valid) {
      throw new PolicyLearningError(
        "authorization_invalid",
        verification.reason,
      );
    }
    if (
      state.operationReceipts[state.operationReceipts.length - 1] !==
        existing ||
      state.activeVersion !== existing.resultingActiveVersion
    ) {
      throw new PolicyLearningError(
        "authorization_replay",
        `${authorization.nonce}:state_changed`,
      );
    }
    const active = state.versions.find(
      (version) => version.version === state.activeVersion,
    );
    if (
      !active ||
      active.digest !== existing.authorization.policyDigest
    ) {
      throw new PolicyLearningError(
        "authorization_replay",
        `${authorization.nonce}:state_integrity_changed`,
      );
    }
    return existing;
  }

  private authorize(input: {
    authorization: PolicyOperationAuthorization;
    operation: PolicyVersionOperation;
    subject: string;
    targetVersion: string;
    policyDigest: string;
    expectedActiveVersion: string;
  }): string {
    const authorization = input.authorization;
    if (
      authorization.operation !== input.operation ||
      authorization.subject !== input.subject ||
      authorization.targetVersion !== input.targetVersion ||
      authorization.policyDigest !== input.policyDigest ||
      authorization.expectedActiveVersion !== input.expectedActiveVersion
    ) {
      throw new PolicyLearningError("authorization_mismatch");
    }

    const verification = verifyPolicyOperationAuthorization({
      authorization,
      publicKeys: this.trustedPublicKeys,
      now: this.clock(),
      maxClockSkewMs: this.authorizationClockSkewMs,
    });
    if (!verification.valid) {
      throw new PolicyLearningError(
        "authorization_invalid",
        verification.reason,
      );
    }
    return verification.fingerprint;
  }

  private operationReceipt(input: {
    authorization: PolicyOperationAuthorization;
    fingerprint: string;
    resultingActiveVersion: string;
  }): PolicyOperationReceipt {
    const receipt: PolicyOperationReceipt = {
      nonce: input.authorization.nonce,
      authorizationFingerprint: input.fingerprint,
      operation: input.authorization.operation,
      targetVersion: input.authorization.targetVersion,
      resultingActiveVersion: input.resultingActiveVersion,
      authorization: structuredClone(input.authorization),
      appliedAt: this.clock().toISOString(),
      recordDigest: "",
    };
    receipt.recordDigest = policyReceiptRecordDigest(receipt);
    return receipt;
  }
}
