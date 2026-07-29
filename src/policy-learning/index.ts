export {
  signPolicyOperationAuthorization,
  verifyPolicyOperationAuthorization,
} from "./authorization";
export type {
  PolicyAuthorizationVerification,
  PolicyOperationAuthorization,
  PolicyVersionOperation,
  UnsignedPolicyOperationAuthorization,
} from "./authorization";

export {
  buildContextualBanditModel,
  combineComponentUncertainty,
  createInitialBanditModel,
  estimateLinearAction,
  trainRidgeComponent,
} from "./bandit";
export type {
  BanditTrainingRow,
  ContextualBanditModel,
  LinearActionStatistics,
  LinearComponentModel,
  LinearPolicyModel,
} from "./bandit";

export {
  AdaptivePolicyEngine,
  PolicyLearningError,
} from "./engine";
export type {
  AdaptivePolicyEngineConfig,
  AdaptivePolicyProposalResult,
  PolicyLearningErrorCode,
} from "./engine";

export {
  collectFeatureNames,
  extractPolicyFeatureVector,
} from "./features";

export {
  rankPolicyCandidates,
} from "./inference";
export type {
  PolicyInferenceResult,
  RankedPolicyAction,
} from "./inference";

export {
  clamp,
  dot,
  finiteNumber,
  identityMatrix,
  invertMatrix,
  softmaxProbabilities,
  stableDigest,
  stableSerialize,
} from "./math";

export {
  buildFittedQModel,
} from "./q";
export type { FittedQModel } from "./q";

export {
  DEFAULT_POLICY_REWARD_WEIGHTS,
  computeWeightedReward,
  emptyPolicyRewardComponents,
  normalizeEvaluatorScore,
} from "./reward";

export {
  assessPolicyCandidate,
  assessPolicyTransition,
  assertPolicySafetyConstraints,
  assertPolicyTransitionSafe,
  containsPermissionWildcard,
} from "./safety";
export type {
  PolicySafetyAssessment,
  PolicySafetyConstraints,
  PolicySafetyReason,
  PolicySafetyReasonCode,
} from "./safety";

export {
  simulatePolicyCandidate,
  simulatePolicyCandidates,
} from "./simulation";
export type { PolicySimulationOutcome } from "./simulation";

export {
  InMemoryAdaptivePolicyStore,
  PolicyStoreConflictError,
} from "./store";
export type {
  AdaptivePolicyEngineState,
  AdaptivePolicyProposal,
  AdaptivePolicyStore,
  AdaptivePolicyVersion,
  PolicyModelVersion,
  PolicyOperationReceipt,
  StoredPolicyObservation,
} from "./store";

export type {
  FeatureVector,
  PolicyCandidate,
  PolicyDenyRule,
  PolicyDocument,
  PolicyFeatureValue,
  PolicyJsonObject,
  PolicyJsonPrimitive,
  PolicyJsonValue,
  PolicyLearningMode,
  PolicyLearningState,
  PolicyObservation,
  PolicyPermission,
  PolicyRewardComponentKey,
  PolicySeverity,
  PolicySimulationBaseline,
  PolicySimulationProfile,
  PolicyTransition,
  RewardComponents,
  RewardWeights,
} from "./types";
