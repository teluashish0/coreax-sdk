export type PolicyJsonPrimitive = string | number | boolean | null;
export type PolicyJsonValue =
  | PolicyJsonPrimitive
  | PolicyJsonValue[]
  | { [key: string]: PolicyJsonValue };
export type PolicyJsonObject = { [key: string]: PolicyJsonValue };

export type PolicyLearningMode = "shadow" | "proposal";
export type PolicySeverity = "low" | "medium" | "high" | "critical";

export type PolicyFeatureValue = number | boolean | null | undefined;

export interface PolicySimulationBaseline {
  incidentCount: number;
  sensitiveIncidentCount?: number;
  falsePositiveRatePct: number;
  latencyMs: number;
}

/**
 * A caller-owned state description. Only `features` are consumed by a model;
 * `context` remains opaque and is never persisted by the learning engine.
 */
export interface PolicyLearningState<TContext = unknown> {
  key?: string;
  features: Readonly<Record<string, PolicyFeatureValue>>;
  severity?: PolicySeverity;
  baseline?: PolicySimulationBaseline;
  context?: TContext;
}

export interface PolicyPermission {
  id?: string;
  actions: readonly string[];
  resources: readonly string[];
  conditions?: PolicyJsonObject;
}

export interface PolicyDenyRule {
  id: string;
  actions?: readonly string[];
  resources?: readonly string[];
  conditions?: PolicyJsonObject;
  required?: boolean;
}

/**
 * The safety layer reasons over permissions and deny rules while leaving
 * application-specific policy data opaque.
 */
export interface PolicyDocument<
  TData extends PolicyJsonObject = PolicyJsonObject,
> {
  permissions: readonly PolicyPermission[];
  denyRules: readonly PolicyDenyRule[];
  data?: TData;
}

export type PolicyRewardComponentKey =
  | "incident_reduction"
  | "sensitive_exposure_prevention"
  | "false_positive_reduction"
  | "latency_reduction"
  | "human_acceptance"
  | "evaluator_score";

export type RewardComponents<
  TKey extends string = PolicyRewardComponentKey,
> = Record<TKey, number>;

export type RewardWeights<
  TKey extends string = PolicyRewardComponentKey,
> = Record<TKey, number>;

export interface PolicySimulationProfile {
  /**
   * Multipliers are relative to the supplied baseline. Values below one are
   * improvements; values above one are regressions.
   */
  incidentMultiplier?: number;
  sensitiveIncidentMultiplier?: number;
  latencyMultiplier?: number;
  falsePositiveDeltaPct?: number;
  humanAcceptance?: number;
  evaluatorScore0to100?: number;
}

export interface PolicyCandidate<
  TAction = PolicyJsonValue,
  TPolicy extends PolicyDocument = PolicyDocument,
> {
  key: string;
  action: TAction;
  targetPolicy: TPolicy;
  priority?: number;
  simulation?: PolicySimulationProfile;
  metadata?: PolicyJsonObject;
}

export interface FeatureVector {
  names: string[];
  values: number[];
  byName: Record<string, number>;
}

export interface PolicyObservation<
  TKey extends string = PolicyRewardComponentKey,
> {
  id: string;
  state: PolicyLearningState;
  actionKey: string;
  rewardComponents: RewardComponents<TKey>;
}

export interface PolicyTransition<
  TKey extends string = PolicyRewardComponentKey,
> {
  state: PolicyLearningState;
  actionKey: string;
  rewardComponents: RewardComponents<TKey>;
  nextState: PolicyLearningState | null;
  nextActionKeys?: readonly string[] | null;
}
