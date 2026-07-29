/**
 * Pure runtime-risk contracts.
 *
 * Evidence is intentionally limited to identifiers, counts, classifications, and
 * hashes. Implementations must never copy raw state values into an assessment.
 */

export type RuntimeRiskSubtype =
  | "behavior_drift"
  | "golden_path_drift"
  | "state_persistence"
  | "data_exposure_risk"
  | "mandate_deviation";

export type RuntimeRiskSeverity = "low" | "medium" | "high" | "critical";

export type RuntimeStateScope =
  | "AGENT"
  | "BOUNDARY"
  | "SERVER"
  | "MCP_SERVER"
  | "TOOL"
  | "ORCHESTRATOR";

export type RuntimeRiskHop = {
  eventId: string;
  timestamp: string;
  traceId?: string;
  spanId?: string;
  causeTraceId?: string;
  causeSpanId?: string;
};

export type DataExposureSink =
  | "egress"
  | "filesystem"
  | "tool_output"
  | "agent_state"
  | "raw_payload"
  | "unknown";

export type DataClassification =
  | "pii"
  | "secret"
  | "phi"
  | "credential"
  | "unknown";

export type DataExposureDetector =
  | "guard"
  | "policy_risk_tag"
  | "classifier"
  | "rule";

export type RuntimeExposureFinding = {
  sink: DataExposureSink;
  detector?: DataExposureDetector;
  classification?: DataClassification;
  severity?: RuntimeRiskSeverity;
  /** A non-secret caller-owned identifier. It is hashed before entering evidence. */
  ruleId?: string;
};

export type RuntimeMandateContext = {
  intentId?: string;
  cartId?: string;
  issuerDid?: string;
  subjectDid?: string;
  constraintsSha256?: string;
  cartSha256?: string;
  /** Stable machine-readable violation codes. */
  violations?: string[];
};

export type RuntimeRiskEvent = {
  id: string;
  /** Strict RFC3339 timestamp with an explicit `Z` or numeric offset. */
  timestamp: string;
  runId: string;
  nodeId: string;
  traceId?: string;
  spanId?: string;
  causeTraceId?: string;
  causeSpanId?: string;
  nodeType?: string;
  server?: string;
  tool?: string;
  decision?: string;
  reasonCode?: string;
  operation?: string;
  latencyMs?: number;
  state?: Partial<Record<RuntimeStateScope, Record<string, unknown>>>;
  riskTags?: string[];
  guardFindings?: number;
  exposures?: RuntimeExposureFinding[];
  mandate?: RuntimeMandateContext;
};

export type SensitiveStateRule = {
  /** Scope in which the value is expected to originate and remain. */
  scope: RuntimeStateScope;
  /** Exact top-level state key within the scope. */
  key: string;
  /** Optional per-key retention limit, inclusive of the first observed hop. */
  maxHops?: number;
};

export type BaselineReadiness = {
  ready: boolean;
  eventCount: number;
  runCount: number;
  minimumEventCount: number;
  minimumRunCount: number;
  reason?: "insufficient_events" | "insufficient_runs";
};

export type RuntimeRiskSignal = {
  code: string;
  subtype: RuntimeRiskSubtype;
  severity: RuntimeRiskSeverity;
  score: number;
  title: string;
  message?: string;
  evidence?: Record<string, unknown>;
  hop?: RuntimeRiskHop;
};

export type NumericDriftFeature = {
  key: string;
  kind: "number";
  currentValue: number;
  baseline: { mean: number; standardDeviation: number; sampleCount: number };
  distance: { zScore: number; absoluteZScore: number };
  weight: number;
  contribution: number;
};

export type CategoricalDriftFeature = {
  key: string;
  kind: "categorical";
  currentValue: string;
  baseline: {
    topValues: Array<{ value: string; percentage: number }>;
    sampleCount: number;
  };
  distance: { surprise: number };
  weight: number;
  contribution: number;
};

export type StringDriftFeature = {
  key: string;
  kind: "string";
  current: { valueSha256: string; characterLength: number };
  baseline: {
    sampleCount: number;
    meanCosineDistance: number;
    standardDeviation?: number;
  };
  distance: {
    cosineSimilarity: number;
    cosineDistance: number;
    zScore?: number;
  };
  weight: number;
  contribution: number;
};

export type BehaviorDriftEvidence = {
  baseline: BaselineReadiness & { nodeId: string };
  features: Array<
    NumericDriftFeature | CategoricalDriftFeature | StringDriftFeature
  >;
  aggregate: { driftScore: number; primaryFeatureKeys: string[] };
};

export type StatePersistenceViolation = {
  key: string;
  kind:
    | "sensitive_persisted"
    | "scope_violation"
    | "unexpected_retention"
    | "cross_node_propagation";
  firstSeen: RuntimeRiskHop;
  lastSeen: RuntimeRiskHop;
  persistedHops: number;
  expectedMaxHops?: number;
  valueSha256?: string;
  nodeIds?: string[];
  observedScopes?: RuntimeStateScope[];
};

export type StatePersistenceEvidence = {
  violations: StatePersistenceViolation[];
};

export type GoldenPathDeviation = {
  kind: "unexpected_transition" | "unexpected_token" | "sequence_outlier";
  atIndex?: number;
  hop?: RuntimeRiskHop;
  details?: {
    from?: string;
    to?: string;
    probability?: number;
    observedCount?: number;
  };
};

export type GoldenPathEvidence = {
  baseline: BaselineReadiness;
  expected: { source: "learned" | "none"; modelId?: string };
  observed: { tokens: string[]; hopsInOrder: RuntimeRiskHop[] };
  deviations: GoldenPathDeviation[];
  crossNode?: {
    score: number;
    baseline: BaselineReadiness;
    expected: { source: "learned" | "none"; modelId?: string };
    observed: { tokens: string[]; hopsInOrder: RuntimeRiskHop[] };
    deviations: GoldenPathDeviation[];
  };
};

export type DataExposureEvidence = {
  exposures: Array<{
    sink: DataExposureSink;
    detector: DataExposureDetector;
    classification: DataClassification;
    severity: RuntimeRiskSeverity;
    hop: RuntimeRiskHop;
    ruleIdSha256?: string;
    riskTag?: string;
    findingCount?: number;
  }>;
};

export type MandateDeviationEvidence = {
  context: {
    intentIdSha256?: string;
    cartIdSha256?: string;
    issuerDidSha256?: string;
    subjectDidSha256?: string;
    constraintsSha256?: string;
    cartSha256?: string;
  };
  violations: Array<{
    code: string;
    hop: RuntimeRiskHop;
    source: "mandate" | "reason" | "risk_tag" | "context";
  }>;
};

export type RuntimeRiskEvidence = {
  behaviorDrift: BehaviorDriftEvidence;
  goldenPathDrift: GoldenPathEvidence;
  statePersistence: StatePersistenceEvidence;
  dataExposureRisk: DataExposureEvidence;
  mandateDeviation: MandateDeviationEvidence;
};

export type RuntimeRiskSubscores = Record<RuntimeRiskSubtype, number>;

export type RuntimeRiskNodeAssessment = {
  runId: string;
  nodeId: string;
  eventCount: number;
  firstTimestamp?: string;
  lastTimestamp?: string;
  overallScore: number;
  subscores: RuntimeRiskSubscores;
  signals: RuntimeRiskSignal[];
  evidence: RuntimeRiskEvidence;
};

export type RuntimeRiskAssessment = {
  runId: string;
  nodeCount: number;
  eventCount: number;
  firstTimestamp?: string;
  lastTimestamp?: string;
  overallScore: number;
  subscores: RuntimeRiskSubscores;
  signals: RuntimeRiskSignal[];
  nodes: RuntimeRiskNodeAssessment[];
  model: {
    version: string;
    aggregation: "maximum";
  };
};

export type RiskComputationResult<Evidence> = {
  score: number;
  evidence: Evidence;
  signals: RuntimeRiskSignal[];
  modelVersion: string;
};
