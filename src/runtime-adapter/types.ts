export const RUNTIME_PROTOCOL_VERSION = "2026-02-01" as const;

export type RuntimeAdapterMode = "local";
export type RuntimeDecisionAction = "allow" | "deny" | "escalate" | "clarify";
export type RuntimeExecutionLayer =
  | "middleware"
  | "decorator"
  | "custom-agent";
export type RuntimeEnforcementMode = "observe" | "enforce";
export type RuntimeEvaluationStrategy = "deny_on_match" | "deny_on_any";

export interface RuntimeObligation {
  type: string;
  params?: Record<string, unknown>;
}

export interface RuntimeAuditRef {
  ref: string;
  kind?: string;
  href?: string;
}

export interface RuntimeDecisionInput {
  protocolVersion?: string;
  requestId?: string;
  context: {
    integrationSurface: "coreax";
    executionLayer: RuntimeExecutionLayer;
    namespace?: string;
    server: string;
    tool: string;
    nodeId?: string;
    runId?: string;
    metadata?: Record<string, unknown>;
  };
  enforcement: {
    mode: RuntimeEnforcementMode;
    strategy?: RuntimeEvaluationStrategy;
    denyOn?: string[];
    forceDeny?: boolean;
  };
  input: {
    reasons: string[];
    riskTags?: string[];
    attributes?: Record<string, unknown>;
  };
}

export interface RuntimeDecisionOutput {
  protocolVersion: string;
  adapterMode: RuntimeAdapterMode;
  evaluationSource: "local" | "custom";
  decision: RuntimeDecisionAction;
  reason?: string;
  reasons: string[];
  obligations: RuntimeObligation[];
  auditRefs: RuntimeAuditRef[];
}

export interface RuntimeAdapterConfig {
  protocolVersion?: string;
}

export interface ResolvedRuntimeAdapterConfig {
  mode: RuntimeAdapterMode;
  protocolVersion: string;
}

export interface RuntimeAdapter {
  evaluate(input: RuntimeDecisionInput): Promise<RuntimeDecisionOutput>;
}
