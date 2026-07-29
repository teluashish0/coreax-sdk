import type {
  RuntimeDecisionInput,
  RuntimeDecisionOutput,
  RuntimeEnforcementMode,
  RuntimeEvaluationStrategy,
  RuntimeExecutionLayer,
} from "./types";
import { RUNTIME_PROTOCOL_VERSION } from "./types";
import { normalizeStringArray } from "./shared";

export interface RuntimeMapperInput {
  executionLayer: RuntimeExecutionLayer;
  namespace?: string;
  server: string;
  tool: string;
  nodeId?: string;
  runId?: string;
  mode?: RuntimeEnforcementMode;
  strategy?: RuntimeEvaluationStrategy;
  denyOn?: string[];
  forceDeny?: boolean;
  reasons?: string[];
  riskTags?: string[];
  attributes?: Record<string, unknown>;
  requestId?: string;
  protocolVersion?: string;
}

export function mapRuntimeDecisionRequest(input: RuntimeMapperInput): RuntimeDecisionInput {
  return {
    protocolVersion:
      typeof input.protocolVersion === "string" && input.protocolVersion.trim()
        ? input.protocolVersion.trim()
        : RUNTIME_PROTOCOL_VERSION,
    ...(typeof input.requestId === "string" && input.requestId.trim() ? { requestId: input.requestId.trim() } : {}),
    context: {
      integrationSurface: "coreax",
      executionLayer: input.executionLayer,
      namespace:
        typeof input.namespace === "string" && input.namespace.trim()
          ? input.namespace.trim()
          : undefined,
      server: String(input.server),
      tool: String(input.tool),
      ...(typeof input.nodeId === "string" && input.nodeId.trim() ? { nodeId: input.nodeId.trim() } : {}),
      ...(typeof input.runId === "string" && input.runId.trim() ? { runId: input.runId.trim() } : {}),
    },
    enforcement: {
      mode: input.mode === "observe" ? "observe" : "enforce",
      strategy: input.strategy === "deny_on_any" ? "deny_on_any" : "deny_on_match",
      denyOn: normalizeStringArray(input.denyOn),
      forceDeny: input.forceDeny === true,
    },
    input: {
      reasons: normalizeStringArray(input.reasons),
      riskTags: normalizeStringArray(input.riskTags),
      attributes: input.attributes && typeof input.attributes === "object" ? input.attributes : {},
    },
  };
}

export interface RuntimeEnforcementDecision {
  shouldBlock: boolean;
  shouldDeny: boolean;
  decision: RuntimeDecisionOutput["decision"];
  reason?: string;
  reasons: string[];
  obligations: RuntimeDecisionOutput["obligations"];
  auditRefs: RuntimeDecisionOutput["auditRefs"];
  evaluationSource: RuntimeDecisionOutput["evaluationSource"];
  adapterMode: RuntimeDecisionOutput["adapterMode"];
}

export function mapRuntimeDecisionToEnforcement(
  output: RuntimeDecisionOutput,
): RuntimeEnforcementDecision {
  return {
    shouldBlock: output.decision !== "allow",
    shouldDeny: output.decision === "deny",
    decision: output.decision,
    ...(output.reason ? { reason: output.reason } : {}),
    reasons: normalizeStringArray(output.reasons),
    obligations: Array.isArray(output.obligations) ? output.obligations : [],
    auditRefs: Array.isArray(output.auditRefs) ? output.auditRefs : [],
    evaluationSource: output.evaluationSource,
    adapterMode: output.adapterMode,
  };
}
