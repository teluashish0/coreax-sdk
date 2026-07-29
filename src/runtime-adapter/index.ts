import type { RuntimeAdapter, RuntimeAdapterConfig } from "./types";
import { LocalRuntimeAdapter } from "./localAdapter";
import { resolveRuntimeAdapterConfig } from "./resolver";

export function createRuntimeAdapter(config?: RuntimeAdapterConfig): RuntimeAdapter {
  const resolved = resolveRuntimeAdapterConfig(config);
  return new LocalRuntimeAdapter(resolved.protocolVersion);
}

export { LocalRuntimeAdapter } from "./localAdapter";
export { resolveRuntimeAdapterConfig } from "./resolver";
export {
  mapRuntimeDecisionRequest,
  mapRuntimeDecisionToEnforcement,
  type RuntimeEnforcementDecision,
  type RuntimeMapperInput,
} from "./mappers";
export type {
  RuntimeAdapter,
  RuntimeAdapterConfig,
  RuntimeAdapterMode,
  RuntimeDecisionAction,
  RuntimeDecisionInput,
  RuntimeDecisionOutput,
  RuntimeExecutionLayer,
  RuntimeEnforcementMode,
  RuntimeEvaluationStrategy,
  RuntimeObligation,
  RuntimeAuditRef,
} from "./types";
export { RUNTIME_PROTOCOL_VERSION } from "./types";
