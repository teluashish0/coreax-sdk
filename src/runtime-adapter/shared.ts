import {
  RUNTIME_PROTOCOL_VERSION,
  type RuntimeDecisionAction,
  type RuntimeDecisionInput,
} from "./types";

export interface NormalizedRuntimeDecisionInput extends RuntimeDecisionInput {
  protocolVersion: string;
  enforcement: {
    mode: "observe" | "enforce";
    strategy: "deny_on_match" | "deny_on_any";
    denyOn: string[];
    forceDeny: boolean;
  };
  input: {
    reasons: string[];
    riskTags: string[];
    attributes: Record<string, unknown>;
  };
}

export function normalizeStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const seen = new Set<string>();
  const out: string[] = [];
  for (const entry of value) {
    const v = String(entry ?? "").trim();
    if (!v || seen.has(v)) continue;
    seen.add(v);
    out.push(v);
  }
  return out;
}

export function normalizeDecisionAction(value: unknown): RuntimeDecisionAction | null {
  return value === "allow" || value === "deny" || value === "escalate" || value === "clarify"
    ? value
    : null;
}

export function normalizeRuntimeDecisionInput(
  input: RuntimeDecisionInput,
  fallbackProtocolVersion: string = RUNTIME_PROTOCOL_VERSION,
): NormalizedRuntimeDecisionInput {
  const protocolVersion =
    typeof input?.protocolVersion === "string" && input.protocolVersion.trim()
      ? input.protocolVersion.trim()
      : fallbackProtocolVersion;
  const mode =
    input?.enforcement?.mode === "observe" ? "observe" : "enforce";
  const strategy = input?.enforcement?.strategy === "deny_on_any" ? "deny_on_any" : "deny_on_match";
  const denyOn = normalizeStringArray(input?.enforcement?.denyOn);
  const forceDeny = input?.enforcement?.forceDeny === true;
  const reasons = normalizeStringArray(input?.input?.reasons);
  const riskTags = normalizeStringArray(input?.input?.riskTags);
  const attributes =
    input?.input?.attributes && typeof input.input.attributes === "object" && !Array.isArray(input.input.attributes)
      ? (input.input.attributes as Record<string, unknown>)
      : {};

  return {
    ...input,
    protocolVersion,
    requestId: typeof input?.requestId === "string" && input.requestId.trim() ? input.requestId.trim() : undefined,
    context: {
      integrationSurface: "coreax",
      executionLayer: input?.context?.executionLayer ?? "middleware",
      server: String(input?.context?.server ?? "unknown"),
      tool: String(input?.context?.tool ?? "unknown"),
      ...(typeof input?.context?.namespace === "string" &&
      input.context.namespace.trim()
        ? { namespace: input.context.namespace.trim() }
        : {}),
      ...(typeof input?.context?.nodeId === "string" && input.context.nodeId.trim() ? { nodeId: input.context.nodeId.trim() } : {}),
      ...(typeof input?.context?.runId === "string" && input.context.runId.trim() ? { runId: input.context.runId.trim() } : {}),
      ...(input?.context?.metadata && typeof input.context.metadata === "object" && !Array.isArray(input.context.metadata)
        ? { metadata: input.context.metadata }
        : {}),
    },
    enforcement: {
      mode,
      strategy,
      denyOn,
      forceDeny,
    },
    input: {
      reasons,
      riskTags,
      attributes,
    },
  };
}
