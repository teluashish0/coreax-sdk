import type { AuditSink } from "../core/contracts";
import type { AgentStateVariables } from "../agent-state";
import type { MiddlewareInvocationState } from "./invocationState";
import {
  createRawPayloadRecorder,
  type RawPayloadCaptureConfig,
  type RawPayloadRecordInput,
} from "./rawPayloads";
import { inferOp } from "./tooling";

export type AuditEnvelopeInput = {
  sdkVersion: string;
  middlewareHop?: { server?: string; tool?: string };
  state: MiddlewareInvocationState;
  startedAt: number;
  server: { name: string; version: string };
  tool: string;
  currentVersion: string;
  ctx: { args: any; idempotencyKey?: string | null; headers?: Record<string, string> };
  latency: number;
  tenant?: string;
  environment?: string;
  client?: string;
  clientVersion?: string;
  traceId: string;
  spanId: string;
  causeTraceId?: string;
  causeSpanId?: string;
  retention?: string;
  registryFrozen: boolean;
  registrySnapshotHash: string;
  checkLevel: string;
  checkKind: string;
  nodeId?: string;
  agentRef?: string;
  agentVariables?: AgentStateVariables;
  testsPerformed: string[];
  testSummary: Record<string, unknown>;
  compliance: { nist: string[]; owasp: string[]; cwe: string[] };
  vulnRefs: { cve: string[]; cwe: string[]; owasp: string[]; nist: string[] };
  ap2?: {
    intentId?: string;
    cartId?: string;
    constraintsSha256?: string;
    cartSha256?: string;
    issuerDid?: string;
    subjectDid?: string;
  };
};

export function stampResultTracing(result: any, traceId: string, spanId: string): void {
  if (!result || typeof result !== "object") return;
  const payload = result as Record<string, any>;
  if (payload.trace === undefined) payload.trace = traceId;
  if (payload.traceId === undefined) payload.traceId = traceId;
  if (payload.trace_id === undefined) payload.trace_id = traceId;
  if (payload.span === undefined) payload.span = spanId;
  if (payload.spanId === undefined) payload.spanId = spanId;
  if (payload.span_id === undefined) payload.span_id = spanId;
}

export function resolveDenialType(reason?: string): "rasp" | "sast" | "dast" | undefined {
  if (!reason) return undefined;
  if (reason === "subprocess_blocked") return "rasp";
  if (reason === "fs_violation" || reason === "egress_violation") return "rasp";
  if (reason.includes("sast")) return "sast";
  if (reason.includes("dast")) return "dast";
  return undefined;
}

export async function captureRawPayloads(input: {
  rawPayloadConfig?: RawPayloadCaptureConfig;
  auditSink: AuditSink;
  tenant?: string;
  environment?: string;
  client?: string;
  clientVersion?: string;
  state: MiddlewareInvocationState;
  nodeId?: string;
  agentRef?: string;
  traceId: string;
  spanId: string;
  tool: string;
  ctx: { args: any; idempotencyKey?: string | null };
  agentVariables?: Record<string, unknown>;
}): Promise<void> {
  if (input.rawPayloadConfig?.enabled !== true) return;
  const recorder = createRawPayloadRecorder({
    auditSink: input.auditSink,
    tenant: input.tenant,
    environment: input.environment,
    client: input.client,
    clientVersion: input.clientVersion,
    config: input.rawPayloadConfig,
  });
  const runId = input.agentRef || (() => {
    throw new Error("[sec0-middleware] agent runId is required when raw payload capture is enabled");
  })();
  const base: Omit<RawPayloadRecordInput, "payload" | "direction"> = {
    runId,
    traceId: input.traceId,
    spanId: input.spanId,
    nodeId: input.nodeId,
    tool: input.tool,
    decision: input.state.decision,
    riskTags: [...input.state.riskTags],
    idempotencyKey: input.ctx.idempotencyKey ?? null,
    agentVariables: input.agentVariables,
  };
  if (input.rawPayloadConfig.captureInputs !== false) {
    await recorder({ ...base, direction: "input", payload: input.ctx.args });
  }
  if (input.rawPayloadConfig.captureOutputs !== false) {
    await recorder({ ...base, direction: "output", payload: input.state.result });
  }
}

export function buildAuditEnvelope(input: AuditEnvelopeInput): Record<string, unknown> {
  const middlewareServer = String(input.middlewareHop?.server || `sec0-middleware@${input.sdkVersion}`);
  const middlewareTool = String(input.middlewareHop?.tool || "mcp.enforce@1.0");
  const targetServer = `${input.server.name}@${input.server.version}`;
  const denialType = resolveDenialType(input.state.decisionReason);

  return {
    ts: new Date(input.startedAt).toISOString(),
    trace_id: input.traceId,
    span_id: input.spanId,
    ...(input.causeTraceId ? { cause_trace_id: input.causeTraceId } : {}),
    ...(input.causeSpanId ? { cause_span_id: input.causeSpanId } : {}),
    tenant: input.tenant || "unknown",
    env: input.environment,
    client: input.client,
    clientVersion: input.clientVersion,
    server: middlewareServer,
    tool: middlewareTool,
    op: inferOp(input.tool, input.ctx.args),
    tool_ref: `${middlewareServer} ${middlewareTool}`,
    node_type: "middleware",
    target_server: targetServer,
    target_tool: input.tool,
    target_tool_ref: `${targetServer} ${input.tool}`,
    status: input.state.error ? "error" : "ok",
    latency_ms: input.latency,
    retries: 0,
    input_sha256: input.state.inputHash,
    output_sha256: input.state.outputHash,
    policy: {
      decision: input.state.decision,
      retention: input.retention,
      ...(input.state.decisionReason ? { reason: input.state.decisionReason } : {}),
      ...(input.ctx.headers && (input.ctx.headers as any)["x-dedupe"]
        ? { duplicate_policy: (input.ctx.headers as any)["x-dedupe"] }
        : {}),
    },
    idempotency_key: input.ctx.idempotencyKey ?? null,
    ...(input.tenant ? { actor: input.tenant } : {}),
    registry_frozen: input.registryFrozen,
    server_snapshot: input.registrySnapshotHash,
    ...(input.state.toolCodeChanged ? { tool_hash_changed: true } : {}),
    check_level: input.checkLevel,
    check_kind: input.checkKind,
    ...(input.state.authObj ? { auth: input.state.authObj } : {}),
    ...(input.state.sast.status ? { sast_status: input.state.sast.status } : {}),
    ...(input.state.sast.findings ? { sast_findings: input.state.sast.findings } : {}),
    ...(input.state.sast.scanId ? { sast_scan_id: input.state.sast.scanId } : {}),
    ...(input.state.sast.rawKey ? { sast_raw_key: input.state.sast.rawKey } : {}),
    ...(input.state.agentGuardRawKey ? { agent_guard_raw_key: input.state.agentGuardRawKey } : {}),
    ...(input.state.agentFindings?.length ? { agent_guard_findings: input.state.agentFindings } : {}),
    ...(input.state.dast.status ? { dast_status: input.state.dast.status } : {}),
    ...(input.state.dast.findings ? { dast_findings: input.state.dast.findings } : {}),
    ...(input.state.dast.scanId ? { dast_scan_id: input.state.dast.scanId } : {}),
    ...(input.state.dast.rawKey ? { dast_raw_key: input.state.dast.rawKey } : {}),
    ...(input.state.escalationResult?.id ? { escalation_id: input.state.escalationResult.id } : {}),
    ...(input.state.escalationResult?.status ? { escalation_status: input.state.escalationResult.status } : {}),
    ...(input.state.riskTags.length ? { risk_tags: input.state.riskTags } : {}),
    ...(input.nodeId
      ? {
          nodeId: input.nodeId,
          agentRef: input.agentRef,
          ...(input.agentVariables ? { agentVariables: input.agentVariables } : {}),
        }
      : {}),
    ...(input.state.decision === "deny" ? { denial_level: "middleware" } : {}),
    ...(input.state.decision === "deny" && denialType ? { denial_type: denialType } : {}),
    ...(input.testsPerformed.length ? { tests_performed: input.testsPerformed } : {}),
    ...(Object.keys(input.testSummary).length ? { test_summary: input.testSummary } : {}),
    ...(input.compliance.nist.length || input.compliance.owasp.length || input.compliance.cwe.length
      ? { compliance: input.compliance }
      : {}),
    ...(input.vulnRefs.cve.length || input.vulnRefs.cwe.length || input.vulnRefs.owasp.length ? { vuln_refs: input.vulnRefs } : {}),
    ...(input.state.egressDomain ? { egress_domain: input.state.egressDomain } : {}),
    ...(input.state.fsPath ? { fs_path: input.state.fsPath } : {}),
    ...(input.state.decisionReason ? { decision_reason: input.state.decisionReason } : {}),
    ...(input.ap2?.intentId ? { ap2_intent_id: input.ap2.intentId } : {}),
    ...(input.ap2?.cartId ? { ap2_cart_id: input.ap2.cartId } : {}),
    ...(input.ap2?.constraintsSha256 ? { ap2_constraints_sha256: input.ap2.constraintsSha256 } : {}),
    ...(input.ap2?.cartSha256 ? { ap2_cart_sha256: input.ap2.cartSha256 } : {}),
    ...(input.ap2?.issuerDid ? { ap2_issuer_did: input.ap2.issuerDid } : {}),
    ...(input.ap2?.subjectDid ? { ap2_subject_did: input.ap2.subjectDid } : {}),
    ...(input.ctx.headers?.["x-ap2-intent-id"] ? { ap2_intent_id: input.ctx.headers["x-ap2-intent-id"] } : {}),
    ...(input.ctx.headers?.["x-ap2-cart-id"] ? { ap2_cart_id: input.ctx.headers["x-ap2-cart-id"] } : {}),
    ...(input.ctx.headers?.["x-ap2-constraints-sha256"]
      ? { ap2_constraints_sha256: input.ctx.headers["x-ap2-constraints-sha256"] }
      : {}),
    ...(input.ctx.headers?.["x-ap2-cart-sha256"] ? { ap2_cart_sha256: input.ctx.headers["x-ap2-cart-sha256"] } : {}),
    ...(input.state.versionChanged
      ? { previous_tool_version: input.state.previousVersion, new_tool_version: input.currentVersion }
      : {}),
    ...(input.state.escalationFailure ? { escalation_error: input.state.escalationFailure } : {}),
    risk_score: input.state.riskTags.length ? Math.min(100, input.state.riskTags.length * 25) : undefined,
  };
}
