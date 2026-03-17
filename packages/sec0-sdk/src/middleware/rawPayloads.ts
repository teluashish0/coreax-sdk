import type { AuditSink } from "../core/contracts";
import { createControlPlaneClient } from "./adapters/controlPlaneClient";
import { uploadScanEvidence } from "./adapters/scanEvidenceUploader";

export type UploadApiConfig = { baseUrl: string; apiKey: string };

export type RawPayloadCaptureConfig = {
  enabled: boolean;
  captureInputs?: boolean;
  captureOutputs?: boolean;
  includeAgentState?: boolean;
  maxBytes?: number;
  redact?: RawPayloadRedactor;
};

export type RawPayloadRecordInput = {
  direction: "input" | "output";
  payload: any;
  runId: string;
  traceId: string;
  spanId: string;
  nodeId?: string;
  tool: string;
  decision: string;
  riskTags: string[];
  idempotencyKey?: string | null;
  agentVariables?: Record<string, unknown>;
};

export type RawPayloadRedactor = (payload: any, ctx: RawPayloadRecordInput) => any | Promise<any>;
export type RawPayloadRecorder = (input: RawPayloadRecordInput) => Promise<void>;

type PayloadSnapshot = {
  payload?: any;
  preview?: string;
  truncated: boolean;
  bytes: number;
};

export async function persistScanRawIfConfigured(opts: {
  tenant?: string;
  level: "gateway" | "middleware";
  kind: "sast" | "dast" | "agent_guard_findings";
  scanId: string;
  raw: any;
  uploadConfig?: UploadApiConfig;
}): Promise<string | null> {
  const tenant = (opts.tenant || "").trim();
  if (!tenant) return null;
  return uploadScanEvidence({
    kind: opts.kind,
    scanId: opts.scanId,
    raw: opts.raw,
    uploadConfig: opts.uploadConfig,
    controlPlaneClientFactory: (baseUrl) => createControlPlaneClient({ baseUrl }),
  });
}

export function createRawPayloadRecorder(params: {
  auditSink: AuditSink;
  tenant?: string;
  environment?: string;
  client?: string;
  clientVersion?: string;
  config: RawPayloadCaptureConfig;
}): RawPayloadRecorder {
  const tenant = ensureRuntimeString(params.tenant, "opts.otel.tenant");
  const environment = ensureRuntimeString(params.environment, "opts.otel.environment or sec0.presign.environment");
  const client = ensureRuntimeString(params.client, "sec0.presign.clientName");
  const clientVersion = ensureRuntimeString(params.clientVersion, "sec0.presign.clientVersion");
  const rawMaxBytes = params.config.maxBytes ?? 64 * 1024;
  if (!Number.isFinite(rawMaxBytes) || rawMaxBytes <= 0) {
    throw new Error("[sec0-middleware] runtime.rawPayloads.maxBytes must be a positive number");
  }
  const maxBytes = Math.floor(rawMaxBytes);
  const includeAgentState = params.config.includeAgentState === true;
  return async (input) => {
    const runId = ensureRuntimeString(input.runId, "agent runId");
    const traceId = ensureRuntimeString(input.traceId, "trace id");
    const spanId = ensureRuntimeString(input.spanId, "span id");
    const tool = ensureRuntimeString(input.tool, "tool name");
    const payloadValue = params.config.redact ? await Promise.resolve(params.config.redact(input.payload, input)) : input.payload;
    const snapshot = preparePayloadSnapshot(payloadValue, maxBytes);
    const metadata: Record<string, unknown> = {
      decision: input.decision,
    };
    if (input.riskTags.length) metadata.risk_tags = [...input.riskTags];
    if (input.idempotencyKey) metadata.idempotency_key = input.idempotencyKey;
    const agentState = includeAgentState ? sanitizeAgentStateForRaw(input.agentVariables) : undefined;
    if (!params.auditSink.appendRawPayload) {
      throw new Error("[sec0-middleware] configured audit sink does not support raw payload capture");
    }
    await params.auditSink.appendRawPayload({
      ts: new Date().toISOString(),
      trace_id: traceId,
      span_id: spanId,
      runId,
      tenant,
      environment,
      client,
      clientVersion,
      nodeId: input.nodeId,
      tool,
      direction: input.direction,
      ...(snapshot.payload !== undefined ? { payload: snapshot.payload } : {}),
      ...(snapshot.preview ? { payload_preview: snapshot.preview } : {}),
      ...(snapshot.truncated ? { payload_truncated: true } : {}),
      payload_bytes: snapshot.bytes,
      ...(Object.keys(metadata).length ? { metadata } : {}),
      ...(agentState ? { agent_state: agentState } : {}),
    });
  };
}

function ensureRuntimeString(value: string | undefined, label: string): string {
  if (typeof value !== "string") {
    throw new Error(`[sec0-middleware] ${label} is required for raw payload capture`);
  }
  const trimmed = value.trim();
  if (!trimmed) {
    throw new Error(`[sec0-middleware] ${label} cannot be empty for raw payload capture`);
  }
  return trimmed;
}

function preparePayloadSnapshot(value: any, maxBytes: number): PayloadSnapshot {
  let json: string;
  try {
    json = JSON.stringify(value ?? null);
  } catch (err: any) {
    throw new Error(`[sec0-middleware] Failed to serialize raw payload: ${err?.message || err}`);
  }
  const bytes = Buffer.byteLength(json, "utf8");
  if (bytes <= maxBytes) {
    return { payload: JSON.parse(json), truncated: false, bytes };
  }
  return { preview: json.slice(0, maxBytes), truncated: true, bytes };
}

function sanitizeAgentStateForRaw(value?: Record<string, unknown>): Record<string, unknown> | undefined {
  if (!value) return undefined;
  try {
    return JSON.parse(JSON.stringify(value));
  } catch (err: any) {
    throw new Error(`[sec0-middleware] Agent state is not JSON serializable (${err?.message || err})`);
  }
}
