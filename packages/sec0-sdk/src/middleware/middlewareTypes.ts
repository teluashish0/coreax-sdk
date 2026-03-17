import type { Sec0Config } from "../audit";
import type { AgentStateVariables } from "../agent-state";
import type {
  ApprovalVerifier,
  AuditSink,
  EscalationReporter,
  PolicyProvider,
  RuntimeInvoker,
} from "../core/contracts";
import type {
  ContextualEvaluatorAdapter,
  EvaluatorInput,
  EvaluatorInputPatch,
  EvaluatorMode,
  EvaluatorSource,
} from "../evaluator";
import type { PolicyObject } from "../policy";
import type { Signer } from "../signer";
import type { RuntimeAdapterConfig } from "../runtime-adapter";
import type { AgentGuardFinding, AgentGuardOptions } from "./agentGuard";
import type { AgentGuardScanFn } from "./compliance";
import type { ControlPlanePolicySource } from "./controlPlanePolicy";
import type { DastOptions } from "./dast";
import type { IdentityContext } from "./identity";
import type { RawPayloadCaptureConfig, UploadApiConfig } from "./rawPayloads";
import type { SastOptions } from "./sast";

type AgentGuardAdapterConfig =
  | { type: "nemo" | "guardrails" | "llmguard"; serviceUrl: string }
  | { type: "custom"; onScanPrompt?: AgentGuardScanFn; onScanOutput?: AgentGuardScanFn; onScanRun?: AgentGuardScanFn };

type MiddlewareAgentGuardOptions = AgentGuardOptions & {
  adapters?: AgentGuardAdapterConfig[];
  run_context?: {
    enabled?: boolean;
    max_chars?: number;
    max_events?: number;
    max_event_chars?: number;
    max_runs?: number;
    ttl_ms?: number;
    include_objective?: boolean;
    include_metadata?: boolean;
  };
};

type MiddlewareContextualEvaluatorOptions = {
  evaluatorSource: EvaluatorSource;
  evaluatorMode: EvaluatorMode;
  debug?: boolean;
  local?: {
    adapter?: ContextualEvaluatorAdapter;
    denyThreshold?: number;
    escalateThreshold?: number;
  };
  controlPlane?: {
    adapter?: ContextualEvaluatorAdapter;
    timeoutMs?: number;
  };
  eligible?: (info: {
    server: { name: string; version: string };
    tool: string;
    toolRef: string;
    op: "read" | "create" | "update" | "delete";
    ctx: { args: any; idempotencyKey?: string | null; headers?: Record<string, string> };
    nodeId?: string;
    agentRunId?: string;
    policy: PolicyObject;
    explicitReasons: string[];
    input: EvaluatorInput;
  }) => boolean;
  buildContext?: (info: {
    tenant?: string;
    server: { name: string; version: string };
    tool: string;
    toolRef: string;
    op: "read" | "create" | "update" | "delete";
    ctx: { args: any; idempotencyKey?: string | null; headers?: Record<string, string> };
    nodeId?: string;
    agentRunId?: string;
    policy: PolicyObject;
    objective?: string | null;
    identity?: IdentityContext;
    explicitReasons: string[];
    defaultInput: EvaluatorInput;
  }) => Promise<EvaluatorInputPatch | null | undefined> | EvaluatorInputPatch | null | undefined;
};

type RuntimeDebugConfig = { policySync?: boolean; sast?: boolean; dast?: boolean };
type PresignFlushConfig = { enabled: boolean; intervalMs: number };
type RuntimeWebhookConfig = { policyUrl?: string };
type RuntimeConfig = {
  uploadApi?: UploadApiConfig;
  debug?: RuntimeDebugConfig;
  presignFlush?: PresignFlushConfig;
  webhook?: RuntimeWebhookConfig;
  forceDastRawUpload?: boolean;
  rawPayloads?: RawPayloadCaptureConfig;
  enforcement?: RuntimeAdapterConfig;
};

export interface MiddlewareAdapters {
  policyProvider?: PolicyProvider;
  approvalVerifier?: ApprovalVerifier;
  escalationReporter?: EscalationReporter;
  auditSink?: AuditSink;
  runtimeInvoker?: RuntimeInvoker;
}

export interface McpServerLike {
  name: string;
  version: string;
  tool(
    nameAtVersion: string,
    handler: (ctx: { args: any; idempotencyKey?: string | null; headers?: Record<string, string> }) => Promise<any> | any,
  ): void;
  __getTools?(): Map<string, (ctx: { args: any; idempotencyKey?: string | null; headers?: Record<string, string> }) => Promise<any> | any>;
  __setTool?(nameAtVersion: string, handler: (ctx: { args: any; idempotencyKey?: string | null; headers?: Record<string, string> }) => Promise<any> | any): void;
}

export interface OTelConfig {
  endpoint: string;
  serviceName: string;
  serviceVersion?: string;
  environment?: string;
  tenant?: string;
}

export interface MiddlewareOptions {
  policy: PolicyObject | string | ControlPlanePolicySource;
  signer: Signer;
  otel: OTelConfig;
  sec0: Sec0Config;
  adapters?: MiddlewareAdapters;
  controlPlaneUrl?: string;
  apiKey?: string;
  auth?: { apiKey?: string; bearerToken?: string };
  runtime?: RuntimeConfig;
  middlewareHop?: {
    server?: string;
    tool?: string;
  };
  telemetry?: { enabled?: boolean };
  agentStateTelemetry?: {
    includeServerSignals?: boolean;
    includeToolSignals?: boolean;
  };
  ap2?: {
    enabled?: boolean;
    requireForSideEffects?: boolean;
    headers?: { intent?: string; cart?: string; bundle?: string };
    trust?: { issuersAllowlist?: string[]; didMethods?: string[]; clockSkewSec?: number };
    tools?: { allow?: string[] };
  };
  sast?: SastOptions;
  dast?: DastOptions;
  agentGuard?: MiddlewareAgentGuardOptions;
  contextualEvaluator?: MiddlewareContextualEvaluatorOptions;
  augment?: (info: {
    tenant: string;
    server: { name: string; version: string };
    tool: string;
    ctx: { args: any; idempotencyKey?: string | null; headers?: Record<string, string> };
  }) => Promise<{ envelope?: Record<string, any>; span?: Record<string, any> }> | { envelope?: Record<string, any>; span?: Record<string, any> };
}

export type PolicyViolation =
  | "policy_fetch_failed"
  | "tool_not_in_allowlist"
  | "version_unpinned"
  | "missing_idempotency_for_side_effect"
  | "missing_audit_signature"
  | "agent_guard_failed"
  | "egress_violation"
  | "fs_violation"
  | "payload_too_large"
  | "subprocess_blocked"
  | "registry_mutation"
  | "handler_swap"
  | "server_code_changed"
  | "tool_code_changed"
  | "skill_version_changed"
  | "skill_code_changed"
  | "skill_scan_pending"
  | "skill_scan_failed"
  | "contextual_evaluator_denied"
  | "contextual_evaluator_escalated";

export class PolicyDeniedError extends Error {
  code = "POLICY_DENIED" as const;
  violation: PolicyViolation;

  constructor(violation: PolicyViolation, message?: string) {
    super(message ?? violation);
    this.violation = violation;
  }
}

export class SigningFailedError extends Error {
  code = "SIGNING_FAILED" as const;
}

export class UnpinnedVersionError extends Error {
  code = "UNPINNED_VERSION" as const;
}

export class IdempotencyRequiredError extends Error {
  code = "IDEMPOTENCY_REQUIRED" as const;
}

export type {
  AgentGuardAdapterConfig,
  MiddlewareAgentGuardOptions,
  MiddlewareContextualEvaluatorOptions,
  PresignFlushConfig,
  RuntimeConfig,
  RuntimeDebugConfig,
  RuntimeWebhookConfig,
};
