import type { AuditSigner, CoreaxAuditConfig } from "../audit";
import type { AuditSink } from "../core";
import type {
  EvaluatorInput,
  SemanticCalibrator,
} from "../evaluator";
import type {
  CoreaxGuard,
  CoreaxGuardConfig,
  GuardDecision,
  GuardPolicyInput,
} from "../guard";

export interface ToolInvocationContext<TArguments = unknown> {
  args: TArguments;
  idempotencyKey?: string | null;
  headers?: Record<string, string>;
}

export type ToolHandler<TArguments = unknown, TResult = unknown> = (
  context: ToolInvocationContext<TArguments>,
) => Promise<TResult> | TResult;

export interface McpServerLike {
  name: string;
  version: string;
  tool(nameAtVersion: string, handler: ToolHandler): void;
  __getTools?(): Map<string, ToolHandler>;
  __setTool?(nameAtVersion: string, handler: ToolHandler): void;
}

export interface MiddlewareContextualEvaluatorOptions {
  semanticCalibrator?: SemanticCalibrator;
  denyThreshold?: number;
  escalateThreshold?: number;
  buildInput(context: {
    server: { name: string; version: string };
    tool: string;
    invocation: ToolInvocationContext;
  }): Promise<EvaluatorInput> | EvaluatorInput;
}

export interface MiddlewareAdapters {
  guard?: CoreaxGuard;
  auditSink?: AuditSink;
}

export interface MiddlewareOptions {
  policy: GuardPolicyInput | string;
  signer: AuditSigner;
  coreax?: CoreaxAuditConfig;
  namespace?: string;
  mode?: CoreaxGuardConfig["mode"];
  guard?: Omit<CoreaxGuardConfig, "mode" | "provider">;
  adapters?: MiddlewareAdapters;
  contextualEvaluator?: MiddlewareContextualEvaluatorOptions;
  onDecision?(event: {
    server: { name: string; version: string };
    tool: string;
    decision: GuardDecision;
  }): Promise<void> | void;
  now?: () => number;
}

export type PolicyViolation =
  | "tool_not_in_allowlist"
  | "version_unpinned"
  | "missing_idempotency_for_side_effect"
  | "agent_guard_failed"
  | "egress_violation"
  | "fs_violation"
  | "payload_too_large"
  | "registry_mutation"
  | "handler_swap"
  | "server_code_changed"
  | "tool_code_changed"
  | "contextual_evaluator_denied"
  | "contextual_evaluator_escalated"
  | "contextual_evaluator_clarification_required";

export class PolicyDeniedError extends Error {
  readonly code = "COREAX_POLICY_DENIED" as const;

  constructor(
    readonly violation: PolicyViolation,
    message: string = violation,
  ) {
    super(message);
  }
}

export class SigningFailedError extends Error {
  readonly code = "COREAX_SIGNING_FAILED" as const;
}

export class UnpinnedVersionError extends Error {
  readonly code = "COREAX_UNPINNED_VERSION" as const;
}

export class IdempotencyRequiredError extends Error {
  readonly code = "COREAX_IDEMPOTENCY_REQUIRED" as const;
}
