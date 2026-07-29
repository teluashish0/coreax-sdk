export type Severity = "low" | "medium" | "high" | "critical";

export type PolicyEnforcementReason =
  | "tool_not_in_allowlist"
  | "version_unpinned"
  | "missing_idempotency_for_side_effect"
  | "egress_violation"
  | "fs_violation"
  | "payload_too_large"
  | "registry_mutation"
  | "handler_swap"
  | "server_code_changed"
  | "tool_code_changed"
  | "agent_guard_failed"
  | "contextual_evaluator_denied"
  | "contextual_evaluator_escalated"
  | "contextual_evaluator_clarification_required";

export interface CoreaxPolicy {
  version: 1;
  tools: {
    allow: string[];
    requirePinnedVersions?: boolean;
  };
  enforcement: {
    denyOn: PolicyEnforcementReason[];
    escalateOn?: PolicyEnforcementReason[];
  };
  privacy?: {
    redactOutputs?: boolean;
  };
  agentGuard?: {
    enabled?: boolean;
    blockOnSeverity?: Severity;
    blockOnCount?: number;
  };
  security?: {
    egressAllowlist?: string[];
    filesystemAllowlist?: string[];
    maxPayloadKb?: number;
    requireIdempotencyForSideEffects?: boolean;
    requireApprovalFor?: PolicyEnforcementReason[];
  };
  metadata?: Record<string, unknown>;
}

export interface ValidationResult {
  valid: boolean;
  errors?: string[];
}
