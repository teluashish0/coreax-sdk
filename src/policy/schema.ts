const enforcementReasons = [
  "tool_not_in_allowlist",
  "version_unpinned",
  "missing_idempotency_for_side_effect",
  "egress_violation",
  "fs_violation",
  "payload_too_large",
  "registry_mutation",
  "handler_swap",
  "server_code_changed",
  "tool_code_changed",
  "agent_guard_failed",
  "contextual_evaluator_denied",
  "contextual_evaluator_escalated",
  "contextual_evaluator_clarification_required",
] as const;

const reasonArray = {
  type: "array",
  uniqueItems: true,
  items: { type: "string", enum: enforcementReasons },
} as const;

export const policySchema = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://coreax.dev/schemas/policy-v1.json",
  type: "object",
  required: ["version", "tools", "enforcement"],
  additionalProperties: false,
  properties: {
    version: { const: 1 },
    tools: {
      type: "object",
      required: ["allow"],
      additionalProperties: false,
      properties: {
        allow: {
          type: "array",
          minItems: 1,
          uniqueItems: true,
          items: { type: "string", minLength: 1 },
        },
        requirePinnedVersions: { type: "boolean" },
      },
    },
    enforcement: {
      type: "object",
      required: ["denyOn"],
      additionalProperties: false,
      properties: {
        denyOn: reasonArray,
        escalateOn: reasonArray,
      },
    },
    privacy: {
      type: "object",
      additionalProperties: false,
      properties: {
        redactOutputs: { type: "boolean" },
      },
    },
    agentGuard: {
      type: "object",
      additionalProperties: false,
      properties: {
        enabled: { type: "boolean" },
        blockOnSeverity: {
          type: "string",
          enum: ["low", "medium", "high", "critical"],
        },
        blockOnCount: { type: "integer", minimum: 1 },
      },
    },
    security: {
      type: "object",
      additionalProperties: false,
      properties: {
        egressAllowlist: {
          type: "array",
          uniqueItems: true,
          items: { type: "string", minLength: 1 },
        },
        filesystemAllowlist: {
          type: "array",
          uniqueItems: true,
          items: { type: "string", minLength: 1 },
        },
        maxPayloadKb: { type: "number", exclusiveMinimum: 0 },
        requireIdempotencyForSideEffects: { type: "boolean" },
        requireApprovalFor: reasonArray,
      },
    },
    metadata: { type: "object" },
  },
} as const;
