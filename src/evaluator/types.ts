import { z } from "zod";

const RFC3339_TIMESTAMP =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-](\d{2}):(\d{2}))$/;

export function isStrictRfc3339Timestamp(value: string): boolean {
  const match = RFC3339_TIMESTAMP.exec(value);
  if (!match) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const offsetHour = match[9] === undefined ? 0 : Number(match[9]);
  const offsetMinute = match[10] === undefined ? 0 : Number(match[10]);
  if (
    year < 1 ||
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > 31 ||
    hour > 23 ||
    minute > 59 ||
    second > 59 ||
    offsetHour > 23 ||
    offsetMinute > 59
  ) {
    return false;
  }
  const calendarCheck = new Date(Date.UTC(year, month - 1, day));
  return (
    calendarCheck.getUTCFullYear() === year &&
    calendarCheck.getUTCMonth() === month - 1 &&
    calendarCheck.getUTCDate() === day &&
    Number.isFinite(Date.parse(value))
  );
}

const EvaluatorTimestampSchema = z
  .string()
  .min(1)
  .max(120)
  .refine(isStrictRfc3339Timestamp, {
    message: "timestamp must be RFC3339 with an explicit timezone",
  });

export const EvaluatorDecisionSchema = z.enum(["allow", "escalate", "clarify", "deny"]);
export type EvaluatorDecision = z.infer<typeof EvaluatorDecisionSchema>;

export const EvaluatorDecisionBasisSchema = z.enum(["semantic_reasoner"]);
export type EvaluatorDecisionBasis = z.infer<typeof EvaluatorDecisionBasisSchema>;

export const EvaluatorModeSchema = z.enum(["sync", "async", "hybrid"]);
export type EvaluatorMode = z.infer<typeof EvaluatorModeSchema>;

export const EvaluatorSourceSchema = z.enum(["disabled", "local", "custom"]);
export type EvaluatorSource = z.infer<typeof EvaluatorSourceSchema>;

export const EvaluatorSeveritySchema = z.enum(["low", "medium", "high", "critical"]);
export type EvaluatorSeverity = z.infer<typeof EvaluatorSeveritySchema>;

export const EvaluatorPrincipleSchema = z.enum([
  "authority_scope_mismatch",
  "boundary_crossing_without_justification",
  "source_use_misalignment",
  "unmet_preconditions",
  "disproportionate_disclosure",
  "insufficient_justification",
]);
export type EvaluatorPrinciple = z.infer<typeof EvaluatorPrincipleSchema>;

const IdentifierSchema = z.object({
  id: z.string().min(1).max(200).optional(),
  type: z.string().min(1).max(120).optional(),
  label: z.string().min(1).max(200).optional(),
}).passthrough();

export const EvaluatorActionSchema = z.object({
  kind: z.string().min(1).max(120),
  summary: z.string().min(1).max(1000),
  operation: z.string().min(1).max(120).optional(),
  sideEffect: z.boolean().optional(),
  disclosure: z.boolean().optional(),
  crossesBoundary: z.boolean().optional(),
  tool: z.object({
    name: z.string().min(1).max(200).optional(),
    version: z.string().min(1).max(120).optional(),
    server: z.string().min(1).max(200).optional(),
  }).passthrough().optional(),
  target: z.object({
    id: z.string().min(1).max(200).optional(),
    type: z.string().min(1).max(120).optional(),
    boundary: z.string().min(1).max(200).optional(),
    owner: z.string().min(1).max(200).optional(),
    classification: z.string().min(1).max(120).optional(),
    destination: z.string().min(1).max(500).optional(),
  }).passthrough().optional(),
  data: z.object({
    classifications: z.array(z.string().min(1).max(120)).max(50).optional(),
    estimatedRecords: z.number().int().nonnegative().optional(),
    destination: z.string().min(1).max(500).optional(),
  }).passthrough().optional(),
}).passthrough();
export type EvaluatorAction = z.infer<typeof EvaluatorActionSchema>;

export const EvaluatorActorSchema = IdentifierSchema.extend({
  role: z.string().min(1).max(120).optional(),
  boundary: z.string().min(1).max(200).optional(),
  labels: z.array(z.string().min(1).max(120)).max(50).optional(),
}).passthrough();
export type EvaluatorActor = z.infer<typeof EvaluatorActorSchema>;

export const EvaluatorPurposeSchema = z.object({
  summary: z.string().min(1).max(1000),
  objective: z.string().min(1).max(2000).optional(),
  justification: z.string().min(1).max(4000).optional(),
  expectedOutcome: z.string().min(1).max(2000).optional(),
}).passthrough();
export type EvaluatorPurpose = z.infer<typeof EvaluatorPurposeSchema>;

export const EvaluatorAuthoritySchema = z.object({
  scope: z.string().min(1).max(120).optional(),
  grantedScopes: z.array(z.string().min(1).max(120)).max(100).default([]),
  allowedBoundaries: z.array(z.string().min(1).max(200)).max(100).default([]),
  approvals: z.array(z.string().min(1).max(120)).max(100).default([]),
  delegations: z.array(z.string().min(1).max(200)).max(50).default([]),
}).passthrough();
export type EvaluatorAuthority = z.infer<typeof EvaluatorAuthoritySchema>;

const SourceDescriptorSchema = IdentifierSchema.extend({
  boundary: z.string().min(1).max(200).optional(),
  classification: z.string().min(1).max(120).optional(),
  provenance: z.string().min(1).max(200).optional(),
  justified: z.boolean().optional(),
  intendedUse: z.string().min(1).max(500).optional(),
}).passthrough();

export const EvaluatorEvidenceEntityRefSchema = z.object({
  id: z.string().min(1).max(200).optional(),
  type: z.string().min(1).max(120).optional(),
  role: z.string().min(1).max(120).optional(),
  label: z.string().min(1).max(200).optional(),
  metadata: z.record(z.unknown()).optional(),
}).passthrough();
export type EvaluatorEvidenceEntityRef = z.infer<typeof EvaluatorEvidenceEntityRefSchema>;

export const EvaluatorEvidenceEventStatusSchema = z.enum([
  "supported",
  "observed",
  "failed",
  "contradicted",
  "recovered",
  "superseded",
]);
export type EvaluatorEvidenceEventStatus = z.infer<typeof EvaluatorEvidenceEventStatusSchema>;

export const EvaluatorEvidenceEventSchema = z.object({
  eventId: z.string().min(1).max(200).optional(),
  timestamp: EvaluatorTimestampSchema.optional(),
  source: z.string().min(1).max(120).optional(),
  kind: z.string().min(1).max(120),
  claim: z.string().min(1).max(1000).optional(),
  claimGroup: z.string().min(1).max(200).optional(),
  summary: z.string().min(1).max(2000),
  status: EvaluatorEvidenceEventStatusSchema,
  confidence: z.number().min(0).max(1).nullable().optional(),
  provenanceRef: z.string().min(1).max(300).optional(),
  entityRefs: z.array(EvaluatorEvidenceEntityRefSchema).max(50).default([]),
  relatedEventIds: z.array(z.string().min(1).max(200)).max(100).default([]),
  contradictionLinks: z.array(z.string().min(1).max(200)).max(100).default([]),
  recoveryLinks: z.array(z.string().min(1).max(200)).max(100).default([]),
  metadata: z.record(z.unknown()).optional(),
}).passthrough();
export type EvaluatorEvidenceEvent = z.infer<typeof EvaluatorEvidenceEventSchema>;

export const EvaluatorActiveStateClaimSchema = z.object({
  key: z.string().min(1).max(200),
  claim: z.string().min(1).max(1000),
  summary: z.string().min(1).max(2000).optional(),
  confidence: z.number().min(0).max(1).nullable().optional(),
  supportingEventIds: z.array(z.string().min(1).max(200)).max(100).default([]),
  contradictingEventIds: z.array(z.string().min(1).max(200)).max(100).default([]),
  recoveryEventIds: z.array(z.string().min(1).max(200)).max(100).default([]),
  provenanceRefs: z.array(z.string().min(1).max(300)).max(100).default([]),
  entities: z.array(EvaluatorEvidenceEntityRefSchema).max(50).default([]),
  metadata: z.record(z.unknown()).optional(),
}).passthrough();
export type EvaluatorActiveStateClaim = z.infer<typeof EvaluatorActiveStateClaimSchema>;

export const EvaluatorActiveStateSchema = z.object({
  verifiedClaims: z.array(EvaluatorActiveStateClaimSchema).max(200).default([]),
  unresolvedClaims: z.array(EvaluatorActiveStateClaimSchema).max(200).default([]),
  supersededClaims: z.array(EvaluatorActiveStateClaimSchema).max(200).default([]),
  contradictedClaims: z.array(EvaluatorActiveStateClaimSchema).max(200).default([]),
  retrievalHints: z.array(z.string().min(1).max(500)).max(200).default([]),
  compacted: z.boolean().default(false),
  metadata: z.record(z.unknown()).optional(),
}).passthrough();
export type EvaluatorActiveState = z.infer<typeof EvaluatorActiveStateSchema>;

export const EvaluatorRetrievedEvidenceSchema = z.object({
  source: z.string().min(1).max(120).default("local"),
  events: z.array(EvaluatorEvidenceEventSchema).max(200).default([]),
  retrievalHints: z.array(z.string().min(1).max(500)).max(200).default([]),
  metadata: z.record(z.unknown()).optional(),
}).passthrough();
export type EvaluatorRetrievedEvidence = z.infer<typeof EvaluatorRetrievedEvidenceSchema>;

export const EvaluatorRuntimeContextSchema = z.object({
  integrationSurface: z.string().min(1).max(120).optional(),
  executionLayer: z.string().min(1).max(120).optional(),
  runId: z.string().min(1).max(200).optional(),
  traceId: z.string().min(1).max(200).optional(),
  spanId: z.string().min(1).max(200).optional(),
  sessionId: z.string().min(1).max(200).optional(),
  workflowState: z.record(z.unknown()).optional(),
  conversationState: z.record(z.unknown()).optional(),
  evidenceEvents: z.array(EvaluatorEvidenceEventSchema).max(300).default([]),
  activeState: EvaluatorActiveStateSchema.default({
    verifiedClaims: [],
    unresolvedClaims: [],
    supersededClaims: [],
    contradictedClaims: [],
    retrievalHints: [],
    compacted: false,
  }),
  retrievedEvidence: EvaluatorRetrievedEvidenceSchema.default({
    source: "local",
    events: [],
    retrievalHints: [],
  }),
  verifiedPrerequisites: z.array(z.string().min(1).max(500)).max(100).default([]),
  unresolvedPrerequisites: z.array(z.string().min(1).max(500)).max(100).default([]),
}).passthrough();
export type EvaluatorRuntimeContext = z.infer<typeof EvaluatorRuntimeContextSchema>;

export const EvaluatorProposalSchema = z.object({
  proposalType: z.enum(["message_proposal", "action_proposal"]),
  content: z.string().min(1).max(4000).optional(),
  toolCall: z.object({
    name: z.string().min(1).max(200),
    arguments: z.record(z.unknown()).default({}),
  }).passthrough().optional(),
}).passthrough();
export type EvaluatorProposal = z.infer<typeof EvaluatorProposalSchema>;

export const EvaluatorGraphContextItemSchema = z.object({
  source: z.string().min(1).max(120),
  summary: z.string().min(1).max(1000),
  ref: z.string().min(1).max(300).optional(),
  relevance: z.number().min(0).max(1).optional(),
  metadata: z.record(z.unknown()).optional(),
}).passthrough();
export type EvaluatorGraphContextItem = z.infer<typeof EvaluatorGraphContextItemSchema>;

export const EvaluatorOrchestrationStateSchema = z.object({
  state: z.enum(["normal", "cautious", "clarify_first", "constrained", "block"]),
  signalCodes: z.array(z.string().min(1).max(120)).max(50).default([]),
  missingFacts: z.array(z.string().min(1).max(500)).max(100).default([]),
  metadata: z.record(z.unknown()).optional(),
}).passthrough();
export type EvaluatorOrchestrationState = z.infer<typeof EvaluatorOrchestrationStateSchema>;

export const EvaluatorSourceUseSchema = z.object({
  sources: z.array(SourceDescriptorSchema).max(100).default([]),
  provenanceSummary: z.string().min(1).max(2000).optional(),
}).passthrough();
export type EvaluatorSourceUse = z.infer<typeof EvaluatorSourceUseSchema>;

export const EvaluatorConstraintsSchema = z.object({
  hard: z.array(z.string().min(1).max(500)).max(100).default([]),
  soft: z.array(z.string().min(1).max(500)).max(100).default([]),
  requiredPrerequisites: z.array(z.string().min(1).max(500)).max(100).default([]),
  requiredApprovals: z.array(z.string().min(1).max(120)).max(100).default([]),
  forbiddenBoundaries: z.array(z.string().min(1).max(200)).max(100).default([]),
  maxClassification: z.string().min(1).max(120).optional(),
  disclosureBudget: z.object({
    maxRecords: z.number().int().nonnegative().optional(),
    maxClassifications: z.array(z.string().min(1).max(120)).max(50).default([]),
  }).passthrough().optional(),
}).passthrough();
export type EvaluatorConstraints = z.infer<typeof EvaluatorConstraintsSchema>;

const EvaluatorHistoryEventSchema = z.object({
  submissionId: z.string().min(1).max(200).optional(),
  decision: EvaluatorDecisionSchema.optional(),
  basis: z.string().min(1).max(120).optional(),
  policyReason: z.string().min(1).max(500).optional(),
  action: z.string().min(1).max(120).optional(),
  summary: z.string().min(1).max(1000).optional(),
  createdAt: EvaluatorTimestampSchema.optional(),
  metadata: z.record(z.unknown()).optional(),
}).passthrough();
export type EvaluatorHistoryEvent = z.infer<typeof EvaluatorHistoryEventSchema>;

export const EvaluatorWorkflowSliceSchema = z.object({
  nodeId: z.string().min(1).max(200).optional(),
  attemptNumber: z.number().int().nonnegative().optional(),
  retryGroup: z.string().min(1).max(200).optional(),
  parentSubmissionIds: z.array(z.string().min(1).max(200)).max(100).default([]),
  boundaryCrossings: z.array(z.string().min(1).max(200)).max(100).default([]),
}).passthrough();
export type EvaluatorWorkflowSlice = z.infer<typeof EvaluatorWorkflowSliceSchema>;

export const EvaluatorDecisionHistorySchema = z.object({
  priorDecisions: z.array(EvaluatorHistoryEventSchema).max(200).default([]),
  priorDenies: z.array(EvaluatorHistoryEventSchema).max(200).default([]),
  priorEscalations: z.array(EvaluatorHistoryEventSchema).max(200).default([]),
  priorClarifications: z.array(EvaluatorHistoryEventSchema).max(200).default([]),
  priorHumanResolutions: z.array(EvaluatorHistoryEventSchema).max(200).default([]),
}).passthrough();
export type EvaluatorDecisionHistory = z.infer<typeof EvaluatorDecisionHistorySchema>;

const EvaluatorExecutionEventSchema = z.object({
  eventId: z.string().min(1).max(200).optional(),
  submissionId: z.string().min(1).max(200).optional(),
  status: z.string().min(1).max(120).optional(),
  summary: z.string().min(1).max(1000).optional(),
  error: z.string().min(1).max(2000).optional(),
  executed: z.boolean().optional(),
  createdAt: EvaluatorTimestampSchema.optional(),
  metadata: z.record(z.unknown()).optional(),
}).passthrough();
export type EvaluatorExecutionEvent = z.infer<typeof EvaluatorExecutionEventSchema>;

export const EvaluatorExecutionHistorySchema = z.object({
  recentExecutions: z.array(EvaluatorExecutionEventSchema).max(200).default([]),
  recentOutcomes: z.array(EvaluatorExecutionEventSchema).max(200).default([]),
  failureCount: z.number().int().nonnegative().default(0),
  recoveryCount: z.number().int().nonnegative().default(0),
}).passthrough();
export type EvaluatorExecutionHistory = z.infer<typeof EvaluatorExecutionHistorySchema>;

export const EvaluatorReflectionEventSchema = z.object({
  reflectionId: z.string().min(1).max(200).optional(),
  submissionId: z.string().min(1).max(200).optional(),
  runId: z.string().min(1).max(200).optional(),
  workflowId: z.string().min(1).max(200).optional(),
  nodeId: z.string().min(1).max(200).optional(),
  planStepId: z.string().min(1).max(200).nullable().optional(),
  toolInvoked: z.string().min(1).max(200).nullable().optional(),
  status: z.string().min(1).max(120).optional(),
  deviationReason: z.string().min(1).max(2000).optional(),
  retryReason: z.string().min(1).max(2000).optional(),
  missingFacts: z.array(z.string().min(1).max(500)).max(100).default([]),
  confidence: z.number().min(0).max(1).nullable().optional(),
  needsClarification: z.boolean().optional(),
  needsHumanReview: z.boolean().optional(),
  boundaryCrossingsObserved: z.array(z.string().min(1).max(300)).max(100).default([]),
  stateChangesObserved: z.array(z.record(z.unknown())).max(100).default([]),
  actor: z.object({
    actor_id: z.string().min(1).max(200),
    actor_type: z.string().min(1).max(120).nullable().optional(),
    actor_role: z.string().min(1).max(120).nullable().optional(),
    source: z.string().min(1).max(200).nullable().optional(),
  }).passthrough().optional(),
  provenance: z.record(z.unknown()).optional(),
  createdAt: EvaluatorTimestampSchema.optional(),
  metadata: z.record(z.unknown()).optional(),
}).passthrough();
export type EvaluatorReflectionEvent = z.infer<typeof EvaluatorReflectionEventSchema>;

export const EvaluatorReflectionHistorySchema = z.object({
  enabled: z.boolean().default(false),
  recentReflections: z.array(EvaluatorReflectionEventSchema).max(200).default([]),
  repeatedDeviationCount: z.number().int().nonnegative().default(0),
  repeatedUncertaintyCount: z.number().int().nonnegative().default(0),
  persistentMissingFacts: z.array(z.string().min(1).max(500)).max(100).default([]),
  reflectionOutcomeDisagreementCount: z.number().int().nonnegative().default(0),
  reflectionConfirmedRetryCount: z.number().int().nonnegative().default(0),
}).passthrough();
export type EvaluatorReflectionHistory = z.infer<typeof EvaluatorReflectionHistorySchema>;

const EvaluatorStateDeltaSchema = z.object({
  resource: z.string().min(1).max(300).optional(),
  boundary: z.string().min(1).max(200).optional(),
  kind: z.string().min(1).max(120).optional(),
  summary: z.string().min(1).max(1000).optional(),
  createdAt: EvaluatorTimestampSchema.optional(),
}).passthrough();
export type EvaluatorStateDelta = z.infer<typeof EvaluatorStateDeltaSchema>;

const EvaluatorAuditEvidenceRefSchema = z.object({
  ref: z.string().min(1).max(300).optional(),
  source: z.string().min(1).max(120).optional(),
  decision: z.string().min(1).max(120).optional(),
  tool: z.string().min(1).max(200).optional(),
  op: z.string().min(1).max(120).optional(),
  summary: z.string().min(1).max(1000).optional(),
}).passthrough();
export type EvaluatorAuditEvidenceRef = z.infer<typeof EvaluatorAuditEvidenceRefSchema>;

export const EvaluatorDerivedFactsSchema = z.object({
  missingApprovals: z.array(z.string().min(1).max(120)).max(100).default([]),
  verifiedFacts: z.array(z.string().min(1).max(500)).max(100).default([]),
  missingFacts: z.array(z.string().min(1).max(500)).max(100).default([]),
  supersededMissingFacts: z.array(z.string().min(1).max(500)).max(100).default([]),
  suggestedQuestions: z.array(z.string().min(1).max(500)).max(100).default([]),
  suggestedSources: z.array(z.string().min(1).max(500)).max(100).default([]),
  resumeConditions: z.array(z.string().min(1).max(500)).max(100).default([]),
  retryCount: z.number().int().nonnegative().default(0),
  retryReasons: z.array(z.string().min(1).max(500)).max(100).default([]),
  recentToolErrors: z.array(z.string().min(1).max(500)).max(100).default([]),
  priorHumanEditCount: z.number().int().nonnegative().default(0),
  unresolvedClarificationCount: z.number().int().nonnegative().default(0),
  priorDenyCount: z.number().int().nonnegative().default(0),
  priorEscalationCount: z.number().int().nonnegative().default(0),
  failureCount: z.number().int().nonnegative().default(0),
  recoveryCount: z.number().int().nonnegative().default(0),
  repeatedReflectionDeviationCount: z.number().int().nonnegative().default(0),
  repeatedReflectionUncertaintyCount: z.number().int().nonnegative().default(0),
  persistentReflectionMissingFacts: z.array(z.string().min(1).max(500)).max(100).default([]),
  reflectionOutcomeDisagreementCount: z.number().int().nonnegative().default(0),
  reflectionConfirmedRetryCount: z.number().int().nonnegative().default(0),
  reflectionEnabled: z.boolean().default(false),
  contradictoryState: z.array(z.string().min(1).max(500)).max(100).default([]),
  exactMatchReusable: z.boolean().default(false),
  managedRuleEligible: z.boolean().default(false),
  lowRiskReadOnly: z.boolean().default(false),
  requiresSemanticReview: z.boolean().default(true),
  sideEffectful: z.boolean().default(false),
  crossBoundary: z.boolean().default(false),
  disclosureRelevant: z.boolean().default(false),
  approvalSensitive: z.boolean().default(false),
}).passthrough();
export type EvaluatorDerivedFacts = z.infer<typeof EvaluatorDerivedFactsSchema>;

export const EvaluatorInputSchema = z.object({
  action: EvaluatorActionSchema,
  actor: EvaluatorActorSchema,
  purpose: EvaluatorPurposeSchema,
  authority: EvaluatorAuthoritySchema,
  runtimeContext: EvaluatorRuntimeContextSchema,
  proposal: EvaluatorProposalSchema.optional(),
  graphContext: z.array(EvaluatorGraphContextItemSchema).max(50).default([]),
  orchestrationState: EvaluatorOrchestrationStateSchema.optional(),
  sourceUse: EvaluatorSourceUseSchema,
  constraints: EvaluatorConstraintsSchema,
  workflowSlice: EvaluatorWorkflowSliceSchema.default({
    parentSubmissionIds: [],
    boundaryCrossings: [],
  }),
  decisionHistory: EvaluatorDecisionHistorySchema.default({
    priorDecisions: [],
    priorDenies: [],
    priorEscalations: [],
    priorClarifications: [],
    priorHumanResolutions: [],
  }),
  executionHistory: EvaluatorExecutionHistorySchema.default({
    recentExecutions: [],
    recentOutcomes: [],
    failureCount: 0,
    recoveryCount: 0,
  }),
  reflectionHistory: EvaluatorReflectionHistorySchema.default({
    enabled: false,
    recentReflections: [],
    repeatedDeviationCount: 0,
    repeatedUncertaintyCount: 0,
    persistentMissingFacts: [],
    reflectionOutcomeDisagreementCount: 0,
    reflectionConfirmedRetryCount: 0,
  }),
  stateDeltas: z.array(EvaluatorStateDeltaSchema).max(200).default([]),
  auditEvidence: z.array(EvaluatorAuditEvidenceRefSchema).max(200).default([]),
  derivedFacts: EvaluatorDerivedFactsSchema.default({
    missingApprovals: [],
    verifiedFacts: [],
    missingFacts: [],
    supersededMissingFacts: [],
    suggestedQuestions: [],
    suggestedSources: [],
    resumeConditions: [],
    retryCount: 0,
    retryReasons: [],
    recentToolErrors: [],
    priorHumanEditCount: 0,
    unresolvedClarificationCount: 0,
    priorDenyCount: 0,
    priorEscalationCount: 0,
    failureCount: 0,
    recoveryCount: 0,
    repeatedReflectionDeviationCount: 0,
    repeatedReflectionUncertaintyCount: 0,
    persistentReflectionMissingFacts: [],
    reflectionOutcomeDisagreementCount: 0,
    reflectionConfirmedRetryCount: 0,
    reflectionEnabled: false,
    contradictoryState: [],
    exactMatchReusable: false,
    managedRuleEligible: false,
    lowRiskReadOnly: false,
    requiresSemanticReview: true,
    sideEffectful: false,
    crossBoundary: false,
    disclosureRelevant: false,
    approvalSensitive: false,
  }),
  metadata: z.record(z.unknown()).default({}),
}).passthrough();
export type EvaluatorInput = z.infer<typeof EvaluatorInputSchema>;
export type DeepPartial<T> =
  T extends Array<infer U>
    ? Array<DeepPartial<U>>
    : T extends Record<string, unknown>
      ? { [K in keyof T]?: DeepPartial<T[K]> }
      : T;
export type EvaluatorInputPatch = DeepPartial<EvaluatorInput>;

export const EvaluatorEvidenceSchema = z.object({
  label: z.string().min(1).max(120),
  detail: z.string().min(1).max(1000),
  path: z.string().min(1).max(300).optional(),
}).passthrough();
export type EvaluatorEvidence = z.infer<typeof EvaluatorEvidenceSchema>;

export const EvaluatorRemediationSchema = z.object({
  summary: z.string().min(1).max(2000),
  steps: z.array(z.string().min(1).max(1000)).max(20).default([]),
}).passthrough();
export type EvaluatorRemediation = z.infer<typeof EvaluatorRemediationSchema>;

export const EvaluatorOutputSchema = z.object({
  decision: EvaluatorDecisionSchema,
  basis: EvaluatorDecisionBasisSchema,
  confidence: z.number().min(0).max(1),
  principles: z.array(EvaluatorPrincipleSchema).max(20),
  summary: z.string().min(1).max(2000),
  reasoning: z.string().min(1).max(4000),
  evidence: z.array(EvaluatorEvidenceSchema).max(50),
  evidenceRefs: z.array(z.string().min(1).max(300)).max(100).default([]),
  suggestedSeverity: EvaluatorSeveritySchema,
  suggestedRemediation: EvaluatorRemediationSchema,
  normalizedFingerprint: z.string().min(8).max(128),
  missingFacts: z.array(z.string().min(1).max(500)).max(100).default([]),
  questions: z.array(z.string().min(1).max(500)).max(100).default([]),
  suggestedSources: z.array(z.string().min(1).max(500)).max(100).default([]),
  resumeConditions: z.array(z.string().min(1).max(500)).max(100).default([]),
  reasonerVersion: z.string().min(1).max(120),
  calibrationVersion: z.string().min(1).max(120),
  calibrationStatus: z.enum([
    "not_configured",
    "no_op",
    "applied",
    "unavailable",
  ]).default("not_configured"),
}).passthrough();
export type EvaluatorOutput = z.infer<typeof EvaluatorOutputSchema>;
