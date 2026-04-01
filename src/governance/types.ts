export type GovernanceJsonPrimitive = string | number | boolean | null;
export type GovernanceJsonValue =
  | GovernanceJsonPrimitive
  | GovernanceJsonValue[]
  | { [key: string]: GovernanceJsonValue };

export interface GovernanceJsonObject {
  [key: string]: GovernanceJsonValue;
}

export type GovernanceMessageRole = "system" | "user" | "assistant";

export interface GovernanceMessage {
  role: GovernanceMessageRole;
  content: string;
}

export interface GovernanceFinding {
  code: string;
  message: string;
  severity?: "low" | "medium" | "high" | "critical" | string;
  source?: string;
  metadata?: GovernanceJsonObject;
}

export type GovernanceEventKind =
  | "candidate_action"
  | "selected_action"
  | "execution_attempt"
  | "execution_result"
  | "human_resolution"
  | "outcome"
  | "state_delta";

export type GovernanceReflectionEventKind = "execution_reflection";

export interface GovernanceActor {
  actor_id: string;
  actor_type?: string | null;
  actor_role?: string | null;
  source?: string | null;
  labels?: string[];
  metadata?: GovernanceJsonObject;
}

export interface GovernanceTarget {
  protocol?: string | null;
  boundary?: string | null;
  resource_type?: string | null;
  resource_id?: string | null;
  action_type: string;
  action_name: string;
  side_effect?: boolean;
  metadata?: GovernanceJsonObject;
}

export interface GovernanceAuthority {
  approvals?: string[];
  entitlements?: string[];
  constraints?: string[];
  risk_class?: string | null;
  metadata?: GovernanceJsonObject;
}

export interface GovernanceEvidenceEntityRef {
  id?: string;
  type?: string;
  role?: string;
  label?: string;
  metadata?: GovernanceJsonObject;
}

export type GovernanceEvidenceEventStatus =
  | "supported"
  | "observed"
  | "failed"
  | "contradicted"
  | "recovered"
  | "superseded";

export interface GovernanceEvidenceEvent {
  eventId?: string;
  timestamp?: string;
  source?: string;
  kind: string;
  claim?: string;
  claimGroup?: string;
  summary: string;
  status: GovernanceEvidenceEventStatus;
  confidence?: number | null;
  provenanceRef?: string;
  entityRefs?: GovernanceEvidenceEntityRef[];
  relatedEventIds?: string[];
  contradictionLinks?: string[];
  recoveryLinks?: string[];
  metadata?: GovernanceJsonObject;
}

export interface GovernanceProvenance {
  parent_submission_ids?: string[];
  source_event_ids?: string[];
  decision_ids?: string[];
  audit_refs?: string[];
  boundary_crossings?: string[];
  metadata?: GovernanceJsonObject;
}

export interface GovernanceSubmission {
  submission_id: string;
  tenant_id: string;
  workflow_id: string;
  node_id: string;
  run_id: string;
  trace_id?: string | null;
  event_kind: GovernanceEventKind;
  actor: GovernanceActor;
  target: GovernanceTarget;
  authority: GovernanceAuthority;
  payload: GovernanceJsonObject;
  state_ref?: string | null;
  state_slice?: GovernanceJsonObject | null;
  evidence_events?: GovernanceEvidenceEvent[];
  provenance: GovernanceProvenance;
  metadata: GovernanceJsonObject;
  created_at: string;
}

export type GovernanceDecisionValue = "allow" | "deny" | "escalate" | "clarify";
export type GovernanceDecisionBasis =
  | "deterministic_guard"
  | "reused_resolution"
  | "managed_rule"
  | "semantic_reasoner"
  | "default_allow";

export interface GovernanceDecision {
  decision_id?: string;
  submission_id: string;
  decision: GovernanceDecisionValue;
  basis?: GovernanceDecisionBasis;
  findings: GovernanceFinding[];
  policy_reason?: string | null;
  confidence?: number | null;
  evidence_refs?: string[];
  principles?: string[];
  normalized_fingerprint?: string | null;
  reasoner_version?: string | null;
  context_compiler_version?: string | null;
  calibration_version?: string | null;
  risk_labels?: string[];
  observe_only?: boolean;
  metadata?: GovernanceJsonObject;
  created_at: string;
}

export interface ClarificationRequest {
  clarification_id: string;
  submission_id: string;
  audience: "operator" | "requester" | "system";
  status: "pending" | "answered" | "closed";
  missing_facts: string[];
  questions: string[];
  preferred_responders?: string[];
  suggested_sources?: string[];
  resume_conditions?: string[];
  metadata?: GovernanceJsonObject;
  created_at: string;
  answered_at?: string | null;
}

export interface ClarificationAnswer {
  answer_id: string;
  clarification_id: string;
  submission_id: string;
  responder: string;
  answers: GovernanceJsonObject;
  feedback?: string | null;
  metadata?: GovernanceJsonObject;
  created_at: string;
}

export type HumanResolutionAction =
  | "approve"
  | "reject"
  | "edit"
  | "ask_clarifying_question"
  | "answer_clarification"
  | "accept_improvement"
  | "reject_improvement";

export interface HumanResolution {
  resolution_id: string;
  submission_id: string;
  action: HumanResolutionAction;
  reviewer: string;
  feedback?: string | null;
  edited_payload?: GovernanceJsonObject | null;
  clarification_id?: string | null;
  metadata?: GovernanceJsonObject;
  created_at: string;
}

export interface ExecutionRecord {
  submission_id: string;
  executed: boolean;
  final_payload?: GovernanceJsonObject | null;
  status: string;
  result_summary?: string | null;
  output_reference?: string | null;
  error?: string | null;
  metadata?: GovernanceJsonObject;
  created_at: string;
}

export interface ExecutionReflectionRecord {
  reflection_id?: string;
  event_kind: GovernanceReflectionEventKind;
  submission_id: string;
  run_id: string;
  workflow_id: string;
  node_id: string;
  trace_id?: string | null;
  actor: GovernanceActor;
  plan_step_id?: string | null;
  tool_invoked?: string | null;
  status: string;
  deviation_reason?: string | null;
  retry_reason?: string | null;
  missing_facts?: string[];
  confidence?: number | null;
  state_changes_observed?: GovernanceJsonObject[];
  boundary_crossings_observed?: string[];
  needs_clarification?: boolean;
  needs_human_review?: boolean;
  provenance: GovernanceProvenance;
  metadata?: GovernanceJsonObject;
  created_at: string;
}

export interface VerifierResult {
  passed?: boolean | null;
  score?: number | null;
  status?: string | null;
  details?: GovernanceJsonObject;
}

export interface OutcomeRecord {
  outcome_id?: string;
  submission_id?: string | null;
  run_id?: string | null;
  workflow_id?: string | null;
  task_success?: boolean | null;
  outcome_success?: boolean | null;
  verifier_result?: VerifierResult | null;
  reward_components?: Record<string, number>;
  business_outcome?: GovernanceJsonObject;
  metadata?: GovernanceJsonObject;
  created_at: string;
}

export type ImprovementSurface =
  | "policy"
  | "guardrail"
  | "review_routing"
  | "prompt_template"
  | "retrieval_config"
  | "context_compiler"
  | "reasoner_instructions"
  | "calibration"
  | "clarification_policy"
  | "orchestrator_overlay"
  | "tool_routing"
  | "code_change"
  | "model_tuning";

export interface ImprovementProposal {
  improvement_id: string;
  submission_id: string;
  surface: ImprovementSurface;
  scope: string;
  summary: string;
  rationale?: string | null;
  proposed_change: GovernanceJsonObject;
  auto_apply_eligible: boolean;
  status?: "proposed" | "accepted" | "rejected" | "applied";
  metadata?: GovernanceJsonObject;
  created_at: string;
}

export interface PromotionEvaluation {
  evaluation_id: string;
  improvement_id: string;
  verdict: "promote" | "hold" | "rollback";
  scope: string;
  metrics: Record<string, number>;
  metadata?: GovernanceJsonObject;
  created_at: string;
}

export type GovernanceAutoresearchMutationSurface =
  | "policy"
  | "prompt_template"
  | "retrieval_config"
  | "context_compiler"
  | "reasoner_instructions"
  | "calibration"
  | "clarification_policy"
  | "review_routing"
  | "orchestrator_overlay";

export type GovernanceAutoresearchJobStatus = "queued" | "running" | "ready" | "failed";
export type GovernanceAutoresearchCandidateStatus =
  | "ready"
  | "gated_out"
  | "promoted"
  | "rolled_back";
export type GovernanceAutoresearchRolloutStatus =
  | "canary"
  | "promoted"
  | "rolled_back"
  | "failed";

export interface GovernanceAutoresearchScope {
  workflow_id: string;
  node_id?: string | null;
}

export interface GovernanceAutoresearchDatasetSummary {
  dataset_version: string;
  replay_rows: number;
  preference_examples: number;
  reward_rows: number;
  reflection_rows: number;
  train_runs: number;
  validation_runs: number;
  held_out_runs: number;
  held_out_suite_ids?: string[];
  metadata?: GovernanceJsonObject;
}

export interface GovernanceAutoresearchCandidateMetrics {
  total_cases: number;
  bad_allows: number;
  unnecessary_exploratory_escalations: number;
  unnecessary_clarifications: number;
  human_agreement_rate: number;
  recovery_after_failures_rate: number;
  reviewer_load: number;
  structural_gate_rate: number;
  exploratory_escalation_rate: number;
}

export interface GovernanceAutoresearchJob {
  job_id: string;
  tenant_id: string;
  scope: GovernanceAutoresearchScope;
  status: GovernanceAutoresearchJobStatus;
  requested_by?: string | null;
  allowed_surfaces: GovernanceAutoresearchMutationSurface[];
  dataset_summary?: GovernanceAutoresearchDatasetSummary | null;
  best_candidate_id?: string | null;
  error_message?: string | null;
  metadata?: GovernanceJsonObject;
  started_at?: string | null;
  completed_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface GovernanceAutoresearchCandidate {
  candidate_id: string;
  job_id: string;
  tenant_id: string;
  surface: GovernanceAutoresearchMutationSurface;
  status: GovernanceAutoresearchCandidateStatus;
  summary: string;
  rationale?: string | null;
  mutation_spec: GovernanceJsonObject;
  baseline_metrics: GovernanceAutoresearchCandidateMetrics;
  validation_metrics: GovernanceAutoresearchCandidateMetrics;
  held_out_metrics: GovernanceAutoresearchCandidateMetrics;
  delta_metrics: Record<string, number>;
  replay_safe: boolean;
  blocked_by_hard_floor: boolean;
  score: number;
  representative_submission_id?: string | null;
  improvement_id?: string | null;
  evaluation_id?: string | null;
  metadata?: GovernanceJsonObject;
  created_at: string;
  updated_at: string;
}

export interface GovernanceAutoresearchRollout {
  rollout_id: string;
  job_id: string;
  candidate_id: string;
  tenant_id: string;
  scope: GovernanceAutoresearchScope;
  status: GovernanceAutoresearchRolloutStatus;
  improvement_id?: string | null;
  evaluation_id?: string | null;
  canary_percentage: number;
  rollback_reason?: string | null;
  baseline_metrics: GovernanceAutoresearchCandidateMetrics;
  candidate_metrics: GovernanceAutoresearchCandidateMetrics;
  mutation_spec: GovernanceJsonObject;
  metadata?: GovernanceJsonObject;
  promoted_at?: string | null;
  rolled_back_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface GovernanceRuntimeConfigAppliedRollout {
  rollout_id: string;
  job_id?: string | null;
  candidate_id?: string | null;
  surface: GovernanceAutoresearchMutationSurface;
  scope: GovernanceAutoresearchScope;
  status: "canary" | "promoted";
  canary_percentage: number;
  applied_via: "canary" | "promoted";
  mutation_spec_hash: string;
  promoted_at?: string | null;
  metadata?: GovernanceJsonObject;
}

export interface GovernanceRuntimeConfigVersions {
  runtime_config_version: string;
  surface_versions: Partial<
    Record<GovernanceAutoresearchMutationSurface, string>
  >;
  context_compiler_version: string;
  reasoner_version: string;
  calibration_version: string;
}

export interface GovernanceRuntimeConfig {
  tenant_id: string;
  workflow_id: string;
  node_id?: string | null;
  actor_id?: string | null;
  run_id?: string | null;
  trace_id?: string | null;
  reflection: {
    enabled: boolean;
    policy_ids: string[];
  };
  surfaces: Partial<
    Record<GovernanceAutoresearchMutationSurface, GovernanceJsonObject>
  >;
  governance: GovernanceJsonObject;
  orchestrator: GovernanceJsonObject;
  applied_rollouts: GovernanceRuntimeConfigAppliedRollout[];
  versions: GovernanceRuntimeConfigVersions;
  resolved_at: string;
}

export interface GovernanceAutoresearchJobDetail {
  job: GovernanceAutoresearchJob;
  candidates: GovernanceAutoresearchCandidate[];
  rollouts: GovernanceAutoresearchRollout[];
}

export interface CreateGovernanceAutoresearchJobInput {
  tenant_id?: string;
  scope: GovernanceAutoresearchScope;
  allowed_surfaces: GovernanceAutoresearchMutationSurface[];
  metadata?: GovernanceJsonObject;
}

export interface PromoteGovernanceAutoresearchJobInput {
  tenant_id?: string;
  candidate_id?: string | null;
  canary_percentage?: number | null;
  metadata?: GovernanceJsonObject;
}

export interface RollbackGovernanceAutoresearchJobInput {
  tenant_id?: string;
  rollout_id?: string | null;
  reason?: string | null;
  metadata?: GovernanceJsonObject;
}

export interface GetGovernanceRuntimeConfigInput {
  tenant_id?: string;
  workflow_id: string;
  node_id?: string | null;
  actor_id?: string | null;
  run_id?: string | null;
  trace_id?: string | null;
}

export interface GovernanceSubmissionResult {
  submission: GovernanceSubmission;
  decision: GovernanceDecision;
  clarification_request?: ClarificationRequest | null;
  human_resolution?: HumanResolution | null;
  allow_execution: boolean;
  effective_payload: GovernanceJsonObject;
  audit?: GovernanceJsonObject;
  guard?: GovernanceJsonObject;
  improvements?: ImprovementProposal[];
  metadata?: GovernanceJsonObject;
}

export interface PendingGovernanceReview {
  submission: GovernanceSubmission;
  decision: GovernanceDecision;
  clarification_request?: ClarificationRequest | null;
  latest_resolution?: HumanResolution | null;
  improvements?: ImprovementProposal[];
}

export interface GovernanceRecord {
  submission: GovernanceSubmission;
  decision?: GovernanceDecision;
  clarification_request?: ClarificationRequest | null;
  clarification_answer?: ClarificationAnswer | null;
  human_resolution?: HumanResolution | null;
  execution_record?: ExecutionRecord | null;
  reflection_records?: ExecutionReflectionRecord[];
  outcome_record?: OutcomeRecord | null;
  improvements?: ImprovementProposal[];
  promotion_evaluations?: PromotionEvaluation[];
}

export interface PreferenceComparison {
  prompt_conversation: GovernanceMessage[];
  completion_A: GovernanceMessage[];
  completion_B: GovernanceMessage[];
}

export interface PreferenceExample {
  submission_id: string;
  resolution_id: string;
  preference_kind: Extract<HumanResolutionAction, "approve" | "reject" | "edit">;
  comparison: PreferenceComparison;
  label: "A" | "B" | "Tie";
  chosen_completion: GovernanceJsonObject;
  rejected_completion: GovernanceJsonObject;
  metadata?: GovernanceJsonObject;
}

export interface RewardOutcomeRow extends GovernanceRecord {
  submission_id: string;
  run_id: string;
}

export interface ReplayEventRow {
  submission_id: string;
  run_id?: string | null;
  event_type:
    | "governance_submission"
    | "governance_decision"
    | "clarification_request"
    | "clarification_answer"
    | "human_resolution"
    | "execution_record"
    | "execution_reflection"
    | "outcome_record"
    | "improvement_proposal"
    | "promotion_evaluation";
  created_at: string;
  payload: GovernanceJsonObject;
}

export interface GovernanceWaitOptions {
  timeoutMs?: number;
  pollIntervalMs?: number;
}

export interface ResolveGovernanceReviewInput {
  submission_id: string;
  action: HumanResolutionAction;
  reviewer: string;
  feedback?: string | null;
  edited_payload?: GovernanceJsonObject | null;
  clarification_id?: string | null;
  metadata?: GovernanceJsonObject;
}
