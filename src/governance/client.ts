import { randomUUID } from "node:crypto";

import {
  GovernanceAbortError,
  GovernanceConflictError,
  GovernanceEvaluatorError,
  GovernanceNotFoundError,
  GovernanceValidationError,
} from "./errors";
import {
  collectInlineGovernanceEvidence,
  unresolvedGovernanceEvidence,
} from "./evidence";
import {
  FileGovernanceStore,
  type GovernanceStore,
} from "./store";
import type {
  ClarificationAnswer,
  ClarificationRequest,
  ExecutionRecord,
  ExecutionReflectionRecord,
  GovernanceDecision,
  GovernanceEvaluation,
  GovernanceEvaluator,
  GovernanceEvidenceCompactionOptions,
  GovernanceFinding,
  GovernanceJsonObject,
  GovernanceSubmission,
  GovernanceSubmissionResult,
  GovernanceWaitOptions,
  HumanResolution,
  ImprovementProposal,
  OutcomeRecord,
  PendingGovernanceReview,
  PreferenceExample,
  PromotionEvaluation,
  ReplayEventRow,
  ResolveGovernanceReviewInput,
  RewardOutcomeRow,
} from "./types";
import {
  cloneGovernanceValue,
  governanceHashOnlyObject,
  governanceSha256,
  governanceValuesEqual,
  governancePersistenceProjection,
  isGovernanceHashOnlyObject,
  isoTimestamp,
  normalizeGovernanceJsonObject,
  optionalString,
  requiredString,
  stringArray,
  timestampMs,
} from "./validation";

export interface GovernanceClient {
  initialize(): Promise<void>;
  submitSubmission(input: {
    submission: GovernanceSubmission;
  }): Promise<GovernanceSubmissionResult>;
  listPendingReviews(): Promise<PendingGovernanceReview[]>;
  getHumanResolution(submissionId: string): Promise<HumanResolution | null>;
  waitForHumanResolution(
    submissionId: string,
    options?: GovernanceWaitOptions,
  ): Promise<HumanResolution | null>;
  resolveReview(input: ResolveGovernanceReviewInput): Promise<HumanResolution>;
  getClarificationRequest(
    submissionId: string,
  ): Promise<ClarificationRequest | null>;
  answerClarification(
    answer: Omit<ClarificationAnswer, "answer_id" | "created_at"> & {
      answer_id?: string;
      created_at?: string;
    },
  ): Promise<ClarificationAnswer>;
  reportExecution(record: ExecutionRecord): Promise<ExecutionRecord>;
  reportReflection(
    record: Omit<ExecutionReflectionRecord, "reflection_id" | "event_kind"> & {
      reflection_id?: string;
      event_kind?: "execution_reflection";
    },
  ): Promise<ExecutionReflectionRecord>;
  reportOutcome(record: OutcomeRecord): Promise<OutcomeRecord>;
  createImprovementProposal(
    proposal: Omit<ImprovementProposal, "improvement_id"> & {
      improvement_id?: string;
    },
  ): Promise<ImprovementProposal>;
  reportPromotionEvaluation(
    evaluation: Omit<PromotionEvaluation, "evaluation_id"> & {
      evaluation_id?: string;
    },
  ): Promise<PromotionEvaluation>;
  exportPreferenceExamples(): Promise<PreferenceExample[]>;
  exportRewardOutcomeRows(): Promise<RewardOutcomeRow[]>;
  exportReplayRows(): Promise<ReplayEventRow[]>;
}

export interface LocalGovernanceClientConfig {
  store?: GovernanceStore;
  rootDir?: string;
  evaluator?: GovernanceEvaluator;
  evidenceCompaction?: GovernanceEvidenceCompactionOptions;
  now?: () => number;
  sleep?: (milliseconds: number) => Promise<void>;
  idFactory?: () => string;
}

export interface GovernedActionSummary {
  status?: string;
  result_summary?: string | null;
  output_reference?: string | null;
  metadata?: GovernanceJsonObject;
}

export interface ExecuteGovernedActionOptions<
  TPayload extends GovernanceJsonObject,
  TResult,
> {
  client: GovernanceClient;
  submission: GovernanceSubmission;
  execute(payload: TPayload): Promise<TResult> | TResult;
  /**
   * Re-supplies an edited payload after restart. It is accepted only when its
   * canonical SHA-256 digest matches the hash-only persisted approval.
   */
  resuppliedEditedPayload?: TPayload;
  waitForResolution?: boolean | GovernanceWaitOptions;
  summarizeResult?(result: TResult): GovernedActionSummary;
  now?: () => string;
}

export interface GovernedActionResult<TResult> {
  submission: GovernanceSubmissionResult;
  human_resolution?: HumanResolution | null;
  execution_record: ExecutionRecord;
  value?: TResult;
}

function validNow(now: () => number): number {
  const value = now();
  if (!Number.isFinite(value)) {
    throw new GovernanceValidationError("Clock returned an invalid timestamp");
  }
  return value;
}

function normalizeEventKind(value: unknown): GovernanceSubmission["event_kind"] {
  if (
    value !== "candidate_action" &&
    value !== "selected_action" &&
    value !== "execution_attempt" &&
    value !== "execution_result" &&
    value !== "human_resolution" &&
    value !== "outcome" &&
    value !== "state_delta"
  ) {
    throw new GovernanceValidationError("Invalid governance event_kind");
  }
  return value;
}

function withoutInlineEvidence(
  value: GovernanceJsonObject,
): GovernanceJsonObject {
  const normalized = cloneGovernanceValue(value);
  delete normalized.evidence_events;
  return normalized;
}

function submissionPersistenceProjection(
  submission: GovernanceSubmission,
): GovernanceSubmission {
  const projected = governancePersistenceProjection(submission);
  projected.payload = governanceHashOnlyObject(submission.payload);
  return projected;
}

function storedSubmissionMatches(
  existing: GovernanceSubmission,
  normalized: GovernanceSubmission,
): boolean {
  const persistedDigest = existing.metadata.submission_sha256;
  if (
    typeof persistedDigest === "string" &&
    /^[a-f0-9]{64}$/.test(persistedDigest)
  ) {
    return persistedDigest === governanceSha256(normalized);
  }
  return governanceValuesEqual(
    existing,
    submissionPersistenceProjection(normalized),
  );
}

function safeEvaluatorError(
  prefix: string,
  error: unknown,
): string {
  const digest = governanceSha256({
    name: error instanceof Error ? error.name : typeof error,
    message: error instanceof Error ? error.message : String(error),
  });
  return `${prefix} [sha256:${digest}]`;
}

export function normalizeGovernanceSubmission(
  submission: Omit<GovernanceSubmission, "submission_id" | "created_at"> &
    Partial<Pick<GovernanceSubmission, "submission_id" | "created_at">>,
  now: () => string = () => new Date().toISOString(),
  evidenceOptions: GovernanceEvidenceCompactionOptions = {},
): GovernanceSubmission {
  const createdAt = submission.created_at ?? now();
  timestampMs(createdAt, "submission.created_at");
  const actorMetadata = submission.actor.metadata
    ? normalizeGovernanceJsonObject(
        submission.actor.metadata,
        "submission.actor.metadata",
      )
    : {};
  const targetMetadata = submission.target.metadata
    ? normalizeGovernanceJsonObject(
        submission.target.metadata,
        "submission.target.metadata",
      )
    : {};
  const authorityMetadata = submission.authority.metadata
    ? normalizeGovernanceJsonObject(
        submission.authority.metadata,
        "submission.authority.metadata",
      )
    : {};
  const provenanceMetadata = submission.provenance.metadata
    ? withoutInlineEvidence(
        normalizeGovernanceJsonObject(
          submission.provenance.metadata,
          "submission.provenance.metadata",
        ),
      )
    : {};
  const metadata = withoutInlineEvidence(
    normalizeGovernanceJsonObject(
      submission.metadata ?? {},
      "submission.metadata",
    ),
  );
  const normalized: GovernanceSubmission = {
    submission_id: requiredString(
      submission.submission_id ?? randomUUID(),
      "submission.submission_id",
    ),
    namespace: requiredString(submission.namespace, "submission.namespace"),
    workflow_id: requiredString(
      submission.workflow_id,
      "submission.workflow_id",
    ),
    node_id: requiredString(submission.node_id, "submission.node_id"),
    run_id: requiredString(submission.run_id, "submission.run_id"),
    trace_id: optionalString(submission.trace_id, "submission.trace_id") ?? null,
    event_kind: normalizeEventKind(submission.event_kind),
    actor: {
      actor_id: requiredString(
        submission.actor.actor_id,
        "submission.actor.actor_id",
      ),
      ...(optionalString(submission.actor.actor_type, "actor.actor_type")
        ? {
            actor_type: optionalString(
              submission.actor.actor_type,
              "actor.actor_type",
            ),
          }
        : {}),
      ...(optionalString(submission.actor.actor_role, "actor.actor_role")
        ? {
            actor_role: optionalString(
              submission.actor.actor_role,
              "actor.actor_role",
            ),
          }
        : {}),
      ...(optionalString(submission.actor.source, "actor.source")
        ? { source: optionalString(submission.actor.source, "actor.source") }
        : {}),
      labels: stringArray(submission.actor.labels),
      metadata: actorMetadata,
    },
    target: {
      ...(optionalString(submission.target.protocol, "target.protocol")
        ? {
            protocol: optionalString(
              submission.target.protocol,
              "target.protocol",
            ),
          }
        : {}),
      ...(optionalString(submission.target.boundary, "target.boundary")
        ? {
            boundary: optionalString(
              submission.target.boundary,
              "target.boundary",
            ),
          }
        : {}),
      ...(optionalString(
        submission.target.resource_type,
        "target.resource_type",
      )
        ? {
            resource_type: optionalString(
              submission.target.resource_type,
              "target.resource_type",
            ),
          }
        : {}),
      ...(optionalString(
        submission.target.resource_id,
        "target.resource_id",
      )
        ? {
            resource_id: optionalString(
              submission.target.resource_id,
              "target.resource_id",
            ),
          }
        : {}),
      action_type: requiredString(
        submission.target.action_type,
        "submission.target.action_type",
      ),
      action_name: requiredString(
        submission.target.action_name,
        "submission.target.action_name",
      ),
      ...(typeof submission.target.side_effect === "boolean"
        ? { side_effect: submission.target.side_effect }
        : {}),
      metadata: targetMetadata,
    },
    authority: {
      approvals: stringArray(submission.authority.approvals),
      entitlements: stringArray(submission.authority.entitlements),
      constraints: stringArray(submission.authority.constraints),
      ...(optionalString(
        submission.authority.risk_class,
        "authority.risk_class",
      )
        ? {
            risk_class: optionalString(
              submission.authority.risk_class,
              "authority.risk_class",
            ),
          }
        : {}),
      metadata: authorityMetadata,
    },
    payload: normalizeGovernanceJsonObject(
      submission.payload,
      "submission.payload",
    ),
    ...(optionalString(submission.state_ref, "submission.state_ref")
      ? {
          state_ref: optionalString(
            submission.state_ref,
            "submission.state_ref",
          ),
        }
      : {}),
    state_slice: submission.state_slice
      ? withoutInlineEvidence(
          normalizeGovernanceJsonObject(
            submission.state_slice,
            "submission.state_slice",
          ),
        )
      : null,
    provenance: {
      parent_submission_ids: stringArray(
        submission.provenance.parent_submission_ids,
      ),
      source_event_ids: stringArray(submission.provenance.source_event_ids),
      decision_ids: stringArray(submission.provenance.decision_ids),
      audit_refs: stringArray(submission.provenance.audit_refs),
      boundary_crossings: stringArray(
        submission.provenance.boundary_crossings,
      ),
      metadata: provenanceMetadata,
    },
    metadata,
    created_at: createdAt,
  };
  normalized.evidence_events = collectInlineGovernanceEvidence(
    {
      evidence_events: submission.evidence_events,
      state_slice: submission.state_slice,
      metadata: submission.metadata,
      provenance: submission.provenance,
    },
    evidenceOptions,
  );
  return cloneGovernanceValue(normalized);
}

type SideEffectClassification = "side_effect" | "read_only" | "unknown";

function classifySideEffect(
  submission: GovernanceSubmission,
): SideEffectClassification {
  if (submission.target.side_effect) return "side_effect";
  const action =
    `${submission.target.action_type} ${submission.target.action_name}`
      .toLowerCase()
      .replace(/[_./:-]+/g, " ");
  if (
    /\b(write|create|update|delete|remove|send|publish|execute|apply|modify|mutate)\b/.test(
      action,
    )
  ) {
    return "side_effect";
  }
  if (/\b(read|get|list|search|query|inspect|describe)\b/.test(action)) {
    return "read_only";
  }
  if (submission.target.side_effect === false) return "read_only";
  if (/\b(tool|call|api|command|operation)\b/.test(action)) {
    return "side_effect";
  }
  return "unknown";
}

function finding(
  code: string,
  message: string,
  severity: GovernanceFinding["severity"],
  metadata?: GovernanceJsonObject,
): GovernanceFinding {
  return {
    code,
    message,
    severity,
    source: "local_governance",
    ...(metadata ? { metadata } : {}),
  };
}

export function evaluateGovernanceSubmissionDeterministically(
  submission: GovernanceSubmission,
): GovernanceEvaluation {
  const sideEffect = classifySideEffect(submission);
  const constraints = (submission.authority.constraints ?? []).map((entry) =>
    entry.toLowerCase(),
  );
  const hardDeny =
    submission.metadata.hard_deny === true ||
    constraints.some((entry) =>
      /^(deny|denied|forbid|forbidden|block|blocked)(:|$)/.test(entry),
    );
  if (hardDeny) {
    return {
      decision: "deny",
      basis: "deterministic_guard",
      policy_reason: "explicit_constraint_denied",
      confidence: 1,
      findings: [
        finding(
          "explicit_constraint_denied",
          "An explicit local authority constraint denies this action.",
          "critical",
        ),
      ],
      risk_labels: ["explicit_deny"],
    };
  }

  const stateSlice = submission.state_slice ?? {};
  const missingFacts = stringArray([
    ...(Array.isArray(submission.metadata.missing_facts)
      ? submission.metadata.missing_facts
      : []),
    ...(Array.isArray(stateSlice.missing_facts)
      ? stateSlice.missing_facts
      : []),
  ]);
  if (missingFacts.length > 0) {
    return {
      decision: "clarify",
      basis: "deterministic_guard",
      policy_reason: "required_facts_missing",
      confidence: 1,
      findings: [
        finding(
          "required_facts_missing",
          "Required facts are missing from the local governance context.",
          "high",
          { missing_facts: missingFacts },
        ),
      ],
      metadata: { missing_facts: missingFacts },
    };
  }

  const unresolvedContradictions = unresolvedGovernanceEvidence(
    submission.evidence_events ?? [],
  );
  if (sideEffect === "side_effect" && unresolvedContradictions.length > 0) {
    return {
      decision: "escalate",
      basis: "deterministic_guard",
      policy_reason: "unresolved_evidence_conflict",
      confidence: 1,
      findings: [
        finding(
          "unresolved_evidence_conflict",
          "A side effect depends on failed or contradictory evidence.",
          "high",
        ),
      ],
      evidence_refs: unresolvedContradictions
        .map((event) => event.eventId)
        .filter((eventId): eventId is string => Boolean(eventId)),
      risk_labels: ["evidence_conflict", "side_effect"],
    };
  }

  if (sideEffect === "unknown") {
    return {
      decision: "escalate",
      basis: "deterministic_guard",
      policy_reason: "side_effect_classification_required",
      confidence: 1,
      findings: [
        finding(
          "side_effect_classification_required",
          "The action is not explicitly classified as read-only or side-effectful.",
          "high",
        ),
      ],
      risk_labels: ["unknown_side_effect_classification"],
    };
  }

  if (
    sideEffect === "side_effect" &&
    (submission.authority.approvals?.length ?? 0) === 0 &&
    (submission.authority.entitlements?.length ?? 0) === 0
  ) {
    return {
      decision: "escalate",
      basis: "deterministic_guard",
      policy_reason: "authority_required_for_side_effect",
      confidence: 1,
      findings: [
        finding(
          "authority_required_for_side_effect",
          "The side effect has no explicit approval or entitlement.",
          "high",
        ),
      ],
      risk_labels: ["missing_authority", "side_effect"],
    };
  }

  return {
    decision: "allow",
    basis: "default_allow",
    policy_reason: "local_checks_satisfied",
    confidence: 1,
    findings: [],
  };
}

export const deterministicGovernanceEvaluator: GovernanceEvaluator = {
  evaluate: evaluateGovernanceSubmissionDeterministically,
};

const GOVERNANCE_DECISION_RANK: Record<
  GovernanceDecision["decision"],
  number
> = {
  allow: 0,
  clarify: 1,
  escalate: 2,
  deny: 3,
};

function selectStricterEvaluation(
  deterministic: GovernanceEvaluation,
  custom: GovernanceEvaluation,
): { evaluation: GovernanceEvaluation; customSelected: boolean } {
  if (
    !Object.prototype.hasOwnProperty.call(
      GOVERNANCE_DECISION_RANK,
      custom.decision,
    )
  ) {
    throw new GovernanceValidationError(
      "Evaluator returned an invalid governance decision",
    );
  }
  if (
    GOVERNANCE_DECISION_RANK[custom.decision] >
    GOVERNANCE_DECISION_RANK[deterministic.decision]
  ) {
    return {
      evaluation: {
        ...custom,
        basis: "custom_evaluator",
        findings: [
          ...(deterministic.findings ?? []),
          ...(custom.findings ?? []),
        ],
        evidence_refs: stringArray([
          ...(deterministic.evidence_refs ?? []),
          ...(custom.evidence_refs ?? []),
        ]),
        principles: stringArray([
          ...(deterministic.principles ?? []),
          ...(custom.principles ?? []),
        ]),
        risk_labels: stringArray([
          ...(deterministic.risk_labels ?? []),
          ...(custom.risk_labels ?? []),
        ]),
      },
      customSelected: true,
    };
  }
  return { evaluation: deterministic, customSelected: false };
}

function normalizeEvaluation(
  submission: GovernanceSubmission,
  evaluation: GovernanceEvaluation,
  createdAt: string,
  decisionId: string,
  custom: boolean,
): GovernanceDecision {
  if (
    evaluation.decision !== "allow" &&
    evaluation.decision !== "deny" &&
    evaluation.decision !== "escalate" &&
    evaluation.decision !== "clarify"
  ) {
    throw new GovernanceValidationError(
      "Evaluator returned an invalid governance decision",
    );
  }
  const confidence =
    evaluation.confidence === undefined || evaluation.confidence === null
      ? undefined
      : Number.isFinite(evaluation.confidence)
        ? Math.max(0, Math.min(1, evaluation.confidence))
        : undefined;
  return {
    decision_id: decisionId,
    submission_id: submission.submission_id,
    decision: evaluation.decision,
    basis:
      evaluation.basis ?? (custom ? "custom_evaluator" : "deterministic_guard"),
    findings: cloneGovernanceValue(evaluation.findings ?? []),
    policy_reason: evaluation.policy_reason ?? null,
    ...(confidence !== undefined ? { confidence } : {}),
    evidence_refs: stringArray(evaluation.evidence_refs),
    principles: stringArray(evaluation.principles),
    risk_labels: stringArray(evaluation.risk_labels),
    observe_only: evaluation.observe_only === true,
    metadata: normalizeGovernanceJsonObject(
      evaluation.metadata ?? {},
      "evaluation.metadata",
    ),
    created_at: createdAt,
  };
}

function clarificationFromDecision(
  submission: GovernanceSubmission,
  decision: GovernanceDecision,
  clarificationId: string,
  createdAt: string,
): ClarificationRequest {
  const missingFacts = stringArray(decision.metadata?.missing_facts);
  return {
    clarification_id: clarificationId,
    submission_id: submission.submission_id,
    audience: "requester",
    status: "pending",
    missing_facts: missingFacts,
    questions:
      missingFacts.length > 0
        ? missingFacts.map((fact) => `Provide the missing fact: ${fact}.`)
        : ["Provide the missing facts required to evaluate this action."],
    resume_conditions: missingFacts,
    metadata: {},
    created_at: createdAt,
  };
}

export class LocalGovernanceClient implements GovernanceClient {
  readonly store: GovernanceStore;

  private readonly customEvaluatorAdapter: GovernanceEvaluator | null;
  private readonly evidenceOptions: GovernanceEvidenceCompactionOptions;
  private readonly now: () => number;
  private readonly sleep: (milliseconds: number) => Promise<void>;
  private readonly idFactory: () => string;
  private readonly volatileResolutions = new Map<string, HumanResolution>();

  constructor(config: LocalGovernanceClientConfig = {}) {
    if (config.store && config.rootDir) {
      throw new GovernanceValidationError(
        "Configure either store or rootDir, not both",
      );
    }
    this.store =
      config.store ?? new FileGovernanceStore({ rootDir: config.rootDir });
    this.customEvaluatorAdapter = config.evaluator ?? null;
    this.evidenceOptions = config.evidenceCompaction ?? {};
    this.now = config.now ?? (() => Date.now());
    this.sleep =
      config.sleep ??
      ((milliseconds: number) =>
        new Promise<void>((resolve) => setTimeout(resolve, milliseconds)));
    this.idFactory = config.idFactory ?? (() => randomUUID());
  }

  initialize(): Promise<void> {
    return this.store.initialize();
  }

  async submitSubmission(input: {
    submission: GovernanceSubmission;
  }): Promise<GovernanceSubmissionResult> {
    const existing = input.submission.submission_id
      ? await this.store.getSubmission(input.submission.submission_id)
      : null;
    const normalized = normalizeGovernanceSubmission(
      input.submission,
      () =>
        existing?.created_at ??
        isoTimestamp(validNow(this.now), "submission.created_at"),
      this.evidenceOptions,
    );
    if (
      existing &&
      !storedSubmissionMatches(existing, normalized)
    ) {
      throw new GovernanceConflictError(
        `Governance submission "${normalized.submission_id}" already exists with different content`,
        { submissionId: normalized.submission_id },
      );
    }
    const submission = existing
      ? normalized
      : await this.store.appendSubmission(normalized);

    const decision = await this.store.getOrAppendDecision(
      submission.submission_id,
      async () => {
      let evaluation = evaluateGovernanceSubmissionDeterministically(submission);
      let customSelected = false;
      try {
        if (
          this.customEvaluatorAdapter &&
          evaluation.decision !== "deny"
        ) {
          const customEvaluation =
            await this.customEvaluatorAdapter.evaluate(
              cloneGovernanceValue(submission),
            );
          const selected = selectStricterEvaluation(
            evaluation,
            customEvaluation,
          );
          evaluation = selected.evaluation;
          customSelected = selected.customSelected;
        }
      } catch (error) {
        throw new GovernanceEvaluatorError(
          safeEvaluatorError(
            "Governance evaluator failed closed",
            error,
          ),
          submission.submission_id,
        );
      }
      try {
        return normalizeEvaluation(
          submission,
          evaluation,
          isoTimestamp(validNow(this.now), "decision.created_at"),
          this.idFactory(),
          customSelected,
        );
      } catch (error) {
        throw new GovernanceEvaluatorError(
          safeEvaluatorError(
            "Governance evaluator returned invalid output",
            error,
          ),
          submission.submission_id,
        );
      }
      },
    );

    let clarification = await this.store.getLatestClarificationRequest(
      submission.submission_id,
    );
    if (decision.decision === "clarify" && !clarification) {
      clarification = await this.store.appendClarificationRequest(
        clarificationFromDecision(
          submission,
          decision,
          this.idFactory(),
          isoTimestamp(validNow(this.now), "clarification.created_at"),
        ),
      );
    }
    const resolution = await this.getHumanResolution(
      submission.submission_id,
    );
    const resolutionAllows =
      decision.decision === "escalate" &&
      resolutionAllowsExecution(resolution);
    return {
      submission,
      decision,
      clarification_request: clarification,
      human_resolution: resolution,
      allow_execution: decision.decision === "allow" || resolutionAllows,
      effective_payload: applyHumanResolutionPayload(
        submission.payload,
        resolution,
      ),
      improvements: (await this.store.readImprovements()).filter(
        (entry) => entry.submission_id === submission.submission_id,
      ),
    };
  }

  listPendingReviews(): Promise<PendingGovernanceReview[]> {
    return this.store.listPendingReviews();
  }

  getHumanResolution(submissionId: string): Promise<HumanResolution | null> {
    const id = requiredString(submissionId, "submissionId");
    const volatile = this.volatileResolutions.get(id);
    return volatile
      ? Promise.resolve(cloneGovernanceValue(volatile))
      : this.store.getLatestResolution(id);
  }

  async waitForHumanResolution(
    submissionId: string,
    options: GovernanceWaitOptions = {},
  ): Promise<HumanResolution | null> {
    const id = requiredString(submissionId, "submissionId");
    if (!(await this.store.getSubmission(id))) {
      throw new GovernanceNotFoundError("Governance submission", id);
    }
    const timeoutMs =
      options.timeoutMs === undefined
        ? 30_000
        : Math.max(1, Math.floor(options.timeoutMs));
    const pollIntervalMs =
      options.pollIntervalMs === undefined
        ? 250
        : Math.max(1, Math.floor(options.pollIntervalMs));
    if (
      !Number.isFinite(timeoutMs) ||
      !Number.isFinite(pollIntervalMs) ||
      timeoutMs <= 0 ||
      pollIntervalMs <= 0
    ) {
      throw new GovernanceValidationError(
        "Wait intervals must be positive finite numbers",
      );
    }
    const startedAt = validNow(this.now);
    while (true) {
      if (options.signal?.aborted) throw new GovernanceAbortError(id);
      const resolution = await this.getHumanResolution(id);
      if (resolution) return resolution;
      if (validNow(this.now) - startedAt >= timeoutMs) return null;
      await this.sleep(pollIntervalMs);
    }
  }

  async resolveReview(
    input: ResolveGovernanceReviewInput,
  ): Promise<HumanResolution> {
    const submissionId = requiredString(
      input.submission_id,
      "input.submission_id",
    );
    const submission = await this.store.getSubmission(submissionId);
    if (!submission) {
      throw new GovernanceNotFoundError("Governance submission", submissionId);
    }
    const decision = await this.store.getDecision(submissionId);
    if (decision?.decision !== "escalate") {
      throw new GovernanceConflictError(
        "Only escalated submissions accept a human resolution",
        { submissionId, decision: decision?.decision ?? "missing" },
      );
    }
    if (input.action === "edit" && !input.edited_payload) {
      throw new GovernanceValidationError(
        "An edit resolution requires edited_payload",
      );
    }
    const resolution = await this.store.appendResolution({
      submission_id: submissionId,
      action: input.action,
      reviewer: requiredString(input.reviewer, "input.reviewer"),
      feedback: optionalString(input.feedback, "input.feedback") ?? null,
      edited_payload: input.edited_payload
        ? normalizeGovernanceJsonObject(
            input.edited_payload,
            "input.edited_payload",
          )
        : null,
      metadata: normalizeGovernanceJsonObject(
        input.metadata ?? {},
        "input.metadata",
      ),
      created_at: isoTimestamp(validNow(this.now), "resolution.created_at"),
    });
    this.volatileResolutions.set(
      submissionId,
      cloneGovernanceValue(resolution),
    );
    return resolution;
  }

  getClarificationRequest(
    submissionId: string,
  ): Promise<ClarificationRequest | null> {
    return this.store.getLatestClarificationRequest(
      requiredString(submissionId, "submissionId"),
    );
  }

  async answerClarification(
    answer: Omit<ClarificationAnswer, "answer_id" | "created_at"> & {
      answer_id?: string;
      created_at?: string;
    },
  ): Promise<ClarificationAnswer> {
    const submissionId = requiredString(
      answer.submission_id,
      "answer.submission_id",
    );
    const clarification = await this.store.getLatestClarificationRequest(
      submissionId,
    );
    if (
      !clarification ||
      clarification.clarification_id !== answer.clarification_id ||
      clarification.status !== "pending"
    ) {
      throw new GovernanceConflictError(
        "Clarification answer does not match a pending request",
        { submissionId },
      );
    }
    const createdAt =
      answer.created_at ??
      isoTimestamp(validNow(this.now), "answer.created_at");
    timestampMs(createdAt, "answer.created_at");
    const stored = await this.store.appendClarificationAnswer({
      ...answer,
      answer_id: answer.answer_id ?? this.idFactory(),
      responder: requiredString(answer.responder, "answer.responder"),
      answers: normalizeGovernanceJsonObject(answer.answers, "answer.answers"),
      metadata: normalizeGovernanceJsonObject(
        answer.metadata ?? {},
        "answer.metadata",
      ),
      created_at: createdAt,
    });
    await this.store.appendClarificationRequest({
      ...clarification,
      status: "answered",
      answered_at: createdAt,
    });
    return stored;
  }

  reportExecution(record: ExecutionRecord): Promise<ExecutionRecord> {
    return this.store.appendExecution(record);
  }

  reportReflection(
    record: Omit<ExecutionReflectionRecord, "reflection_id" | "event_kind"> & {
      reflection_id?: string;
      event_kind?: "execution_reflection";
    },
  ): Promise<ExecutionReflectionRecord> {
    return this.store.appendReflection(record);
  }

  reportOutcome(record: OutcomeRecord): Promise<OutcomeRecord> {
    return this.store.appendOutcome(record);
  }

  createImprovementProposal(
    proposal: Omit<ImprovementProposal, "improvement_id"> & {
      improvement_id?: string;
    },
  ): Promise<ImprovementProposal> {
    return this.store.appendImprovement(proposal);
  }

  reportPromotionEvaluation(
    evaluation: Omit<PromotionEvaluation, "evaluation_id"> & {
      evaluation_id?: string;
    },
  ): Promise<PromotionEvaluation> {
    return this.store.appendPromotionEvaluation(evaluation);
  }

  exportPreferenceExamples(): Promise<PreferenceExample[]> {
    return this.store.exportPreferenceExamples();
  }

  exportRewardOutcomeRows(): Promise<RewardOutcomeRow[]> {
    return this.store.exportRewardOutcomeRows();
  }

  exportReplayRows(): Promise<ReplayEventRow[]> {
    return this.store.exportReplayRows();
  }
}

export function applyHumanResolutionPayload(
  originalPayload: GovernanceJsonObject,
  resolution?: HumanResolution | null,
): GovernanceJsonObject {
  return resolution?.action === "edit" &&
    resolution.edited_payload &&
    !isGovernanceHashOnlyObject(resolution.edited_payload)
    ? cloneGovernanceValue(resolution.edited_payload)
    : cloneGovernanceValue(originalPayload);
}

function resolutionAllowsExecution(
  resolution?: HumanResolution | null,
): boolean {
  if (resolution?.action === "approve") return true;
  return Boolean(
    resolution?.action === "edit" &&
      resolution.edited_payload &&
      !isGovernanceHashOnlyObject(resolution.edited_payload),
  );
}

function applyResuppliedEditedPayload(
  originalPayload: GovernanceJsonObject,
  resolution: HumanResolution | null,
  resupplied: GovernanceJsonObject | undefined,
): {
  allowExecution: boolean;
  effectivePayload: GovernanceJsonObject;
} {
  if (
    resolution?.action !== "edit" ||
    !resolution.edited_payload ||
    !isGovernanceHashOnlyObject(resolution.edited_payload) ||
    !resupplied
  ) {
    return {
      allowExecution: resolutionAllowsExecution(resolution),
      effectivePayload: applyHumanResolutionPayload(
        originalPayload,
        resolution,
      ),
    };
  }
  return resolution.edited_payload.sha256 === governanceSha256(resupplied)
    ? {
        allowExecution: true,
        effectivePayload: cloneGovernanceValue(resupplied),
      }
    : {
        allowExecution: false,
        effectivePayload: cloneGovernanceValue(originalPayload),
      };
}

function summarizeValue(value: unknown): string {
  if (typeof value === "string") return value.slice(0, 500);
  try {
    return JSON.stringify(value).slice(0, 500);
  } catch {
    return String(value).slice(0, 500);
  }
}

export async function executeGovernedAction<
  TPayload extends GovernanceJsonObject,
  TResult,
>(
  options: ExecuteGovernedActionOptions<TPayload, TResult>,
): Promise<GovernedActionResult<TResult>> {
  const now = options.now ?? (() => new Date().toISOString());
  const submission = await options.client.submitSubmission({
    submission: normalizeGovernanceSubmission(options.submission, now),
  });
  let resolution = submission.human_resolution ?? null;
  let effectivePayload = submission.effective_payload;
  let allowExecution = submission.allow_execution;
  if (!allowExecution && resolution?.action === "edit") {
    const resupplied = applyResuppliedEditedPayload(
      submission.submission.payload,
      resolution,
      options.resuppliedEditedPayload,
    );
    effectivePayload = resupplied.effectivePayload;
    allowExecution = resupplied.allowExecution;
  }

  if (
    !allowExecution &&
    submission.decision.decision === "escalate" &&
    options.waitForResolution
  ) {
    resolution = await options.client.waitForHumanResolution(
      submission.submission.submission_id,
      options.waitForResolution === true
        ? undefined
        : options.waitForResolution,
    );
    if (resolution) {
      const resupplied = applyResuppliedEditedPayload(
        submission.submission.payload,
        resolution,
        options.resuppliedEditedPayload,
      );
      effectivePayload = resupplied.effectivePayload;
      allowExecution = resupplied.allowExecution;
    }
  }

  if (!allowExecution) {
    const executionRecord = await options.client.reportExecution({
      submission_id: submission.submission.submission_id,
      executed: false,
      final_payload: effectivePayload,
      status: "blocked",
      error: submission.decision.policy_reason ?? "execution_blocked",
      created_at: now(),
    });
    return {
      submission,
      human_resolution: resolution,
      execution_record: executionRecord,
    };
  }

  try {
    const value = await options.execute(effectivePayload as TPayload);
    const summary = options.summarizeResult?.(value) ?? {
      status: "succeeded",
      result_summary: summarizeValue(value),
    };
    const executionRecord = await options.client.reportExecution({
      submission_id: submission.submission.submission_id,
      executed: true,
      final_payload: effectivePayload,
      status: summary.status ?? "succeeded",
      result_summary: summary.result_summary ?? null,
      output_reference: summary.output_reference ?? null,
      metadata: summary.metadata ?? {},
      created_at: now(),
    });
    return {
      submission,
      human_resolution: resolution,
      execution_record: executionRecord,
      value,
    };
  } catch (error) {
    const executionRecord = await options.client.reportExecution({
      submission_id: submission.submission.submission_id,
      executed: false,
      final_payload: effectivePayload,
      status: "failed",
      error: error instanceof Error ? error.message : String(error),
      created_at: now(),
    });
    throw Object.assign(
      error instanceof Error ? error : new Error(String(error)),
      { coreaxExecutionRecord: executionRecord },
    );
  }
}
