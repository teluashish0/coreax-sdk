import { randomUUID } from "node:crypto";

import type {
  ClarificationAnswer,
  ClarificationRequest,
  CreateGovernanceAutoresearchJobInput,
  ExecutionRecord,
  ExecutionReflectionRecord,
  GetGovernanceRuntimeConfigInput,
  GovernanceAutoresearchJob,
  GovernanceAutoresearchJobDetail,
  GovernanceJsonObject,
  GovernanceRuntimeConfig,
  GovernanceSubmission,
  GovernanceSubmissionResult,
  GovernanceWaitOptions,
  HumanResolution,
  ImprovementProposal,
  OutcomeRecord,
  PendingGovernanceReview,
  PreferenceExample,
  PromoteGovernanceAutoresearchJobInput,
  PromotionEvaluation,
  ReplayEventRow,
  RollbackGovernanceAutoresearchJobInput,
  ResolveGovernanceReviewInput,
  RewardOutcomeRow,
} from "./types";

export interface GovernanceClient {
  submitSubmission(input: { submission: GovernanceSubmission }): Promise<GovernanceSubmissionResult>;
  listPendingReviews(): Promise<PendingGovernanceReview[]>;
  getHumanResolution(submissionId: string): Promise<HumanResolution | null>;
  waitForHumanResolution(
    submissionId: string,
    options?: GovernanceWaitOptions,
  ): Promise<HumanResolution | null>;
  resolveReview(input: ResolveGovernanceReviewInput): Promise<HumanResolution>;
  getClarificationRequest(submissionId: string): Promise<ClarificationRequest | null>;
  answerClarification(answer: ClarificationAnswer): Promise<ClarificationAnswer>;
  reportExecution(result: ExecutionRecord): Promise<ExecutionRecord>;
  reportReflection(result: ExecutionReflectionRecord): Promise<ExecutionReflectionRecord>;
  reportOutcome(result: OutcomeRecord): Promise<OutcomeRecord>;
  createImprovementProposal(input: ImprovementProposal): Promise<ImprovementProposal>;
  reportPromotionEvaluation(input: PromotionEvaluation): Promise<PromotionEvaluation>;
  exportPreferenceExamples(): Promise<PreferenceExample[]>;
  exportRewardOutcomeRows(): Promise<RewardOutcomeRow[]>;
  exportReplayRows(): Promise<ReplayEventRow[]>;
  createAutoresearchJob(
    input: CreateGovernanceAutoresearchJobInput,
  ): Promise<GovernanceAutoresearchJob>;
  listAutoresearchJobs(): Promise<GovernanceAutoresearchJob[]>;
  getAutoresearchJob(jobId: string): Promise<GovernanceAutoresearchJobDetail>;
  promoteAutoresearchJob(
    jobId: string,
    input?: PromoteGovernanceAutoresearchJobInput,
  ): Promise<GovernanceAutoresearchJobDetail>;
  rollbackAutoresearchJob(
    jobId: string,
    input?: RollbackGovernanceAutoresearchJobInput,
  ): Promise<GovernanceAutoresearchJobDetail>;
  getRuntimeConfig(input: GetGovernanceRuntimeConfigInput): Promise<GovernanceRuntimeConfig>;
}

export interface HttpGovernanceClientConfig {
  baseUrl: string;
  headers?: Record<string, string>;
  fetchImpl?: typeof fetch;
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

function asObject(value: unknown): GovernanceJsonObject {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as GovernanceJsonObject)
    : {};
}

function summarizeValue(value: unknown): string {
  if (typeof value === "string") {
    return value.slice(0, 500);
  }
  try {
    return JSON.stringify(value).slice(0, 500);
  } catch {
    return String(value).slice(0, 500);
  }
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.map((entry) => String(entry)) : [];
}

function normalizeEvidenceEvents(value: unknown): GovernanceSubmission["evidence_events"] {
  if (!Array.isArray(value)) return [];
  return value
    .filter((entry) => entry && typeof entry === "object")
    .map((entry) => {
      const row = asObject(entry);
      return {
        eventId: typeof row.eventId === "string" ? row.eventId : undefined,
        timestamp: typeof row.timestamp === "string" ? row.timestamp : undefined,
        source: typeof row.source === "string" ? row.source : undefined,
        kind: String(row.kind || ""),
        claim: typeof row.claim === "string" ? row.claim : undefined,
        claimGroup: typeof row.claimGroup === "string" ? row.claimGroup : undefined,
        summary: String(row.summary || row.claim || ""),
        status: String(row.status || "observed") as NonNullable<
          GovernanceSubmission["evidence_events"]
        >[number]["status"],
        confidence:
          typeof row.confidence === "number" && Number.isFinite(row.confidence)
            ? Math.max(0, Math.min(1, row.confidence))
            : null,
        provenanceRef:
          typeof row.provenanceRef === "string" ? row.provenanceRef : undefined,
        entityRefs: Array.isArray(row.entityRefs)
          ? row.entityRefs
              .filter((entity) => entity && typeof entity === "object")
              .map((entity) => {
                const normalized = asObject(entity);
                return {
                  id: typeof normalized.id === "string" ? normalized.id : undefined,
                  type: typeof normalized.type === "string" ? normalized.type : undefined,
                  role: typeof normalized.role === "string" ? normalized.role : undefined,
                  label: typeof normalized.label === "string" ? normalized.label : undefined,
                  metadata: asObject(normalized.metadata),
                };
              })
          : [],
        relatedEventIds: asStringArray(row.relatedEventIds),
        contradictionLinks: asStringArray(row.contradictionLinks),
        recoveryLinks: asStringArray(row.recoveryLinks),
        metadata: asObject(row.metadata),
      };
    })
    .filter((entry) => entry.kind && entry.summary);
}

function collectInlineEvidenceEvents(
  submission: Omit<GovernanceSubmission, "submission_id" | "created_at"> &
    Partial<Pick<GovernanceSubmission, "submission_id" | "created_at">>,
): GovernanceSubmission["evidence_events"] {
  const stateSlice = asObject(submission.state_slice);
  const metadata = asObject(submission.metadata);
  const provenanceMetadata = asObject(submission.provenance?.metadata);
  return normalizeEvidenceEvents([
    ...(submission.evidence_events || []),
    ...(Array.isArray(stateSlice.evidence_events) ? stateSlice.evidence_events : []),
    ...(Array.isArray(metadata.evidence_events) ? metadata.evidence_events : []),
    ...(Array.isArray(provenanceMetadata.evidence_events) ? provenanceMetadata.evidence_events : []),
  ]);
}

export function normalizeGovernanceSubmission(
  submission: Omit<GovernanceSubmission, "submission_id" | "created_at"> &
    Partial<Pick<GovernanceSubmission, "submission_id" | "created_at">>,
  now: () => string = () => new Date().toISOString(),
): GovernanceSubmission {
  return {
    ...submission,
    submission_id: submission.submission_id || randomUUID(),
    trace_id: submission.trace_id || null,
    actor: {
      ...submission.actor,
      metadata: asObject(submission.actor?.metadata),
    },
    target: {
      ...submission.target,
      metadata: asObject(submission.target?.metadata),
    },
    authority: {
      ...submission.authority,
      approvals: Array.isArray(submission.authority?.approvals)
        ? submission.authority.approvals.map((entry) => String(entry))
        : [],
      entitlements: Array.isArray(submission.authority?.entitlements)
        ? submission.authority.entitlements.map((entry) => String(entry))
        : [],
      constraints: Array.isArray(submission.authority?.constraints)
        ? submission.authority.constraints.map((entry) => String(entry))
        : [],
      metadata: asObject(submission.authority?.metadata),
    },
    payload: asObject(submission.payload),
    state_slice: submission.state_slice ? asObject(submission.state_slice) : null,
    evidence_events: collectInlineEvidenceEvents(submission),
    provenance: {
      ...submission.provenance,
      parent_submission_ids: Array.isArray(submission.provenance?.parent_submission_ids)
        ? submission.provenance.parent_submission_ids.map((entry) => String(entry))
        : [],
      source_event_ids: Array.isArray(submission.provenance?.source_event_ids)
        ? submission.provenance.source_event_ids.map((entry) => String(entry))
        : [],
      decision_ids: Array.isArray(submission.provenance?.decision_ids)
        ? submission.provenance.decision_ids.map((entry) => String(entry))
        : [],
      audit_refs: Array.isArray(submission.provenance?.audit_refs)
        ? submission.provenance.audit_refs.map((entry) => String(entry))
        : [],
      boundary_crossings: Array.isArray(submission.provenance?.boundary_crossings)
        ? submission.provenance.boundary_crossings.map((entry) => String(entry))
        : [],
      metadata: asObject(submission.provenance?.metadata),
    },
    metadata: asObject(submission.metadata),
    created_at: submission.created_at || now(),
  };
}

export function applyHumanResolutionPayload(
  originalPayload: GovernanceJsonObject,
  resolution?: HumanResolution | null,
): GovernanceJsonObject {
  if (resolution?.action === "edit" && resolution.edited_payload) {
    return resolution.edited_payload;
  }
  return originalPayload;
}

export class HttpGovernanceClient implements GovernanceClient {
  private readonly baseUrl: string;
  private readonly headers: Record<string, string>;
  private readonly fetchImpl: typeof fetch;

  constructor(config: HttpGovernanceClientConfig) {
    this.baseUrl = config.baseUrl.replace(/\/+$/, "");
    this.headers = config.headers || {};
    this.fetchImpl = config.fetchImpl || fetch;
  }

  private async request<T>(path: string, init?: RequestInit): Promise<T> {
    const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
      ...init,
      headers: {
        "content-type": "application/json",
        ...this.headers,
        ...(init?.headers || {}),
      },
    });
    if (!response.ok) {
      const text = await response.text();
      throw new Error(`governance_http_${response.status}:${text}`);
    }
    return (await response.json()) as T;
  }

  submitSubmission(input: { submission: GovernanceSubmission }): Promise<GovernanceSubmissionResult> {
    return this.request("/governance/submissions", {
      method: "POST",
      body: JSON.stringify(input),
    });
  }

  async listPendingReviews(): Promise<PendingGovernanceReview[]> {
    const payload = await this.request<{ pending: PendingGovernanceReview[] }>("/governance/pending");
    return payload.pending || [];
  }

  async getHumanResolution(submissionId: string): Promise<HumanResolution | null> {
    const payload = await this.request<{ resolution?: HumanResolution | null }>(
      `/governance/submissions/${encodeURIComponent(submissionId)}/resolution`,
    );
    return payload.resolution || null;
  }

  async waitForHumanResolution(
    submissionId: string,
    options: GovernanceWaitOptions = {},
  ): Promise<HumanResolution | null> {
    const timeoutMs = options.timeoutMs ?? 30_000;
    const pollIntervalMs = options.pollIntervalMs ?? 1_000;
    const deadline = Date.now() + timeoutMs;

    while (Date.now() <= deadline) {
      const resolution = await this.getHumanResolution(submissionId);
      if (resolution) {
        return resolution;
      }
      await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
    }
    return null;
  }

  resolveReview(input: ResolveGovernanceReviewInput): Promise<HumanResolution> {
    return this.request("/governance/resolutions", {
      method: "POST",
      body: JSON.stringify(input),
    });
  }

  async getClarificationRequest(submissionId: string): Promise<ClarificationRequest | null> {
    const payload = await this.request<{ clarification?: ClarificationRequest | null }>(
      `/governance/submissions/${encodeURIComponent(submissionId)}/clarification`,
    );
    return payload.clarification || null;
  }

  answerClarification(answer: ClarificationAnswer): Promise<ClarificationAnswer> {
    return this.request("/governance/clarifications/answers", {
      method: "POST",
      body: JSON.stringify(answer),
    });
  }

  reportExecution(result: ExecutionRecord): Promise<ExecutionRecord> {
    return this.request("/governance/executions", {
      method: "POST",
      body: JSON.stringify(result),
    });
  }

  reportReflection(result: ExecutionReflectionRecord): Promise<ExecutionReflectionRecord> {
    return this.request("/governance/reflections", {
      method: "POST",
      body: JSON.stringify(result),
    });
  }

  reportOutcome(result: OutcomeRecord): Promise<OutcomeRecord> {
    return this.request("/governance/outcomes", {
      method: "POST",
      body: JSON.stringify(result),
    });
  }

  createImprovementProposal(input: ImprovementProposal): Promise<ImprovementProposal> {
    return this.request("/governance/improvements", {
      method: "POST",
      body: JSON.stringify(input),
    });
  }

  reportPromotionEvaluation(input: PromotionEvaluation): Promise<PromotionEvaluation> {
    return this.request("/governance/promotions", {
      method: "POST",
      body: JSON.stringify(input),
    });
  }

  exportPreferenceExamples(): Promise<PreferenceExample[]> {
    return this.request("/governance/export/preferences");
  }

  exportRewardOutcomeRows(): Promise<RewardOutcomeRow[]> {
    return this.request("/governance/export/reward-outcomes");
  }

  exportReplayRows(): Promise<ReplayEventRow[]> {
    return this.request("/governance/export/replay");
  }

  createAutoresearchJob(
    input: CreateGovernanceAutoresearchJobInput,
  ): Promise<GovernanceAutoresearchJob> {
    return this.request("/governance/autoresearch/jobs", {
      method: "POST",
      body: JSON.stringify(input),
    });
  }

  async listAutoresearchJobs(): Promise<GovernanceAutoresearchJob[]> {
    const payload = await this.request<{ jobs: GovernanceAutoresearchJob[] }>(
      "/governance/autoresearch/jobs",
    );
    return payload.jobs || [];
  }

  getAutoresearchJob(jobId: string): Promise<GovernanceAutoresearchJobDetail> {
    return this.request(`/governance/autoresearch/jobs/${encodeURIComponent(jobId)}`);
  }

  promoteAutoresearchJob(
    jobId: string,
    input: PromoteGovernanceAutoresearchJobInput = {},
  ): Promise<GovernanceAutoresearchJobDetail> {
    return this.request(`/governance/autoresearch/jobs/${encodeURIComponent(jobId)}/promote`, {
      method: "POST",
      body: JSON.stringify(input),
    });
  }

  rollbackAutoresearchJob(
    jobId: string,
    input: RollbackGovernanceAutoresearchJobInput = {},
  ): Promise<GovernanceAutoresearchJobDetail> {
    return this.request(`/governance/autoresearch/jobs/${encodeURIComponent(jobId)}/rollback`, {
      method: "POST",
      body: JSON.stringify(input),
    });
  }

  getRuntimeConfig(input: GetGovernanceRuntimeConfigInput): Promise<GovernanceRuntimeConfig> {
    const params = new URLSearchParams();
    if (input.tenant_id) params.set("tenant", input.tenant_id);
    params.set("workflow_id", input.workflow_id);
    if (input.node_id) params.set("node_id", input.node_id);
    if (input.actor_id) params.set("actor_id", input.actor_id);
    if (input.run_id) params.set("run_id", input.run_id);
    if (input.trace_id) params.set("trace_id", input.trace_id);
    const suffix = params.toString();
    return this.request(`/governance/runtime-config${suffix ? `?${suffix}` : ""}`);
  }
}

export async function executeGovernedAction<
  TPayload extends GovernanceJsonObject,
  TResult,
>(
  options: ExecuteGovernedActionOptions<TPayload, TResult>,
): Promise<GovernedActionResult<TResult>> {
  const now = options.now || (() => new Date().toISOString());
  const submission = await options.client.submitSubmission({
    submission: normalizeGovernanceSubmission(options.submission, now),
  });
  const waitForResolution = options.waitForResolution ?? false;

  let resolution = submission.human_resolution || null;
  let effectivePayload = submission.effective_payload;
  let allowExecution = submission.allow_execution;

  if (!allowExecution && submission.decision.decision !== "deny" && waitForResolution) {
    resolution = await options.client.waitForHumanResolution(
      submission.submission.submission_id,
      waitForResolution === true ? undefined : waitForResolution,
    );
    if (resolution) {
      effectivePayload = applyHumanResolutionPayload(submission.submission.payload, resolution);
      allowExecution = resolution.action === "approve" || resolution.action === "edit";
    }
  }

  if (!allowExecution) {
    const executionRecord = await options.client.reportExecution({
      submission_id: submission.submission.submission_id,
      executed: false,
      final_payload: effectivePayload,
      status: "blocked",
      error: submission.decision.policy_reason || "execution_blocked",
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
    const summary = options.summarizeResult?.(value) || {
      status: "succeeded",
      result_summary: summarizeValue(value),
    };
    const executionRecord = await options.client.reportExecution({
      submission_id: submission.submission.submission_id,
      executed: true,
      final_payload: effectivePayload,
      status: summary.status || "succeeded",
      result_summary: summary.result_summary || null,
      output_reference: summary.output_reference || null,
      metadata: summary.metadata || {},
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
    throw Object.assign(error instanceof Error ? error : new Error(String(error)), {
      sec0ExecutionRecord: executionRecord,
    });
  }
}
