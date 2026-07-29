import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  open,
  realpath,
} from "node:fs/promises";
import { dirname, relative, resolve } from "node:path";

import {
  acquireFileLock,
  releaseFileLock,
} from "../internal/fileLock";
import {
  GovernanceConflictError,
  GovernanceNotFoundError,
  GovernanceStoreCorruptionError,
  GovernanceStoreNotInitializedError,
  GovernanceValidationError,
} from "./errors";
import type {
  ClarificationAnswer,
  ClarificationRequest,
  ExecutionRecord,
  ExecutionReflectionRecord,
  GovernanceDecision,
  GovernanceJsonObject,
  GovernanceJsonValue,
  GovernanceRecord,
  GovernanceSubmission,
  HumanResolution,
  ImprovementProposal,
  OutcomeRecord,
  PendingGovernanceReview,
  PreferenceComparison,
  PreferenceExample,
  PromotionEvaluation,
  ReplayEventRow,
  RewardOutcomeRow,
} from "./types";
import {
  canonicalGovernanceJson,
  cloneGovernanceValue,
  governanceHashOnlyObject,
  governancePersistenceProjection,
  governanceSha256,
  governanceValuesEqual,
  requiredString,
  timestampMs,
} from "./validation";

export interface FileGovernanceStorePaths {
  submissions: string;
  decisions: string;
  clarifications: string;
  clarificationAnswers: string;
  resolutions: string;
  executions: string;
  reflections: string;
  outcomes: string;
  improvements: string;
  promotions: string;
}

export interface FileGovernanceStoreConfig {
  rootDir?: string;
  paths?: Partial<FileGovernanceStorePaths>;
}

export interface GovernanceStore {
  initialize(): Promise<void>;
  appendSubmission(submission: GovernanceSubmission): Promise<GovernanceSubmission>;
  appendDecision(decision: GovernanceDecision): Promise<GovernanceDecision>;
  getOrAppendDecision(
    submissionId: string,
    create: () => Promise<GovernanceDecision>,
  ): Promise<GovernanceDecision>;
  appendClarificationRequest(
    clarification: Omit<ClarificationRequest, "clarification_id"> & {
      clarification_id?: string;
    },
  ): Promise<ClarificationRequest>;
  appendClarificationAnswer(
    answer: Omit<ClarificationAnswer, "answer_id"> & { answer_id?: string },
  ): Promise<ClarificationAnswer>;
  appendResolution(
    resolution: Omit<HumanResolution, "resolution_id"> & {
      resolution_id?: string;
    },
  ): Promise<HumanResolution>;
  appendExecution(record: ExecutionRecord): Promise<ExecutionRecord>;
  appendReflection(
    reflection: Omit<ExecutionReflectionRecord, "reflection_id" | "event_kind"> & {
      reflection_id?: string;
      event_kind?: "execution_reflection";
    },
  ): Promise<ExecutionReflectionRecord>;
  appendOutcome(outcome: OutcomeRecord): Promise<OutcomeRecord>;
  appendImprovement(
    improvement: Omit<ImprovementProposal, "improvement_id"> & {
      improvement_id?: string;
    },
  ): Promise<ImprovementProposal>;
  appendPromotionEvaluation(
    evaluation: Omit<PromotionEvaluation, "evaluation_id"> & {
      evaluation_id?: string;
    },
  ): Promise<PromotionEvaluation>;
  readSubmissions(): Promise<GovernanceSubmission[]>;
  readDecisions(): Promise<GovernanceDecision[]>;
  readClarificationRequests(): Promise<ClarificationRequest[]>;
  readClarificationAnswers(): Promise<ClarificationAnswer[]>;
  readResolutions(): Promise<HumanResolution[]>;
  readExecutions(): Promise<ExecutionRecord[]>;
  readReflections(): Promise<ExecutionReflectionRecord[]>;
  readOutcomes(): Promise<OutcomeRecord[]>;
  readImprovements(): Promise<ImprovementProposal[]>;
  readPromotions(): Promise<PromotionEvaluation[]>;
  getSubmission(submissionId: string): Promise<GovernanceSubmission | null>;
  getDecision(submissionId: string): Promise<GovernanceDecision | null>;
  getLatestClarificationRequest(
    submissionId: string,
  ): Promise<ClarificationRequest | null>;
  getLatestClarificationAnswer(
    submissionId: string,
  ): Promise<ClarificationAnswer | null>;
  getLatestResolution(submissionId: string): Promise<HumanResolution | null>;
  getReflections(submissionId: string): Promise<ExecutionReflectionRecord[]>;
  listPendingReviews(): Promise<PendingGovernanceReview[]>;
  getJoinedRecords(): Promise<GovernanceRecord[]>;
  exportPreferenceExamples(): Promise<PreferenceExample[]>;
  exportRewardOutcomeRows(): Promise<RewardOutcomeRow[]>;
  exportReplayRows(): Promise<ReplayEventRow[]>;
}

interface GovernanceLogValues {
  submissions: GovernanceSubmission;
  decisions: GovernanceDecision;
  clarifications: ClarificationRequest;
  clarificationAnswers: ClarificationAnswer;
  resolutions: HumanResolution;
  executions: ExecutionRecord;
  reflections: ExecutionReflectionRecord;
  outcomes: OutcomeRecord;
  improvements: ImprovementProposal;
  promotions: PromotionEvaluation;
}

type GovernanceLogKind = keyof GovernanceLogValues;

const LOG_KINDS: GovernanceLogKind[] = [
  "submissions",
  "decisions",
  "clarifications",
  "clarificationAnswers",
  "resolutions",
  "executions",
  "reflections",
  "outcomes",
  "improvements",
  "promotions",
];

const GLOBAL_STORE_MUTATIONS = new Map<string, Promise<void>>();
const NOFOLLOW = constants.O_NOFOLLOW ?? 0;

function isErrorCode(error: unknown, code: string): boolean {
  return (
    error instanceof Error &&
    "code" in error &&
    (error as NodeJS.ErrnoException).code === code
  );
}

function defaultPaths(rootDir: string): FileGovernanceStorePaths {
  return {
    submissions: resolve(rootDir, "submissions.ndjson"),
    decisions: resolve(rootDir, "decisions.ndjson"),
    clarifications: resolve(rootDir, "clarifications.ndjson"),
    clarificationAnswers: resolve(rootDir, "clarification-answers.ndjson"),
    resolutions: resolve(rootDir, "resolutions.ndjson"),
    executions: resolve(rootDir, "executions.ndjson"),
    reflections: resolve(rootDir, "reflections.ndjson"),
    outcomes: resolve(rootDir, "outcomes.ndjson"),
    improvements: resolve(rootDir, "improvements.ndjson"),
    promotions: resolve(rootDir, "promotions.ndjson"),
  };
}

function resolveConfiguredPath(rootDir: string, value: string): string {
  const filePath = resolve(rootDir, value);
  const relativePath = relative(rootDir, filePath);
  if (
    !relativePath ||
    relativePath === ".." ||
    relativePath.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`) ||
    resolve(rootDir, relativePath) !== filePath
  ) {
    throw new GovernanceValidationError(
      "Governance log paths must remain inside rootDir",
    );
  }
  return filePath;
}

interface GovernanceLogBody {
  format: "coreax-governance-log";
  version: 2;
  kind: GovernanceLogKind;
  sequence: number;
  previous_checksum: string | null;
  value: GovernanceJsonObject;
}

interface GovernanceLogEnvelope extends GovernanceLogBody {
  checksum: string;
}

function validateLogValue(kind: GovernanceLogKind, value: unknown): void {
  canonicalGovernanceJson(value);
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new GovernanceValidationError(`${kind} record must be an object`);
  }
  const row = value as Record<string, unknown>;
  timestampMs(row.created_at, `${kind}.created_at`);

  switch (kind) {
    case "submissions":
      requiredString(row.submission_id, "submission.submission_id");
      requiredString(row.namespace, "submission.namespace");
      requiredString(row.workflow_id, "submission.workflow_id");
      requiredString(row.node_id, "submission.node_id");
      requiredString(row.run_id, "submission.run_id");
      if (Array.isArray(row.evidence_events)) {
        for (const [index, event] of row.evidence_events.entries()) {
          if (
            event &&
            typeof event === "object" &&
            !Array.isArray(event) &&
            (event as Record<string, unknown>).timestamp !== undefined
          ) {
            timestampMs(
              (event as Record<string, unknown>).timestamp,
              `submission.evidence_events[${index}].timestamp`,
            );
          }
        }
      }
      break;
    case "decisions":
      requiredString(row.decision_id, "decision.decision_id");
      requiredString(row.submission_id, "decision.submission_id");
      if (
        row.decision !== "allow" &&
        row.decision !== "deny" &&
        row.decision !== "escalate" &&
        row.decision !== "clarify"
      ) {
        throw new GovernanceValidationError("Invalid governance decision");
      }
      break;
    case "clarifications":
      requiredString(row.clarification_id, "clarification.clarification_id");
      requiredString(row.submission_id, "clarification.submission_id");
      if (
        row.status !== "pending" &&
        row.status !== "answered" &&
        row.status !== "closed"
      ) {
        throw new GovernanceValidationError("Invalid clarification status");
      }
      if (row.answered_at !== undefined && row.answered_at !== null) {
        timestampMs(row.answered_at, "clarification.answered_at");
      }
      break;
    case "clarificationAnswers":
      requiredString(row.answer_id, "answer.answer_id");
      requiredString(row.clarification_id, "answer.clarification_id");
      requiredString(row.submission_id, "answer.submission_id");
      break;
    case "resolutions":
      requiredString(row.resolution_id, "resolution.resolution_id");
      requiredString(row.submission_id, "resolution.submission_id");
      if (
        row.action !== "approve" &&
        row.action !== "reject" &&
        row.action !== "edit"
      ) {
        throw new GovernanceValidationError("Invalid human resolution action");
      }
      break;
    case "executions":
      requiredString(row.submission_id, "execution.submission_id");
      requiredString(row.status, "execution.status");
      break;
    case "reflections":
      requiredString(row.reflection_id, "reflection.reflection_id");
      requiredString(row.submission_id, "reflection.submission_id");
      if (row.event_kind !== "execution_reflection") {
        throw new GovernanceValidationError("Invalid reflection event kind");
      }
      break;
    case "outcomes":
      requiredString(row.outcome_id, "outcome.outcome_id");
      if (!row.submission_id && !row.run_id) {
        throw new GovernanceValidationError(
          "Outcome requires submission_id or run_id",
        );
      }
      break;
    case "improvements":
      requiredString(row.improvement_id, "improvement.improvement_id");
      requiredString(row.submission_id, "improvement.submission_id");
      break;
    case "promotions":
      requiredString(row.evaluation_id, "promotion.evaluation_id");
      requiredString(row.improvement_id, "promotion.improvement_id");
      break;
  }
}

function encodeLogRecord<K extends GovernanceLogKind>(
  kind: K,
  value: GovernanceLogValues[K],
  sequence: number,
  previousChecksum: string | null,
): string {
  const body: GovernanceLogBody = {
    format: "coreax-governance-log",
    version: 2,
    kind,
    sequence,
    previous_checksum: previousChecksum,
    value: value as unknown as GovernanceJsonObject,
  };
  return `${canonicalGovernanceJson({
    ...body,
    checksum: governanceSha256(body),
  })}\n`;
}

function hashedText(value: string): string {
  return `[REDACTED sha256:${governanceSha256(value)}]`;
}

function hashedStrings(values: string[] | undefined): string[] | undefined {
  return values?.map(hashedText);
}

function persistenceLogValue<K extends GovernanceLogKind>(
  kind: K,
  value: GovernanceLogValues[K],
): GovernanceLogValues[K] {
  const projected = governancePersistenceProjection(value);
  if (kind === "submissions") {
    const submission = projected as GovernanceSubmission;
    const original = value as GovernanceSubmission;
    submission.payload = governanceHashOnlyObject(original.payload);
    submission.actor = {
      ...submission.actor,
      actor_id: hashedText(original.actor.actor_id),
      ...(original.actor.source
        ? { source: hashedText(original.actor.source) }
        : {}),
      ...(original.actor.labels
        ? { labels: hashedStrings(original.actor.labels) }
        : {}),
      ...(original.actor.metadata
        ? { metadata: governanceHashOnlyObject(original.actor.metadata) }
        : {}),
    };
    submission.target = {
      ...submission.target,
      ...(original.target.protocol
        ? { protocol: hashedText(original.target.protocol) }
        : {}),
      ...(original.target.boundary
        ? { boundary: hashedText(original.target.boundary) }
        : {}),
      ...(original.target.resource_type
        ? { resource_type: hashedText(original.target.resource_type) }
        : {}),
      ...(original.target.resource_id
        ? { resource_id: hashedText(original.target.resource_id) }
        : {}),
      ...(original.target.metadata
        ? { metadata: governanceHashOnlyObject(original.target.metadata) }
        : {}),
    };
    submission.authority = {
      ...submission.authority,
      ...(original.authority.approvals
        ? { approvals: hashedStrings(original.authority.approvals) }
        : {}),
      ...(original.authority.entitlements
        ? { entitlements: hashedStrings(original.authority.entitlements) }
        : {}),
      ...(original.authority.constraints
        ? { constraints: hashedStrings(original.authority.constraints) }
        : {}),
      ...(original.authority.metadata
        ? { metadata: governanceHashOnlyObject(original.authority.metadata) }
        : {}),
    };
    if (original.state_ref) {
      submission.state_ref = hashedText(original.state_ref);
    }
    submission.state_slice = original.state_slice
      ? governanceHashOnlyObject(original.state_slice)
      : original.state_slice;
    submission.metadata = {
      ...governanceHashOnlyObject(original.metadata),
      submission_sha256: governanceSha256(original),
    };
    if (original.evidence_events) {
      submission.evidence_events = original.evidence_events.map((event) => ({
        ...event,
        kind: hashedText(event.kind),
        summary: hashedText(event.summary),
        ...(event.claim ? { claim: hashedText(event.claim) } : {}),
        ...(event.claimGroup
          ? { claimGroup: hashedText(event.claimGroup) }
          : {}),
        ...(event.source ? { source: hashedText(event.source) } : {}),
        ...(event.provenanceRef
          ? { provenanceRef: hashedText(event.provenanceRef) }
          : {}),
        entityRefs: event.entityRefs?.map((entity) => ({
          ...(entity.id ? { id: hashedText(entity.id) } : {}),
          ...(entity.type ? { type: hashedText(entity.type) } : {}),
          ...(entity.role ? { role: hashedText(entity.role) } : {}),
          ...(entity.label ? { label: hashedText(entity.label) } : {}),
          ...(entity.metadata
            ? { metadata: governanceHashOnlyObject(entity.metadata) }
            : {}),
        })),
        ...(event.metadata
          ? { metadata: governanceHashOnlyObject(event.metadata) }
          : {}),
      }));
    }
    submission.provenance = {
      ...submission.provenance,
      audit_refs: hashedStrings(original.provenance.audit_refs),
      boundary_crossings: hashedStrings(
        original.provenance.boundary_crossings,
      ),
      ...(original.provenance.metadata
        ? {
            metadata: governanceHashOnlyObject(
              original.provenance.metadata,
            ),
          }
        : {}),
    };
  } else if (kind === "decisions") {
    const decision = projected as GovernanceDecision;
    const original = value as GovernanceDecision;
    decision.findings = original.findings.map((finding) => ({
      ...finding,
      message: hashedText(finding.message),
      ...(finding.source ? { source: hashedText(finding.source) } : {}),
      ...(finding.metadata
        ? { metadata: governanceHashOnlyObject(finding.metadata) }
        : {}),
    }));
    if (original.policy_reason) {
      decision.policy_reason = hashedText(original.policy_reason);
    }
    if (original.evidence_refs) {
      decision.evidence_refs = hashedStrings(original.evidence_refs);
    }
    if (original.principles) {
      decision.principles = hashedStrings(original.principles);
    }
    if (original.risk_labels) {
      decision.risk_labels = hashedStrings(original.risk_labels);
    }
    if (original.metadata) {
      decision.metadata = governanceHashOnlyObject(original.metadata);
    }
  } else if (kind === "clarifications") {
    const clarification = projected as ClarificationRequest;
    const original = value as ClarificationRequest;
    clarification.missing_facts = hashedStrings(original.missing_facts) ?? [];
    clarification.questions = hashedStrings(original.questions) ?? [];
    if (original.preferred_responders) {
      clarification.preferred_responders = hashedStrings(
        original.preferred_responders,
      );
    }
    if (original.suggested_sources) {
      clarification.suggested_sources = hashedStrings(
        original.suggested_sources,
      );
    }
    if (original.resume_conditions) {
      clarification.resume_conditions = hashedStrings(
        original.resume_conditions,
      );
    }
    if (original.metadata) {
      clarification.metadata = governanceHashOnlyObject(original.metadata);
    }
  } else if (kind === "resolutions") {
    const resolution = projected as HumanResolution;
    const original = value as HumanResolution;
    resolution.reviewer = hashedText(original.reviewer);
    if (original.feedback) {
      resolution.feedback = hashedText(original.feedback);
    }
    if (original.metadata) {
      resolution.metadata = governanceHashOnlyObject(original.metadata);
    }
    if (original.edited_payload) {
      resolution.edited_payload = governanceHashOnlyObject(
        original.edited_payload,
      );
    }
  } else if (kind === "executions") {
    const execution = projected as ExecutionRecord;
    const original = value as ExecutionRecord;
    if (original.final_payload) {
      execution.final_payload = governanceHashOnlyObject(
        original.final_payload,
      );
    }
    if (original.result_summary) {
      execution.result_summary =
        `[REDACTED sha256:${governanceSha256(original.result_summary)}]`;
    }
    if (original.error) {
      execution.error =
        `[REDACTED sha256:${governanceSha256(original.error)}]`;
    }
    if (original.output_reference) {
      execution.output_reference = hashedText(original.output_reference);
    }
    if (original.metadata) {
      execution.metadata = governanceHashOnlyObject(original.metadata);
    }
  } else if (kind === "clarificationAnswers") {
    const answer = projected as ClarificationAnswer;
    const original = value as ClarificationAnswer;
    answer.responder = hashedText(original.responder);
    answer.answers = governanceHashOnlyObject(original.answers);
    if (original.feedback) answer.feedback = hashedText(original.feedback);
    if (original.metadata) {
      answer.metadata = governanceHashOnlyObject(original.metadata);
    }
  } else if (kind === "reflections") {
    const reflection = projected as ExecutionReflectionRecord;
    const original = value as ExecutionReflectionRecord;
    if (original.deviation_reason) {
      reflection.deviation_reason = hashedText(original.deviation_reason);
    }
    if (original.retry_reason) {
      reflection.retry_reason = hashedText(original.retry_reason);
    }
    if (original.missing_facts) {
      reflection.missing_facts = hashedStrings(original.missing_facts);
    }
    if (original.boundary_crossings_observed) {
      reflection.boundary_crossings_observed = hashedStrings(
        original.boundary_crossings_observed,
      );
    }
    if (original.state_changes_observed) {
      reflection.state_changes_observed =
        original.state_changes_observed.map(governanceHashOnlyObject);
    }
    if (original.metadata) {
      reflection.metadata = governanceHashOnlyObject(original.metadata);
    }
    reflection.provenance = {
      ...reflection.provenance,
      ...(original.provenance.audit_refs
        ? { audit_refs: hashedStrings(original.provenance.audit_refs) }
        : {}),
      ...(original.provenance.boundary_crossings
        ? {
            boundary_crossings: hashedStrings(
              original.provenance.boundary_crossings,
            ),
          }
        : {}),
      ...(original.provenance.metadata
        ? {
            metadata: governanceHashOnlyObject(
              original.provenance.metadata,
            ),
          }
        : {}),
    };
  } else if (kind === "outcomes") {
    const outcome = projected as OutcomeRecord;
    const original = value as OutcomeRecord;
    if (original.business_outcome) {
      outcome.business_outcome = governanceHashOnlyObject(
        original.business_outcome,
      );
    }
    if (original.verifier_result?.details) {
      outcome.verifier_result = {
        ...outcome.verifier_result,
        details: governanceHashOnlyObject(original.verifier_result.details),
      };
    }
    if (original.metadata) {
      outcome.metadata = governanceHashOnlyObject(original.metadata);
    }
  } else if (kind === "improvements") {
    const improvement = projected as ImprovementProposal;
    const original = value as ImprovementProposal;
    improvement.scope = hashedText(original.scope);
    improvement.summary = hashedText(original.summary);
    if (original.rationale) {
      improvement.rationale = hashedText(original.rationale);
    }
    improvement.proposed_change = governanceHashOnlyObject(
      original.proposed_change,
    );
    if (original.metadata) {
      improvement.metadata = governanceHashOnlyObject(original.metadata);
    }
  } else if (kind === "promotions") {
    const promotion = projected as PromotionEvaluation;
    const original = value as PromotionEvaluation;
    promotion.scope = hashedText(original.scope);
    if (original.metadata) {
      promotion.metadata = governanceHashOnlyObject(original.metadata);
    }
  }
  return projected;
}

function decodeLogRecord<K extends GovernanceLogKind>(
  line: string,
  expectedKind: K,
  filePath: string,
  lineNumber: number,
  previousChecksum: string | null,
): { value: GovernanceLogValues[K]; checksum: string } {
  try {
    const parsed = JSON.parse(line) as Partial<GovernanceLogEnvelope>;
    if (
      parsed.format !== "coreax-governance-log" ||
      parsed.version !== 2 ||
      parsed.kind !== expectedKind ||
      parsed.sequence !== lineNumber ||
      parsed.previous_checksum !== previousChecksum ||
      !parsed.value ||
      typeof parsed.checksum !== "string"
    ) {
      throw new GovernanceValidationError("Unsupported record envelope");
    }
    const body: GovernanceLogBody = {
      format: parsed.format,
      version: parsed.version,
      kind: parsed.kind,
      sequence: parsed.sequence,
      previous_checksum: parsed.previous_checksum,
      value: parsed.value,
    };
    if (governanceSha256(body) !== parsed.checksum) {
      throw new GovernanceValidationError("Checksum mismatch");
    }
    validateLogValue(expectedKind, parsed.value);
    return {
      value: cloneGovernanceValue(
        parsed.value,
      ) as unknown as GovernanceLogValues[K],
      checksum: parsed.checksum,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new GovernanceStoreCorruptionError(filePath, lineNumber, message);
  }
}

async function readCompleteLogState<K extends GovernanceLogKind>(
  filePath: string,
  kind: K,
): Promise<{
  values: GovernanceLogValues[K][];
  lastChecksum: string | null;
}> {
  const content = await readSecureFile(filePath);
  if (!content) return { values: [], lastChecksum: null };
  if (!content.endsWith("\n")) {
    throw new GovernanceStoreCorruptionError(
      filePath,
      0,
      "truncated log tail",
    );
  }
  const lines = content.split("\n");
  lines.pop();
  const values: GovernanceLogValues[K][] = [];
  let lastChecksum: string | null = null;
  lines.forEach((line, index) => {
    const decoded = decodeLogRecord(
      line,
      kind,
      filePath,
      index + 1,
      lastChecksum,
    );
    values.push(decoded.value);
    lastChecksum = decoded.checksum;
  });
  return { values, lastChecksum };
}

async function readCompleteLog<K extends GovernanceLogKind>(
  filePath: string,
  kind: K,
): Promise<GovernanceLogValues[K][]> {
  return (await readCompleteLogState(filePath, kind)).values;
}

async function recoverTruncatedTail(filePath: string): Promise<void> {
  const handle = await open(
    filePath,
    constants.O_RDWR | NOFOLLOW,
  );
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) {
      throw new GovernanceValidationError(
        "Governance log path must be a regular file",
      );
    }
    const data = await handle.readFile();
    if (data.length === 0 || data[data.length - 1] === 0x0a) return;
    const lastNewline = data.lastIndexOf(0x0a);
    await handle.truncate(lastNewline < 0 ? 0 : lastNewline + 1);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function ensureFile(
  filePath: string,
  rootDir: string,
  realRootDir: string,
): Promise<void> {
  await mkdir(dirname(filePath), { recursive: true, mode: 0o700 });
  const realParent = await realpath(dirname(filePath));
  const expectedRealParent = resolve(
    realRootDir,
    relative(rootDir, dirname(filePath)),
  );
  if (realParent !== expectedRealParent) {
    throw new GovernanceValidationError(
      "Governance log paths must not traverse symbolic-link directories",
    );
  }
  const parentRelative = relative(realRootDir, realParent);
  if (
    parentRelative === ".." ||
    parentRelative.startsWith(
      `..${process.platform === "win32" ? "\\" : "/"}`,
    )
  ) {
    throw new GovernanceValidationError(
      "Governance log parent escapes rootDir through a symbolic link",
    );
  }
  try {
    const existing = await lstat(filePath);
    if (existing.isSymbolicLink() || !existing.isFile()) {
      throw new GovernanceValidationError(
        "Governance log path must be a regular file, not a symbolic link",
      );
    }
  } catch (error) {
    if (!isErrorCode(error, "ENOENT")) throw error;
  }
  const handle = await open(
    filePath,
    constants.O_WRONLY |
      constants.O_APPEND |
      constants.O_CREAT |
      NOFOLLOW,
    0o600,
  );
  try {
    if (!(await handle.stat()).isFile()) {
      throw new GovernanceValidationError(
        "Governance log path must be a regular file",
      );
    }
  } finally {
    await handle.close();
  }
}

async function durableAppend(filePath: string, content: string): Promise<void> {
  const handle = await open(
    filePath,
    constants.O_WRONLY | constants.O_APPEND | NOFOLLOW,
  );
  try {
    if (!(await handle.stat()).isFile()) {
      throw new GovernanceValidationError(
        "Governance log path must be a regular file",
      );
    }
    await handle.appendFile(content, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function readSecureFile(filePath: string): Promise<string> {
  const handle = await open(filePath, constants.O_RDONLY | NOFOLLOW);
  try {
    if (!(await handle.stat()).isFile()) {
      throw new GovernanceValidationError(
        "Governance log path must be a regular file",
      );
    }
    return await handle.readFile("utf8");
  } finally {
    await handle.close();
  }
}

async function withGovernanceLock<T>(
  rootDir: string,
  operation: () => Promise<T>,
): Promise<T> {
  await mkdir(rootDir, { recursive: true, mode: 0o700 });
  const rootStat = await lstat(rootDir);
  if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) {
    throw new GovernanceValidationError(
      "Governance rootDir must be a real directory, not a symbolic link",
    );
  }
  await chmod(rootDir, 0o700);
  const lock = await acquireFileLock({
    rootDir,
    name: "governance-writer",
    error: (message) => new GovernanceValidationError(message),
  });
  try {
    return await operation();
  } finally {
    await releaseFileLock(lock);
  }
}

function latestBySubmissionId<T extends { submission_id: string }>(
  rows: T[],
): Map<string, T> {
  const output = new Map<string, T>();
  for (const row of rows) output.set(row.submission_id, row);
  return output;
}

function latestOutcomeBySubmissionId(
  rows: OutcomeRecord[],
): Map<string, OutcomeRecord> {
  const output = new Map<string, OutcomeRecord>();
  for (const row of rows) {
    if (row.submission_id) output.set(row.submission_id, row);
  }
  return output;
}

function persistedPayloadHash(payload: GovernanceJsonObject): string {
  return payload.redacted === true && typeof payload.sha256 === "string"
    ? payload.sha256
    : governanceSha256(payload);
}

function stableJson(value: GovernanceJsonValue | undefined): GovernanceJsonValue {
  return JSON.parse(canonicalGovernanceJson(value ?? null)) as GovernanceJsonValue;
}

function submissionPrompt(submission: GovernanceSubmission): string {
  return [
    `namespace: ${submission.namespace}`,
    `workflow_id: ${submission.workflow_id}`,
    `node_id: ${submission.node_id}`,
    `run_id: ${submission.run_id}`,
    `event_kind: ${submission.event_kind}`,
    `actor: ${canonicalGovernanceJson(submission.actor)}`,
    `target: ${canonicalGovernanceJson(submission.target)}`,
    `authority: ${canonicalGovernanceJson(submission.authority)}`,
    `payload: ${canonicalGovernanceJson(submission.payload)}`,
    `state_slice: ${canonicalGovernanceJson(submission.state_slice ?? {})}`,
    `provenance: ${canonicalGovernanceJson(submission.provenance)}`,
  ].join("\n");
}

function assistantCompletion(
  payload: GovernanceJsonObject,
): PreferenceComparison["completion_A"] {
  return [{ role: "assistant", content: canonicalGovernanceJson(payload) }];
}

function chosenAndRejectedForResolution(
  submission: GovernanceSubmission,
  resolution: HumanResolution,
): { chosen: GovernanceJsonObject; rejected: GovernanceJsonObject } {
  const executeOriginal: GovernanceJsonObject = {
    mode: "execute",
    event_kind: submission.event_kind,
    target: stableJson(
      submission.target as unknown as GovernanceJsonValue,
    ) as GovernanceJsonObject,
    payload: stableJson(submission.payload) as GovernanceJsonObject,
  };
  if (resolution.action === "edit") {
    return {
      chosen: {
        ...executeOriginal,
        payload: stableJson(
          resolution.edited_payload ?? {},
        ) as GovernanceJsonObject,
      },
      rejected: executeOriginal,
    };
  }
  if (resolution.action === "reject") {
    return {
      chosen: {
        mode: "reject",
        event_kind: submission.event_kind,
        target: executeOriginal.target!,
        reason: resolution.feedback ?? "human_rejected",
      },
      rejected: executeOriginal,
    };
  }
  return {
    chosen: executeOriginal,
    rejected: {
      mode: "escalate",
      event_kind: submission.event_kind,
      target: executeOriginal.target!,
      reason: "unnecessary_human_review",
    },
  };
}

export class FileGovernanceStore implements GovernanceStore {
  readonly rootDir: string;
  readonly paths: FileGovernanceStorePaths;

  private initialized = false;
  private initialization: Promise<void> | null = null;
  private mutations: Promise<void> = Promise.resolve();

  constructor(config: FileGovernanceStoreConfig = {}) {
    this.rootDir = resolve(
      config.rootDir ?? resolve(process.cwd(), ".coreax", "governance"),
    );
    const defaults = defaultPaths(this.rootDir);
    this.paths = Object.fromEntries(
      LOG_KINDS.map((kind) => [
        kind,
        resolveConfiguredPath(
          this.rootDir,
          config.paths?.[kind] ?? defaults[kind],
        ),
      ]),
    ) as unknown as FileGovernanceStorePaths;
    if (new Set(Object.values(this.paths)).size !== LOG_KINDS.length) {
      throw new GovernanceValidationError(
        "Governance log paths must be distinct",
      );
    }
  }

  initialize(): Promise<void> {
    if (this.initialized) return Promise.resolve();
    if (this.initialization) return this.initialization;
    this.initialization = this.initializeFiles().finally(() => {
      this.initialization = null;
    });
    return this.initialization;
  }

  private async initializeFiles(): Promise<void> {
    await this.enqueueMutation(async () => {
      const realRootDir = await realpath(this.rootDir);
      for (const kind of LOG_KINDS) {
        await ensureFile(
          this.paths[kind],
          this.rootDir,
          realRootDir,
        );
        await recoverTruncatedTail(this.paths[kind]);
      }
      await this.validateConsistency();
    });
    this.initialized = true;
  }

  private assertInitialized(): void {
    if (!this.initialized) throw new GovernanceStoreNotInitializedError();
  }

  private enqueueMutation<T>(operation: () => Promise<T>): Promise<T> {
    const previous =
      GLOBAL_STORE_MUTATIONS.get(this.rootDir) ?? Promise.resolve();
    const lockedOperation = () =>
      withGovernanceLock(this.rootDir, operation);
    const run = previous.then(lockedOperation, lockedOperation);
    const settled = run.then(
      () => undefined,
      () => undefined,
    );
    this.mutations = settled;
    GLOBAL_STORE_MUTATIONS.set(this.rootDir, settled);
    void settled.then(() => {
      if (GLOBAL_STORE_MUTATIONS.get(this.rootDir) === settled) {
        GLOBAL_STORE_MUTATIONS.delete(this.rootDir);
      }
    });
    return run;
  }

  private async readKind<K extends GovernanceLogKind>(
    kind: K,
  ): Promise<GovernanceLogValues[K][]> {
    this.assertInitialized();
    await (GLOBAL_STORE_MUTATIONS.get(this.rootDir) ?? this.mutations);
    return withGovernanceLock(this.rootDir, () =>
      readCompleteLog(this.paths[kind], kind),
    );
  }

  private async readKindUnchecked<K extends GovernanceLogKind>(
    kind: K,
  ): Promise<GovernanceLogValues[K][]> {
    return readCompleteLog(this.paths[kind], kind);
  }

  private async appendKind<K extends GovernanceLogKind>(
    kind: K,
    value: GovernanceLogValues[K],
    options: {
      uniqueKey?: (row: GovernanceLogValues[K]) => string;
      allowUpdate?: boolean;
      submissionId?: string | null;
      improvementId?: string | null;
    } = {},
  ): Promise<GovernanceLogValues[K]> {
    this.assertInitialized();
    validateLogValue(kind, value);
    const original = cloneGovernanceValue(value);
    const normalized = persistenceLogValue(kind, original);
    validateLogValue(kind, normalized);
    return this.enqueueMutation(async () => {
      await recoverTruncatedTail(this.paths[kind]);
      if (options.submissionId) {
        const submissions = await this.readKindUnchecked("submissions");
        if (
          !submissions.some(
            (submission) =>
              submission.submission_id === options.submissionId,
          )
        ) {
          throw new GovernanceNotFoundError(
            "Governance submission",
            options.submissionId,
          );
        }
      }
      if (options.improvementId) {
        const improvements = await this.readKindUnchecked("improvements");
        if (
          !improvements.some(
            (improvement) =>
              improvement.improvement_id === options.improvementId,
          )
        ) {
          throw new GovernanceNotFoundError(
            "Improvement proposal",
            options.improvementId,
          );
        }
      }
      const state = await readCompleteLogState(this.paths[kind], kind);
      const rows = state.values;
      if (options.uniqueKey) {
        const key = options.uniqueKey(normalized);
        const existing = rows.filter(
          (row) => options.uniqueKey!(row) === key,
        ).at(-1);
        if (existing && governanceValuesEqual(existing, normalized)) {
          return cloneGovernanceValue(original);
        }
        if (existing && !options.allowUpdate) {
          throw new GovernanceConflictError(
            `${kind} record "${key}" already exists`,
            { kind, key },
          );
        }
      }
      await durableAppend(
        this.paths[kind],
        encodeLogRecord(
          kind,
          normalized,
          rows.length + 1,
          state.lastChecksum,
        ),
      );
      return cloneGovernanceValue(original);
    });
  }

  private async validateConsistency(): Promise<void> {
    const [
      submissions,
      decisions,
      clarifications,
      answers,
      resolutions,
      executions,
      reflections,
      outcomes,
      improvements,
      promotions,
    ] = await Promise.all([
      this.readKindUnchecked("submissions"),
      this.readKindUnchecked("decisions"),
      this.readKindUnchecked("clarifications"),
      this.readKindUnchecked("clarificationAnswers"),
      this.readKindUnchecked("resolutions"),
      this.readKindUnchecked("executions"),
      this.readKindUnchecked("reflections"),
      this.readKindUnchecked("outcomes"),
      this.readKindUnchecked("improvements"),
      this.readKindUnchecked("promotions"),
    ]);
    const submissionIds = new Set(submissions.map((row) => row.submission_id));
    const improvementIds = new Set(
      improvements.map((row) => row.improvement_id),
    );
    const referencedSubmissionIds = [
      ...decisions,
      ...clarifications,
      ...answers,
      ...resolutions,
      ...executions,
      ...reflections,
      ...improvements,
      ...outcomes.filter((row) => Boolean(row.submission_id)),
    ].map((row) => String(row.submission_id));
    const orphan = referencedSubmissionIds.find(
      (submissionId) => !submissionIds.has(submissionId),
    );
    if (orphan) {
      throw new GovernanceStoreCorruptionError(
        this.rootDir,
        0,
        `orphan record for submission "${orphan}"`,
      );
    }
    const orphanPromotion = promotions.find(
      (row) => !improvementIds.has(row.improvement_id),
    );
    if (orphanPromotion) {
      throw new GovernanceStoreCorruptionError(
        this.paths.promotions,
        0,
        `orphan promotion "${orphanPromotion.evaluation_id}"`,
      );
    }
    const submissionsById = new Map<string, GovernanceSubmission>();
    for (const submission of submissions) {
      const existing = submissionsById.get(submission.submission_id);
      if (existing && !governanceValuesEqual(existing, submission)) {
        throw new GovernanceStoreCorruptionError(
          this.paths.submissions,
          0,
          `conflicting submission "${submission.submission_id}"`,
        );
      }
      submissionsById.set(submission.submission_id, submission);
    }
    const resolutionsBySubmission = new Map<string, HumanResolution>();
    for (const resolution of resolutions) {
      const existing = resolutionsBySubmission.get(resolution.submission_id);
      if (existing && !governanceValuesEqual(existing, resolution)) {
        throw new GovernanceStoreCorruptionError(
          this.paths.resolutions,
          0,
          `conflicting resolution for "${resolution.submission_id}"`,
        );
      }
      resolutionsBySubmission.set(resolution.submission_id, resolution);
    }
  }

  appendSubmission(
    submission: GovernanceSubmission,
  ): Promise<GovernanceSubmission> {
    return this.appendKind("submissions", submission, {
      uniqueKey: (row) => row.submission_id,
    });
  }

  appendDecision(decision: GovernanceDecision): Promise<GovernanceDecision> {
    const normalized: GovernanceDecision = {
      ...decision,
      decision_id: decision.decision_id ?? randomUUID(),
    };
    return this.appendKind("decisions", normalized, {
      uniqueKey: (row) => row.submission_id,
      submissionId: normalized.submission_id,
    });
  }

  getOrAppendDecision(
    submissionId: string,
    create: () => Promise<GovernanceDecision>,
  ): Promise<GovernanceDecision> {
    this.assertInitialized();
    const normalizedSubmissionId = requiredString(
      submissionId,
      "submissionId",
    );
    return this.enqueueMutation(async () => {
      const submissions = await this.readKindUnchecked("submissions");
      if (
        !submissions.some(
          (submission) =>
            submission.submission_id === normalizedSubmissionId,
        )
      ) {
        throw new GovernanceNotFoundError(
          "Governance submission",
          normalizedSubmissionId,
        );
      }
      const state = await readCompleteLogState(
        this.paths.decisions,
        "decisions",
      );
      const existing = state.values
        .filter(
          (decision) =>
            decision.submission_id === normalizedSubmissionId,
        )
        .at(-1);
      if (existing) return cloneGovernanceValue(existing);

      const created = cloneGovernanceValue(await create());
      if (created.submission_id !== normalizedSubmissionId) {
        throw new GovernanceValidationError(
          "Created governance decision does not match its submission",
        );
      }
      created.decision_id ??= randomUUID();
      validateLogValue("decisions", created);
      const persisted = persistenceLogValue("decisions", created);
      validateLogValue("decisions", persisted);
      await durableAppend(
        this.paths.decisions,
        encodeLogRecord(
          "decisions",
          persisted,
          state.values.length + 1,
          state.lastChecksum,
        ),
      );
      return cloneGovernanceValue(created);
    });
  }

  appendClarificationRequest(
    clarification: Omit<ClarificationRequest, "clarification_id"> & {
      clarification_id?: string;
    },
  ): Promise<ClarificationRequest> {
    const normalized: ClarificationRequest = {
      ...clarification,
      clarification_id: clarification.clarification_id ?? randomUUID(),
    };
    return this.appendKind("clarifications", normalized, {
      uniqueKey: (row) => row.clarification_id,
      allowUpdate: true,
      submissionId: normalized.submission_id,
    });
  }

  appendClarificationAnswer(
    answer: Omit<ClarificationAnswer, "answer_id"> & { answer_id?: string },
  ): Promise<ClarificationAnswer> {
    const normalized: ClarificationAnswer = {
      ...answer,
      answer_id: answer.answer_id ?? randomUUID(),
    };
    return this.appendKind("clarificationAnswers", normalized, {
      uniqueKey: (row) => row.answer_id,
      submissionId: normalized.submission_id,
    });
  }

  appendResolution(
    resolution: Omit<HumanResolution, "resolution_id"> & {
      resolution_id?: string;
    },
  ): Promise<HumanResolution> {
    const normalized: HumanResolution = {
      ...resolution,
      resolution_id: resolution.resolution_id ?? randomUUID(),
    };
    return this.appendKind("resolutions", normalized, {
      uniqueKey: (row) => row.submission_id,
      submissionId: normalized.submission_id,
    });
  }

  appendExecution(record: ExecutionRecord): Promise<ExecutionRecord> {
    return this.appendKind("executions", record, {
      submissionId: record.submission_id,
    });
  }

  appendReflection(
    reflection: Omit<ExecutionReflectionRecord, "reflection_id" | "event_kind"> & {
      reflection_id?: string;
      event_kind?: "execution_reflection";
    },
  ): Promise<ExecutionReflectionRecord> {
    const normalized: ExecutionReflectionRecord = {
      ...reflection,
      event_kind: "execution_reflection",
      reflection_id: reflection.reflection_id ?? randomUUID(),
    };
    return this.appendKind("reflections", normalized, {
      uniqueKey: (row) => row.reflection_id!,
      submissionId: normalized.submission_id,
    });
  }

  appendOutcome(outcome: OutcomeRecord): Promise<OutcomeRecord> {
    const normalized: OutcomeRecord = {
      ...outcome,
      outcome_id: outcome.outcome_id ?? randomUUID(),
    };
    return this.appendKind("outcomes", normalized, {
      uniqueKey: (row) => row.outcome_id!,
      submissionId: normalized.submission_id,
    });
  }

  appendImprovement(
    improvement: Omit<ImprovementProposal, "improvement_id"> & {
      improvement_id?: string;
    },
  ): Promise<ImprovementProposal> {
    const normalized: ImprovementProposal = {
      ...improvement,
      improvement_id: improvement.improvement_id ?? randomUUID(),
    };
    return this.appendKind("improvements", normalized, {
      uniqueKey: (row) => row.improvement_id,
      submissionId: normalized.submission_id,
    });
  }

  appendPromotionEvaluation(
    evaluation: Omit<PromotionEvaluation, "evaluation_id"> & {
      evaluation_id?: string;
    },
  ): Promise<PromotionEvaluation> {
    const normalized: PromotionEvaluation = {
      ...evaluation,
      evaluation_id: evaluation.evaluation_id ?? randomUUID(),
    };
    return this.appendKind("promotions", normalized, {
      uniqueKey: (row) => row.evaluation_id,
      improvementId: normalized.improvement_id,
    });
  }

  readSubmissions(): Promise<GovernanceSubmission[]> {
    return this.readKind("submissions");
  }
  readDecisions(): Promise<GovernanceDecision[]> {
    return this.readKind("decisions");
  }
  readClarificationRequests(): Promise<ClarificationRequest[]> {
    return this.readKind("clarifications");
  }
  readClarificationAnswers(): Promise<ClarificationAnswer[]> {
    return this.readKind("clarificationAnswers");
  }
  readResolutions(): Promise<HumanResolution[]> {
    return this.readKind("resolutions");
  }
  readExecutions(): Promise<ExecutionRecord[]> {
    return this.readKind("executions");
  }
  readReflections(): Promise<ExecutionReflectionRecord[]> {
    return this.readKind("reflections");
  }
  readOutcomes(): Promise<OutcomeRecord[]> {
    return this.readKind("outcomes");
  }
  readImprovements(): Promise<ImprovementProposal[]> {
    return this.readKind("improvements");
  }
  readPromotions(): Promise<PromotionEvaluation[]> {
    return this.readKind("promotions");
  }

  async getSubmission(submissionId: string): Promise<GovernanceSubmission | null> {
    return (
      (await this.readSubmissions()).find(
        (submission) => submission.submission_id === submissionId,
      ) ?? null
    );
  }

  async getDecision(submissionId: string): Promise<GovernanceDecision | null> {
    return (
      (await this.readDecisions())
        .filter((decision) => decision.submission_id === submissionId)
        .at(-1) ?? null
    );
  }

  async getLatestClarificationRequest(
    submissionId: string,
  ): Promise<ClarificationRequest | null> {
    return (
      (await this.readClarificationRequests())
        .filter((row) => row.submission_id === submissionId)
        .at(-1) ?? null
    );
  }

  async getLatestClarificationAnswer(
    submissionId: string,
  ): Promise<ClarificationAnswer | null> {
    return (
      (await this.readClarificationAnswers())
        .filter((row) => row.submission_id === submissionId)
        .at(-1) ?? null
    );
  }

  async getLatestResolution(
    submissionId: string,
  ): Promise<HumanResolution | null> {
    return (
      (await this.readResolutions())
        .filter((row) => row.submission_id === submissionId)
        .at(-1) ?? null
    );
  }

  async getReflections(
    submissionId: string,
  ): Promise<ExecutionReflectionRecord[]> {
    return (await this.readReflections()).filter(
      (row) => row.submission_id === submissionId,
    );
  }

  async listPendingReviews(): Promise<PendingGovernanceReview[]> {
    const [
      submissions,
      decisions,
      resolutions,
      clarifications,
      answers,
      improvements,
    ] = await Promise.all([
      this.readSubmissions(),
      this.readDecisions(),
      this.readResolutions(),
      this.readClarificationRequests(),
      this.readClarificationAnswers(),
      this.readImprovements(),
    ]);
    const submissionsById = latestBySubmissionId(submissions);
    const decisionsById = latestBySubmissionId(decisions);
    const resolutionsById = latestBySubmissionId(resolutions);
    const clarificationsById = latestBySubmissionId(clarifications);
    const answersById = latestBySubmissionId(answers);

    return [...decisionsById.values()]
      .filter(
        (decision) =>
          decision.decision === "escalate" || decision.decision === "clarify",
      )
      .filter((decision) => {
        if (decision.decision === "escalate") {
          return !resolutionsById.has(decision.submission_id);
        }
        const clarification = clarificationsById.get(decision.submission_id);
        return (
          !clarification ||
          (clarification.status === "pending" &&
            !answersById.has(decision.submission_id))
        );
      })
      .flatMap((decision) => {
        const submission = submissionsById.get(decision.submission_id);
        if (!submission) return [];
        return [
          {
            submission,
            decision,
            clarification_request:
              clarificationsById.get(decision.submission_id) ?? null,
            latest_resolution:
              resolutionsById.get(decision.submission_id) ?? null,
            improvements: improvements.filter(
              (entry) => entry.submission_id === decision.submission_id,
            ),
          },
        ];
      });
  }

  private getReviewKey(submission: GovernanceSubmission): string {
    return governanceSha256({
      namespace: submission.namespace,
      workflow_id: submission.workflow_id,
      actor: submission.actor,
      target: submission.target,
      authority: submission.authority,
      event_kind: submission.event_kind,
      payload_sha256: persistedPayloadHash(submission.payload),
    });
  }

  async getJoinedRecords(): Promise<GovernanceRecord[]> {
    const [
      submissions,
      decisions,
      clarifications,
      answers,
      resolutions,
      executions,
      reflections,
      outcomes,
      improvements,
      promotions,
    ] = await Promise.all([
      this.readSubmissions(),
      this.readDecisions(),
      this.readClarificationRequests(),
      this.readClarificationAnswers(),
      this.readResolutions(),
      this.readExecutions(),
      this.readReflections(),
      this.readOutcomes(),
      this.readImprovements(),
      this.readPromotions(),
    ]);
    const decisionsById = latestBySubmissionId(decisions);
    const clarificationsById = latestBySubmissionId(clarifications);
    const answersById = latestBySubmissionId(answers);
    const resolutionsById = latestBySubmissionId(resolutions);
    const executionsById = latestBySubmissionId(executions);
    const outcomesById = latestOutcomeBySubmissionId(outcomes);

    return submissions.map((submission) => {
      const matchingImprovements = improvements.filter(
        (entry) => entry.submission_id === submission.submission_id,
      );
      const improvementIds = new Set(
        matchingImprovements.map((entry) => entry.improvement_id),
      );
      return {
        submission,
        decision: decisionsById.get(submission.submission_id),
        clarification_request:
          clarificationsById.get(submission.submission_id) ?? null,
        clarification_answer:
          answersById.get(submission.submission_id) ?? null,
        human_resolution:
          resolutionsById.get(submission.submission_id) ?? null,
        execution_record:
          executionsById.get(submission.submission_id) ?? null,
        reflection_records: reflections.filter(
          (entry) => entry.submission_id === submission.submission_id,
        ),
        outcome_record: outcomesById.get(submission.submission_id) ?? null,
        improvements: matchingImprovements,
        promotion_evaluations: promotions.filter((entry) =>
          improvementIds.has(entry.improvement_id),
        ),
      };
    });
  }

  async exportPreferenceExamples(): Promise<PreferenceExample[]> {
    return (await this.getJoinedRecords())
      .filter(
        (
          record,
        ): record is GovernanceRecord & { human_resolution: HumanResolution } =>
          Boolean(record.human_resolution),
      )
      .map((record) => {
        const resolution = record.human_resolution;
        const { chosen, rejected } = chosenAndRejectedForResolution(
          record.submission,
          resolution,
        );
        return {
          submission_id: record.submission.submission_id,
          resolution_id: resolution.resolution_id,
          preference_kind: resolution.action,
          comparison: {
            prompt_conversation: [
              {
                role: "system",
                content:
                  "Choose the preferred governance outcome for this workflow event.",
              },
              { role: "user", content: submissionPrompt(record.submission) },
            ],
            completion_A: assistantCompletion(chosen),
            completion_B: assistantCompletion(rejected),
          },
          label: "A",
          chosen_completion: chosen,
          rejected_completion: rejected,
          metadata: {
            review_key: this.getReviewKey(record.submission),
            submission_payload_hash: persistedPayloadHash(
              record.submission.payload,
            ),
            resolution_feedback: resolution.feedback ?? null,
          },
        };
      });
  }

  async exportRewardOutcomeRows(): Promise<RewardOutcomeRow[]> {
    return (await this.getJoinedRecords()).map((record) => ({
      ...record,
      submission_id: record.submission.submission_id,
      run_id: record.submission.run_id,
    }));
  }

  async exportReplayRows(): Promise<ReplayEventRow[]> {
    const [
      submissions,
      decisions,
      clarifications,
      answers,
      resolutions,
      executions,
      reflections,
      outcomes,
      improvements,
      promotions,
    ] = await Promise.all([
      this.readSubmissions(),
      this.readDecisions(),
      this.readClarificationRequests(),
      this.readClarificationAnswers(),
      this.readResolutions(),
      this.readExecutions(),
      this.readReflections(),
      this.readOutcomes(),
      this.readImprovements(),
      this.readPromotions(),
    ]);
    const runBySubmission = new Map(
      submissions.map((row) => [row.submission_id, row.run_id]),
    );
    const submissionByImprovement = new Map(
      improvements.map((row) => [row.improvement_id, row.submission_id]),
    );
    const row = (
      submissionId: string,
      eventType: ReplayEventRow["event_type"],
      createdAt: string,
      payload: unknown,
      runId?: string | null,
    ): ReplayEventRow => ({
      submission_id: submissionId,
      run_id: runId ?? runBySubmission.get(submissionId) ?? null,
      event_type: eventType,
      created_at: createdAt,
      payload: cloneGovernanceValue(payload) as GovernanceJsonObject,
    });
    return [
      ...submissions.map((entry) =>
        row(
          entry.submission_id,
          "governance_submission",
          entry.created_at,
          entry,
          entry.run_id,
        ),
      ),
      ...decisions.map((entry) =>
        row(
          entry.submission_id,
          "governance_decision",
          entry.created_at,
          entry,
        ),
      ),
      ...clarifications.map((entry) =>
        row(
          entry.submission_id,
          "clarification_request",
          entry.created_at,
          entry,
        ),
      ),
      ...answers.map((entry) =>
        row(
          entry.submission_id,
          "clarification_answer",
          entry.created_at,
          entry,
        ),
      ),
      ...resolutions.map((entry) =>
        row(
          entry.submission_id,
          "human_resolution",
          entry.created_at,
          entry,
        ),
      ),
      ...executions.map((entry) =>
        row(
          entry.submission_id,
          "execution_record",
          entry.created_at,
          entry,
        ),
      ),
      ...reflections.map((entry) =>
        row(
          entry.submission_id,
          "execution_reflection",
          entry.created_at,
          entry,
          entry.run_id,
        ),
      ),
      ...outcomes
        .filter((entry) => Boolean(entry.submission_id))
        .map((entry) =>
          row(
            entry.submission_id!,
            "outcome_record",
            entry.created_at,
            entry,
            entry.run_id,
          ),
        ),
      ...improvements.map((entry) =>
        row(
          entry.submission_id,
          "improvement_proposal",
          entry.created_at,
          entry,
        ),
      ),
      ...promotions.flatMap((entry) => {
        const submissionId = submissionByImprovement.get(entry.improvement_id);
        return submissionId
          ? [
              row(
                submissionId,
                "promotion_evaluation",
                entry.created_at,
                entry,
              ),
            ]
          : [];
      }),
    ].sort((left, right) => left.created_at.localeCompare(right.created_at));
  }
}
