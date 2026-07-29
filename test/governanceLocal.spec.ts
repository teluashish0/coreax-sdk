import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  compactGovernanceEvidence,
  evaluateGovernanceSubmissionDeterministically,
  executeGovernedAction,
  FileGovernanceStore,
    GovernanceEvaluatorError,
    GovernanceStoreCorruptionError,
    GovernanceStoreNotInitializedError,
    GovernanceValidationError,
  LocalGovernanceClient,
  normalizeGovernanceSubmission,
  type GovernanceEvidenceEvent,
  type GovernanceJsonObject,
  type GovernanceSubmission,
} from "../src/governance";

const tempDirectories: string[] = [];
const FIXED_TIME = Date.parse("2026-02-03T04:05:06.000Z");

function makeTempDirectory(): string {
  const directory = fs.mkdtempSync(
    path.join(os.tmpdir(), "coreax-governance-"),
  );
  tempDirectories.push(directory);
  return directory;
}

afterEach(() => {
  vi.unstubAllGlobals();
  while (tempDirectories.length > 0) {
    fs.rmSync(tempDirectories.pop()!, { force: true, recursive: true });
  }
});

function submission(
  id: string,
  overrides: Partial<GovernanceSubmission> = {},
): GovernanceSubmission {
  return normalizeGovernanceSubmission(
    {
      submission_id: id,
      namespace: "local",
      workflow_id: "workflow-1",
      node_id: "node-1",
      run_id: "run-1",
      trace_id: "trace-1",
      event_kind: "selected_action",
      actor: { actor_id: "agent-1", actor_type: "agent" },
      target: {
        action_type: "tool_call",
        action_name: "get_record",
        side_effect: false,
      },
      authority: {},
      payload: { record_id: "record-1" },
      state_slice: {},
      provenance: {},
      metadata: {},
      ...overrides,
    },
    () => new Date(FIXED_TIME).toISOString(),
  );
}

describe("governance evidence compaction", () => {
  it("hoists inline evidence, deduplicates identities, and preserves conflict recovery", () => {
    const normalized = normalizeGovernanceSubmission(
      {
        submission_id: "evidence-submission",
        namespace: "local",
        workflow_id: "workflow-1",
        node_id: "node-1",
        run_id: "run-1",
        event_kind: "selected_action",
        actor: { actor_id: "agent-1" },
        target: {
          action_type: "tool_call",
          action_name: "update_record",
          side_effect: true,
        },
        authority: { approvals: ["review-1"] },
        payload: {},
        evidence_events: [
          {
            eventId: "evidence-supported",
            kind: "claim_check",
            summary: "The account was initially verified.",
            status: "supported",
          },
          {
            eventId: "evidence-conflict",
            kind: "claim_check",
            summary: "A later source contradicted the account.",
            status: "contradicted",
            contradictionLinks: ["evidence-supported"],
          },
        ],
        state_slice: {
          evidence_events: [
            {
              eventId: "evidence-recovery",
              kind: "claim_check",
              summary: "A trusted source recovered the account claim.",
              status: "recovered",
              recoveryLinks: ["evidence-conflict"],
            },
          ],
        },
        provenance: {},
        metadata: {
          evidence_events: [
            {
              eventId: "low-value-observation",
              kind: "telemetry",
              summary: "An unrelated observation.",
              status: "observed",
            },
            {
              eventId: "evidence-supported",
              kind: "claim_check",
              summary: "The account was initially verified.",
              status: "supported",
            },
          ],
        },
      },
      () => new Date(FIXED_TIME).toISOString(),
      { maxEvents: 3 },
    );

    expect(
      normalized.evidence_events?.map((event) => event.eventId).sort(),
    ).toEqual([
      "evidence-conflict",
      "evidence-recovery",
      "evidence-supported",
    ]);
    expect(
      normalized.evidence_events?.find(
        (event) => event.eventId === "evidence-supported",
      )?.summary,
    ).toBe("The account was initially verified.");
    expect(normalized.metadata).not.toHaveProperty("evidence_events");
    expect(normalized.state_slice).not.toHaveProperty("evidence_events");

    const withoutIds = compactGovernanceEvidence([
      {
        kind: "observation",
        summary: "Deterministic identity",
        status: "observed",
      },
      {
        kind: "observation",
        summary: "Deterministic identity",
        status: "observed",
      },
    ]);
    expect(withoutIds).toHaveLength(1);
    expect(withoutIds[0]?.eventId).toMatch(/^evidence-[a-f0-9]{24}$/);
  });
});

describe("deterministic local governance evaluator", () => {
  it("allows safe reads and conservatively gates missing authority, facts, and evidence", () => {
    expect(
      evaluateGovernanceSubmissionDeterministically(
        submission("safe-read"),
      ).decision,
    ).toBe("allow");

    expect(
      evaluateGovernanceSubmissionDeterministically(
        submission("side-effect", {
          target: {
            action_type: "tool_call",
            action_name: "update_record",
            side_effect: true,
          },
        }),
      ),
    ).toMatchObject({
      decision: "escalate",
      policy_reason: "authority_required_for_side_effect",
    });

    expect(
      evaluateGovernanceSubmissionDeterministically(
        submission("missing-facts", {
          metadata: { missing_facts: ["verified account owner"] },
        }),
      ),
    ).toMatchObject({
      decision: "clarify",
      policy_reason: "required_facts_missing",
    });

    expect(
      evaluateGovernanceSubmissionDeterministically(
        submission("hard-deny", {
          authority: { constraints: ["deny:restricted_resource"] },
        }),
      ),
    ).toMatchObject({
      decision: "deny",
      policy_reason: "explicit_constraint_denied",
    });

    const conflictingEvidence: GovernanceEvidenceEvent[] = [
      {
        eventId: "failed-check",
        kind: "authority_check",
        summary: "Authority lookup failed.",
        status: "failed",
      },
    ];
    expect(
      evaluateGovernanceSubmissionDeterministically(
        submission("evidence-conflict", {
          target: {
            action_type: "tool_call",
            action_name: "update_record",
            side_effect: true,
          },
          authority: { approvals: ["review-1"] },
          evidence_events: conflictingEvidence,
        }),
      ),
    ).toMatchObject({
      decision: "escalate",
      policy_reason: "unresolved_evidence_conflict",
    });

    expect(
      evaluateGovernanceSubmissionDeterministically(
        submission("mixed-write-name", {
          target: {
            action_type: "tool_call",
            action_name: "read_then_delete_record",
            side_effect: false,
          },
        }),
      ),
    ).toMatchObject({
      decision: "escalate",
      policy_reason: "authority_required_for_side_effect",
    });

    expect(
      evaluateGovernanceSubmissionDeterministically(
        submission("unknown-action", {
          target: {
            action_type: "workflow",
            action_name: "reconcile",
          },
        }),
      ),
    ).toMatchObject({
      decision: "escalate",
      policy_reason: "side_effect_classification_required",
    });
  });

  it("accepts only chronological, claim-consistent recovery evidence", () => {
    const baseWrite = {
      target: {
        action_type: "tool_call",
        action_name: "update_record",
        side_effect: true,
      },
      authority: { approvals: ["review-1"] },
    } satisfies Partial<GovernanceSubmission>;
    const failed: GovernanceEvidenceEvent = {
      eventId: "authority-failed",
      timestamp: "2026-07-29T10:00:00Z",
      kind: "authority_check",
      claimGroup: "record_authority",
      summary: "Authority verification failed.",
      status: "failed",
    };

    const unrelated = evaluateGovernanceSubmissionDeterministically(
      submission("unrelated-recovery", {
        ...baseWrite,
        evidence_events: [
          failed,
          {
            eventId: "different-recovery",
            timestamp: "2026-07-29T10:01:00Z",
            kind: "authority_check",
            claimGroup: "different_claim",
            summary: "A different claim recovered.",
            status: "recovered",
            recoveryLinks: ["authority-failed"],
          },
        ],
      }),
    );
    const outOfOrder = evaluateGovernanceSubmissionDeterministically(
      submission("early-recovery", {
        ...baseWrite,
        evidence_events: [
          failed,
          {
            eventId: "early-recovery",
            timestamp: "2026-07-29T09:59:00Z",
            kind: "authority_check",
            claimGroup: "record_authority",
            summary: "An older result claimed recovery.",
            status: "recovered",
            recoveryLinks: ["authority-failed"],
          },
        ],
      }),
    );
    const valid = evaluateGovernanceSubmissionDeterministically(
      submission("valid-recovery", {
        ...baseWrite,
        evidence_events: [
          failed,
          {
            eventId: "valid-recovery",
            timestamp: "2026-07-29T10:01:00Z",
            kind: "authority_check",
            claimGroup: "record_authority",
            summary: "A later check recovered the same claim.",
            status: "recovered",
            recoveryLinks: ["authority-failed"],
          },
        ],
      }),
    );

    expect(unrelated).toMatchObject({
      decision: "escalate",
      policy_reason: "unresolved_evidence_conflict",
    });
    expect(outOfOrder).toMatchObject({
      decision: "escalate",
      policy_reason: "unresolved_evidence_conflict",
    });
    expect(valid.decision).toBe("allow");
  });

  it("rejects timezone-less and impossible governance timestamps", () => {
    expect(() =>
      normalizeGovernanceSubmission({
        ...submission("invalid-created-at"),
        created_at: "2026-07-29T10:00:00",
      }),
    ).toThrow(GovernanceValidationError);
    expect(() =>
      submission("invalid-evidence-time", {
        evidence_events: [
          {
            timestamp: "2026-02-30T10:00:00Z",
            kind: "verification",
            summary: "Impossible date.",
            status: "observed",
          },
        ],
      }),
    ).toThrow(GovernanceValidationError);
  });
});

describe("local governance persistence", () => {
  it("creates state only on initialize and makes no implicit outbound request", async () => {
    const rootDir = path.join(makeTempDirectory(), "state");
    const outbound = vi.fn(() => {
      throw new Error("Outbound access is disabled");
    });
    vi.stubGlobal("fetch", outbound);
    const client = new LocalGovernanceClient({
      rootDir,
      now: () => FIXED_TIME,
    });

    expect(fs.existsSync(rootDir)).toBe(false);
    await expect(
      client.submitSubmission({ submission: submission("before-init") }),
    ).rejects.toBeInstanceOf(GovernanceStoreNotInitializedError);
    await client.initialize();
    expect(fs.existsSync(rootDir)).toBe(true);

    const result = await client.submitSubmission({
      submission: submission("local-read"),
    });
    expect(result).toMatchObject({
      decision: { decision: "allow" },
      allow_execution: true,
    });
    expect(outbound).not.toHaveBeenCalled();
  });

  it("records edited execution, reflection, outcome, and replay data across restart", async () => {
    const rootDir = path.join(makeTempDirectory(), "state");
    let generatedId = 0;
    const client = new LocalGovernanceClient({
      rootDir,
      now: () => FIXED_TIME,
      idFactory: () => `generated-${++generatedId}`,
    });
    await client.initialize();
    const governedSubmission = submission("governed-write", {
      target: {
        action_type: "tool_call",
        action_name: "update_record",
        side_effect: true,
      },
      payload: { record_id: "record-1", owner: "unverified-owner" },
    });
    const initial = await client.submitSubmission({
      submission: governedSubmission,
    });
    expect(initial.decision.decision).toBe("escalate");
    await client.resolveReview({
      submission_id: governedSubmission.submission_id,
      action: "edit",
      reviewer: "local-reviewer",
      edited_payload: {
        record_id: "record-1",
        owner: "verified-owner",
      },
    });

    const execute = vi.fn(async (payload: GovernanceJsonObject) => ({
      appliedOwner: payload.owner,
    }));
    const executed = await executeGovernedAction({
      client,
      submission: governedSubmission,
      execute,
      now: () => new Date(FIXED_TIME).toISOString(),
    });
    expect(execute).toHaveBeenCalledWith({
      owner: "verified-owner",
      record_id: "record-1",
    });
    expect(executed.execution_record).toMatchObject({
      executed: true,
      final_payload: { owner: "verified-owner" },
    });

    await Promise.all(
      Array.from({ length: 6 }, (_, index) =>
        client.reportReflection({
          submission_id: governedSubmission.submission_id,
          reflection_id: `reflection-${index}`,
          run_id: governedSubmission.run_id,
          workflow_id: governedSubmission.workflow_id,
          node_id: governedSubmission.node_id,
          actor: governedSubmission.actor,
          status: index === 5 ? "completed" : "observed",
          provenance: {},
          created_at: new Date(FIXED_TIME + index + 1).toISOString(),
        }),
      ),
    );
    await client.reportOutcome({
      outcome_id: "outcome-1",
      submission_id: governedSubmission.submission_id,
      run_id: governedSubmission.run_id,
      workflow_id: governedSubmission.workflow_id,
      task_success: true,
      outcome_success: true,
      created_at: new Date(FIXED_TIME + 20).toISOString(),
    });

    const reopened = new FileGovernanceStore({ rootDir });
    await reopened.initialize();
    const joined = await reopened.getJoinedRecords();
    expect(joined).toHaveLength(1);
    expect(joined[0]).toMatchObject({
      human_resolution: { action: "edit" },
      execution_record: { executed: true, status: "succeeded" },
      outcome_record: { outcome_success: true },
    });
    expect(joined[0]?.reflection_records).toHaveLength(6);
    expect(await reopened.exportPreferenceExamples()).toMatchObject([
      { preference_kind: "edit" },
    ]);
    const replayTypes = (await reopened.exportReplayRows()).map(
      (row) => row.event_type,
    );
    expect(replayTypes).toContain("execution_record");
    expect(replayTypes).toContain("execution_reflection");
    expect(replayTypes).toContain("outcome_record");
  });

  it("fails closed after restart when an edited payload is intentionally hash-only", async () => {
    const rootDir = path.join(makeTempDirectory(), "state");
    const governedSubmission = submission("restart-edit", {
      target: {
        action_type: "tool_call",
        action_name: "update_record",
        side_effect: true,
      },
      payload: { record_id: "record-1", owner: "unverified-owner" },
    });
    const first = new LocalGovernanceClient({
      rootDir,
      now: () => FIXED_TIME,
    });
    await first.initialize();
    await first.submitSubmission({ submission: governedSubmission });
    await first.resolveReview({
      submission_id: governedSubmission.submission_id,
      action: "edit",
      reviewer: "local-reviewer",
      edited_payload: {
        record_id: "record-1",
        owner: "verified-owner",
      },
    });

    const reopened = new LocalGovernanceClient({
      rootDir,
      now: () => FIXED_TIME,
    });
    await reopened.initialize();
    const execute = vi.fn();
    const result = await executeGovernedAction({
      client: reopened,
      submission: governedSubmission,
      execute,
      now: () => new Date(FIXED_TIME).toISOString(),
    });

    expect(execute).not.toHaveBeenCalled();
    expect(result.human_resolution).toMatchObject({
      action: "edit",
      edited_payload: {
        redacted: true,
        sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
      },
    });
    expect(result.execution_record).toMatchObject({
      executed: false,
      status: "blocked",
    });

    const recoveredExecute = vi.fn(async (payload: GovernanceJsonObject) => ({
      owner: payload.owner,
    }));
    const recovered = await executeGovernedAction({
      client: reopened,
      submission: governedSubmission,
      resuppliedEditedPayload: {
        record_id: "record-1",
        owner: "verified-owner",
      },
      execute: recoveredExecute,
      now: () => new Date(FIXED_TIME).toISOString(),
    });
    expect(recoveredExecute).toHaveBeenCalledWith({
      owner: "verified-owner",
      record_id: "record-1",
    });
    expect(recovered.execution_record.executed).toBe(true);
  });

  it("repairs a truncated tail and rejects a complete invalid integrity envelope", async () => {
    const rootDir = path.join(makeTempDirectory(), "state");
    const store = new FileGovernanceStore({ rootDir });
    await store.initialize();
    await store.appendSubmission(submission("recovery-submission"));
    await store.appendDecision({
      decision_id: "decision-1",
      submission_id: "recovery-submission",
      decision: "allow",
      findings: [],
      created_at: new Date(FIXED_TIME).toISOString(),
    });
    fs.appendFileSync(store.paths.decisions, '{"incomplete":', "utf8");
    const before = fs.statSync(store.paths.decisions).size;

    const recovered = new FileGovernanceStore({ rootDir });
    await recovered.initialize();
    expect(fs.statSync(store.paths.decisions).size).toBeLessThan(before);
    await expect(
      recovered.getDecision("recovery-submission"),
    ).resolves.toMatchObject({ decision_id: "decision-1" });

    fs.appendFileSync(store.paths.outcomes, "{}\n", "utf8");
    const corrupted = new FileGovernanceStore({ rootDir });
    await expect(corrupted.initialize()).rejects.toBeInstanceOf(
      GovernanceStoreCorruptionError,
    );
  });

  it("fails closed on live truncation, path escape, and linked log files", async () => {
    const directory = makeTempDirectory();
    const rootDir = path.join(directory, "state");
    expect(
      () =>
        new FileGovernanceStore({
          rootDir,
          paths: { submissions: "../outside.ndjson" },
        }),
    ).toThrow("inside rootDir");

    const store = new FileGovernanceStore({ rootDir });
    await store.initialize();
    await store.appendSubmission(submission("live-truncation"));
    await expect(
      store.appendClarificationRequest({
        submission_id: "live-truncation",
        audience: "requester",
        status: "answered",
        missing_facts: [],
        questions: [],
        created_at: new Date(FIXED_TIME).toISOString(),
        answered_at: "2026-02-03T04:05:06",
      }),
    ).rejects.toBeInstanceOf(GovernanceValidationError);
    fs.appendFileSync(store.paths.submissions, '{"incomplete":', "utf8");
    await expect(store.readSubmissions()).rejects.toBeInstanceOf(
      GovernanceStoreCorruptionError,
    );

    const linkedRoot = path.join(directory, "linked-state");
    fs.mkdirSync(linkedRoot, { recursive: true });
    const outside = path.join(directory, "outside.ndjson");
    fs.writeFileSync(outside, "outside-must-remain-unchanged", "utf8");
    fs.symlinkSync(
      outside,
      path.join(linkedRoot, "submissions.ndjson"),
    );
    const linked = new FileGovernanceStore({ rootDir: linkedRoot });
    await expect(linked.initialize()).rejects.toBeInstanceOf(
      GovernanceValidationError,
    );
    expect(fs.readFileSync(outside, "utf8")).toBe(
      "outside-must-remain-unchanged",
    );
  });

  it("fails closed when an injected evaluator is unavailable", async () => {
    const rootDir = path.join(makeTempDirectory(), "state");
    const client = new LocalGovernanceClient({
      rootDir,
      now: () => FIXED_TIME,
      evaluator: {
        evaluate: async () => {
          throw new Error("Evaluator unavailable");
        },
      },
    });
    await client.initialize();
    const blocked = submission("evaluator-failure");
    await expect(
      client.submitSubmission({ submission: blocked }),
    ).rejects.toBeInstanceOf(GovernanceEvaluatorError);
    await expect(
      client.store.getSubmission(blocked.submission_id),
    ).resolves.toMatchObject({ submission_id: blocked.submission_id });
    await expect(
      client.store.getDecision(blocked.submission_id),
    ).resolves.toBeNull();
  });

  it("redacts evaluator failures and serializes decision creation across clients", async () => {
    const rootDir = path.join(makeTempDirectory(), "state");
    const firstEvaluator = vi.fn(async () => ({
      decision: "allow" as const,
      findings: [],
    }));
    const secondEvaluator = vi.fn(async () => ({
      decision: "deny" as const,
      policy_reason: "caller_denied",
      findings: [],
    }));
    const first = new LocalGovernanceClient({
      rootDir,
      now: () => FIXED_TIME,
      evaluator: { evaluate: firstEvaluator },
    });
    const second = new LocalGovernanceClient({
      rootDir,
      now: () => FIXED_TIME,
      evaluator: { evaluate: secondEvaluator },
    });
    await Promise.all([first.initialize(), second.initialize()]);
    const concurrent = submission("concurrent-decision");
    const [left, right] = await Promise.all([
      first.submitSubmission({ submission: concurrent }),
      second.submitSubmission({ submission: concurrent }),
    ]);
    expect(left.decision.decision).toBe(right.decision.decision);
    expect(left.decision.decision_id).toBe(right.decision.decision_id);
    expect(firstEvaluator.mock.calls.length + secondEvaluator.mock.calls.length)
      .toBe(1);
    await expect(first.store.readDecisions()).resolves.toHaveLength(1);

    const secret = "opaque-evaluator-failure-material";
    const failing = new LocalGovernanceClient({
      rootDir: path.join(makeTempDirectory(), "failure-state"),
      now: () => FIXED_TIME,
      evaluator: {
        evaluate: async () => {
          throw new Error(secret);
        },
      },
    });
    await failing.initialize();
    await expect(
      failing.submitSubmission({
        submission: submission("redacted-evaluator-error"),
      }),
    ).rejects.toSatisfy(
      (error: unknown) =>
        error instanceof GovernanceEvaluatorError &&
        !error.message.includes(secret) &&
        /\[sha256:[a-f0-9]{64}\]/.test(error.message),
    );
  });

  it("uses an explicitly injected evaluator and persists its local decision", async () => {
    const rootDir = path.join(makeTempDirectory(), "state");
    const evaluator = vi.fn(async () => ({
      decision: "deny" as const,
      policy_reason: "caller_local_rule",
      findings: [],
    }));
    const client = new LocalGovernanceClient({
      rootDir,
      now: () => FIXED_TIME,
      evaluator: { evaluate: evaluator },
    });
    await client.initialize();
    const result = await client.submitSubmission({
      submission: submission("custom-evaluator"),
    });

    expect(evaluator).toHaveBeenCalledTimes(1);
    expect(result).toMatchObject({
      decision: {
        decision: "deny",
        basis: "custom_evaluator",
        policy_reason: "caller_local_rule",
      },
      allow_execution: false,
    });
    await expect(
      client.store.getDecision("custom-evaluator"),
    ).resolves.toMatchObject({ decision: "deny" });
  });

  it("never lets a custom evaluator loosen deterministic governance", async () => {
    const rootDir = path.join(makeTempDirectory(), "state");
    const evaluator = vi.fn(async () => ({
      decision: "allow" as const,
      policy_reason: "caller_would_allow",
      findings: [],
    }));
    const client = new LocalGovernanceClient({
      rootDir,
      now: () => FIXED_TIME,
      evaluator: { evaluate: evaluator },
    });
    await client.initialize();
    const escalated = await client.submitSubmission({
      submission: submission("deterministic-escalation", {
        target: {
          action_type: "tool_call",
          action_name: "delete_record",
          side_effect: true,
        },
      }),
    });
    const denied = await client.submitSubmission({
      submission: submission("deterministic-deny", {
        authority: { constraints: ["deny:restricted"] },
      }),
    });

    expect(escalated.decision).toMatchObject({
      decision: "escalate",
      basis: "deterministic_guard",
      policy_reason: "authority_required_for_side_effect",
    });
    expect(denied.decision).toMatchObject({
      decision: "deny",
      basis: "deterministic_guard",
    });
    expect(evaluator).toHaveBeenCalledTimes(1);
  });

  it("hashes payloads, results, and errors before persistence", async () => {
    const rootDir = path.join(makeTempDirectory(), "state");
    const client = new LocalGovernanceClient({
      rootDir,
      now: () => FIXED_TIME,
    });
    await client.initialize();
    const rawPayload = "payload-value-that-must-not-persist";
    const rawResult = "result-value-that-must-not-persist";
    const rawError = "error-value-that-must-not-persist";
    const rawCredential = ["sk", "super-secret-value"].join("-");
    const governed = submission("secret-persistence", {
      payload: {
        record_id: "record-1",
        ordinary_field: rawPayload,
        api_key: rawCredential,
      },
    });
    const submitted = await client.submitSubmission({ submission: governed });
    expect(submitted.effective_payload.ordinary_field).toBe(rawPayload);
    await client.reportExecution({
      submission_id: governed.submission_id,
      executed: false,
      final_payload: governed.payload,
      status: "failed",
      result_summary: rawResult,
      error: rawError,
      created_at: new Date(FIXED_TIME).toISOString(),
    });

    const persisted = Object.values(
      (client.store as FileGovernanceStore).paths,
    )
      .map((filePath) => fs.readFileSync(filePath, "utf8"))
      .join("\n");
    expect(persisted).not.toContain(rawPayload);
    expect(persisted).not.toContain(rawResult);
    expect(persisted).not.toContain(rawError);
    expect(persisted).not.toContain(rawCredential);
    expect(persisted).toContain("[REDACTED sha256:");

    const reopened = new FileGovernanceStore({ rootDir });
    await reopened.initialize();
    await expect(
      reopened.getSubmission(governed.submission_id),
    ).resolves.toMatchObject({
      payload: {
        redacted: true,
        sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
      },
    });
  });

  it("hashes opaque prose, signed URLs, findings, and review feedback", async () => {
    const rootDir = path.join(makeTempDirectory(), "state");
    const opaque = "opaque-material-7f1c2a9b";
    const signedUrl =
      "https://files.example.test/report?signature=opaque-url-value";
    const client = new LocalGovernanceClient({
      rootDir,
      now: () => FIXED_TIME,
      evaluator: {
        evaluate: async () => ({
          decision: "escalate" as const,
          policy_reason: opaque,
          findings: [
            {
              code: "custom_finding",
              message: `finding-${opaque}`,
              metadata: { detail: opaque },
            },
          ],
        }),
      },
    });
    await client.initialize();
    const governed = submission("opaque-persistence", {
      target: {
        action_type: "tool_call",
        action_name: "update_record",
        side_effect: true,
        resource_id: signedUrl,
      },
      authority: { constraints: [opaque] },
      payload: { value: opaque },
      evidence_events: [
        {
          eventId: "opaque-evidence",
          kind: "observation",
          summary: `summary-${opaque}`,
          status: "observed",
        },
      ],
      metadata: { unstructured: opaque },
    });
    await client.submitSubmission({ submission: governed });
    await client.resolveReview({
      submission_id: governed.submission_id,
      action: "approve",
      reviewer: opaque,
      feedback: `feedback-${opaque}`,
    });
    await client.reportExecution({
      submission_id: governed.submission_id,
      executed: false,
      status: "blocked",
      output_reference: signedUrl,
      metadata: { note: opaque },
      created_at: new Date(FIXED_TIME).toISOString(),
    });

    const persisted = Object.values(
      (client.store as FileGovernanceStore).paths,
    )
      .map((filePath) => fs.readFileSync(filePath, "utf8"))
      .join("\n");
    expect(persisted).not.toContain(opaque);
    expect(persisted).not.toContain(signedUrl);
    expect(persisted).toMatch(/\[REDACTED sha256:[a-f0-9]{64}\]/);
  });

  it("serializes cross-instance writes and detects reordered log rows", async () => {
    const rootDir = path.join(makeTempDirectory(), "state");
    const first = new FileGovernanceStore({ rootDir });
    const second = new FileGovernanceStore({ rootDir });
    await Promise.all([first.initialize(), second.initialize()]);
    await Promise.all(
      Array.from({ length: 10 }, (_, index) =>
        (index % 2 === 0 ? first : second).appendSubmission(
          submission(`concurrent-${index}`),
        ),
      ),
    );
    expect(await first.readSubmissions()).toHaveLength(10);

    const lines = fs
      .readFileSync(first.paths.submissions, "utf8")
      .trimEnd()
      .split("\n");
    fs.writeFileSync(
      first.paths.submissions,
      `${[lines[1], lines[0], ...lines.slice(2)].join("\n")}\n`,
      "utf8",
    );
    const corrupted = new FileGovernanceStore({ rootDir });
    await expect(corrupted.initialize()).rejects.toBeInstanceOf(
      GovernanceStoreCorruptionError,
    );
  });
});
