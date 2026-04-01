import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import { FileGovernanceStore } from "../src/governance";
import {
  executeGovernedAction,
  normalizeGovernanceSubmission,
} from "../src/governance/client";
import type { GovernanceClient } from "../src/governance/client";

const tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sec0-governance-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    fs.rmSync(tempDirs.pop()!, { force: true, recursive: true });
  }
});

describe("governance store", () => {
  it("hoists inline evidence events from submission context into the canonical payload", () => {
    const submission = normalizeGovernanceSubmission({
      tenant_id: "tenant-a",
      workflow_id: "retail",
      node_id: "agent-1",
      run_id: "run-1",
      trace_id: "trace-1",
      event_kind: "selected_action",
      actor: { actor_id: "agent-1", actor_type: "agent" },
      target: { action_type: "tool_call", action_name: "modify_pending_order_payment" },
      authority: {},
      payload: { payment_method_id: "pm_old" },
      state_slice: {
        evidence_events: [
          {
            kind: "claim_verification",
            summary: "State slice verified the acting subject.",
            claim: "The acting subject has been verified.",
            status: "supported",
            entityRefs: [],
            relatedEventIds: [],
            contradictionLinks: [],
            recoveryLinks: [],
          },
        ],
      },
      provenance: {
        metadata: {
          evidence_events: [
            {
              kind: "runtime_error",
              summary: "An earlier lookup failed.",
              claim: "A prior lookup attempt failed.",
              status: "superseded",
              entityRefs: [],
              relatedEventIds: [],
              contradictionLinks: [],
              recoveryLinks: [],
            },
          ],
        },
      },
      metadata: {
        evidence_events: [
          {
            kind: "user_confirmation",
            summary: "The user explicitly confirmed the requested change.",
            claim: "The user explicitly confirmed the requested change.",
            status: "supported",
            entityRefs: [],
            relatedEventIds: [],
            contradictionLinks: [],
            recoveryLinks: [],
          },
        ],
      },
    });

    expect(submission.evidence_events).toHaveLength(3);
    expect(submission.evidence_events?.map((event) => event.kind).sort()).toEqual([
      "claim_verification",
      "runtime_error",
      "user_confirmation",
    ]);
  });

  it("exports edited, approved, and rejected preference examples from normalized records", () => {
    const store = new FileGovernanceStore({ rootDir: makeTempDir() });
    const baseSubmission = normalizeGovernanceSubmission({
      tenant_id: "tenant-a",
      workflow_id: "retail",
      node_id: "agent-1",
      run_id: "run-1",
      trace_id: "trace-1",
      event_kind: "selected_action",
      actor: { actor_id: "agent-1", actor_type: "agent" },
      target: { action_type: "tool_call", action_name: "modify_pending_order_payment" },
      authority: {},
      payload: { order_id: "#1", payment_method_id: "pm_old" },
      state_slice: { explicit_user_confirmation: false },
      provenance: {},
      metadata: {},
    });

    const approvedSubmission = { ...baseSubmission, submission_id: "submission-approve" };
    const rejectedSubmission = { ...baseSubmission, submission_id: "submission-reject" };
    const editedSubmission = { ...baseSubmission, submission_id: "submission-edit" };

    for (const submission of [approvedSubmission, rejectedSubmission, editedSubmission]) {
      store.appendSubmission(submission);
      store.appendDecision({
        submission_id: submission.submission_id,
        decision: "escalate",
        findings: [],
        policy_reason: "requires_review",
        created_at: submission.created_at,
      });
    }

    store.appendResolution({
      submission_id: approvedSubmission.submission_id,
      action: "approve",
      reviewer: "alice",
      created_at: approvedSubmission.created_at,
    });
    store.appendResolution({
      submission_id: rejectedSubmission.submission_id,
      action: "reject",
      reviewer: "alice",
      feedback: "missing consent",
      created_at: rejectedSubmission.created_at,
    });
    store.appendResolution({
      submission_id: editedSubmission.submission_id,
      action: "edit",
      reviewer: "alice",
      edited_payload: { order_id: "#1", payment_method_id: "pm_verified" },
      created_at: editedSubmission.created_at,
    });

    const examples = store.exportPreferenceExamples();
    expect(examples).toHaveLength(3);
    expect(examples.map((example) => example.preference_kind).sort()).toEqual([
      "approve",
      "edit",
      "reject",
    ]);

    const editedExample = examples.find((example) => example.preference_kind === "edit");
    expect(editedExample?.chosen_completion).toMatchObject({
      mode: "execute",
      payload: { payment_method_id: "pm_verified" },
    });
    expect(editedExample?.rejected_completion).toMatchObject({
      mode: "execute",
      payload: { payment_method_id: "pm_old" },
    });
  });

  it("joins reflection records and exports them as replay events", () => {
    const store = new FileGovernanceStore({ rootDir: makeTempDir() });
    const submission = normalizeGovernanceSubmission({
      submission_id: "submission-reflection",
      tenant_id: "tenant-a",
      workflow_id: "retail",
      node_id: "agent-1",
      run_id: "run-1",
      trace_id: "trace-1",
      event_kind: "selected_action",
      actor: { actor_id: "agent-1", actor_type: "agent" },
      target: { action_type: "tool_call", action_name: "modify_pending_order_payment" },
      authority: {},
      payload: { payment_method_id: "pm_old" },
      state_slice: {},
      provenance: {},
      metadata: {},
    });

    store.appendSubmission(submission);
    store.appendReflection({
      submission_id: submission.submission_id,
      run_id: submission.run_id,
      workflow_id: submission.workflow_id,
      node_id: submission.node_id,
      trace_id: submission.trace_id,
      actor: { actor_id: "agent-1", actor_type: "agent" },
      status: "retrying",
      retry_reason: "missing account confirmation",
      missing_facts: ["confirmed billing account"],
      provenance: { audit_refs: ["audit://1"] },
      created_at: submission.created_at,
    });

    const joined = store.getJoinedRecords();
    expect(joined[0]?.reflection_records).toHaveLength(1);
    expect(joined[0]?.reflection_records?.[0]).toMatchObject({
      event_kind: "execution_reflection",
      retry_reason: "missing account confirmation",
    });

    const replayRows = store.exportReplayRows();
    expect(replayRows.some((row) => row.event_type === "execution_reflection")).toBe(true);
  });
});

describe("executeGovernedAction", () => {
  it("waits for a human edit and reports the edited execution", async () => {
    const submitProposal = vi.fn(async () => ({
      submission: normalizeGovernanceSubmission({
        submission_id: "submission-1",
        tenant_id: "tenant-a",
        workflow_id: "retail",
        node_id: "agent-1",
        run_id: "run-1",
        trace_id: "trace-1",
        event_kind: "selected_action",
        actor: { actor_id: "agent-1", actor_type: "agent" },
        target: { action_type: "tool_call", action_name: "modify_pending_order_payment" },
        authority: {},
        payload: { payment_method_id: "pm_old" },
        state_slice: {},
        provenance: {},
        metadata: {},
      }),
      decision: {
        submission_id: "submission-1",
        decision: "escalate" as const,
        findings: [],
        policy_reason: "requires_review",
        created_at: new Date().toISOString(),
      },
      human_resolution: null,
      allow_execution: false,
      effective_payload: { payment_method_id: "pm_old" },
    }));
    const waitForHumanResolution = vi.fn(async () => ({
      resolution_id: "resolution-1",
      submission_id: "submission-1",
      action: "edit" as const,
      reviewer: "alice",
      edited_payload: { payment_method_id: "pm_verified" },
      created_at: new Date().toISOString(),
    }));
    const reportExecution = vi.fn(async (execution) => execution);

    const client: GovernanceClient = {
      submitSubmission: submitProposal,
      listPendingReviews: vi.fn(),
      getHumanResolution: vi.fn(),
      waitForHumanResolution,
      resolveReview: vi.fn(),
      getClarificationRequest: vi.fn(),
      answerClarification: vi.fn(),
      reportExecution,
      reportReflection: vi.fn(),
      reportOutcome: vi.fn(),
      createImprovementProposal: vi.fn(),
      reportPromotionEvaluation: vi.fn(),
      exportPreferenceExamples: vi.fn(),
      exportRewardOutcomeRows: vi.fn(),
      exportReplayRows: vi.fn(),
      createAutoresearchJob: vi.fn(),
      listAutoresearchJobs: vi.fn(),
      getAutoresearchJob: vi.fn(),
      promoteAutoresearchJob: vi.fn(),
      rollbackAutoresearchJob: vi.fn(),
      getRuntimeConfig: vi.fn(),
    };

    const execute = vi.fn(async (args: { payment_method_id: string }) => ({
      applied_payment_method_id: args.payment_method_id,
    }));

    const result = await executeGovernedAction({
      client,
      submission: {
        submission_id: "submission-1",
        tenant_id: "tenant-a",
        workflow_id: "retail",
        node_id: "agent-1",
        run_id: "run-1",
        trace_id: "trace-1",
        event_kind: "selected_action",
        actor: { actor_id: "agent-1", actor_type: "agent" },
        target: { action_type: "tool_call", action_name: "modify_pending_order_payment" },
        authority: {},
        payload: { payment_method_id: "pm_old" },
        state_slice: {},
        provenance: {},
        metadata: {},
        created_at: new Date().toISOString(),
      },
      waitForResolution: true,
      execute,
    });

    expect(waitForHumanResolution).toHaveBeenCalledWith("submission-1", undefined);
    expect(execute).toHaveBeenCalledWith({ payment_method_id: "pm_verified" });
    expect(reportExecution).toHaveBeenCalledWith(
      expect.objectContaining({
        submission_id: "submission-1",
        executed: true,
        final_payload: { payment_method_id: "pm_verified" },
      }),
    );
    expect(result.value).toEqual({ applied_payment_method_id: "pm_verified" });
  });
});
