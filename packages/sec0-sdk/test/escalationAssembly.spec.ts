import { describe, expect, it, vi } from "vitest";
import { createEscalationFromState } from "../src/middleware/escalationAssembly";
import { createMiddlewareInvocationState } from "../src/middleware/invocationState";

describe("escalationAssembly", () => {
  it("prefers evaluator escalation metadata for evaluator-driven denials", async () => {
    const reporter = {
      create: vi.fn(async (input) => ({ id: "esc-1", status: "pending", input } as any)),
    };
    const state = createMiddlewareInvocationState();
    state.decision = "deny";
    state.error = { violation: "contextual_evaluator_denied" } as any;
    state.contextualEvaluatorViolation = "contextual_evaluator_denied";
    state.contextualEvaluatorFinding = {
      severity: "high",
      fingerprint: "fp-1",
      confidence: 0.91,
      principles: ["principle-a"],
      summary: "Evaluator summary",
      reasoning: "Evaluator reasoning",
      snapshot: { kind: "snapshot" },
    };
    state.riskTags = ["contextual_evaluator_denied"];

    const result = await createEscalationFromState({
      state,
      policy: {
        default_retention: "default",
        enforcement: { deny_on: ["contextual_evaluator_denied"] },
        security: { side_effects: { approve_high_risk: true } },
      } as any,
      escalationReporter: reporter as any,
      tenant: "tenant-a",
      server: { name: "demo", version: "1.0.0" },
      tool: "write@1.0",
      ctx: { args: { ok: true } },
      nodeId: "node-1",
      agentRef: "run-1",
      traceId: "trace-1",
      spanId: "span-1",
    });

    expect(result.escalationResult).toEqual(expect.objectContaining({ id: "esc-1", status: "pending" }));
    expect(reporter.create).toHaveBeenCalledWith(
      expect.objectContaining({
        findingSource: "evaluator",
        evaluatorSnapshot: { kind: "snapshot" },
      }),
    );
  });
});
