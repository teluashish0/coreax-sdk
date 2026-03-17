import { describe, expect, it, vi } from "vitest";
import { runContextualEvaluation } from "../src/middleware/contextualEvaluatorFlow";

describe("contextualEvaluatorFlow", () => {
  it("appends contextual findings and schedules hybrid follow-up evaluations", async () => {
    const schedule = vi.fn();
    const addAttrs = vi.fn();
    const result = await runContextualEvaluation({
      manager: {
        enabled: true,
        source: "control-plane",
        mode: "hybrid",
        evaluate: vi.fn(async () => ({
          output: {
            decision: "deny",
            confidence: 0.93,
            principles: ["least-privilege"],
          },
          finding: {
            source: "evaluator",
            code: "contextual_evaluator",
            severity: "high",
            message: "Denied by evaluator",
            confidence: 0.93,
            principles: ["least-privilege"],
            fingerprint: "eval-fp-1",
            summary: "Denied by evaluator",
            reasoning: "Reasoning",
            snapshot: { input: { kind: "input" }, output: { kind: "output" } },
          },
        })),
        schedule,
      } as any,
      tenant: "tenant-a",
      server: { name: "demo", version: "1.0.0" },
      tool: "write@1.0",
      ctx: { args: { ok: true } },
      policy: { default_retention: "default", enforcement: { deny_on: ["contextual_evaluator_denied"] } } as any,
      incomingAgentState: {} as any,
      violation: "agent_guard_failed",
      findings: [
        {
          code: "agent_policy_violation",
          message: "Blocked earlier",
          tags: [],
        },
      ] as any,
      content: { ok: true },
      addAttrs,
      includeContextualFindingInAgentFindings: true,
    });

    expect(result.contextualViolation).toBe("contextual_evaluator_denied");
    expect(result.contextualAgentFindings).toHaveLength(1);
    expect(result.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: "agent_policy_violation" }),
        expect.objectContaining({ code: "contextual_evaluator", fingerprint: "eval-fp-1" }),
      ]),
    );
    expect(schedule).toHaveBeenCalledTimes(1);
    expect(addAttrs).toHaveBeenCalledWith(
      expect.objectContaining({
        "evaluator.source": "control-plane",
        "evaluator.mode": "hybrid",
        "evaluator.eligible": true,
      }),
    );
  });
});
