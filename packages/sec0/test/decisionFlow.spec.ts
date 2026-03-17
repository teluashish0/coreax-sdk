import { describe, expect, it, vi } from "vitest";
import {
  annotateApprovedFindings,
  createDecisionFlow,
} from "../src/middleware/decisionFlow";

describe("decisionFlow", () => {
  it("scrubs approval tokens from headers and args before downstream processing", async () => {
    const ctx = {
      args: { approvalToken: "arg-token", keep: true },
      headers: {
        "x-sec0-approval-token": "header-token",
        authorization: "Bearer abc",
      },
    };
    const verify = vi.fn(async () => ({ valid: true, approval: { id: "apr-1" } }));
    const flow = createDecisionFlow({
      ctx,
      tenant: "tenant-a",
      server: { name: "demo", version: "1.0.0" },
      tool: "echo@1.0",
      nodeId: "node-1",
      agentRunId: "run-1",
      approvalVerifier: { verify },
      runtimeInvoker: { evaluate: vi.fn(async () => ({ decision: "allow", shouldDeny: false } as any)) },
      getPolicyDenyOn: () => [],
    });

    await flow.verifyApprovalIfAny();

    expect(verify).toHaveBeenCalledWith({
      token: "header-token",
      toolRef: "mcp://demo/echo@1.0",
      nodeId: "node-1",
      agentRef: "run-1",
    });
    expect(ctx.headers).not.toHaveProperty("x-sec0-approval-token");
    expect(ctx.args).not.toHaveProperty("approvalToken");
    expect(ctx.args.keep).toBe(true);
  });

  it("memoizes approval verification and runtime deny decisions per invocation", async () => {
    const verify = vi.fn(async () => ({ valid: true, approval: { id: "apr-1" } }));
    const evaluate = vi.fn(async () => ({ decision: "deny", shouldDeny: true } as any));
    const flow = createDecisionFlow({
      ctx: { args: {}, headers: { "x-sec0-approval": "approved" } },
      tenant: () => "tenant-b",
      server: { name: "demo", version: "1.0.0" },
      tool: "write@1.0",
      nodeId: "node-2",
      agentRunId: "run-2",
      approvalVerifier: { verify },
      runtimeInvoker: { evaluate },
      getPolicyDenyOn: () => ["agent_guard_failed"],
    });

    expect(await flow.verifyApprovalIfAny()).toEqual({
      valid: true,
      approval: { id: "apr-1" },
    });
    expect(await flow.verifyApprovalIfAny()).toEqual({
      valid: true,
      approval: { id: "apr-1" },
    });
    expect(verify).toHaveBeenCalledTimes(1);

    expect(await flow.shouldRuntimeDeny(["agent_guard_failed"], { requestIdSuffix: "a" })).toBe(true);
    expect(await flow.shouldRuntimeDeny(["agent_guard_failed"], { requestIdSuffix: "a" })).toBe(true);
    expect(evaluate).toHaveBeenCalledTimes(1);
  });

  it("rewrites approved agent-policy findings while leaving unrelated findings intact", () => {
    const findings = [
      {
        code: "agent_policy_violation",
        message: "Denied by policy",
        evidence: "original",
        tags: ["existing"],
      },
      {
        code: "other",
        message: "Other finding",
      },
    ] as any;

    const approved = annotateApprovedFindings(findings, {
      valid: true,
      approval: { id: "apr-7", reason: "human override" },
    });

    expect(approved?.[0].message).toContain("(approved)");
    expect(approved?.[0].evidence).toContain("approval_id=apr-7");
    expect(approved?.[0].evidence).toContain("reason=human override");
    expect(approved?.[0].tags).toContain("approval_id:apr-7");
    expect(approved?.[1]).toEqual(findings[1]);
  });
});
