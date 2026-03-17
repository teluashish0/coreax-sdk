import type { ApprovalVerifier, ApprovalVerificationResult, RuntimeInvoker } from "../core/contracts";
import { mapRuntimeDecisionRequest, mapRuntimeDecisionToLegacy } from "../runtime-adapter";
import type { AgentGuardFinding } from "./agentGuard";
import { normalizePolicyReasonToken, readHeaderCaseInsensitive, toolUri } from "./tooling";

export type ApprovalResolution = {
  valid: boolean;
  approval?: any;
} | null;

export type DecisionFlowContext = {
  ctx: { args: any; idempotencyKey?: string | null; headers?: Record<string, string> };
  tenant?: string | (() => string | undefined);
  server: { name: string; version: string };
  tool: string;
  nodeId?: string;
  agentRunId?: string;
  approvalVerifier: ApprovalVerifier;
  runtimeInvoker: RuntimeInvoker;
  getPolicyDenyOn: () => string[];
};

export function extractApprovalToken(
  ctx: DecisionFlowContext["ctx"],
  readHeader: typeof readHeaderCaseInsensitive = readHeaderCaseInsensitive,
): string | undefined {
  const headerToken =
    readHeader(ctx.headers as any, "x-sec0-approval-token") ||
    readHeader(ctx.headers as any, "x-sec0-approval");
  const args: any = ctx?.args;
  const argToken =
    args && typeof args === "object"
      ? typeof args.__sec0_approval_token === "string"
        ? args.__sec0_approval_token
        : typeof args.approval_token === "string"
          ? args.approval_token
          : typeof args.approvalToken === "string"
            ? args.approvalToken
            : undefined
      : undefined;
  const normalized = typeof headerToken === "string" && headerToken.trim()
    ? headerToken.trim()
    : typeof argToken === "string" && argToken.trim()
      ? argToken.trim()
      : "";
  return normalized || undefined;
}

export function scrubApprovalToken(ctx: DecisionFlowContext["ctx"]): void {
  try {
    if (ctx.headers) {
      delete (ctx.headers as any)["x-sec0-approval-token"];
      delete (ctx.headers as any)["X-Sec0-Approval-Token"];
      delete (ctx.headers as any)["x-sec0-approval"];
      delete (ctx.headers as any)["X-Sec0-Approval"];
    }
  } catch {}
  try {
    const args: any = ctx?.args;
    if (args && typeof args === "object") {
      delete args.__sec0_approval_token;
      delete args.approval_token;
      delete args.approvalToken;
    }
  } catch {}
}

export function annotateApprovedFindings(
  findings: AgentGuardFinding[] | undefined,
  approval: ApprovalVerificationResult | null | undefined,
): AgentGuardFinding[] | undefined {
  if (!Array.isArray(findings) || !findings.length || !approval?.valid) {
    return findings;
  }
  try {
    const approvalId = typeof approval?.approval === "object" && approval.approval && typeof (approval.approval as any).id === "string"
      ? (approval.approval as any).id
      : "";
    const approvalReason = typeof approval?.approval === "object" && approval.approval && typeof (approval.approval as any).reason === "string"
      ? (approval.approval as any).reason
      : "";
    const suffix = approvalId ? `approved=true approval_id=${approvalId}` : "approved=true";
    return findings.map((finding) => {
      if (!finding || finding.code !== "agent_policy_violation") return finding;
      const msg =
        typeof finding.message === "string" && finding.message.includes("approved")
          ? finding.message
          : `${finding.message} (approved)`;
      const evidenceBase = typeof finding.evidence === "string" && finding.evidence.trim() ? finding.evidence.trim() : "";
      const evidence = [evidenceBase, suffix, approvalReason ? `reason=${String(approvalReason).slice(0, 160)}` : ""]
        .filter(Boolean)
        .join("; ")
        .slice(0, 480);
      const tags = Array.isArray((finding as any).tags) ? [...((finding as any).tags as string[])] : [];
      if (approvalId) tags.push(`approval_id:${approvalId}`);
      return { ...finding, message: msg, evidence, tags };
    });
  } catch {
    return findings;
  }
}

export function createDecisionFlow(context: DecisionFlowContext) {
  const approvalTokenRaw = extractApprovalToken(context.ctx);
  if (approvalTokenRaw) {
    scrubApprovalToken(context.ctx);
  }

  let approvalChecked: ApprovalResolution = null;
  const runtimeDecisionCache: Map<string, boolean> = new Map();

  const verifyApprovalIfAny = async (): Promise<ApprovalResolution> => {
    if (!approvalTokenRaw) return null;
    if (approvalChecked) return approvalChecked;
    try {
      const output = await context.approvalVerifier.verify({
        token: approvalTokenRaw,
        toolRef: toolUri(context.server.name, context.tool),
        nodeId: context.nodeId || undefined,
        agentRef: context.agentRunId || undefined,
      });
      approvalChecked = output ? { valid: output.valid, approval: output.approval } : null;
      return approvalChecked;
    } catch {
      return null;
    }
  };

  const shouldRuntimeDeny = async (
    reasons: string[],
    opts?: { requestIdSuffix?: string; strategy?: "deny_on_match" | "deny_on_any"; forceDeny?: boolean },
  ): Promise<boolean> => {
    const normalizedReasons = reasons.map((entry) => String(entry ?? "").trim()).filter(Boolean);
    if (!normalizedReasons.length) return false;
    const denyOn = context.getPolicyDenyOn();
    const strategy = opts?.strategy ?? "deny_on_match";
    const forceDeny = opts?.forceDeny === true;
    const cacheKey = `${strategy}|${forceDeny ? "1" : "0"}|${denyOn.join(",")}|${normalizedReasons.join(",")}`;
    const cached = runtimeDecisionCache.get(cacheKey);
    if (typeof cached === "boolean") return cached;
    const runtimeDecision = await context.runtimeInvoker.evaluate(
      mapRuntimeDecisionRequest({
        executionLayer: "middleware",
        tenant: typeof context.tenant === "function" ? context.tenant() : context.tenant,
        server: context.server.name,
        tool: context.tool,
        nodeId: context.nodeId,
        runId: context.agentRunId,
        mode: "enforce",
        strategy,
        denyOn,
        forceDeny,
        reasons: normalizedReasons,
        requestId: `${toolUri(context.server.name, context.tool)}:${opts?.requestIdSuffix || "runtime"}`,
      }),
    );
    const shouldDeny = mapRuntimeDecisionToLegacy(runtimeDecision).shouldDeny;
    runtimeDecisionCache.set(cacheKey, shouldDeny);
    return shouldDeny;
  };

  const policyDeniesReason = (reason: string): boolean => {
    if (!reason) return false;
    return context.getPolicyDenyOn().includes(normalizePolicyReasonToken(reason));
  };

  return {
    approvalTokenRaw,
    verifyApprovalIfAny,
    shouldRuntimeDeny,
    policyDeniesReason,
  };
}
