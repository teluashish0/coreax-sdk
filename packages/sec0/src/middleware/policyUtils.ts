import type { ContextualEvaluatorFinding } from "../evaluator";
import type { PolicyObject } from "../policy";
import type { AgentGuardFinding } from "./agentGuard";
import { normalizePolicyReasonArray, normalizePolicyReasonToken } from "./tooling";

export type ResolvedHumanEscalationConfig = {
  approvalStrategy?: "auto_allow" | "single_approver" | "human_quorum";
  timeoutAction?: "auto_approve" | "auto_reject";
  minApprovals?: number;
  minRejections?: number;
  requiredRoles?: string[];
  vetoRoles?: string[];
  approvalSetId?: string;
};

export type ResolvedEscalationPolicy = {
  enabled: boolean;
  escalateOn: Set<string>;
  human: ResolvedHumanEscalationConfig;
};

function asOptionalPositiveInt(value: unknown): number | undefined {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return undefined;
  const floored = Math.floor(parsed);
  return floored > 0 ? floored : undefined;
}

function asOptionalStringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const out: string[] = [];
  for (const entry of value) {
    const normalized = String(entry || "").trim();
    if (!normalized) continue;
    out.push(normalized);
  }
  return out.length ? Array.from(new Set(out)) : undefined;
}

export function normalizePolicyObject(input: any): any {
  const obj: any = input && typeof input === "object" ? input : {};
  const enforcement: any = obj.enforcement && typeof obj.enforcement === "object" ? obj.enforcement : {};
  if (!Array.isArray(enforcement.deny_on)) enforcement.deny_on = [];
  if (enforcement.escalate_on !== undefined && !Array.isArray(enforcement.escalate_on)) {
    enforcement.escalate_on = [];
  }
  obj.enforcement = enforcement;
  return obj;
}

export function resolveEscalationPolicy(policyObj: PolicyObject): ResolvedEscalationPolicy {
  const security = (policyObj as any)?.security;
  const sideEffects = security && typeof security === "object" ? (security as any).side_effects : undefined;
  const approveHighRisk = sideEffects?.approve_high_risk === true;
  const denyOn = normalizePolicyReasonArray((policyObj as any)?.enforcement?.deny_on);
  const escalateOnRaw = (policyObj as any)?.enforcement?.escalate_on;
  const escalateOn = Array.isArray(escalateOnRaw) ? normalizePolicyReasonArray(escalateOnRaw) : denyOn;
  const humanRaw =
    sideEffects && typeof sideEffects === "object"
      ? ((sideEffects as any).human_escalation && typeof (sideEffects as any).human_escalation === "object"
          ? (sideEffects as any).human_escalation
          : (sideEffects as any).humanEscalation && typeof (sideEffects as any).humanEscalation === "object"
            ? (sideEffects as any).humanEscalation
            : undefined)
      : undefined;
  const strategyRaw = String(humanRaw?.approval_strategy || "").trim().toLowerCase();
  const approvalStrategy =
    strategyRaw === "auto_allow" || strategyRaw === "single_approver" || strategyRaw === "human_quorum"
      ? (strategyRaw as ResolvedHumanEscalationConfig["approvalStrategy"])
      : undefined;
  const timeoutRaw = String(humanRaw?.timeout_action || "").trim().toLowerCase();
  const timeoutAction =
    timeoutRaw === "auto_approve" || timeoutRaw === "auto_reject"
      ? (timeoutRaw as ResolvedHumanEscalationConfig["timeoutAction"])
      : undefined;
  const human: ResolvedHumanEscalationConfig = {
    ...(approvalStrategy ? { approvalStrategy } : {}),
    ...(timeoutAction ? { timeoutAction } : {}),
    ...(asOptionalPositiveInt(humanRaw?.min_approvals) ? { minApprovals: asOptionalPositiveInt(humanRaw?.min_approvals)! } : {}),
    ...(asOptionalPositiveInt(humanRaw?.min_rejections) ? { minRejections: asOptionalPositiveInt(humanRaw?.min_rejections)! } : {}),
    ...(asOptionalStringArray(humanRaw?.required_roles) ? { requiredRoles: asOptionalStringArray(humanRaw?.required_roles)! } : {}),
    ...(asOptionalStringArray(humanRaw?.veto_roles) ? { vetoRoles: asOptionalStringArray(humanRaw?.veto_roles)! } : {}),
    ...(typeof humanRaw?.approval_set_id === "string" && humanRaw.approval_set_id.trim()
      ? { approvalSetId: humanRaw.approval_set_id.trim() }
      : {}),
  };
  return {
    enabled: approveHighRisk && escalateOn.length > 0,
    escalateOn: new Set(escalateOn),
    human,
  };
}

export function severityForViolation(violation: string): "low" | "medium" | "high" | "critical" {
  const normalized = normalizePolicyReasonToken(violation);
  if (
    normalized === "registry_mutation" ||
    normalized === "handler_swap" ||
    normalized === "server_code_changed" ||
    normalized === "tool_code_changed" ||
    normalized === "subprocess_blocked"
  ) {
    return "critical";
  }
  if (
    normalized === "agent_guard_failed" ||
    normalized === "tool_not_in_allowlist" ||
    normalized === "version_unpinned" ||
    normalized === "contextual_evaluator_denied" ||
    normalized === "contextual_evaluator_escalated" ||
    normalized === "skill_scan_failed" ||
    normalized === "skill_code_changed" ||
    normalized === "skill_version_changed"
  ) {
    return "high";
  }
  if (
    normalized === "egress_violation" ||
    normalized === "fs_violation" ||
    normalized === "missing_idempotency_for_side_effect" ||
    normalized === "payload_too_large" ||
    normalized === "missing_audit_signature"
  ) {
    return "medium";
  }
  return "low";
}

export function normalizeEscalationFindingSeverity(raw: unknown): "low" | "medium" | "high" | "critical" | null {
  const normalized = String(raw || "").trim().toLowerCase();
  if (normalized === "low" || normalized === "medium" || normalized === "high" || normalized === "critical") {
    return normalized;
  }
  return null;
}

function escalationFindingSeverityWeight(raw: unknown): number {
  const severity = normalizeEscalationFindingSeverity(raw);
  if (severity === "critical") return 4;
  if (severity === "high") return 3;
  if (severity === "medium") return 2;
  if (severity === "low") return 1;
  return 0;
}

function isRuleBackedAgentFinding(finding: AgentGuardFinding | null | undefined): boolean {
  if (!finding || typeof finding !== "object") return false;
  const source = String(finding.source || "").trim().toLowerCase();
  if (source === "evaluator") return false;
  return Boolean(
    (typeof finding.rule_id === "string" && finding.rule_id.trim()) ||
      (typeof finding.policy_id === "string" && finding.policy_id.trim()) ||
      (typeof finding.pack_id === "string" && finding.pack_id.trim()),
  );
}

function hasConcreteRuleFinding(findings: AgentGuardFinding[] | undefined): boolean {
  if (!Array.isArray(findings) || findings.length === 0) return false;
  return findings.some((finding) => isRuleBackedAgentFinding(finding));
}

export function sortEscalationFindingsForReporting(findings: AgentGuardFinding[] | undefined): AgentGuardFinding[] {
  if (!Array.isArray(findings) || findings.length === 0) return [];
  return [...findings].sort((left, right) => {
    const leftRule = isRuleBackedAgentFinding(left);
    const rightRule = isRuleBackedAgentFinding(right);
    if (leftRule !== rightRule) return leftRule ? -1 : 1;
    const leftSeverity = escalationFindingSeverityWeight(left?.severity);
    const rightSeverity = escalationFindingSeverityWeight(right?.severity);
    if (leftSeverity !== rightSeverity) return rightSeverity - leftSeverity;
    const leftMessage = String(left?.message || "").trim().toLowerCase();
    const rightMessage = String(right?.message || "").trim().toLowerCase();
    return leftMessage.localeCompare(rightMessage);
  });
}

export function selectPrimaryEscalationFinding(findings: AgentGuardFinding[] | undefined): AgentGuardFinding | null {
  const ordered = sortEscalationFindingsForReporting(findings);
  return ordered[0] ?? null;
}

function isContextualEscalationViolation(reason: string | null | undefined): boolean {
  const normalized = normalizePolicyReasonToken(reason || "");
  return normalized === "contextual_evaluator_denied" || normalized === "contextual_evaluator_escalated";
}

export function preferredEscalationFindingSource(params: {
  violation: string | null;
  findings: AgentGuardFinding[] | undefined;
  contextualFinding: ContextualEvaluatorFinding | null;
}): "rule" | "evaluator" {
  if (hasConcreteRuleFinding(params.findings)) return "rule";
  if (params.contextualFinding && isContextualEscalationViolation(params.violation)) return "evaluator";
  if (params.violation && !isContextualEscalationViolation(params.violation)) return "rule";
  if (params.contextualFinding) return "evaluator";
  return "rule";
}
