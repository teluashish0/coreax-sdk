import { stableSerialize } from "./math";
import type {
  PolicyCandidate,
  PolicyDenyRule,
  PolicyDocument,
  PolicyPermission,
} from "./types";

export type PolicySafetyReasonCode =
  | "wildcard_permission_expansion"
  | "permission_expansion"
  | "required_deny_missing"
  | "required_deny_weakened";

export interface PolicySafetyReason {
  code: PolicySafetyReasonCode;
  detail: string;
}

export interface PolicySafetyConstraints {
  requiredDenyRuleIds?: readonly string[];
  /**
   * Exact, non-wildcard additions may only be enabled deliberately. Wildcard
   * expansion is never permitted.
   */
  allowExactPermissionExpansion?: boolean;
}

export interface PolicySafetyAssessment {
  allowed: boolean;
  reasons: PolicySafetyReason[];
}

export function assertPolicySafetyConstraints(
  constraints: PolicySafetyConstraints,
): void {
  if (
    !constraints ||
    typeof constraints !== "object" ||
    Array.isArray(constraints) ||
    (constraints.allowExactPermissionExpansion !== undefined &&
      typeof constraints.allowExactPermissionExpansion !== "boolean") ||
    (constraints.requiredDenyRuleIds !== undefined &&
      (!Array.isArray(constraints.requiredDenyRuleIds) ||
        constraints.requiredDenyRuleIds.some(
          (ruleId) =>
            typeof ruleId !== "string" ||
            ruleId.trim() !== ruleId ||
            ruleId.length === 0,
        ) ||
        new Set(constraints.requiredDenyRuleIds).size !==
          constraints.requiredDenyRuleIds.length))
  ) {
    throw new TypeError("invalid_policy_safety_constraints");
  }
}

function normalizedStrings(values: readonly string[] | undefined): string[] {
  return [...new Set((values ?? []).map((value) => value.trim()).filter(Boolean))]
    .sort((left, right) => left.localeCompare(right));
}

function canonicalPermission(permission: PolicyPermission): string {
  return stableSerialize({
    id: permission.id?.trim() || null,
    actions: normalizedStrings(permission.actions),
    resources: normalizedStrings(permission.resources),
    conditions: permission.conditions ?? null,
  });
}

function canonicalDenyRule(rule: PolicyDenyRule): string {
  return stableSerialize({
    id: rule.id.trim(),
    actions: normalizedStrings(rule.actions),
    resources: normalizedStrings(rule.resources),
    conditions: rule.conditions ?? null,
    required: rule.required === true,
  });
}

export function containsPermissionWildcard(
  permission: PolicyPermission,
): boolean {
  const values = [...permission.actions, ...permission.resources];
  return values.some((rawValue) => {
    const value = rawValue.trim().toLowerCase();
    return (
      value === "all" ||
      value === "any" ||
      value.includes("*") ||
      value.includes("?")
    );
  });
}

/**
 * Evaluates a complete transition, so an opaque mutation cannot evade the
 * safety boundary by using an unrecognized operation name.
 */
export function assessPolicyTransition<
  TPolicy extends PolicyDocument,
>(input: {
  currentPolicy: TPolicy;
  targetPolicy: TPolicy;
  constraints?: PolicySafetyConstraints;
}): PolicySafetyAssessment {
  const reasons: PolicySafetyReason[] = [];
  const constraints = input.constraints ?? {};
  assertPolicySafetyConstraints(constraints);

  const currentPermissionSet = new Set(
    input.currentPolicy.permissions.map(canonicalPermission),
  );
  for (const permission of input.targetPolicy.permissions) {
    const canonical = canonicalPermission(permission);
    if (currentPermissionSet.has(canonical)) continue;

    if (containsPermissionWildcard(permission)) {
      reasons.push({
        code: "wildcard_permission_expansion",
        detail: `Permission ${permission.id || canonical} introduces a wildcard.`,
      });
    } else if (!constraints.allowExactPermissionExpansion) {
      reasons.push({
        code: "permission_expansion",
        detail: `Permission ${permission.id || canonical} expands the current permission set.`,
      });
    }
  }

  const currentRules = new Map(
    input.currentPolicy.denyRules.map((rule) => [rule.id, rule] as const),
  );
  const targetRules = new Map(
    input.targetPolicy.denyRules.map((rule) => [rule.id, rule] as const),
  );
  const requiredIds = new Set([
    ...(constraints.requiredDenyRuleIds ?? []),
    ...input.currentPolicy.denyRules
      .filter((rule) => rule.required)
      .map((rule) => rule.id),
  ]);

  for (const ruleId of [...requiredIds].sort((left, right) =>
    left.localeCompare(right),
  )) {
    const targetRule = targetRules.get(ruleId);
    if (!targetRule) {
      reasons.push({
        code: "required_deny_missing",
        detail: `Required deny rule ${ruleId} is missing.`,
      });
      continue;
    }

    const currentRule = currentRules.get(ruleId);
    if (
      currentRule &&
      canonicalDenyRule(currentRule) !== canonicalDenyRule(targetRule)
    ) {
      reasons.push({
        code: "required_deny_weakened",
        detail: `Required deny rule ${ruleId} changed.`,
      });
    }
  }

  return { allowed: reasons.length === 0, reasons };
}

export function assessPolicyCandidate<
  TAction,
  TPolicy extends PolicyDocument,
>(input: {
  currentPolicy: TPolicy;
  candidate: PolicyCandidate<TAction, TPolicy>;
  constraints?: PolicySafetyConstraints;
}): PolicySafetyAssessment {
  return assessPolicyTransition({
    currentPolicy: input.currentPolicy,
    targetPolicy: input.candidate.targetPolicy,
    constraints: input.constraints,
  });
}

export function assertPolicyTransitionSafe<
  TPolicy extends PolicyDocument,
>(input: {
  currentPolicy: TPolicy;
  targetPolicy: TPolicy;
  constraints?: PolicySafetyConstraints;
}): void {
  const assessment = assessPolicyTransition(input);
  if (!assessment.allowed) {
    throw new Error(
      `unsafe_policy_transition:${assessment.reasons
        .map((reason) => reason.code)
        .join(",")}`,
    );
  }
}
