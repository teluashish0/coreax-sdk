import {
  EvaluatorDerivedFactsSchema,
  EvaluatorOrchestrationStateSchema,
  type EvaluatorActiveState,
  type EvaluatorDerivedFacts,
  type EvaluatorGraphContextItem,
  type EvaluatorInput,
  type EvaluatorOrchestrationState,
} from "./types";
import {
  compactText,
  normalizeString,
  normalizeStringArray,
} from "./classification";
import { validatedEvaluatorRecoveryTargetIds } from "./evidence";

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function uniqueStrings(
  values: Iterable<unknown>,
  maxItems = 100,
): string[] {
  const seen = new Set<string>();
  const result: string[] = [];
  for (const value of values) {
    const text = compactText(normalizeString(value), 500);
    const key = text.toLowerCase();
    if (!key || seen.has(key)) continue;
    seen.add(key);
    result.push(text);
    if (result.length >= maxItems) break;
  }
  return result;
}

function executionFailed(entry: Record<string, unknown>): boolean {
  if (normalizeString(entry.error)) return true;
  const status = normalizeString(entry.status).toLowerCase();
  return Boolean(
    status &&
      ![
        "success",
        "succeeded",
        "complete",
        "completed",
        "applied",
        "recovered",
      ].includes(status),
  );
}

function executionExplicitlyRecovered(entry: Record<string, unknown>): boolean {
  const status = normalizeString(entry.status).toLowerCase();
  return status === "recovered";
}

function executionIdentity(entry: Record<string, unknown>): string {
  return normalizeString(entry.eventId || entry.submissionId);
}

/**
 * A recovery can clear execution failures only when every reported failure is
 * identified and explicitly targeted by a valid, same-axis evidence recovery.
 */
export function evaluatorExecutionFailuresAreRecovered(
  input: EvaluatorInput,
  facts: EvaluatorDerivedFacts = input.derivedFacts,
): boolean {
  const failures = input.executionHistory.recentExecutions
    .map(record)
    .filter(executionFailed);
  const declaredFailureCount = Math.max(
    input.executionHistory.failureCount,
    facts.failureCount,
  );
  if (declaredFailureCount === 0 && failures.length === 0) return true;
  if (failures.length === 0 || declaredFailureCount > failures.length) {
    return false;
  }
  const recoveryTargets = validatedEvaluatorRecoveryTargetIds(
    input.runtimeContext.evidenceEvents,
  );
  if (
    failures.some((failure) => {
      const identity = executionIdentity(failure);
      return !identity || !recoveryTargets.has(identity);
    })
  ) {
    return false;
  }

  const failureTexts = new Set(
    failures
      .map((failure) =>
        normalizeString(failure.error || failure.summary).toLowerCase(),
      )
      .filter(Boolean),
  );
  return facts.recentToolErrors.every((error) =>
    failureTexts.has(normalizeString(error).toLowerCase()),
  );
}

export interface EvaluatorGraphSignals {
  summaries: string[];
  contradictionSummaries: string[];
  failureSummaries: string[];
  boundarySummaries: string[];
}

export function analyzeEvaluatorGraphContext(
  items: readonly EvaluatorGraphContextItem[],
): EvaluatorGraphSignals {
  const signals: EvaluatorGraphSignals = {
    summaries: [],
    contradictionSummaries: [],
    failureSummaries: [],
    boundarySummaries: [],
  };

  for (const item of items) {
    const summary = compactText(normalizeString(item.summary), 500);
    if (!summary) continue;
    signals.summaries.push(summary);
    const metadata = record(item.metadata);
    const status = normalizeString(metadata.status).toLowerCase();
    const signalCodes = normalizeStringArray(metadata.signalCodes);
    const lower = summary.toLowerCase();

    if (
      status === "contradicted" ||
      signalCodes.some((code) => code.includes("contradict")) ||
      /\bcontradict(?:ed|ion|ory)?\b|\bconflicting evidence\b/.test(lower)
    ) {
      signals.contradictionSummaries.push(summary);
    }
    if (
      ["failed", "error", "unresolved"].includes(status) ||
      signalCodes.some((code) => /fail|error|unresolved/.test(code)) ||
      /\bfailed\b|\bruntime error\b|\bunresolved\b/.test(lower)
    ) {
      signals.failureSummaries.push(summary);
    }
    if (
      signalCodes.some((code) => /boundary|egress|disclosure/.test(code)) ||
      /\bcross[- ]boundary\b|\begress\b|\bexternal disclosure\b/.test(lower)
    ) {
      signals.boundarySummaries.push(summary);
    }
  }

  return {
    summaries: uniqueStrings(signals.summaries, 50),
    contradictionSummaries: uniqueStrings(
      signals.contradictionSummaries,
      50,
    ),
    failureSummaries: uniqueStrings(signals.failureSummaries, 50),
    boundarySummaries: uniqueStrings(signals.boundarySummaries, 50),
  };
}

export function deriveEvaluatorFacts(input: {
  evaluatorInput: EvaluatorInput;
  activeState: EvaluatorActiveState;
}): EvaluatorDerivedFacts {
  const source = input.evaluatorInput;
  const existing = source.derivedFacts;
  const executions = source.executionHistory.recentExecutions.map(record);
  const outcomes = source.executionHistory.recentOutcomes.map(record);
  const reflections = source.reflectionHistory.recentReflections;
  const workflowState = record(source.runtimeContext.workflowState);

  const executionErrors = executions
    .filter(executionFailed)
    .map((entry) => normalizeString(entry.error || entry.summary))
    .filter(Boolean);
  const recentToolErrors = uniqueStrings([
    ...existing.recentToolErrors,
    ...normalizeStringArray(workflowState.recent_tool_errors),
    ...executionErrors,
  ]);
  const reflectionRetryReasons = reflections
    .map((reflection) => normalizeString(reflection.retryReason))
    .filter(Boolean);
  const retryReasons = uniqueStrings([
    ...existing.retryReasons,
    ...reflectionRetryReasons,
  ]);
  const attemptRetries = Math.max(
    0,
    (source.workflowSlice.attemptNumber ?? 0) - 1,
  );
  const retryCount = Math.max(
    existing.retryCount,
    attemptRetries,
    reflectionRetryReasons.length,
  );
  const observedFailureCount = executions.filter(executionFailed).length;
  const observedRecoveryCount = [...executions, ...outcomes].filter(
    executionExplicitlyRecovered,
  ).length;

  const verifiedFacts = uniqueStrings([
    ...existing.verifiedFacts,
    ...source.runtimeContext.verifiedPrerequisites,
    ...input.activeState.verifiedClaims.map((claim) => claim.claim),
  ]);
  const supersededMissingFacts = uniqueStrings([
    ...existing.supersededMissingFacts,
    ...input.activeState.supersededClaims.map((claim) => claim.claim),
  ]);
  const resolved = new Set(
    [...verifiedFacts, ...supersededMissingFacts].map((value) =>
      value.toLowerCase(),
    ),
  );
  const missingFacts = uniqueStrings([
    ...existing.missingFacts,
    ...source.runtimeContext.unresolvedPrerequisites,
    ...source.constraints.requiredPrerequisites,
    ...source.reflectionHistory.persistentMissingFacts,
    ...reflections.flatMap((reflection) => reflection.missingFacts),
    ...input.activeState.unresolvedClaims.map((claim) => claim.claim),
  ]).filter((fact) => !resolved.has(fact.toLowerCase()));
  const contradictoryState = uniqueStrings([
    ...existing.contradictoryState,
    ...input.activeState.contradictedClaims.map((claim) => claim.claim),
  ]);

  return EvaluatorDerivedFactsSchema.parse({
    ...existing,
    verifiedFacts,
    missingFacts,
    supersededMissingFacts,
    suggestedSources: uniqueStrings([
      ...existing.suggestedSources,
      ...input.activeState.retrievalHints,
      ...source.runtimeContext.retrievedEvidence.retrievalHints,
    ]),
    retryCount,
    retryReasons,
    recentToolErrors,
    priorHumanEditCount: Math.max(
      existing.priorHumanEditCount,
      source.decisionHistory.priorHumanResolutions.filter((resolution) =>
        /edit/i.test(normalizeString(resolution.action)),
      ).length,
    ),
    unresolvedClarificationCount: Math.max(
      existing.unresolvedClarificationCount,
      source.decisionHistory.priorClarifications.length,
    ),
    priorDenyCount: Math.max(
      existing.priorDenyCount,
      source.decisionHistory.priorDenies.length,
    ),
    priorEscalationCount: Math.max(
      existing.priorEscalationCount,
      source.decisionHistory.priorEscalations.length,
    ),
    failureCount: Math.max(
      existing.failureCount,
      source.executionHistory.failureCount,
      observedFailureCount,
    ),
    recoveryCount: Math.max(
      existing.recoveryCount,
      source.executionHistory.recoveryCount,
      observedRecoveryCount,
      input.activeState.supersededClaims.length > 0 ? 1 : 0,
      input.activeState.verifiedClaims.some(
        (claim) => claim.recoveryEventIds.length > 0,
      )
        ? 1
        : 0,
    ),
    repeatedReflectionDeviationCount: Math.max(
      existing.repeatedReflectionDeviationCount,
      source.reflectionHistory.repeatedDeviationCount,
    ),
    repeatedReflectionUncertaintyCount: Math.max(
      existing.repeatedReflectionUncertaintyCount,
      source.reflectionHistory.repeatedUncertaintyCount,
    ),
    persistentReflectionMissingFacts: uniqueStrings([
      ...existing.persistentReflectionMissingFacts,
      ...source.reflectionHistory.persistentMissingFacts,
    ]),
    reflectionOutcomeDisagreementCount: Math.max(
      existing.reflectionOutcomeDisagreementCount,
      source.reflectionHistory.reflectionOutcomeDisagreementCount,
    ),
    reflectionConfirmedRetryCount: Math.max(
      existing.reflectionConfirmedRetryCount,
      source.reflectionHistory.reflectionConfirmedRetryCount,
    ),
    reflectionEnabled:
      existing.reflectionEnabled || source.reflectionHistory.enabled,
    contradictoryState,
    sideEffectful:
      existing.sideEffectful || source.action.sideEffect === true,
    crossBoundary:
      existing.crossBoundary || source.action.crossesBoundary === true,
    disclosureRelevant:
      existing.disclosureRelevant || source.action.disclosure === true,
  });
}

export function deriveEvaluatorOrchestrationState(input: {
  evaluatorInput: EvaluatorInput;
  facts: EvaluatorDerivedFacts;
  activeState: EvaluatorActiveState;
  graphSignals?: EvaluatorGraphSignals;
}): EvaluatorOrchestrationState {
  const facts = input.facts;
  const graph = input.graphSignals ?? analyzeEvaluatorGraphContext(
    input.evaluatorInput.graphContext,
  );
  const signalCodes: string[] = [];
  const missingFacts = uniqueStrings(facts.missingFacts);
  let state: EvaluatorOrchestrationState["state"] = "normal";

  const linkedRecovery =
    input.activeState.supersededClaims.some(
      (claim) => claim.recoveryEventIds.length > 0,
    ) ||
    input.activeState.verifiedClaims.some(
      (claim) => claim.recoveryEventIds.length > 0,
    );
  const hasExecutionFailureSignals =
    facts.failureCount > 0 || facts.recentToolErrors.length > 0;
  const recovered =
    linkedRecovery &&
    (!hasExecutionFailureSignals ||
      evaluatorExecutionFailuresAreRecovered(input.evaluatorInput, facts)) &&
    input.activeState.unresolvedClaims.length === 0 &&
    input.activeState.contradictedClaims.length === 0 &&
    graph.failureSummaries.length === 0 &&
    graph.contradictionSummaries.length === 0 &&
    missingFacts.length === 0;

  if (!recovered) {
    if (
      facts.contradictoryState.length > 0 ||
      graph.contradictionSummaries.length > 0
    ) {
      state = "constrained";
      signalCodes.push("contradictory_state");
    }
    if (
      facts.failureCount >= 2 &&
      (facts.retryCount >= 1 || facts.recentToolErrors.length >= 2)
    ) {
      state = "constrained";
      signalCodes.push("repeated_failed_retry");
    }
    if (facts.repeatedReflectionUncertaintyCount > 0) {
      state = "constrained";
      signalCodes.push("reflection_uncertainty");
    }
    if (
      state === "normal" &&
      missingFacts.length > 0 &&
      (input.evaluatorInput.action.sideEffect ||
        input.evaluatorInput.action.crossesBoundary ||
        input.evaluatorInput.proposal?.proposalType === "message_proposal")
    ) {
      state = "clarify_first";
      signalCodes.push("missing_facts");
    }
    if (
      state === "normal" &&
      (facts.failureCount > 0 ||
        facts.retryCount > 0 ||
        graph.failureSummaries.length > 0)
    ) {
      state = "cautious";
      signalCodes.push("unstable_execution_context");
    }
  } else {
    signalCodes.push("recovered_context");
  }

  const derived = EvaluatorOrchestrationStateSchema.parse({
    state,
    signalCodes,
    missingFacts,
  });
  if (!input.evaluatorInput.orchestrationState) return derived;

  const explicit = EvaluatorOrchestrationStateSchema.parse(
    input.evaluatorInput.orchestrationState,
  );
  const rank: Record<EvaluatorOrchestrationState["state"], number> = {
    normal: 0,
    cautious: 1,
    clarify_first: 2,
    constrained: 3,
    block: 4,
  };
  return EvaluatorOrchestrationStateSchema.parse({
    ...explicit,
    state:
      rank[explicit.state] >= rank[derived.state]
        ? explicit.state
        : derived.state,
    signalCodes: uniqueStrings([
      ...explicit.signalCodes,
      ...derived.signalCodes,
    ], 50),
    missingFacts: uniqueStrings([
      ...explicit.missingFacts,
      ...derived.missingFacts,
    ]),
  });
}
