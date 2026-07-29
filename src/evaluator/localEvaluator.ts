import { applySemanticCalibration, type SemanticCalibrator } from "./calibration";
import { contentExcerptFromEvaluatorInput } from "./detectorSignals";
import {
  buildRemediation,
  classifyEvaluatorActionEffect,
  classificationRank,
  compactText,
  hashFingerprint,
  isKnownClassification,
  maxClassificationRank,
  missingScopes,
  normalizeString,
  normalizeStringArray,
  severityFromScore,
} from "./classification";
import { resolveEvaluatorActiveState } from "./evidence";
import {
  analyzeEvaluatorGraphContext,
  deriveEvaluatorFacts,
  deriveEvaluatorOrchestrationState,
  evaluatorExecutionFailuresAreRecovered,
} from "./reasoning";
import { applyDetectorFindingSignals } from "./scoring";
import {
  EvaluatorInputSchema,
  EvaluatorOutputSchema,
  type EvaluatorEvidence,
  type EvaluatorInput,
  type EvaluatorOutput,
  type EvaluatorPrinciple,
  type EvaluatorSourceUse,
} from "./types";

export type LocalContextualEvaluatorOptions = {
  denyThreshold?: number;
  escalateThreshold?: number;
  semanticCalibrator?: SemanticCalibrator;
};

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

function recentReflectionNeedsHumanReview(input: EvaluatorInput): boolean {
  return input.reflectionHistory.recentReflections.some(
    (reflection) =>
      reflection.needsHumanReview === true ||
      reflection.needsClarification === true,
  );
}

function contentHasPromptInjection(text: string): boolean {
  const normalized = text.toLowerCase();
  if (!normalized) return false;
  return [
    /\bignore (?:all |any )?(?:previous|prior|system|developer) instructions?\b/,
    /\boverride (?:the )?(?:system|developer|safety|security) (?:message|instructions?|policy)\b/,
    /\breveal (?:the )?(?:system prompt|developer message|hidden instructions?|secrets?|credentials?)\b/,
    /\bjailbreak\b/,
    /\bdo not follow (?:the )?(?:system|developer|safety) (?:message|instructions?)\b/,
    /<\|(?:system|developer|assistant)\|>/,
  ].some((pattern) => pattern.test(normalized));
}

function strongCommitment(text: string): boolean {
  return /\b(?:done|completed|fixed|resolved|sent|processed|updated|changed|ordered|cancelled|canceled|all set|i did|i have)\b/i.test(
    text,
  );
}

function outputSummary(
  decision: EvaluatorOutput["decision"],
  principles: EvaluatorPrinciple[],
  missingFacts: string[],
): string {
  if (decision === "allow") {
    return principles.length === 0
      ? "Local contextual review found no material risk."
      : `Local contextual review found only minor concerns: ${principles.join(", ")}.`;
  }
  if (decision === "deny") {
    return principles.length > 0
      ? `Local contextual review denied the action due to ${principles.join(", ")}.`
      : "Local contextual review denied the action based on hard runtime evidence.";
  }
  if (decision === "clarify") {
    return missingFacts.length > 0
      ? `Clarification is required before proceeding: ${missingFacts.join(", ")}.`
      : "Clarification is required before proceeding.";
  }
  return principles.length > 0
    ? `Human review is required due to ${principles.join(", ")}.`
    : "Human review is required before execution.";
}

function prepareInput(rawInput: EvaluatorInput): EvaluatorInput {
  const parsed = EvaluatorInputSchema.parse(rawInput);
  const activeState = resolveEvaluatorActiveState({
    explicitState: parsed.runtimeContext.activeState,
    evidenceEvents: parsed.runtimeContext.evidenceEvents,
  });
  const graphSignals = analyzeEvaluatorGraphContext(parsed.graphContext);
  const derivedFacts = deriveEvaluatorFacts({
    evaluatorInput: parsed,
    activeState,
  });
  const orchestrationState = deriveEvaluatorOrchestrationState({
    evaluatorInput: parsed,
    facts: derivedFacts,
    activeState,
    graphSignals,
  });

  return EvaluatorInputSchema.parse({
    ...parsed,
    runtimeContext: {
      ...parsed.runtimeContext,
      activeState,
    },
    derivedFacts,
    orchestrationState,
  });
}

export function evaluateContextualInputLocal(
  rawInput: EvaluatorInput,
  options: LocalContextualEvaluatorOptions = {},
): EvaluatorOutput {
  const input = prepareInput(rawInput);
  const principles = new Set<EvaluatorPrinciple>();
  const evidence: EvaluatorEvidence[] = [];
  const reasoningParts: string[] = [];
  const graphSignals = analyzeEvaluatorGraphContext(input.graphContext);
  const activeState = input.runtimeContext.activeState;
  const facts = input.derivedFacts;
  const orchestration = input.orchestrationState!;
  let score = 0;

  const addFinding = (
    principle: EvaluatorPrinciple,
    weight: number,
    label: string,
    detail: string,
    path?: string,
  ) => {
    if (!principles.has(principle)) {
      principles.add(principle);
      score += weight;
    }
    evidence.push({
      label,
      detail: compactText(detail, 1000),
      ...(path ? { path } : {}),
    });
    reasoningParts.push(compactText(detail, 320));
  };

  const targetBoundary = normalizeString(
    input.action.target?.boundary || input.action.data?.destination,
  ).toLowerCase();
  const allowedBoundaries = new Set(
    normalizeStringArray(input.authority.allowedBoundaries),
  );
  const forbiddenBoundaries = new Set(
    normalizeStringArray(input.constraints.forbiddenBoundaries),
  );
  const hardConstraints = normalizeStringArray(input.constraints.hard);
  const verifiedPrerequisites = new Set(
    normalizeStringArray(input.runtimeContext.verifiedPrerequisites),
  );
  const unverifiedHardConstraints = hardConstraints.filter(
    (constraint) => !verifiedPrerequisites.has(constraint),
  );
  const explicitHardDenyConstraint = hardConstraints.some((constraint) =>
    /^(?:deny|denied|forbid|forbidden|block|blocked)(?::|$)/.test(
      constraint,
    ),
  );
  const missingApprovals = normalizeStringArray(
    input.constraints.requiredApprovals,
  ).filter(
    (approval) =>
      !normalizeStringArray(input.authority.approvals).includes(approval),
  );
  const justification = normalizeString(input.purpose.justification);
  const sourceClassifications = input.sourceUse.sources.map(
    (source: EvaluatorSourceUse["sources"][number]) => source.classification,
  );
  const actionClassifications = [
    input.action.target?.classification,
    ...(input.action.data?.classifications || []),
  ];
  const maxObservedClassification = maxClassificationRank([
    ...actionClassifications,
    ...sourceClassifications,
  ]);
  const maxDisclosedClassification = maxClassificationRank(
    actionClassifications,
  );
  const maxAllowedClassification = input.constraints.maxClassification
    ? classificationRank(input.constraints.maxClassification)
    : 99;
  const observedClassifications = [
    ...actionClassifications,
    ...sourceClassifications,
  ].filter((value): value is string => Boolean(normalizeString(value)));
  const unknownObservedClassification = observedClassifications.some(
    (value) => !isKnownClassification(value),
  );
  const unknownMaxClassification = Boolean(
    input.constraints.maxClassification &&
      !isKnownClassification(input.constraints.maxClassification),
  );
  const actionEffect = classifyEvaluatorActionEffect(input);
  const consequentialAction =
    actionEffect === "write" ||
    input.action.disclosure === true ||
    input.action.crossesBoundary === true;
  const missingBoundaryAuthority =
    consequentialAction && allowedBoundaries.size === 0;
  const missingBoundaryTarget = consequentialAction && !targetBoundary;
  const outsideAllowedBoundary = Boolean(
    targetBoundary && !allowedBoundaries.has(targetBoundary),
  );
  const explicitlyForbiddenBoundary = Boolean(
    targetBoundary && forbiddenBoundaries.has(targetBoundary),
  );
  const classificationExceeded =
    maxObservedClassification > maxAllowedClassification;
  const scopesMissing = missingScopes(input);
  const contentExcerpt = contentExcerptFromEvaluatorInput(input);
  const semanticContent = [
    normalizeString(input.action.summary),
    normalizeString(input.proposal?.content),
    normalizeString(input.purpose.summary),
    normalizeString(input.purpose.justification),
    contentExcerpt,
  ]
    .filter(Boolean)
    .join(" ");
  const promptInjection = contentHasPromptInjection(semanticContent);
  const verificationOutstanding =
    activeState.unresolvedClaims.length > 0 ||
    activeState.contradictedClaims.length > 0 ||
    facts.missingFacts.length > 0;
  const linkedRecovery =
    activeState.supersededClaims.some(
      (claim) => claim.recoveryEventIds.length > 0,
    ) ||
    activeState.verifiedClaims.some(
      (claim) => claim.recoveryEventIds.length > 0,
    );
  const recoveredContext =
    !verificationOutstanding &&
    facts.persistentReflectionMissingFacts.length === 0 &&
    graphSignals.failureSummaries.length === 0 &&
    graphSignals.contradictionSummaries.length === 0 &&
    linkedRecovery &&
    evaluatorExecutionFailuresAreRecovered(input);

  if (graphSignals.summaries.length > 0) {
    reasoningParts.push(
      compactText(
        `The local run graph supplied relevant context: ${graphSignals.summaries
          .slice(0, 3)
          .join(" | ")}.`,
        320,
      ),
    );
  }

  if (input.runtimeContext.retrievedEvidence.events.length > 0) {
    reasoningParts.push(
      compactText(
        `${input.runtimeContext.retrievedEvidence.events.length} caller-supplied retrieved evidence item(s) were treated as advisory unless promoted into the active state.`,
        320,
      ),
    );
  }

  if (orchestration.state === "block") {
    addFinding(
      "unmet_preconditions",
      0.4,
      "orchestration_block",
      "The current orchestration state explicitly blocks additional proposals.",
      "orchestrationState.state",
    );
  } else if (orchestration.state === "constrained") {
    addFinding(
      "unmet_preconditions",
      0.25,
      "orchestration_constrained",
      "Repeated failures, contradictions, or uncertainty constrain the current run.",
      "orchestrationState.state",
    );
  } else if (orchestration.state === "clarify_first") {
    addFinding(
      "insufficient_justification",
      0.2,
      "orchestration_clarify_first",
      "Missing facts must be clarified before another consequential proposal.",
      "orchestrationState.state",
    );
  } else if (orchestration.state === "cautious") {
    reasoningParts.push(
      "The current run is cautious because a recent execution or retry signal is not yet stable.",
    );
  }

  if (activeState.supersededClaims.length > 0) {
    reasoningParts.push(
      compactText(
        `Later evidence superseded earlier failures for ${activeState.supersededClaims
          .map((claim) => claim.claim)
          .join(", ")}.`,
        320,
      ),
    );
  }

  if (outsideAllowedBoundary) {
    addFinding(
      "authority_scope_mismatch",
      0.35,
      "boundary",
      `Action targets boundary "${targetBoundary}" outside granted authority.`,
      "action.target.boundary",
    );
  }

  if (missingBoundaryAuthority) {
    addFinding(
      "authority_scope_mismatch",
      0.35,
      "boundary_authority",
      "A consequential action has no explicitly allowed authority boundary.",
      "authority.allowedBoundaries",
    );
  }

  if (missingBoundaryTarget) {
    addFinding(
      "authority_scope_mismatch",
      0.35,
      "boundary_target",
      "A consequential action must identify the exact target authority boundary.",
      "action.target.boundary",
    );
  }

  if (actionEffect === "unknown") {
    addFinding(
      "unmet_preconditions",
      0.3,
      "action_effect_unknown",
      "The action is not explicitly classifiable as read-only or side-effectful.",
      "action.operation",
    );
  }

  if (scopesMissing.length > 0) {
    addFinding(
      "authority_scope_mismatch",
      0.3,
      "scopes",
      `Required scopes are missing: ${scopesMissing.join(", ")}.`,
      "authority.grantedScopes",
    );
  }

  if (explicitlyForbiddenBoundary) {
    addFinding(
      "boundary_crossing_without_justification",
      0.3,
      "forbidden_boundary",
      `Target boundary "${targetBoundary}" is explicitly forbidden.`,
      "constraints.forbiddenBoundaries",
    );
  }

  if (input.action.crossesBoundary && justification.length < 24) {
    addFinding(
      "boundary_crossing_without_justification",
      0.22,
      "cross_boundary",
      "The action crosses a trust boundary without a concrete justification.",
      "purpose.justification",
    );
  }

  if (
    graphSignals.boundarySummaries.length > 0 &&
    input.action.crossesBoundary
  ) {
    addFinding(
      "boundary_crossing_without_justification",
      0.2,
      "graph_boundary",
      `The run graph contains related boundary risk: ${graphSignals.boundarySummaries.join(" | ")}.`,
      "graphContext",
    );
  }

  for (const source of input.sourceUse.sources) {
    if (source.justified === false) {
      addFinding(
        "source_use_misalignment",
        0.22,
        "source_justification",
        `Source "${source.label || source.id || source.type || "unknown"}" is not justified for this action.`,
        "sourceUse.sources",
      );
      break;
    }
  }

  if (classificationExceeded) {
    addFinding(
      "source_use_misalignment",
      0.25,
      "classification",
      "Observed data classification exceeds the configured maximum.",
      "constraints.maxClassification",
    );
  }

  if (unknownObservedClassification || unknownMaxClassification) {
    addFinding(
      "source_use_misalignment",
      0.35,
      "classification_unknown",
      "An unknown data-classification label was treated as restricted and requires explicit correction.",
      unknownMaxClassification
        ? "constraints.maxClassification"
        : "action.data.classifications",
    );
  }

  if (unverifiedHardConstraints.length > 0) {
    addFinding(
      "unmet_preconditions",
      0.3,
      "hard_constraints_unverified",
      `Hard constraints require explicit verification: ${unverifiedHardConstraints.join(", ")}.`,
      "constraints.hard",
    );
  }

  if (facts.missingFacts.length > 0 && !facts.lowRiskReadOnly) {
    addFinding(
      "unmet_preconditions",
      0.22,
      "missing_facts",
      `The action depends on unresolved facts: ${facts.missingFacts.join(", ")}.`,
      "derivedFacts.missingFacts",
    );
  }

  if (missingApprovals.length > 0) {
    addFinding(
      "unmet_preconditions",
      0.3,
      "approvals",
      `Required approvals are missing: ${missingApprovals.join(", ")}.`,
      "constraints.requiredApprovals",
    );
  }

  if (facts.failureCount > 0 && !recoveredContext) {
    addFinding(
      "unmet_preconditions",
      Math.min(0.22, 0.1 + facts.failureCount * 0.03),
      "execution_failures",
      `Related execution history contains ${facts.failureCount} unresolved failure(s).`,
      "executionHistory",
    );
  }

  if (facts.recentToolErrors.length > 0 && !recoveredContext) {
    const errorReferences = facts.recentToolErrors
      .slice(0, 3)
      .map((error) => hashFingerprint(error).slice(0, 16));
    addFinding(
      "unmet_preconditions",
      Math.min(0.28, 0.12 + facts.recentToolErrors.length * 0.04),
      "runtime_errors",
      `Recent runtime errors remain relevant (${facts.recentToolErrors.length}; sha256 refs: ${errorReferences.join(", ")}).`,
      "derivedFacts.recentToolErrors",
    );
  }

  if (
    input.action.sideEffect &&
    facts.retryCount > 0 &&
    facts.failureCount > 0 &&
    !recoveredContext
  ) {
    addFinding(
      "unmet_preconditions",
      Math.min(0.3, 0.14 + facts.failureCount * 0.04),
      "repeated_failed_retry",
      "A consequential action is being retried after failed execution attempts.",
      "derivedFacts.retryCount",
    );
  }

  if (facts.priorHumanEditCount > 0) {
    addFinding(
      "insufficient_justification",
      0.16,
      "prior_human_edits",
      "Related proposals previously required human edits.",
      "derivedFacts.priorHumanEditCount",
    );
  }

  const contradictions = Array.from(
    new Set([
      ...facts.contradictoryState,
      ...graphSignals.contradictionSummaries,
    ]),
  );
  if (contradictions.length > 0) {
    addFinding(
      "source_use_misalignment",
      Math.min(0.28, 0.12 + contradictions.length * 0.04),
      "contradictory_state",
      `Current evidence conflicts with action assumptions: ${contradictions.join(" | ")}.`,
      "runtimeContext.activeState.contradictedClaims",
    );
  }

  if (
    input.action.disclosure &&
    ((typeof input.constraints.disclosureBudget?.maxRecords === "number" &&
      typeof input.action.data?.estimatedRecords === "number" &&
      input.action.data.estimatedRecords >
        input.constraints.disclosureBudget.maxRecords) ||
      maxDisclosedClassification >= 2)
  ) {
    addFinding(
      "disproportionate_disclosure",
      0.25,
      "disclosure",
      "The proposed disclosure exceeds the justified data scope.",
      "action.data",
    );
  }

  if (
    (input.action.sideEffect ||
      input.action.disclosure ||
      input.action.crossesBoundary ||
      maxObservedClassification >= 2 ||
      facts.retryCount > 0) &&
    justification.length < 24
  ) {
    addFinding(
      "insufficient_justification",
      0.16,
      "justification",
      "A risky action lacks a concrete justification tied to its objective.",
      "purpose.justification",
    );
  }

  if (facts.persistentReflectionMissingFacts.length > 0) {
    addFinding(
      "unmet_preconditions",
      0.18,
      "reflection_missing_facts",
      `Structured reflection still reports missing facts: ${facts.persistentReflectionMissingFacts.join(", ")}.`,
      "reflectionHistory.persistentMissingFacts",
    );
  }

  if (
    facts.repeatedReflectionDeviationCount > 0 ||
    facts.reflectionConfirmedRetryCount > 0
  ) {
    addFinding(
      "insufficient_justification",
      0.16,
      "reflection_deviation",
      "Structured reflection indicates repeated deviation or retry behavior.",
      "reflectionHistory",
    );
  }

  if (
    facts.repeatedReflectionUncertaintyCount > 0 ||
    recentReflectionNeedsHumanReview(input)
  ) {
    addFinding(
      "insufficient_justification",
      0.18,
      "reflection_uncertainty",
      "Structured reflection requests clarification or human review.",
      "reflectionHistory",
    );
  }

  if (facts.reflectionOutcomeDisagreementCount > 0) {
    addFinding(
      "source_use_misalignment",
      0.16,
      "reflection_outcome_disagreement",
      "Structured reflection conflicts with recent execution outcomes.",
      "reflectionHistory.reflectionOutcomeDisagreementCount",
    );
  }

  if (
    input.proposal?.proposalType === "message_proposal" &&
    strongCommitment(normalizeString(input.proposal.content)) &&
    (facts.missingFacts.length > 0 ||
      orchestration.state !== "normal" ||
      facts.persistentReflectionMissingFacts.length > 0)
  ) {
    addFinding(
      "insufficient_justification",
      0.22,
      "message_commitment",
      "The proposed message claims completion while the run remains unresolved.",
      "proposal.content",
    );
  }

  if (promptInjection) {
    addFinding(
      "source_use_misalignment",
      0.38,
      "prompt_injection",
      "Untrusted content contains instructions attempting to override the trusted execution context.",
      "action.summary",
    );
    if (
      input.action.sideEffect ||
      input.action.disclosure ||
      input.proposal?.toolCall
    ) {
      addFinding(
        "boundary_crossing_without_justification",
        0.32,
        "prompt_injection_execution",
        "The injected instruction is coupled to a consequential action and cannot be executed safely.",
        "action",
      );
    }
  }

  if (recoveredContext) {
    evidence.push({
      label: "recovered_context",
      detail:
        "Later evidence resolved prior failures; stale failure signals were not treated as active blockers.",
      path: "runtimeContext.activeState",
    });
    reasoningParts.push(
      "Later local evidence recovered the runtime context and superseded stale failures.",
    );
  }

  const detectorFindings = applyDetectorFindingSignals({
    input,
    contentExcerpt,
    addFinding,
    evidence,
    reasoningParts,
  });

  score = clamp(score, 0, 1);
  const denyThreshold = Number.isFinite(options.denyThreshold)
    ? clamp(Number(options.denyThreshold), 0, 1)
    : 0.88;
  const escalateThreshold = Number.isFinite(options.escalateThreshold)
    ? clamp(Number(options.escalateThreshold), 0, denyThreshold)
    : 0.48;
  const clarificationPending =
    facts.missingFacts.length > 0 ||
    facts.unresolvedClarificationCount > 0 ||
    facts.persistentReflectionMissingFacts.length > 0 ||
    orchestration.state === "clarify_first";
  const hardDeny =
    orchestration.state === "block" ||
    explicitHardDenyConstraint ||
    missingBoundaryAuthority ||
    missingBoundaryTarget ||
    outsideAllowedBoundary ||
    explicitlyForbiddenBoundary ||
    classificationExceeded ||
    unknownObservedClassification ||
    unknownMaxClassification ||
    actionEffect === "unknown" ||
    scopesMissing.length > 0 ||
    detectorFindings.some((finding) => finding.hardDeny) ||
    (promptInjection &&
      Boolean(
        input.action.sideEffect ||
          input.action.disclosure ||
          input.proposal?.toolCall,
      )) ||
    (principles.has("authority_scope_mismatch") &&
      principles.has("unmet_preconditions")) ||
    (!clarificationPending && score >= denyThreshold);
  const needsClarification =
    clarificationPending &&
    !principles.has("authority_scope_mismatch") &&
    !principles.has("source_use_misalignment");
  const repeatedFailuresNeedReview =
    input.action.sideEffect &&
    !recoveredContext &&
    facts.failureCount >= 2 &&
    (facts.retryCount >= 1 || facts.recentToolErrors.length >= 2);
  const needsHumanJudgment =
    promptInjection ||
    missingApprovals.length > 0 ||
    facts.approvalSensitive ||
    facts.priorHumanEditCount > 0 ||
    facts.priorEscalationCount > 0 ||
    repeatedFailuresNeedReview ||
    orchestration.state === "constrained" ||
    recentReflectionNeedsHumanReview(input) ||
    (input.action.sideEffect && input.action.crossesBoundary) ||
    principles.size > 0 ||
    score >= escalateThreshold;

  let decision: EvaluatorOutput["decision"] = "allow";
  if (hardDeny) decision = "deny";
  else if (needsClarification) decision = "clarify";
  else if (needsHumanJudgment) decision = "escalate";

  const orderedPrinciples = Array.from(principles).sort();
  const questions =
    input.derivedFacts.suggestedQuestions.length > 0
      ? normalizeStringArray(input.derivedFacts.suggestedQuestions)
      : facts.missingFacts
          .slice(0, 4)
          .map((fact) => `What evidence would resolve: ${fact}?`);
  const reasoning =
    reasoningParts.length > 0
      ? compactText(reasoningParts.join(" "), 4000)
      : "The local deterministic reasoner found no contextual mismatch.";
  const fingerprint = hashFingerprint({
    action: {
      kind: normalizeString(input.action.kind).toLowerCase(),
      operation: normalizeString(input.action.operation).toLowerCase(),
      targetBoundary,
    },
    proposal: input.proposal ?? null,
    principles: orderedPrinciples,
    scopesMissing,
    hardConstraints,
    missingApprovals,
    missingFacts: facts.missingFacts,
    activeState: {
      verified: activeState.verifiedClaims.map((claim) => claim.key),
      unresolved: activeState.unresolvedClaims.map((claim) => claim.key),
      superseded: activeState.supersededClaims.map((claim) => claim.key),
      contradicted: activeState.contradictedClaims.map((claim) => claim.key),
    },
    orchestration,
    graphSignals,
    failures: facts.failureCount,
    retries: facts.retryCount,
    recovery: facts.recoveryCount,
    promptInjection,
    detectorFindings: detectorFindings.map((finding) => ({
      code: finding.code,
      hardDeny: finding.hardDeny,
      ruleId: finding.ruleId ?? null,
    })),
  });
  const confidence =
    orderedPrinciples.length === 0
      ? 0.84
      : clamp(0.58 + score * 0.36, 0.58, 0.98);

  return EvaluatorOutputSchema.parse({
    decision,
    basis: "semantic_reasoner",
    confidence,
    principles: orderedPrinciples,
    summary: compactText(
      outputSummary(decision, orderedPrinciples, facts.missingFacts),
      2000,
    ),
    reasoning,
    evidence: evidence.slice(0, 50),
    evidenceRefs: Array.from(
      new Set([
        ...evidence.map((entry) => normalizeString(entry.path)).filter(Boolean),
        ...input.auditEvidence
          .map((entry) => normalizeString(entry.ref))
          .filter(Boolean),
      ]),
    ).slice(0, 100),
    suggestedSeverity: severityFromScore(score),
    suggestedRemediation: buildRemediation(orderedPrinciples),
    normalizedFingerprint: fingerprint,
    missingFacts: facts.missingFacts,
    questions: questions.slice(0, 100),
    suggestedSources: normalizeStringArray(
      input.derivedFacts.suggestedSources,
    ),
    resumeConditions: normalizeStringArray(
      input.derivedFacts.resumeConditions,
    ),
    reasonerVersion: "coreax-local-reasoner-v2",
    calibrationVersion: "none",
    calibrationStatus: "not_configured",
  });
}

export async function evaluateContextualInputLocalAsync(
  rawInput: EvaluatorInput,
  options: LocalContextualEvaluatorOptions = {},
): Promise<EvaluatorOutput> {
  const preparedInput = prepareInput(rawInput);
  const deterministicOutput = evaluateContextualInputLocal(
    preparedInput,
    options,
  );
  return applySemanticCalibration({
    evaluatorInput: preparedInput,
    deterministicOutput,
    calibrator: options.semanticCalibrator,
    denyThreshold: options.denyThreshold,
    escalateThreshold: options.escalateThreshold,
  });
}

export function createLocalContextualEvaluator(
  options: LocalContextualEvaluatorOptions = {},
) {
  return {
    async evaluate(input: EvaluatorInput): Promise<EvaluatorOutput> {
      return evaluateContextualInputLocalAsync(input, options);
    },
  };
}
