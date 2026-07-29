import {
  EvaluatorDecisionSchema,
  EvaluatorEvidenceSchema,
  EvaluatorOutputSchema,
  EvaluatorPrincipleSchema,
  type EvaluatorDecision,
  type EvaluatorEvidence,
  type EvaluatorInput,
  type EvaluatorOutput,
  type EvaluatorPrinciple,
} from "./types";
import {
  compactText,
  hashFingerprint,
  normalizeString,
  severityFromScore,
} from "./classification";

export interface SemanticCalibrationResult {
  decision?: EvaluatorDecision;
  riskScore?: number;
  confidence?: number;
  principles?: readonly EvaluatorPrinciple[];
  summary?: string;
  reasoning?: string;
  evidence?: readonly EvaluatorEvidence[];
  missingFacts?: readonly string[];
  questions?: readonly string[];
  version?: string;
}

export interface SemanticCalibrator {
  calibrate(input: {
    evaluatorInput: EvaluatorInput;
    deterministicOutput: EvaluatorOutput;
  }): Promise<SemanticCalibrationResult | null>;
}

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

function finite(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

const DECISION_RANK: Record<EvaluatorDecision, number> = {
  allow: 0,
  clarify: 1,
  escalate: 2,
  deny: 3,
};

function stricterDecision(
  left: EvaluatorDecision,
  right: EvaluatorDecision,
): EvaluatorDecision {
  return DECISION_RANK[right] > DECISION_RANK[left] ? right : left;
}

function normalizeCalibration(
  value: SemanticCalibrationResult,
): SemanticCalibrationResult {
  const decision = EvaluatorDecisionSchema.safeParse(value.decision);
  const principles = (value.principles ?? [])
    .map((principle) => EvaluatorPrincipleSchema.safeParse(principle))
    .filter((result) => result.success)
    .map((result) => result.data);
  const evidence = (value.evidence ?? [])
    .map((entry) => EvaluatorEvidenceSchema.safeParse(entry))
    .filter((result) => result.success)
    .map((result) => result.data);
  return {
    ...(decision.success ? { decision: decision.data } : {}),
    ...(finite(value.riskScore) !== null
      ? { riskScore: clamp(finite(value.riskScore)!, 0, 1) }
      : {}),
    ...(finite(value.confidence) !== null
      ? { confidence: clamp(finite(value.confidence)!, 0, 1) }
      : {}),
    principles,
    ...(normalizeString(value.summary)
      ? { summary: compactText(normalizeString(value.summary), 1000) }
      : {}),
    ...(normalizeString(value.reasoning)
      ? { reasoning: compactText(normalizeString(value.reasoning), 1200) }
      : {}),
    evidence,
    missingFacts: (value.missingFacts ?? [])
      .map((entry) => compactText(normalizeString(entry), 500))
      .filter(Boolean),
    questions: (value.questions ?? [])
      .map((entry) => compactText(normalizeString(entry), 500))
      .filter(Boolean),
    version: compactText(normalizeString(value.version) || "custom-advisory", 120),
  };
}

/**
 * Applies caller-supplied semantic advice monotonically. Deterministic deny,
 * escalation, and clarification outcomes are immutable; only an allow may be
 * tightened. An unavailable calibrator returns the deterministic output.
 */
export async function applySemanticCalibration(input: {
  evaluatorInput: EvaluatorInput;
  deterministicOutput: EvaluatorOutput;
  calibrator?: SemanticCalibrator;
  denyThreshold?: number;
  escalateThreshold?: number;
}): Promise<EvaluatorOutput> {
  const deterministic = input.deterministicOutput;
  if (!input.calibrator) {
    return EvaluatorOutputSchema.parse({
      ...deterministic,
      calibrationVersion: "none",
      calibrationStatus: "not_configured",
    });
  }

  if (deterministic.decision !== "allow") {
    return EvaluatorOutputSchema.parse({
      ...deterministic,
      calibrationVersion: "advisory-skipped",
      calibrationStatus: "no_op",
    });
  }

  let rawCalibration: SemanticCalibrationResult | null;
  try {
    rawCalibration = await input.calibrator.calibrate({
      evaluatorInput: input.evaluatorInput,
      deterministicOutput: deterministic,
    });
  } catch {
    return EvaluatorOutputSchema.parse({
      ...deterministic,
      calibrationVersion: "unavailable",
      calibrationStatus: "unavailable",
    });
  }

  if (!rawCalibration) {
    return EvaluatorOutputSchema.parse({
      ...deterministic,
      calibrationVersion: "custom-advisory",
      calibrationStatus: "no_op",
    });
  }

  const calibration = normalizeCalibration(rawCalibration);
  const denyThreshold = clamp(input.denyThreshold ?? 0.85, 0, 1);
  const escalateThreshold = clamp(
    input.escalateThreshold ?? 0.45,
    0,
    denyThreshold,
  );
  let recommendation = calibration.decision ?? "allow";
  if (typeof calibration.riskScore === "number") {
    if (calibration.riskScore >= denyThreshold) {
      recommendation = stricterDecision(recommendation, "deny");
    } else if (calibration.riskScore >= escalateThreshold) {
      recommendation = stricterDecision(recommendation, "escalate");
    }
  }

  if (recommendation === "allow") {
    return EvaluatorOutputSchema.parse({
      ...deterministic,
      calibrationVersion: calibration.version,
      calibrationStatus: "no_op",
    });
  }

  const principles = Array.from(
    new Set([
      ...deterministic.principles,
      ...(calibration.principles ?? []),
    ]),
  ).sort();
  const calibrationEvidence: EvaluatorEvidence[] = [
    ...(calibration.evidence ?? []),
    {
      label: "semantic_calibration",
      detail:
        calibration.summary ||
        `Caller-provided semantic calibration recommended ${recommendation}.`,
      path: "semanticCalibrator",
    },
  ];
  const riskScore = calibration.riskScore ?? 0.5;
  const output = {
    ...deterministic,
    decision: recommendation,
    confidence: Math.max(
      deterministic.confidence,
      calibration.confidence ?? deterministic.confidence,
    ),
    principles,
    summary:
      calibration.summary ||
      `Advisory semantic calibration tightened the decision to ${recommendation}.`,
    reasoning: compactText(
      [
        deterministic.reasoning,
        calibration.reasoning ||
          "Caller-provided semantic advice increased caution and could not weaken deterministic enforcement.",
      ].join(" "),
      4000,
    ),
    evidence: [...deterministic.evidence, ...calibrationEvidence].slice(0, 50),
    evidenceRefs: Array.from(
      new Set([...deterministic.evidenceRefs, "semanticCalibrator"]),
    ).slice(0, 100),
    suggestedSeverity:
      riskScore > 0
        ? severityFromScore(
            Math.max(
              riskScore,
              deterministic.suggestedSeverity === "critical"
                ? 0.9
                : deterministic.suggestedSeverity === "high"
                  ? 0.7
                  : deterministic.suggestedSeverity === "medium"
                    ? 0.45
                    : 0.2,
            ),
          )
        : deterministic.suggestedSeverity,
    missingFacts: Array.from(
      new Set([
        ...deterministic.missingFacts,
        ...(calibration.missingFacts ?? []),
      ]),
    ).slice(0, 100),
    questions: Array.from(
      new Set([
        ...deterministic.questions,
        ...(calibration.questions ?? []),
      ]),
    ).slice(0, 100),
    normalizedFingerprint: hashFingerprint({
      deterministic: deterministic.normalizedFingerprint,
      decision: recommendation,
      principles,
      version: calibration.version,
    }),
    calibrationVersion: calibration.version,
    calibrationStatus: "applied" as const,
  };
  return EvaluatorOutputSchema.parse(output);
}
