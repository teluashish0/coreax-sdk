import type {
  DataClassification,
  DataExposureDetector,
  DataExposureEvidence,
  DataExposureSink,
  RiskComputationResult,
  RuntimeRiskEvent,
  RuntimeRiskSeverity,
} from "./types";
import {
  clamp,
  extractRiskTags,
  finiteConfigNumber,
  privacyHash,
  safeIdentifier,
  safeModelVersion,
  severityFromScore,
  severityScore,
  sortedEvents,
  toHop,
} from "./util";

export type DataExposureConfig = {
  modelVersion: string;
  aggregateSignalThreshold: number;
  defaultExposureScore: number;
  guardFindingScore: number;
  maximumExposures: number;
};

export const DEFAULT_DATA_EXPOSURE_CONFIG: DataExposureConfig = Object.freeze({
  modelVersion: "coreax-runtime-risk-v1",
  aggregateSignalThreshold: 60,
  defaultExposureScore: 20,
  guardFindingScore: 15,
  maximumExposures: 25,
});

export type DataExposureInput = {
  nodeId: string;
  events: readonly RuntimeRiskEvent[];
  config?: Partial<DataExposureConfig>;
};

type Exposure = DataExposureEvidence["exposures"][number];

const RISK_TAG_EXPOSURES: Readonly<
  Record<
    string,
    {
      sink: DataExposureSink;
      classification: DataClassification;
      severity: RuntimeRiskSeverity;
      score: number;
    }
  >
> = Object.freeze({
  egress_violation: {
    sink: "egress",
    classification: "unknown",
    severity: "high",
    score: 35,
  },
  fs_violation: {
    sink: "filesystem",
    classification: "unknown",
    severity: "high",
    score: 30,
  },
  payload_too_large: {
    sink: "raw_payload",
    classification: "unknown",
    severity: "medium",
    score: 20,
  },
  guard_failed: {
    sink: "tool_output",
    classification: "unknown",
    severity: "medium",
    score: 25,
  },
  sensitive_state_egress: {
    sink: "egress",
    classification: "secret",
    severity: "critical",
    score: 50,
  },
});

function resolvedConfig(
  overrides: Partial<DataExposureConfig> | undefined,
): DataExposureConfig {
  const merged = { ...DEFAULT_DATA_EXPOSURE_CONFIG, ...overrides };
  return {
    ...merged,
    modelVersion: safeModelVersion(merged.modelVersion),
    aggregateSignalThreshold: finiteConfigNumber(
      merged.aggregateSignalThreshold,
      "dataExposure.aggregateSignalThreshold",
      { minimum: 0, maximum: 100 },
    ),
    defaultExposureScore: finiteConfigNumber(
      merged.defaultExposureScore,
      "dataExposure.defaultExposureScore",
      { minimum: 1, maximum: 100 },
    ),
    guardFindingScore: finiteConfigNumber(
      merged.guardFindingScore,
      "dataExposure.guardFindingScore",
      { minimum: 1, maximum: 100 },
    ),
    maximumExposures: finiteConfigNumber(
      merged.maximumExposures,
      "dataExposure.maximumExposures",
      { minimum: 1, maximum: 10_000, integer: true },
    ),
  };
}

const EXPOSURE_SINKS = new Set<DataExposureSink>([
  "egress",
  "filesystem",
  "tool_output",
  "agent_state",
  "raw_payload",
  "unknown",
]);
const EXPOSURE_DETECTORS = new Set<DataExposureDetector>([
  "guard",
  "policy_risk_tag",
  "classifier",
  "rule",
]);
const DATA_CLASSIFICATIONS = new Set<DataClassification>([
  "pii",
  "secret",
  "phi",
  "credential",
  "unknown",
]);
const RISK_SEVERITIES = new Set<RuntimeRiskSeverity>([
  "low",
  "medium",
  "high",
  "critical",
]);

function explicitExposure(
  rawFinding: unknown,
  hop: Exposure["hop"],
  defaultScore: number,
): { exposure: Exposure; contribution: number } {
  const finding =
    rawFinding && typeof rawFinding === "object" && !Array.isArray(rawFinding)
      ? (rawFinding as Record<string, unknown>)
      : {};
  const sink =
    typeof finding.sink === "string" &&
    EXPOSURE_SINKS.has(finding.sink as DataExposureSink)
      ? (finding.sink as DataExposureSink)
      : "unknown";
  const detector =
    finding.detector === undefined
      ? "rule"
      : typeof finding.detector === "string" &&
          EXPOSURE_DETECTORS.has(
            finding.detector as DataExposureDetector,
          )
        ? (finding.detector as DataExposureDetector)
        : "rule";
  const classification =
    finding.classification === undefined
      ? "unknown"
      : typeof finding.classification === "string" &&
          DATA_CLASSIFICATIONS.has(
            finding.classification as DataClassification,
          )
        ? (finding.classification as DataClassification)
        : "unknown";
  const hasExplicitSeverity = finding.severity !== undefined;
  const validSeverity =
    typeof finding.severity === "string" &&
    RISK_SEVERITIES.has(finding.severity as RuntimeRiskSeverity);
  const malformed =
    Object.keys(finding).length === 0 ||
    sink === "unknown" && finding.sink !== "unknown" ||
    finding.detector !== undefined &&
      detector === "rule" &&
      finding.detector !== "rule" ||
    finding.classification !== undefined &&
      classification === "unknown" &&
      finding.classification !== "unknown" ||
    hasExplicitSeverity && !validSeverity ||
    finding.ruleId !== undefined && typeof finding.ruleId !== "string";
  const severity: RuntimeRiskSeverity = malformed
    ? "critical"
    : validSeverity
      ? (finding.severity as RuntimeRiskSeverity)
      : "medium";
  return {
    exposure: {
      sink,
      detector,
      classification,
      severity,
      hop,
      ...(finding.ruleId !== undefined
        ? { ruleIdSha256: privacyHash(finding.ruleId) }
        : {}),
    },
    contribution: malformed
      ? severityScore("critical")
      : hasExplicitSeverity
        ? severityScore(severity)
        : defaultScore,
  };
}

export function computeDataExposureRisk(
  input: DataExposureInput,
): RiskComputationResult<DataExposureEvidence> {
  const config = resolvedConfig(input.config);
  const events = sortedEvents(input.events);
  const exposures: Exposure[] = [];
  let score = 0;

  const addExposure = (exposure: Exposure, contribution: number): void => {
    if (exposures.length >= Math.max(0, config.maximumExposures)) return;
    exposures.push(exposure);
    score += Math.max(0, contribution);
  };

  for (const event of events) {
    if (exposures.length >= Math.max(0, config.maximumExposures)) break;
    const hop = toHop(event);
    for (const finding of event.exposures ?? []) {
      const normalized = explicitExposure(
        finding,
        hop,
        config.defaultExposureScore,
      );
      addExposure(normalized.exposure, normalized.contribution);
    }
    for (const tag of extractRiskTags(event)) {
      const normalized = tag.trim().toLowerCase();
      const mapped = RISK_TAG_EXPOSURES[normalized];
      if (!mapped) continue;
      addExposure(
        {
          sink: mapped.sink,
          detector: "policy_risk_tag",
          classification: mapped.classification,
          severity: mapped.severity,
          hop,
          riskTag: normalized,
        },
        mapped.score,
      );
    }
    const findingCount =
      event.guardFindings === undefined
        ? 0
        : finiteConfigNumber(
            event.guardFindings,
            `event ${safeIdentifier(event.id)} guardFindings`,
            { minimum: 0, maximum: 1_000_000, integer: true },
          );
    if (findingCount > 0) {
      addExposure(
        {
          sink: "tool_output",
          detector: "guard",
          classification: "unknown",
          severity: "medium",
          hop,
          findingCount,
        },
        config.guardFindingScore,
      );
    }
  }

  score = clamp(score, 0, 100);
  const signals =
    score >= config.aggregateSignalThreshold && exposures.length > 0
      ? [
          {
            code: "data_exposure_risk:aggregate",
            subtype: "data_exposure_risk" as const,
            severity: severityFromScore(score),
            score,
            title: "Data exposure risk",
            message: `${exposures.length} exposure signals for node ${safeIdentifier(input.nodeId)}`,
            evidence: { exposureCount: exposures.length },
            ...(events.length > 0
              ? { hop: toHop(events[events.length - 1]) }
              : {}),
          },
        ]
      : [];
  return {
    score,
    evidence: { exposures },
    signals,
    modelVersion: config.modelVersion,
  };
}
