import type {
  MandateDeviationEvidence,
  RiskComputationResult,
  RuntimeRiskEvent,
} from "./types";
import {
  clamp,
  extractRiskTags,
  finiteConfigNumber,
  looksSensitiveString,
  safeCode,
  safeIdentifier,
  safeModelVersion,
  severityFromScore,
  sha256Hex,
  sortedEvents,
  toHop,
} from "./util";

export type MandateDeviationConfig = {
  modelVersion: string;
  aggregateSignalThreshold: number;
  violationScore: number;
  maximumViolations: number;
};

export const DEFAULT_MANDATE_DEVIATION_CONFIG: MandateDeviationConfig =
  Object.freeze({
    modelVersion: "coreax-runtime-risk-v1",
    aggregateSignalThreshold: 60,
    violationScore: 40,
    maximumViolations: 20,
  });

export type MandateDeviationInput = {
  nodeId: string;
  events: readonly RuntimeRiskEvent[];
  config?: Partial<MandateDeviationConfig>;
};

function resolvedConfig(
  overrides: Partial<MandateDeviationConfig> | undefined,
): MandateDeviationConfig {
  const merged = { ...DEFAULT_MANDATE_DEVIATION_CONFIG, ...overrides };
  return {
    ...merged,
    modelVersion: safeModelVersion(merged.modelVersion),
    aggregateSignalThreshold: finiteConfigNumber(
      merged.aggregateSignalThreshold,
      "mandateDeviation.aggregateSignalThreshold",
      { minimum: 0, maximum: 100 },
    ),
    violationScore: finiteConfigNumber(
      merged.violationScore,
      "mandateDeviation.violationScore",
      { minimum: 1, maximum: 100 },
    ),
    maximumViolations: finiteConfigNumber(
      merged.maximumViolations,
      "mandateDeviation.maximumViolations",
      { minimum: 1, maximum: 10_000, integer: true },
    ),
  };
}

function isMandateViolationCode(value: string): boolean {
  const normalized = value.trim().toLowerCase();
  return (
    normalized.startsWith("ap2_") ||
    normalized.includes("ap2_mandate") ||
    normalized === "mandate_missing" ||
    normalized === "mandate_invalid"
  );
}

function privacyPreservingCode(value: string): string {
  if (looksSensitiveString(value)) return `sha256:${sha256Hex(value)}`;
  const normalized = safeCode(value);
  return /^ap2_[a-z0-9_.:-]{1,64}$/.test(normalized) ||
    normalized === "mandate_missing" ||
    normalized === "mandate_invalid" ||
    CONTEXT_DEVIATION_CODES.has(normalized)
    ? normalized
    : `sha256:${sha256Hex(value)}`;
}

function hashIfPresent(value: string | undefined): string | undefined {
  const normalized = value?.trim();
  return normalized ? sha256Hex(normalized) : undefined;
}

function canonicalDigest(value: string | undefined): string | undefined {
  const normalized = value?.trim();
  if (!normalized) return undefined;
  return /^[a-f0-9]{64}$/i.test(normalized)
    ? normalized.toLowerCase()
    : sha256Hex(normalized);
}

const CONTEXT_FIELDS = [
  "intentId",
  "cartId",
  "issuerDid",
  "subjectDid",
  "constraintsSha256",
  "cartSha256",
] as const;

type MandateContextField = (typeof CONTEXT_FIELDS)[number];

const CONTEXT_DEVIATION_CODE: Record<MandateContextField, string> = {
  intentId: "mandate_intent_changed",
  cartId: "mandate_cart_changed",
  issuerDid: "mandate_issuer_changed",
  subjectDid: "mandate_subject_changed",
  constraintsSha256: "mandate_constraints_changed",
  cartSha256: "mandate_cart_digest_changed",
};

const CONTEXT_MISSING_CODE: Record<MandateContextField, string> = {
  intentId: "mandate_intent_missing",
  cartId: "mandate_cart_missing",
  issuerDid: "mandate_issuer_missing",
  subjectDid: "mandate_subject_missing",
  constraintsSha256: "mandate_constraints_missing",
  cartSha256: "mandate_cart_digest_missing",
};

const CONTEXT_DEVIATION_CODES = new Set(
  [
    ...Object.values(CONTEXT_DEVIATION_CODE),
    ...Object.values(CONTEXT_MISSING_CODE),
  ],
);

function mandateContextDigest(
  mandate: RuntimeRiskEvent["mandate"],
  field: MandateContextField,
): string | undefined {
  const value = mandate?.[field];
  return field === "constraintsSha256" || field === "cartSha256"
    ? canonicalDigest(value)
    : hashIfPresent(value);
}

export function computeMandateDeviation(
  input: MandateDeviationInput,
): RiskComputationResult<MandateDeviationEvidence> {
  const config = resolvedConfig(input.config);
  const events = sortedEvents(input.events);
  const expectedContext = new Map<MandateContextField, string>();
  const contextFirstSeenAt = new Map<MandateContextField, number>();
  for (let index = 0; index < events.length; index += 1) {
    const event = events[index];
    for (const field of CONTEXT_FIELDS) {
      const digest = mandateContextDigest(event.mandate, field);
      if (digest && !expectedContext.has(field)) {
        expectedContext.set(field, digest);
        contextFirstSeenAt.set(field, index);
      }
    }
  }
  const context: MandateDeviationEvidence["context"] = {
    ...(expectedContext.get("intentId")
      ? { intentIdSha256: expectedContext.get("intentId") }
      : {}),
    ...(expectedContext.get("cartId")
      ? { cartIdSha256: expectedContext.get("cartId") }
      : {}),
    ...(expectedContext.get("issuerDid")
      ? { issuerDidSha256: expectedContext.get("issuerDid") }
      : {}),
    ...(expectedContext.get("subjectDid")
      ? { subjectDidSha256: expectedContext.get("subjectDid") }
      : {}),
    ...(expectedContext.get("constraintsSha256")
      ? { constraintsSha256: expectedContext.get("constraintsSha256") }
      : {}),
    ...(expectedContext.get("cartSha256")
      ? { cartSha256: expectedContext.get("cartSha256") }
      : {}),
  };

  const violations: MandateDeviationEvidence["violations"] = [];
  const seen = new Set<string>();
  const addViolation = (
    event: RuntimeRiskEvent,
    rawCode: string,
    source: MandateDeviationEvidence["violations"][number]["source"],
  ): void => {
    if (violations.length >= Math.max(0, config.maximumViolations)) return;
    const code = privacyPreservingCode(rawCode);
    const identity = `${event.id}:${source}:${code}`;
    if (seen.has(identity)) return;
    seen.add(identity);
    violations.push({ code, hop: toHop(event), source });
  };

  for (let index = 0; index < events.length; index += 1) {
    const event = events[index];
    for (const field of CONTEXT_FIELDS) {
      const current = mandateContextDigest(event.mandate, field);
      const expected = expectedContext.get(field);
      const firstSeenAt = contextFirstSeenAt.get(field);
      if (
        expected &&
        firstSeenAt !== undefined &&
        index > firstSeenAt &&
        !current
      ) {
        addViolation(event, CONTEXT_MISSING_CODE[field], "context");
      } else if (current && expected && current !== expected) {
        addViolation(
          event,
          CONTEXT_DEVIATION_CODE[field],
          "context",
        );
      }
    }
    for (const violation of event.mandate?.violations ?? []) {
      addViolation(event, violation, "mandate");
    }
    const reason = event.reasonCode ?? "";
    if (isMandateViolationCode(reason)) addViolation(event, reason, "reason");
    for (const tag of extractRiskTags(event)) {
      if (isMandateViolationCode(tag)) addViolation(event, tag, "risk_tag");
    }
  }

  const score = clamp(
    violations.length * Math.max(0, config.violationScore),
    0,
    100,
  );
  const signals =
    score >= config.aggregateSignalThreshold && violations.length > 0
      ? [
          {
            code: "mandate_deviation:aggregate",
            subtype: "mandate_deviation" as const,
            severity: severityFromScore(score),
            score,
            title: "Mandate deviation",
            message: `${violations.length} mandate deviations for node ${safeIdentifier(input.nodeId)}`,
            evidence: { violationCount: violations.length },
            ...(events.length > 0
              ? { hop: toHop(events[events.length - 1]) }
              : {}),
          },
        ]
      : [];
  return {
    score,
    evidence: { context, violations },
    signals,
    modelVersion: config.modelVersion,
  };
}
