import { createHash } from "node:crypto";

import type {
  BaselineReadiness,
  RuntimeRiskEvent,
  RuntimeRiskHop,
  RuntimeRiskSeverity,
  RuntimeStateScope,
} from "./types";

export const RUNTIME_STATE_SCOPES: readonly RuntimeStateScope[] = [
  "AGENT",
  "BOUNDARY",
  "SERVER",
  "MCP_SERVER",
  "TOOL",
  "ORCHESTRATOR",
];

export function clamp(value: number, minimum: number, maximum: number): number {
  if (!Number.isFinite(value)) return minimum;
  return Math.max(minimum, Math.min(maximum, value));
}

export function clamp01(value: number): number {
  return clamp(value, 0, 1);
}

export function mean(values: readonly number[]): number {
  if (values.length === 0) return 0;
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

export function standardDeviation(
  values: readonly number[],
  providedMean?: number,
): number {
  if (values.length < 2) return 0;
  const average = providedMean ?? mean(values);
  const variance =
    values.reduce((sum, value) => sum + (value - average) ** 2, 0) /
    (values.length - 1);
  return Math.sqrt(Math.max(0, variance));
}

export function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export type FiniteConfigNumberOptions = {
  minimum?: number;
  maximum?: number;
  integer?: boolean;
  exclusiveMinimum?: boolean;
};

export function finiteConfigNumber(
  value: unknown,
  label: string,
  options: FiniteConfigNumberOptions = {},
): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new TypeError(`${label} must be a finite number`);
  }
  if (options.integer && !Number.isInteger(value)) {
    throw new TypeError(`${label} must be an integer`);
  }
  if (
    options.minimum !== undefined &&
    (options.exclusiveMinimum
      ? value <= options.minimum
      : value < options.minimum)
  ) {
    throw new RangeError(
      `${label} must be ${
        options.exclusiveMinimum ? "greater than" : "at least"
      } ${options.minimum}`,
    );
  }
  if (options.maximum !== undefined && value > options.maximum) {
    throw new RangeError(`${label} must be at most ${options.maximum}`);
  }
  return value;
}

export function safeModelVersion(value: unknown): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new TypeError("runtime risk modelVersion must be a non-empty string");
  }
  return safeIdentifier(value);
}

function stableValue(value: unknown, seen: Set<object>, depth: number): unknown {
  if (depth > 8) return "[depth-limit]";
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (typeof value === "number") {
    return Number.isFinite(value) ? value : String(value);
  }
  if (typeof value === "bigint") return value.toString();
  if (
    typeof value === "undefined" ||
    typeof value === "function" ||
    typeof value === "symbol"
  ) {
    return String(value);
  }
  if (value instanceof Date) return Number.isFinite(value.getTime()) ? value.toISOString() : "";
  if (typeof value !== "object") return String(value);
  if (seen.has(value)) return "[circular]";
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      return value.slice(0, 100).map((entry) => stableValue(entry, seen, depth + 1));
    }
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .slice(0, 100)
        .map(([key, entry]) => [key, stableValue(entry, seen, depth + 1)]),
    );
  } finally {
    seen.delete(value);
  }
}

export function privacyHash(value: unknown): string {
  return sha256Hex(JSON.stringify(stableValue(value, new Set(), 0)));
}

const RFC3339_TIMESTAMP =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|([+-])(\d{2}):(\d{2}))$/;

export function timestampMilliseconds(timestamp: string): number {
  if (typeof timestamp !== "string") {
    throw new TypeError(
      "runtime risk timestamps must be RFC3339 strings with an explicit zone",
    );
  }
  const match = RFC3339_TIMESTAMP.exec(timestamp);
  if (!match) {
    throw new TypeError(
      "runtime risk timestamps must be RFC3339 strings with an explicit zone",
    );
  }
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const millisecond = Number((match[7] ?? "").padEnd(3, "0").slice(0, 3));
  const offsetHour = match[8] === "Z" ? 0 : Number(match[10]);
  const offsetMinute = match[8] === "Z" ? 0 : Number(match[11]);
  const leapYear =
    year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const daysInMonth = [
    31,
    leapYear ? 29 : 28,
    31,
    30,
    31,
    30,
    31,
    31,
    30,
    31,
    30,
    31,
  ];
  if (
    year === 0 ||
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > daysInMonth[month - 1] ||
    hour > 23 ||
    minute > 59 ||
    second > 59 ||
    offsetHour > 23 ||
    offsetMinute > 59
  ) {
    throw new TypeError("runtime risk timestamp is not a valid RFC3339 instant");
  }
  const localDate = new Date(0);
  localDate.setUTCFullYear(year, month - 1, day);
  localDate.setUTCHours(hour, minute, second, millisecond);
  const localMilliseconds = localDate.getTime();
  const offsetSign = match[8] === "Z" || match[9] === "+" ? 1 : -1;
  const milliseconds =
    localMilliseconds -
    offsetSign * (offsetHour * 60 + offsetMinute) * 60_000;
  if (!Number.isFinite(milliseconds)) {
    throw new TypeError("runtime risk timestamp is outside the supported range");
  }
  return milliseconds;
}

export function toIso(timestamp: string): string {
  return new Date(timestampMilliseconds(timestamp)).toISOString();
}

export function compareEvents(
  left: RuntimeRiskEvent,
  right: RuntimeRiskEvent,
): number {
  const timeDifference =
    timestampMilliseconds(left.timestamp) -
    timestampMilliseconds(right.timestamp);
  return timeDifference || left.id.localeCompare(right.id);
}

export function sortedEvents(
  events: readonly RuntimeRiskEvent[],
): RuntimeRiskEvent[] {
  assertUniqueEventIds(events);
  return [...events].sort(compareEvents);
}

export function assertUniqueEventIds(
  events: readonly RuntimeRiskEvent[],
): void {
  const seen = new Set<string>();
  for (const event of events) {
    if (typeof event?.id !== "string" || !event.id.trim()) {
      throw new TypeError("runtime risk event IDs must be non-empty strings");
    }
    if (event.id !== event.id.trim()) {
      throw new TypeError(
        "runtime risk event IDs must not contain surrounding whitespace",
      );
    }
    const normalized = safeIdentifier(event.id);
    if (seen.has(normalized)) {
      throw new TypeError("runtime risk event IDs must be unique");
    }
    seen.add(normalized);
  }
}

export function toHop(event: RuntimeRiskEvent): RuntimeRiskHop {
  return {
    eventId: safeIdentifier(event.id),
    timestamp: toIso(event.timestamp),
    ...(event.traceId ? { traceId: safeIdentifier(event.traceId) } : {}),
    ...(event.spanId ? { spanId: safeIdentifier(event.spanId) } : {}),
    ...(event.causeTraceId
      ? { causeTraceId: safeIdentifier(event.causeTraceId) }
      : {}),
    ...(event.causeSpanId
      ? { causeSpanId: safeIdentifier(event.causeSpanId) }
      : {}),
  };
}

export function severityFromScore(score: number): RuntimeRiskSeverity {
  const bounded = clamp(score, 0, 100);
  if (bounded >= 80) return "critical";
  if (bounded >= 60) return "high";
  if (bounded >= 40) return "medium";
  return "low";
}

export function severityScore(severity: RuntimeRiskSeverity): number {
  switch (severity) {
    case "critical":
      return 50;
    case "high":
      return 35;
    case "medium":
      return 20;
    case "low":
      return 10;
    default:
      return 50;
  }
}

export function stripToolVersion(tool: string): string {
  const normalized = String(tool || "").trim();
  if (!normalized) return "";
  const separator = normalized.lastIndexOf("@");
  if (separator <= 0) return normalized;
  const suffix = normalized.slice(separator + 1);
  return /^\d+(\.\d+){0,3}([+-][A-Za-z0-9._-]+)?$/.test(suffix)
    ? normalized.slice(0, separator)
    : normalized;
}

export function getScopeState(
  state: RuntimeRiskEvent["state"],
  scope: RuntimeStateScope,
): Record<string, unknown> | undefined {
  const value = state?.[scope];
  return value && typeof value === "object" && !Array.isArray(value)
    ? value
    : undefined;
}

export function extractRiskTags(event: RuntimeRiskEvent): string[] {
  const tags = new Set<string>();
  for (const tag of event.riskTags ?? []) {
    const normalized = String(tag || "").trim();
    if (normalized) tags.add(normalized);
  }
  for (const scope of RUNTIME_STATE_SCOPES) {
    const values = getScopeState(event.state, scope);
    const scopedTags = values?.risk_tags;
    if (!Array.isArray(scopedTags)) continue;
    for (const tag of scopedTags) {
      const normalized = typeof tag === "string" ? tag.trim() : "";
      if (normalized) tags.add(normalized);
    }
  }
  return [...tags].sort();
}

export function looksSensitiveString(value: string): boolean {
  const bounded = value.trim().slice(0, 2048);
  if (!bounded) return false;
  return (
    /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i.test(bounded) ||
    /\b(?:sk|pk)-[A-Za-z0-9_-]{12,}\b/.test(bounded) ||
    /\bAKIA[0-9A-Z]{16}\b/.test(bounded) ||
    /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/.test(
      bounded,
    ) ||
    (/[A-Za-z0-9_-]{32,}/.test(bounded) &&
      /[A-Za-z]/.test(bounded) &&
      /\d/.test(bounded))
  );
}

export function safeIdentifier(value: unknown): string {
  const normalized = String(value ?? "").trim();
  if (!normalized) return "unknown";
  if (
    normalized.length <= 128 &&
    /^[A-Za-z0-9_.:@/-]+$/.test(normalized) &&
    !looksSensitiveString(normalized)
  ) {
    return normalized;
  }
  return `sha256:${sha256Hex(normalized)}`;
}

export function safeCode(value: unknown): string {
  const raw = String(value ?? "").trim();
  const normalized = raw
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_.:-]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 96);
  if (!normalized) return "unknown";
  return raw.length > 96 || looksSensitiveString(raw)
    ? `sha256:${sha256Hex(raw)}`
    : normalized;
}

export function baselineReadiness(
  events: readonly RuntimeRiskEvent[],
  minimumEventCount: number,
  minimumRunCount: number,
): BaselineReadiness {
  for (const event of events) timestampMilliseconds(event.timestamp);
  const eventCount = events.length;
  const runCount = new Set(
    events.map((event) => event.runId.trim()).filter(Boolean),
  ).size;
  const requiredEvents = Math.max(0, Math.floor(minimumEventCount));
  const requiredRuns = Math.max(0, Math.floor(minimumRunCount));
  if (eventCount < requiredEvents) {
    return {
      ready: false,
      eventCount,
      runCount,
      minimumEventCount: requiredEvents,
      minimumRunCount: requiredRuns,
      reason: "insufficient_events",
    };
  }
  if (runCount < requiredRuns) {
    return {
      ready: false,
      eventCount,
      runCount,
      minimumEventCount: requiredEvents,
      minimumRunCount: requiredRuns,
      reason: "insufficient_runs",
    };
  }
  return {
    ready: true,
    eventCount,
    runCount,
    minimumEventCount: requiredEvents,
    minimumRunCount: requiredRuns,
  };
}

export type FlattenStringOptions = {
  maxDepth: number;
  maxKeys: number;
  maxCharacters: number;
  includeScopes: RuntimeStateScope[];
  allowlistKeys?: ReadonlySet<string>;
  excludeLeafKeys?: ReadonlySet<string>;
};

export function flattenStringValues(
  state: RuntimeRiskEvent["state"],
  options: FlattenStringOptions,
): Map<string, { value: string; characterLength: number }> {
  const output = new Map<
    string,
    { value: string; characterLength: number }
  >();
  if (!state || typeof state !== "object") return output;

  const maximumDepth = Math.max(1, Math.floor(options.maxDepth));
  const maximumKeys = Math.max(1, Math.floor(options.maxKeys));
  const maximumCharacters = Math.max(
    32,
    Math.floor(options.maxCharacters),
  );
  const excluded = new Set(
    [...(options.excludeLeafKeys ?? [])].map((key) => key.toLowerCase()),
  );

  const add = (rawKey: string, rawValue: string): void => {
    if (
      output.size >= maximumKeys ||
      options.allowlistKeys?.has(rawKey) === false
    ) {
      return;
    }
    const value = rawValue.slice(0, maximumCharacters);
    if (!value.trim()) return;
    const leaf = rawKey.split(".").at(-1)?.toLowerCase() ?? "";
    if (excluded.has(leaf)) return;
    output.set(safeIdentifier(rawKey), {
      value,
      characterLength: value.length,
    });
  };

  const walk = (
    scope: RuntimeStateScope,
    value: unknown,
    path: string[],
    depth: number,
  ): void => {
    if (output.size >= maximumKeys || depth > maximumDepth || value == null) {
      return;
    }
    if (typeof value === "string") {
      add(`${scope}:${path.join(".")}`, value);
      return;
    }
    if (Array.isArray(value)) {
      const strings = value.filter(
        (entry): entry is string => typeof entry === "string",
      );
      if (strings.length > 0) add(`${scope}:${path.join(".")}`, strings.join(" "));
      return;
    }
    if (typeof value !== "object") return;
    for (const [key, entry] of Object.entries(
      value as Record<string, unknown>,
    ).sort(([left], [right]) => left.localeCompare(right))) {
      walk(scope, entry, [...path, key], depth + 1);
      if (output.size >= maximumKeys) return;
    }
  };

  for (const scope of options.includeScopes) {
    const scopedState = getScopeState(state, scope);
    if (scopedState) walk(scope, scopedState, [], 0);
    if (output.size >= maximumKeys) break;
  }
  return output;
}
