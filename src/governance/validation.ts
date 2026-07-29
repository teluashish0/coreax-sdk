import { createHash } from "node:crypto";

import { GovernanceValidationError } from "./errors";
import type {
  GovernanceJsonObject,
  GovernanceJsonValue,
} from "./types";

export function requiredString(value: unknown, label: string): string {
  const normalized = typeof value === "string" ? value.trim() : "";
  if (!normalized) {
    throw new GovernanceValidationError(`${label} is required`);
  }
  return normalized;
}

export function optionalString(
  value: unknown,
  label: string,
): string | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string") {
    throw new GovernanceValidationError(`${label} must be a string`);
  }
  return value.trim() || undefined;
}

export function timestampMs(value: unknown, label: string): number {
  if (typeof value !== "string" || !value.trim()) {
    throw new GovernanceValidationError(
      `${label} must be an RFC3339 timestamp with an explicit timezone`,
    );
  }
  const match =
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-](\d{2}):(\d{2}))$/.exec(
      value,
    );
  if (!match) {
    throw new GovernanceValidationError(
      `${label} must be an RFC3339 timestamp with an explicit timezone`,
    );
  }
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const offsetHour = match[9] === undefined ? 0 : Number(match[9]);
  const offsetMinute = match[10] === undefined ? 0 : Number(match[10]);
  const calendarCheck = new Date(Date.UTC(year, month - 1, day));
  const parsed = Date.parse(value);
  if (
    year < 1 ||
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > 31 ||
    hour > 23 ||
    minute > 59 ||
    second > 59 ||
    offsetHour > 23 ||
    offsetMinute > 59 ||
    calendarCheck.getUTCFullYear() !== year ||
    calendarCheck.getUTCMonth() !== month - 1 ||
    calendarCheck.getUTCDate() !== day ||
    !Number.isFinite(parsed)
  ) {
    throw new GovernanceValidationError(
      `${label} must be an RFC3339 timestamp with an explicit timezone`,
    );
  }
  return parsed;
}

export function isoTimestamp(value: number, label: string): string {
  if (!Number.isFinite(value)) {
    throw new GovernanceValidationError(`${label} is not a valid timestamp`);
  }
  try {
    return new Date(value).toISOString();
  } catch {
    throw new GovernanceValidationError(`${label} is not a valid timestamp`);
  }
}

function assertJsonValue(
  value: unknown,
  label: string,
  ancestors: Set<object>,
): asserts value is GovernanceJsonValue {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new GovernanceValidationError(
        `${label} contains a non-finite number`,
      );
    }
    return;
  }
  if (typeof value !== "object") {
    throw new GovernanceValidationError(
      `${label} must contain only JSON values`,
    );
  }
  if (ancestors.has(value)) {
    throw new GovernanceValidationError(`${label} must not contain cycles`);
  }
  ancestors.add(value);
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      assertJsonValue(value[index], `${label}[${index}]`, ancestors);
    }
  } else {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new GovernanceValidationError(
        `${label} must contain plain objects`,
      );
    }
    for (const key of Object.keys(value)) {
      assertJsonValue(
        (value as Record<string, unknown>)[key],
        `${label}.${key}`,
        ancestors,
      );
    }
  }
  ancestors.delete(value);
}

function sortJson(value: GovernanceJsonValue): GovernanceJsonValue {
  if (Array.isArray(value)) return value.map(sortJson);
  if (value && typeof value === "object") {
    const sorted = Object.create(null) as GovernanceJsonObject;
    for (const key of Object.keys(value).sort()) {
      sorted[key] = sortJson(value[key]!);
    }
    return sorted;
  }
  return value;
}

export function canonicalGovernanceJson(value: unknown): string {
  assertJsonValue(value, "value", new Set<object>());
  return JSON.stringify(sortJson(value));
}

export function normalizeGovernanceJsonObject(
  value: unknown,
  label: string,
): GovernanceJsonObject {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new GovernanceValidationError(`${label} must be a JSON object`);
  }
  assertJsonValue(value, label, new Set<object>());
  return JSON.parse(canonicalGovernanceJson(value)) as GovernanceJsonObject;
}

export function cloneGovernanceValue<T>(value: T): T {
  return JSON.parse(canonicalGovernanceJson(value)) as T;
}

export function governanceValuesEqual(left: unknown, right: unknown): boolean {
  try {
    return canonicalGovernanceJson(left) === canonicalGovernanceJson(right);
  } catch {
    return false;
  }
}

export function governanceSha256(value: unknown): string {
  return createHash("sha256")
    .update(
      typeof value === "string"
        ? value
        : canonicalGovernanceJson(value),
      "utf8",
    )
    .digest("hex");
}

const SENSITIVE_KEY =
  /(?:^|[_-])(?:authorization|cookie|password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|client[_-]?secret)(?:$|[_-])/i;
const SENSITIVE_STRING_PATTERNS = [
  /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/i,
  /\b(?:password|passwd|pwd|secret|token|api[_-]?key|authorization)\s*[:=]\s*\S+/i,
  /\bAKIA[A-Z0-9]{16}\b/,
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/,
  /\bsk-[A-Za-z0-9_-]{16,}\b/,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /\b[a-z][a-z0-9+.-]*:\/\/[^/\s:@]+:[^/\s@]+@/i,
];

function redactionMarker(value: unknown): string {
  return `[REDACTED sha256:${governanceSha256(value)}]`;
}

function redactGovernanceValue(
  value: GovernanceJsonValue,
  key = "",
): GovernanceJsonValue {
  if (SENSITIVE_KEY.test(key)) return redactionMarker(value);
  if (typeof value === "string") {
    return SENSITIVE_STRING_PATTERNS.some((pattern) => pattern.test(value))
      ? redactionMarker(value)
      : value;
  }
  if (Array.isArray(value)) {
    return value.map((entry) => redactGovernanceValue(entry));
  }
  if (value && typeof value === "object") {
    const redacted = Object.create(null) as GovernanceJsonObject;
    for (const [entryKey, entryValue] of Object.entries(value)) {
      redacted[entryKey] = redactGovernanceValue(entryValue, entryKey);
    }
    return redacted;
  }
  return value;
}

export function governancePersistenceProjection<T>(value: T): T {
  assertJsonValue(value, "value", new Set<object>());
  return JSON.parse(
    canonicalGovernanceJson(
      redactGovernanceValue(value as unknown as GovernanceJsonValue),
    ),
  ) as T;
}

export function governanceHashOnlyObject(
  value: GovernanceJsonObject,
): GovernanceJsonObject {
  return {
    redacted: true,
    sha256: governanceSha256(value),
  };
}

export function isGovernanceHashOnlyObject(
  value: GovernanceJsonObject | null | undefined,
): boolean {
  if (!value) return false;
  const keys = Object.keys(value).sort();
  return (
    keys.length === 2 &&
    keys[0] === "redacted" &&
    keys[1] === "sha256" &&
    value.redacted === true &&
    typeof value.sha256 === "string" &&
    /^[a-f0-9]{64}$/.test(value.sha256)
  );
}

export function stringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.map((entry) => String(entry).trim()).filter(Boolean))];
}
