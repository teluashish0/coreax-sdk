import { createHash } from "node:crypto";

import { EscalationValidationError } from "./errors";
import type {
  EscalationJsonObject,
  EscalationJsonValue,
  EscalationRequest,
  EscalationResolution,
} from "./types";

export function requiredString(value: unknown, label: string): string {
  const normalized = typeof value === "string" ? value.trim() : "";
  if (!normalized) {
    throw new EscalationValidationError(`${label} is required`);
  }
  return normalized;
}

export function optionalString(value: unknown, label: string): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string") {
    throw new EscalationValidationError(`${label} must be a string`);
  }
  const normalized = value.trim();
  return normalized || undefined;
}

export function timestampMs(value: unknown, label: string): number {
  if (typeof value !== "string" || !value.trim()) {
    throw new EscalationValidationError(
      `${label} must be an RFC3339 timestamp with an explicit timezone`,
    );
  }
  const match =
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-](\d{2}):(\d{2}))$/.exec(
      value,
    );
  const milliseconds = Date.parse(value);
  if (!match || !Number.isFinite(milliseconds)) {
    throw new EscalationValidationError(
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
    calendarCheck.getUTCDate() !== day
  ) {
    throw new EscalationValidationError(
      `${label} must be an RFC3339 timestamp with an explicit timezone`,
    );
  }
  return milliseconds;
}

function assertJsonValue(
  value: unknown,
  label: string,
  ancestors: Set<object>,
): asserts value is EscalationJsonValue {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new EscalationValidationError(`${label} contains a non-finite number`);
    }
    return;
  }
  if (typeof value !== "object") {
    throw new EscalationValidationError(`${label} must contain only JSON values`);
  }
  if (ancestors.has(value)) {
    throw new EscalationValidationError(`${label} must not contain cycles`);
  }
  ancestors.add(value);
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      assertJsonValue(value[index], `${label}[${index}]`, ancestors);
    }
  } else {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new EscalationValidationError(`${label} must contain plain objects`);
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

export function normalizeJsonObject(
  value: unknown,
  label: string,
): EscalationJsonObject {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new EscalationValidationError(`${label} must be a JSON object`);
  }
  assertJsonValue(value, label, new Set<object>());
  return JSON.parse(canonicalJson(value)) as EscalationJsonObject;
}

function sortJson(value: EscalationJsonValue): EscalationJsonValue {
  if (Array.isArray(value)) {
    return value.map(sortJson);
  }
  if (value && typeof value === "object") {
    const sorted = Object.create(null) as EscalationJsonObject;
    for (const key of Object.keys(value).sort()) {
      sorted[key] = sortJson(value[key]!);
    }
    return sorted;
  }
  return value;
}

export function canonicalJson(value: unknown): string {
  assertJsonValue(value, "value", new Set<object>());
  return JSON.stringify(sortJson(value));
}

export function sha256(value: string | Uint8Array): string {
  return createHash("sha256")
    .update(typeof value === "string" ? Buffer.from(value, "utf8") : value)
    .digest("hex");
}

export function sameValue(left: unknown, right: unknown): boolean {
  try {
    return canonicalJson(left) === canonicalJson(right);
  } catch {
    return false;
  }
}

export function validateEscalationRequest(
  value: unknown,
): asserts value is EscalationRequest {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new EscalationValidationError("Escalation request must be an object");
  }
  const request = value as Record<string, unknown>;
  requiredString(request.id, "request.id");
  requiredString(request.action, "request.action");
  normalizeJsonObject(request.scope, "request.scope");
  requiredString(request.reason, "request.reason");
  optionalString(request.requestedBy, "request.requestedBy");
  if (request.metadata !== undefined) {
    normalizeJsonObject(request.metadata, "request.metadata");
  }
  const createdAt = timestampMs(request.createdAt, "request.createdAt");
  const expiresAt = timestampMs(request.expiresAt, "request.expiresAt");
  if (expiresAt <= createdAt) {
    throw new EscalationValidationError(
      "request.expiresAt must be later than request.createdAt",
    );
  }
}

export function validateEscalationResolution(
  value: unknown,
): asserts value is EscalationResolution {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new EscalationValidationError("Escalation resolution must be an object");
  }
  const resolution = value as Record<string, unknown>;
  requiredString(resolution.id, "resolution.id");
  requiredString(resolution.escalationId, "resolution.escalationId");
  if (resolution.decision !== "approve" && resolution.decision !== "reject") {
    throw new EscalationValidationError(
      'resolution.decision must be "approve" or "reject"',
    );
  }
  requiredString(resolution.resolvedBy, "resolution.resolvedBy");
  optionalString(resolution.notes, "resolution.notes");
  if (resolution.metadata !== undefined) {
    normalizeJsonObject(resolution.metadata, "resolution.metadata");
  }
  timestampMs(resolution.resolvedAt, "resolution.resolvedAt");
}
