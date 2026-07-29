import {
  sign as signBytes,
  verify as verifyBytes,
  type KeyLike,
} from "node:crypto";

import { stableDigest, stableSerialize } from "./math";

export type PolicyVersionOperation = "promote" | "rollback";

export interface UnsignedPolicyOperationAuthorization {
  format: "coreax_policy_operation_v1";
  operation: PolicyVersionOperation;
  subject: string;
  targetVersion: string;
  policyDigest: string;
  expectedActiveVersion: string;
  nonce: string;
  keyId: string;
  issuedAt: string;
  expiresAt: string;
}

export interface PolicyOperationAuthorization
  extends UnsignedPolicyOperationAuthorization {
  signature: string;
}

export interface PolicyAuthorizationVerification {
  valid: boolean;
  reason?:
    | "invalid_format"
    | "unknown_key"
    | "invalid_time"
    | "not_yet_valid"
    | "expired"
    | "invalid_signature";
  fingerprint: string;
}

const RFC3339_TIMESTAMP =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|([+-])(\d{2}):(\d{2}))$/;

/**
 * Parses the deliberately narrow timestamp format accepted by signed policy
 * operations. Ambiguous local times, date-only strings, and numeric epochs are
 * not valid authorization data.
 */
export function parsePolicyRfc3339Timestamp(value: string): number | null {
  const match = RFC3339_TIMESTAMP.exec(value);
  if (!match) return null;

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
    return null;
  }

  const localDate = new Date(0);
  localDate.setUTCFullYear(year, month - 1, day);
  localDate.setUTCHours(hour, minute, second, millisecond);
  const localMilliseconds = localDate.getTime();
  const offsetSign = match[8] === "Z" || match[9] === "+" ? 1 : -1;
  const offsetMilliseconds =
    offsetSign * (offsetHour * 60 + offsetMinute) * 60_000;
  const timestamp = localMilliseconds - offsetMilliseconds;
  return Number.isFinite(timestamp) ? timestamp : null;
}

function authorizationPayload(
  authorization: UnsignedPolicyOperationAuthorization,
): string {
  return stableSerialize({
    format: authorization.format,
    operation: authorization.operation,
    subject: authorization.subject,
    targetVersion: authorization.targetVersion,
    policyDigest: authorization.policyDigest,
    expectedActiveVersion: authorization.expectedActiveVersion,
    nonce: authorization.nonce,
    keyId: authorization.keyId,
    issuedAt: authorization.issuedAt,
    expiresAt: authorization.expiresAt,
  });
}

export function policyAuthorizationFingerprint(
  authorization: PolicyOperationAuthorization,
): string {
  const scalar = (value: unknown): string =>
    typeof value === "string" ? value : `[invalid:${typeof value}]`;
  return stableDigest({
    format: scalar(authorization.format),
    operation: scalar(authorization.operation),
    subject: scalar(authorization.subject),
    targetVersion: scalar(authorization.targetVersion),
    policyDigest: scalar(authorization.policyDigest),
    expectedActiveVersion: scalar(authorization.expectedActiveVersion),
    nonce: scalar(authorization.nonce),
    keyId: scalar(authorization.keyId),
    issuedAt: scalar(authorization.issuedAt),
    expiresAt: scalar(authorization.expiresAt),
    signature: scalar(authorization.signature),
  });
}

function validateRequiredStrings(
  authorization: UnsignedPolicyOperationAuthorization,
): boolean {
  return [
    authorization.subject,
    authorization.targetVersion,
    authorization.policyDigest,
    authorization.expectedActiveVersion,
    authorization.nonce,
    authorization.keyId,
    authorization.issuedAt,
    authorization.expiresAt,
  ].every((value) => typeof value === "string" && value.trim().length > 0);
}

export function signPolicyOperationAuthorization(input: {
  authorization: UnsignedPolicyOperationAuthorization;
  privateKey: KeyLike;
}): PolicyOperationAuthorization {
  const requiredStringsValid = validateRequiredStrings(input.authorization);
  const issuedAt = requiredStringsValid
    ? parsePolicyRfc3339Timestamp(input.authorization.issuedAt)
    : null;
  const expiresAt = requiredStringsValid
    ? parsePolicyRfc3339Timestamp(input.authorization.expiresAt)
    : null;
  if (
    input.authorization.format !== "coreax_policy_operation_v1" ||
    !requiredStringsValid ||
    issuedAt === null ||
    expiresAt === null ||
    expiresAt <= issuedAt
  ) {
    throw new Error("invalid_policy_authorization");
  }
  const signature = signBytes(
    null,
    Buffer.from(authorizationPayload(input.authorization), "utf8"),
    input.privateKey,
  ).toString("base64url");
  return {
    format: input.authorization.format,
    operation: input.authorization.operation,
    subject: input.authorization.subject,
    targetVersion: input.authorization.targetVersion,
    policyDigest: input.authorization.policyDigest,
    expectedActiveVersion: input.authorization.expectedActiveVersion,
    nonce: input.authorization.nonce,
    keyId: input.authorization.keyId,
    issuedAt: input.authorization.issuedAt,
    expiresAt: input.authorization.expiresAt,
    signature,
  };
}

export function verifyPolicyOperationAuthorization(input: {
  authorization: PolicyOperationAuthorization;
  publicKeys: Readonly<Record<string, KeyLike>>;
  now: Date | string;
  maxClockSkewMs?: number;
}): PolicyAuthorizationVerification {
  const fingerprint = policyAuthorizationFingerprint(input.authorization);
  const authorization = input.authorization;

  if (
    authorization.format !== "coreax_policy_operation_v1" ||
    (authorization.operation !== "promote" &&
      authorization.operation !== "rollback") ||
    !validateRequiredStrings(authorization) ||
    typeof authorization.signature !== "string" ||
    authorization.signature.length === 0
  ) {
    return { valid: false, reason: "invalid_format", fingerprint };
  }

  const publicKey = Object.prototype.hasOwnProperty.call(
    input.publicKeys,
    authorization.keyId,
  )
    ? input.publicKeys[authorization.keyId]
    : undefined;
  if (!publicKey) {
    return { valid: false, reason: "unknown_key", fingerprint };
  }

  const issuedAt = parsePolicyRfc3339Timestamp(authorization.issuedAt);
  const expiresAt = parsePolicyRfc3339Timestamp(authorization.expiresAt);
  const now =
    input.now instanceof Date
      ? input.now.getTime()
      : parsePolicyRfc3339Timestamp(input.now);
  if (
    issuedAt === null ||
    expiresAt === null ||
    now === null ||
    !Number.isFinite(now) ||
    expiresAt <= issuedAt
  ) {
    return { valid: false, reason: "invalid_time", fingerprint };
  }

  const clockSkew = input.maxClockSkewMs ?? 30_000;
  if (!Number.isFinite(clockSkew) || clockSkew < 0) {
    return { valid: false, reason: "invalid_time", fingerprint };
  }
  if (issuedAt > now + clockSkew) {
    return { valid: false, reason: "not_yet_valid", fingerprint };
  }
  if (expiresAt < now - clockSkew) {
    return { valid: false, reason: "expired", fingerprint };
  }

  try {
    const valid = verifyBytes(
      null,
      Buffer.from(authorizationPayload(authorization), "utf8"),
      publicKey,
      Buffer.from(authorization.signature, "base64url"),
    );
    return valid
      ? { valid: true, fingerprint }
      : { valid: false, reason: "invalid_signature", fingerprint };
  } catch {
    return { valid: false, reason: "invalid_signature", fingerprint };
  }
}
