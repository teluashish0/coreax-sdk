import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  openSync,
  readFileSync,
} from "node:fs";
import path from "node:path";

import {
  canonicalize,
  fromBase64,
  sha256Hex,
  type Verifier,
} from "../signer";
import type {
  AuditVerificationResult,
  SignedAuditEnvelope,
} from "./types";

export type AuditKeyResolver =
  | ReadonlyMap<string, Verifier>
  | ((keyId: string) => Verifier | null | undefined | Promise<Verifier | null | undefined>);

export type AuditBundleManifest = {
  files: Record<string, string>;
};

export function parseAuditSignature(value: unknown): {
  keyId: string;
  signature: Uint8Array;
} | null {
  if (typeof value !== "string") return null;
  const match = /^(ed25519:[0-9a-f]{64}):([A-Za-z0-9+/]+={0,2})$/i.exec(value.trim());
  if (!match) return null;
  try {
    const signature = fromBase64(match[2]);
    return signature.length === 64
      ? { keyId: match[1], signature }
      : null;
  } catch {
    return null;
  }
}

async function resolveVerifier(resolver: AuditKeyResolver, keyId: string): Promise<Verifier | null> {
  if (typeof resolver === "function") {
    return (await resolver(keyId)) || null;
  }
  return resolver.get(keyId) || null;
}

export async function verifyAuditEnvelope(
  envelope: SignedAuditEnvelope | Record<string, unknown>,
  resolver: AuditKeyResolver,
): Promise<AuditVerificationResult> {
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) {
    return { valid: false, reason: "invalid_json" };
  }
  const parsed = parseAuditSignature(envelope.sig);
  if (!envelope.sig) return { valid: false, reason: "missing_signature" };
  if (!parsed) return { valid: false, reason: "unsupported_signature" };
  let verifier: Verifier | null;
  try {
    verifier = await resolveVerifier(resolver, parsed.keyId);
  } catch {
    return { valid: false, reason: "unknown_key" };
  }
  if (!verifier) return { valid: false, reason: "unknown_key" };
  const unsigned = { ...envelope };
  delete unsigned.sig;
  let valid = false;
  try {
    valid = await Promise.resolve(
      verifier.verify(Buffer.from(canonicalize(unsigned)), parsed.signature),
    );
  } catch {
    valid = false;
  }
  return valid
    ? { valid: true, keyId: parsed.keyId }
    : { valid: false, reason: "invalid_signature" };
}

export async function verifyAuditLog(
  filePath: string,
  resolver: AuditKeyResolver,
): Promise<AuditVerificationResult> {
  let contents: string;
  try {
    contents = readVerificationFile(filePath);
  } catch {
    return { valid: false, reason: "io_error" };
  }
  if (!contents) return { valid: false, reason: "empty_log" };
  if (!contents.endsWith("\n")) {
    return { valid: false, reason: "truncated_log" };
  }
  const lines = contents.split("\n");
  let keyId: string | null = null;
  let records = 0;
  let previousLine: string | null = null;
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index].trim();
    if (!line) continue;
    let row: Record<string, unknown>;
    try {
      row = JSON.parse(line) as Record<string, unknown>;
    } catch (error) {
      return {
        valid: false,
        reason: "invalid_json",
        line: index + 1,
        error: error instanceof Error ? error.message : String(error),
      };
    }
    if (!Number.isInteger(row.sequence) || Number(row.sequence) !== records) {
      return {
        valid: false,
        reason: "invalid_sequence",
        line: index + 1,
      };
    }
    const expectedPrevious = previousLine
      ? sha256Hex(previousLine)
      : null;
    if (row.previous_sha256 !== expectedPrevious) {
      return {
        valid: false,
        reason: "invalid_chain",
        line: index + 1,
      };
    }
    const result = await verifyAuditEnvelope(row, resolver);
    if (!result.valid) return { ...result, line: index + 1 };
    if (keyId && keyId !== result.keyId) {
      return { valid: false, reason: "mixed_signers", line: index + 1 };
    }
    keyId = result.keyId;
    records += 1;
    previousLine = line;
  }
  if (!keyId || !previousLine) {
    return { valid: false, reason: "empty_log" };
  }

  const headPath = auditHeadPath(filePath);
  if (!existsSync(headPath)) {
    return { valid: false, reason: "missing_head" };
  }
  let head: Record<string, unknown>;
  try {
    head = JSON.parse(readVerificationFile(headPath)) as Record<
      string,
      unknown
    >;
  } catch {
    return { valid: false, reason: "invalid_head" };
  }
  const headVerification = await verifyAuditEnvelope(head, resolver);
  if (!headVerification.valid) {
    return { valid: false, reason: "invalid_head" };
  }
  const dateMatch = /^audit-(\d{4}-\d{2}-\d{2})\.ndjson$/.exec(
    path.basename(filePath),
  );
  if (
    head.format !== "coreax-audit-head" ||
    head.version !== 1 ||
    head.records !== records ||
    head.tail_sha256 !== sha256Hex(previousLine) ||
    (dateMatch && head.date !== dateMatch[1]) ||
    headVerification.keyId !== keyId
  ) {
    return { valid: false, reason: "head_mismatch" };
  }
  return { valid: true, keyId, records };
}

function auditHeadPath(filePath: string): string {
  return filePath.endsWith(".ndjson")
    ? `${filePath.slice(0, -".ndjson".length)}.head.json`
    : `${filePath}.head.json`;
}

function readVerificationFile(filePath: string): string {
  const descriptor = openSync(
    filePath,
    constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
  );
  try {
    if (!fstatSync(descriptor).isFile()) {
      throw new Error("Audit path is not a regular file");
    }
    return readFileSync(descriptor, "utf8");
  } finally {
    closeSync(descriptor);
  }
}

export function verifyAuditBundle(
  manifest: AuditBundleManifest,
  readFile: (path: string) => Uint8Array = (path) => readFileSync(path),
): { valid: true } | { valid: false; file: string; expected: string; actual: string } {
  for (const [file, expected] of Object.entries(manifest.files).sort(([a], [b]) => a.localeCompare(b))) {
    const actual = createHash("sha256").update(readFile(file)).digest("hex");
    if (actual !== expected.toLowerCase()) {
      return { valid: false, file, expected: expected.toLowerCase(), actual };
    }
  }
  return { valid: true };
}
