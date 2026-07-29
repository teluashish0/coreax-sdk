import {
  createPrivateKey,
  createPublicKey,
  randomBytes,
  sign as signBytes,
  verify as verifyBytes,
  type KeyObject,
} from "node:crypto";
import { constants } from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  open,
  realpath,
} from "node:fs/promises";
import { resolve } from "node:path";

import {
  ApprovalCapabilityIssueError,
  EscalationStoreNotInitializedError,
} from "./errors";
import { escalationStatus } from "./manager";
import type {
  ApprovalCapabilityClaims,
  ApprovalCapabilityVerification,
  ApprovalNonceStore,
  Awaitable,
  EscalationJsonObject,
  EscalationResolution,
  EscalationState,
} from "./types";
import {
  canonicalJson,
  normalizeJsonObject,
  requiredString,
  sha256,
  timestampMs,
  validateEscalationRequest,
  validateEscalationResolution,
} from "./validation";

export type ApprovalSigningKey = KeyObject | string | Buffer;
export type ApprovalVerificationKey = KeyObject | string | Buffer;

export interface ApprovalKeyResolver {
  resolveApprovalKey(
    keyId: string,
  ): Awaitable<ApprovalVerificationKey | null>;
}

export interface ApprovedEscalationState extends EscalationState {
  status: "approved";
  resolution: EscalationResolution;
}

export interface IssueApprovalCapabilityInput {
  state: EscalationState | null | undefined;
  privateKey: ApprovalSigningKey;
  keyId?: string;
  ttlMs?: number;
  nonce?: string;
  now?: () => number;
}

export interface VerifyApprovalCapabilityInput {
  token?: string | null;
  expected: {
    escalationId: string;
    approvalId: string;
    action: string;
    scope: EscalationJsonObject;
  };
  nonceStore: ApprovalNonceStore;
  publicKey?: ApprovalVerificationKey;
  expectedKeyId?: string;
  keyResolver?:
    | ApprovalKeyResolver
    | ((
        keyId: string,
      ) => Awaitable<ApprovalVerificationKey | null>);
  now?: () => number;
  clockSkewMs?: number;
}

interface CapabilityHeader {
  alg: "EdDSA";
  typ: "coreax-approval+json";
  kid: string;
}

function toPrivateKey(key: ApprovalSigningKey): KeyObject {
  let normalized: KeyObject;
  if (typeof key === "string" || Buffer.isBuffer(key)) {
    normalized = createPrivateKey(key);
  } else {
    normalized = key;
  }
  if (normalized.type !== "private" || normalized.asymmetricKeyType !== "ed25519") {
    throw new ApprovalCapabilityIssueError(
      "Approval capabilities require an Ed25519 private key",
    );
  }
  return normalized;
}

function toPublicKey(key: ApprovalVerificationKey): KeyObject {
  let parsed: KeyObject;
  if (typeof key === "string" || Buffer.isBuffer(key)) {
    parsed = createPublicKey(key);
  } else {
    parsed = key;
  }
  const normalized = parsed.type === "private" ? createPublicKey(parsed) : parsed;
  if (normalized.asymmetricKeyType !== "ed25519") {
    throw new TypeError("Approval capabilities require an Ed25519 public key");
  }
  return normalized;
}

export function fingerprintApprovalKey(
  key: ApprovalVerificationKey,
): string {
  const publicKey = toPublicKey(key);
  const encoded = publicKey.export({ format: "der", type: "spki" });
  return `ed25519:${sha256(encoded)}`;
}

export function digestApprovalScope(scope: EscalationJsonObject): string {
  return sha256(canonicalJson(normalizeJsonObject(scope, "scope")));
}

export function assertEscalationApproved(
  state: EscalationState | null | undefined,
  now: number = Date.now(),
): ApprovedEscalationState {
  if (!state) {
    throw new ApprovalCapabilityIssueError(
      "Cannot issue approval capability without an escalation resolution",
      { status: "missing" },
    );
  }
  try {
    validateEscalationRequest(state.request);
    if (!state.resolution) {
      throw new ApprovalCapabilityIssueError(
        "Cannot issue approval capability for a pending escalation",
        { escalationId: state.request.id, status: "pending" },
      );
    }
    validateEscalationResolution(state.resolution);
    if (
      state.resolution.escalationId !== state.request.id ||
      state.resolution.decision !== "approve" ||
      escalationStatus(state.request, state.resolution, now) !== "approved"
    ) {
      throw new ApprovalCapabilityIssueError(
        "Cannot issue approval capability without a current approval",
        {
          escalationId: state.request.id,
          status: escalationStatus(state.request, state.resolution, now),
        },
      );
    }
    const resolvedAt = timestampMs(
      state.resolution.resolvedAt,
      "resolution.resolvedAt",
    );
    const createdAt = timestampMs(state.request.createdAt, "request.createdAt");
    const expiresAt = timestampMs(state.request.expiresAt, "request.expiresAt");
    if (resolvedAt < createdAt || resolvedAt > now || resolvedAt >= expiresAt) {
      throw new ApprovalCapabilityIssueError(
        "Approval resolution is outside the escalation approval window",
        { escalationId: state.request.id },
      );
    }
    return {
      request: state.request,
      resolution: state.resolution,
      status: "approved",
    };
  } catch (error) {
    if (error instanceof ApprovalCapabilityIssueError) throw error;
    const message = error instanceof Error ? error.message : String(error);
    throw new ApprovalCapabilityIssueError(
      `Invalid escalation resolution: ${message}`,
    );
  }
}

function positiveTtl(value: number | undefined, remainingMs: number): number {
  if (value === undefined) return remainingMs;
  if (!Number.isFinite(value) || value <= 0) {
    throw new ApprovalCapabilityIssueError(
      "Approval capability ttlMs must be a positive finite number",
    );
  }
  return Math.max(1, Math.floor(value));
}

function encodePart(value: unknown): string {
  return Buffer.from(canonicalJson(value), "utf8").toString("base64url");
}

export function issueApprovalCapability(
  input: IssueApprovalCapabilityInput,
): string {
  const now = (input.now ?? (() => Date.now()))();
  if (!Number.isFinite(now)) {
    throw new ApprovalCapabilityIssueError(
      "Approval capability clock returned an invalid timestamp",
    );
  }
  const state = assertEscalationApproved(input.state, now);
  const requestExpiresAt = timestampMs(
    state.request.expiresAt,
    "request.expiresAt",
  );
  const ttlMs = positiveTtl(input.ttlMs, requestExpiresAt - now);
  const expiresAt = Math.min(requestExpiresAt, now + ttlMs);
  if (expiresAt <= now) {
    throw new ApprovalCapabilityIssueError(
      "Approval capability expiration must be in the future",
      { escalationId: state.request.id },
    );
  }

  const privateKey = toPrivateKey(input.privateKey);
  const fingerprint = fingerprintApprovalKey(createPublicKey(privateKey));
  const keyId = input.keyId
    ? requiredString(input.keyId, "keyId")
    : fingerprint;
  if (keyId !== fingerprint) {
    throw new ApprovalCapabilityIssueError(
      "Approval capability keyId must match the Ed25519 public-key fingerprint",
    );
  }
  const nonce = input.nonce
    ? requiredString(input.nonce, "nonce")
    : randomBytes(24).toString("base64url");
  if (nonce.length > 512) {
    throw new ApprovalCapabilityIssueError(
      "Approval capability nonce must not exceed 512 characters",
    );
  }
  const header: CapabilityHeader = {
    alg: "EdDSA",
    typ: "coreax-approval+json",
    kid: keyId,
  };
  const claims: ApprovalCapabilityClaims = {
    version: 1,
    kind: "coreax-approval",
    approvalId: state.resolution.id,
    escalationId: state.request.id,
    action: state.request.action,
    scopeDigest: digestApprovalScope(state.request.scope),
    issuedAt: new Date(now).toISOString(),
    expiresAt: new Date(expiresAt).toISOString(),
    nonce,
  };
  const headerPart = encodePart(header);
  const claimsPart = encodePart(claims);
  const signingInput = Buffer.from(`${headerPart}.${claimsPart}`, "ascii");
  const signature = signBytes(null, signingInput, privateKey);
  return `${headerPart}.${claimsPart}.${signature.toString("base64url")}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function parseToken(token: string):
  | {
      header: CapabilityHeader;
      claims: ApprovalCapabilityClaims;
      signature: Buffer;
      signingInput: Buffer;
    }
  | { failure: "malformed" | "unsupported" | "invalid_claims" } {
  if (token.length > 32_768) return { failure: "malformed" };
  const parts = token.split(".");
  if (
    parts.length !== 3 ||
    parts.some((part) => !part || !/^[A-Za-z0-9_-]+$/.test(part))
  ) {
    return { failure: "malformed" };
  }

  let headerValue: unknown;
  let claimsValue: unknown;
  let signature: Buffer;
  try {
    headerValue = JSON.parse(
      Buffer.from(parts[0]!, "base64url").toString("utf8"),
    );
    claimsValue = JSON.parse(
      Buffer.from(parts[1]!, "base64url").toString("utf8"),
    );
    signature = Buffer.from(parts[2]!, "base64url");
  } catch {
    return { failure: "malformed" };
  }

  if (!isRecord(headerValue)) return { failure: "malformed" };
  if (
    headerValue.alg !== "EdDSA" ||
    headerValue.typ !== "coreax-approval+json" ||
    typeof headerValue.kid !== "string" ||
    !headerValue.kid.trim()
  ) {
    return { failure: "unsupported" };
  }
  if (!isRecord(claimsValue)) return { failure: "invalid_claims" };
  if (
    claimsValue.version !== 1 ||
    claimsValue.kind !== "coreax-approval" ||
    typeof claimsValue.approvalId !== "string" ||
    !claimsValue.approvalId ||
    typeof claimsValue.escalationId !== "string" ||
    !claimsValue.escalationId ||
    typeof claimsValue.action !== "string" ||
    !claimsValue.action ||
    typeof claimsValue.scopeDigest !== "string" ||
    !/^[a-f0-9]{64}$/.test(claimsValue.scopeDigest) ||
    typeof claimsValue.issuedAt !== "string" ||
    typeof claimsValue.expiresAt !== "string" ||
    typeof claimsValue.nonce !== "string" ||
    !claimsValue.nonce ||
    claimsValue.nonce.length > 512 ||
    signature.length !== 64
  ) {
    return { failure: "invalid_claims" };
  }
  try {
    timestampMs(claimsValue.issuedAt, "claims.issuedAt");
    timestampMs(claimsValue.expiresAt, "claims.expiresAt");
  } catch {
    return { failure: "invalid_claims" };
  }

  return {
    header: headerValue as unknown as CapabilityHeader,
    claims: claimsValue as unknown as ApprovalCapabilityClaims,
    signature,
    signingInput: Buffer.from(`${parts[0]}.${parts[1]}`, "ascii"),
  };
}

async function resolvePublicKey(
  input: VerifyApprovalCapabilityInput,
  keyId: string,
): Promise<ApprovalVerificationKey | null> {
  if (input.expectedKeyId && keyId !== input.expectedKeyId) return null;
  if (input.keyResolver) {
    return typeof input.keyResolver === "function"
      ? input.keyResolver(keyId)
      : input.keyResolver.resolveApprovalKey(keyId);
  }
  if (!input.publicKey) return null;
  return fingerprintApprovalKey(input.publicKey) === keyId
    ? input.publicKey
    : null;
}

async function verifyApprovalCapabilityInternal(
  input: VerifyApprovalCapabilityInput,
): Promise<ApprovalCapabilityVerification> {
  if (!input.token) return { valid: false, reason: "missing" };
  const parsed = parseToken(input.token);
  if ("failure" in parsed) {
    return { valid: false, reason: parsed.failure };
  }

  let publicKey: ApprovalVerificationKey | null;
  try {
    publicKey = await resolvePublicKey(input, parsed.header.kid);
  } catch {
    return { valid: false, reason: "unknown_key" };
  }
  if (!publicKey) return { valid: false, reason: "unknown_key" };
  try {
    if (fingerprintApprovalKey(publicKey) !== parsed.header.kid) {
      return { valid: false, reason: "unknown_key" };
    }
  } catch {
    return { valid: false, reason: "unknown_key" };
  }

  try {
    if (
      !verifyBytes(
        null,
        parsed.signingInput,
        toPublicKey(publicKey),
        parsed.signature,
      )
    ) {
      return { valid: false, reason: "invalid_signature" };
    }
  } catch {
    return { valid: false, reason: "invalid_signature" };
  }

  const now = (input.now ?? (() => Date.now()))();
  if (!Number.isFinite(now)) {
    return { valid: false, reason: "invalid_claims" };
  }
  if (
    input.clockSkewMs !== undefined &&
    (!Number.isFinite(input.clockSkewMs) || input.clockSkewMs < 0)
  ) {
    return { valid: false, reason: "invalid_claims" };
  }
  const clockSkewMs =
    input.clockSkewMs === undefined
      ? 0
      : Math.floor(input.clockSkewMs);
  const issuedAt = timestampMs(parsed.claims.issuedAt, "claims.issuedAt");
  const expiresAt = timestampMs(parsed.claims.expiresAt, "claims.expiresAt");
  if (issuedAt > now + clockSkewMs) {
    return { valid: false, reason: "not_yet_valid" };
  }
  if (expiresAt <= now - clockSkewMs || expiresAt <= issuedAt) {
    return { valid: false, reason: "expired" };
  }
  if (parsed.claims.escalationId !== input.expected.escalationId) {
    return { valid: false, reason: "escalation_mismatch" };
  }
  if (parsed.claims.approvalId !== input.expected.approvalId) {
    return { valid: false, reason: "approval_mismatch" };
  }
  if (parsed.claims.action !== input.expected.action) {
    return { valid: false, reason: "action_mismatch" };
  }
  let expectedScopeDigest: string;
  try {
    expectedScopeDigest = digestApprovalScope(input.expected.scope);
  } catch {
    return { valid: false, reason: "scope_mismatch" };
  }
  if (parsed.claims.scopeDigest !== expectedScopeDigest) {
    return { valid: false, reason: "scope_mismatch" };
  }

  try {
    const consumed = await input.nonceStore.consume(
      parsed.claims.nonce,
      parsed.claims.expiresAt,
    );
    if (!consumed) return { valid: false, reason: "replayed" };
  } catch {
    return { valid: false, reason: "nonce_store_error" };
  }
  return {
    valid: true,
    keyId: parsed.header.kid,
    claims: parsed.claims,
  };
}

export async function verifyApprovalCapability(
  input: VerifyApprovalCapabilityInput,
): Promise<ApprovalCapabilityVerification> {
  try {
    return await verifyApprovalCapabilityInternal(input);
  } catch {
    return { valid: false, reason: "invalid_claims" };
  }
}

export class StaticApprovalKeyring implements ApprovalKeyResolver {
  private readonly keys = new Map<string, ApprovalVerificationKey>();

  constructor(
    entries:
      | ReadonlyMap<string, ApprovalVerificationKey>
      | Readonly<Record<string, ApprovalVerificationKey>>,
  ) {
    if (entries instanceof Map) {
      for (const [keyId, key] of entries) this.keys.set(keyId, key);
    } else {
      for (const [keyId, key] of Object.entries(entries)) {
        this.keys.set(keyId, key);
      }
    }
  }

  resolveApprovalKey(keyId: string): ApprovalVerificationKey | null {
    return this.keys.get(keyId) ?? null;
  }
}

export class MemoryApprovalNonceStore implements ApprovalNonceStore {
  private readonly consumed = new Map<string, number>();

  constructor(private readonly now: () => number = () => Date.now()) {}

  consume(nonce: string, expiresAt: string): boolean {
    const now = this.now();
    if (!Number.isFinite(now)) {
      throw new TypeError("Nonce store clock returned an invalid timestamp");
    }
    for (const [candidate, expiration] of this.consumed) {
      if (expiration <= now) this.consumed.delete(candidate);
    }
    if (this.consumed.has(nonce)) return false;
    const expiration = timestampMs(expiresAt, "expiresAt");
    if (expiration <= now) return false;
    this.consumed.set(nonce, expiration);
    return true;
  }
}

export interface FileApprovalNonceStoreConfig {
  rootDir?: string;
  now?: () => number;
}

export class FileApprovalNonceStore implements ApprovalNonceStore {
  readonly rootDir: string;
  private initialized = false;
  private canonicalRoot: string | null = null;
  private readonly now: () => number;

  constructor(config: FileApprovalNonceStoreConfig = {}) {
    this.rootDir = resolve(
      config.rootDir ??
        resolve(process.cwd(), ".coreax", "escalation", "consumed-nonces"),
    );
    this.now = config.now ?? (() => Date.now());
  }

  async initialize(): Promise<void> {
    await mkdir(this.rootDir, { recursive: true, mode: 0o700 });
    const stats = await lstat(this.rootDir);
    if (stats.isSymbolicLink() || !stats.isDirectory()) {
      throw new TypeError(
        "Approval nonce rootDir must be a real directory, not a symlink",
      );
    }
    await chmod(this.rootDir, 0o700);
    this.canonicalRoot = await realpath(this.rootDir);
    this.initialized = true;
  }

  async consume(nonce: string, expiresAt: string): Promise<boolean> {
    if (!this.initialized || !this.canonicalRoot) {
      throw new EscalationStoreNotInitializedError();
    }
    const nonceDigest = sha256(requiredString(nonce, "nonce"));
    const expiration = timestampMs(expiresAt, "expiresAt");
    const filePath = resolve(this.canonicalRoot, `${nonceDigest}.used`);
    let handle;
    const now = this.now();
    if (!Number.isFinite(now)) {
      throw new TypeError("Nonce store clock returned an invalid timestamp");
    }
    if (expiration <= now) return false;
    try {
      handle = await open(filePath, "wx", 0o600);
    } catch (error) {
      if (
        error &&
        typeof error === "object" &&
        "code" in error &&
        error.code === "EEXIST"
      ) {
        return false;
      }
      throw error;
    }
    try {
      await handle.writeFile(
        `${canonicalJson({
          format: "coreax-consumed-approval-nonce",
          version: 1,
          nonceDigest,
          expiresAt,
          consumedAt: new Date(now).toISOString(),
        })}\n`,
        "utf8",
      );
      await handle.sync();
    } finally {
      await handle.close();
    }
    const directory = await open(
      this.canonicalRoot,
      constants.O_RDONLY,
    );
    try {
      await directory.sync();
    } finally {
      await directory.close();
    }
    return true;
  }
}
