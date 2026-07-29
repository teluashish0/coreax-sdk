export type EscalationJsonPrimitive = string | number | boolean | null;
export type EscalationJsonValue =
  | EscalationJsonPrimitive
  | EscalationJsonValue[]
  | { [key: string]: EscalationJsonValue };

export interface EscalationJsonObject {
  [key: string]: EscalationJsonValue;
}

export type Awaitable<T> = T | Promise<T>;

export type EscalationDecision = "approve" | "reject";
export type EscalationStatus = "pending" | "approved" | "rejected" | "expired";

export interface CreateEscalationInput {
  id?: string;
  action: string;
  scope: EscalationJsonObject;
  reason: string;
  requestedBy?: string;
  metadata?: EscalationJsonObject;
  ttlMs?: number;
}

export interface EscalationRequest {
  id: string;
  action: string;
  scope: EscalationJsonObject;
  reason: string;
  requestedBy?: string;
  metadata?: EscalationJsonObject;
  createdAt: string;
  expiresAt: string;
}

export interface ResolveEscalationInput {
  escalationId: string;
  decision: EscalationDecision;
  resolvedBy: string;
  resolutionId?: string;
  notes?: string;
  metadata?: EscalationJsonObject;
}

export interface EscalationResolution {
  id: string;
  escalationId: string;
  decision: EscalationDecision;
  resolvedBy: string;
  notes?: string;
  metadata?: EscalationJsonObject;
  resolvedAt: string;
}

export interface EscalationState {
  request: EscalationRequest;
  resolution: EscalationResolution | null;
  status: EscalationStatus;
}

export interface PendingEscalationStore {
  initialize?(): Awaitable<void>;
  putPending(request: EscalationRequest): Awaitable<EscalationRequest>;
  getPending(escalationId: string): Awaitable<EscalationRequest | null>;
  listPending(): Awaitable<EscalationRequest[]>;
}

export interface EscalationResolutionStore {
  initialize?(): Awaitable<void>;
  putResolution(resolution: EscalationResolution): Awaitable<EscalationResolution>;
  getResolution(escalationId: string): Awaitable<EscalationResolution | null>;
}

export interface EscalationStore
  extends PendingEscalationStore,
    EscalationResolutionStore {}

/**
 * Optional caller-owned notification hook. CoreAX does not provide a network
 * implementation or invoke any endpoint unless the caller supplies one.
 */
export interface EscalationReporter {
  reportEscalation(request: EscalationRequest): Awaitable<void>;
}

/**
 * Optional caller-owned source of resolutions. Returned resolutions are
 * validated and persisted by the local manager before they can be trusted.
 */
export interface EscalationResolver {
  getResolution(request: EscalationRequest): Awaitable<EscalationResolution | null>;
}

export interface EscalationWaitOptions {
  signal?: AbortSignal;
  timeoutMs?: number;
  pollIntervalMs?: number;
}

export interface LocalEscalationManagerConfig {
  store?: EscalationStore;
  reporter?: EscalationReporter;
  resolver?: EscalationResolver;
  defaultTtlMs?: number;
  now?: () => number;
  sleep?: (milliseconds: number) => Promise<void>;
  idFactory?: () => string;
}

export interface LocalEscalationManager {
  initialize(): Promise<void>;
  create(input: CreateEscalationInput): Promise<EscalationState>;
  get(escalationId: string): Promise<EscalationState | null>;
  listPending(): Promise<EscalationState[]>;
  resolve(input: ResolveEscalationInput): Promise<EscalationState>;
  waitForResolution(
    escalationId: string,
    options?: EscalationWaitOptions,
  ): Promise<EscalationState>;
  requireApproved(escalationId: string): Promise<EscalationState>;
}

export interface ApprovalCapabilityClaims {
  version: 1;
  kind: "coreax-approval";
  approvalId: string;
  escalationId: string;
  action: string;
  scopeDigest: string;
  issuedAt: string;
  expiresAt: string;
  nonce: string;
}

export type ApprovalCapabilityFailureReason =
  | "missing"
  | "malformed"
  | "unsupported"
  | "unknown_key"
  | "invalid_signature"
  | "invalid_claims"
  | "not_yet_valid"
  | "expired"
  | "escalation_mismatch"
  | "approval_mismatch"
  | "action_mismatch"
  | "scope_mismatch"
  | "replayed"
  | "nonce_store_error";

export type ApprovalCapabilityVerification =
  | {
      valid: true;
      keyId: string;
      claims: ApprovalCapabilityClaims;
    }
  | {
      valid: false;
      reason: ApprovalCapabilityFailureReason;
    };

export interface ApprovalNonceStore {
  /**
   * Atomically records a nonce. Returns false if it was already consumed.
   */
  consume(nonce: string, expiresAt: string): Awaitable<boolean>;
}
