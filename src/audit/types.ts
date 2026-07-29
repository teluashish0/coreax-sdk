import type { Signer, Verifier } from "../signer";

export interface AuditSigner extends Signer, Verifier {
  /** Raw 32-byte Ed25519 public key used to derive and validate `keyId`. */
  readonly publicKey: Uint8Array;
}

export interface CoreaxAuditConfig {
  /** Audit directory. Defaults to `./.coreax/audit`. */
  directory?: string;
}

export interface AuditEnvelopeMinimal {
  ts: string;
  trace_id: string;
  span_id: string;
  namespace: string;
  server: string;
  tool: string;
  status: "ok" | "error";
  latency_ms: number;
  retries: number;
  input_sha256: string | null;
  output_sha256: string | null;
  policy: {
    decision: "allow" | "deny";
    policyHash?: string;
  };
  idempotency_key: string | null;
  nodeId?: string | null;
  agentRef?: string | null;
}

export interface CoreaxAppenderOptions {
  config?: CoreaxAuditConfig;
  signer: AuditSigner;
}

export type SignedAuditEnvelope = AuditEnvelopeMinimal & {
  sequence: number;
  previous_sha256: string | null;
  sig: string;
};

export type AuditVerificationFailure =
  | "io_error"
  | "invalid_json"
  | "truncated_log"
  | "empty_log"
  | "missing_signature"
  | "unsupported_signature"
  | "unknown_key"
  | "invalid_signature"
  | "mixed_signers"
  | "invalid_sequence"
  | "invalid_chain"
  | "missing_head"
  | "invalid_head"
  | "head_mismatch";

export type AuditVerificationResult =
  | { valid: true; keyId: string; records?: number }
  | {
      valid: false;
      reason: AuditVerificationFailure;
      line?: number;
      error?: string;
    };
