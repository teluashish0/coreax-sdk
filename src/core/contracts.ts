import type { AuditEnvelopeMinimal } from "../audit";
import type {
  ApprovalCapabilityVerification,
  EscalationJsonObject,
} from "../escalation";
import type { GuardPolicyInput } from "../guard";

export interface PolicyContext {
  action?: string;
  scope?: Record<string, unknown>;
}

export interface PolicySnapshot<TPolicy = GuardPolicyInput> {
  policy: TPolicy;
  hash: string;
  version?: string;
}

/**
 * Caller-supplied policy source. CoreAX ships local file/object providers and
 * never discovers or contacts a vendor policy service.
 */
export interface PolicyProvider<TPolicy = GuardPolicyInput> {
  getPolicy(context?: PolicyContext): Promise<PolicySnapshot<TPolicy>>;
}

export interface ApprovalProviderInput {
  capability?: string | null;
  escalationId: string;
  approvalId: string;
  action: string;
  scope: EscalationJsonObject;
}

/**
 * Caller-supplied capability verifier. Missing and invalid capabilities must
 * return a non-valid result; implementations must not default to approval.
 */
export interface ApprovalProvider {
  verify(
    input: ApprovalProviderInput,
  ): Promise<ApprovalCapabilityVerification>;
}

export interface AuditSink {
  initialize?(): void;
  append(envelope: AuditEnvelopeMinimal & { sig?: string }): Promise<void>;
  flush?(): Promise<void>;
}
