import type { CoreaxPolicy } from "../policy";
import type { AgentGuardFinding } from "../middleware/agentGuard";
import type {
  ApprovalKeyResolver,
  ApprovalNonceStore,
  ApprovalVerificationKey,
  Awaitable,
  CreateEscalationInput,
  EscalationRequest,
  EscalationState,
  EscalationReporter,
  EscalationResolver,
  LocalEscalationManager,
} from "../escalation";

export type GuardMode = "enforce" | "observe";
export type GuardProviderPrecedence = "custom-first" | "local-first";
export type GuardOutcome = "allow" | "redact" | "block" | "escalate";

export type GuardInputKind =
  | "message_outbound"
  | "tool_call"
  | "mcp_call"
  | "api_call";

export interface GuardInputContext {
  runId?: string;
  nodeId?: string;
  threadId?: string;
  channelId?: string;
  target?: string;
  tags?: string[];
  /**
   * Filesystem paths supplied by the trusted execution harness. Never forward
   * model-authored metadata into this field.
   */
  filesystemPaths?: string[];
  metadata?: Record<string, unknown>;
}

export interface GuardInput {
  kind: GuardInputKind;
  content?: unknown;
  target?: string;
  context?: GuardInputContext;
}

export interface GuardRule {
  id?: string;
  kind?: GuardInputKind | GuardInputKind[] | "*";
  target?: string | string[];
  tagsAny?: string[];
  outcome: GuardOutcome;
  reason?: string;
  violation?: string;
  redact?: {
    replacement?: string;
    patterns?: string[];
  };
}

export interface GuardPolicy {
  version?: string;
  defaultOutcome?: Extract<GuardOutcome, "allow" | "block">;
  rules?: GuardRule[];
}

export type GuardPolicyInput = GuardPolicy | CoreaxPolicy;

export interface GuardLocalPolicyProviderConfig {
  policy?: GuardPolicyInput;
  policyPath?: string;
  cacheTtlMs?: number;
}

export interface GuardCustomPolicyProviderConfig {
  getPolicy(input: GuardInput): Promise<GuardProviderSnapshot | GuardPolicyInput>;
}

export interface GuardProviderConfig {
  precedence?: GuardProviderPrecedence;
  local?: GuardLocalPolicyProviderConfig;
  /** Explicit caller-supplied provider. CoreAX never performs network discovery. */
  custom?: GuardCustomPolicyProviderConfig;
}

export interface GuardApprovalCapabilityContext {
  input: GuardInput;
  decision: GuardDecision;
  resolution: GuardEscalationResolution;
}

/**
 * Local verification inputs for an approval capability supplied after a
 * resolution is available. Guarded execution fails closed when this
 * configuration, the capability, its signing key, or replay state is missing.
 */
export interface GuardApprovalCapabilityConfig {
  getCapability(
    context: GuardApprovalCapabilityContext,
  ): Awaitable<string | null | undefined>;
  nonceStore: ApprovalNonceStore;
  publicKey?: ApprovalVerificationKey;
  expectedKeyId?: string;
  keyResolver?:
    | ApprovalKeyResolver
    | ((
        keyId: string,
      ) => Awaitable<ApprovalVerificationKey | null>);
  clockSkewMs?: number;
}

export interface GuardEscalationLifecycleConfig {
  enabled?: boolean;
  waitForResolutionByDefault?: boolean;
  timeoutMs?: number;
  pollIntervalMs?: number;
  ttlSeconds?: number;
  requestedBy?: string;
  manager?: LocalEscalationManager;
  reporter?: EscalationReporter;
  resolver?: EscalationResolver;
  approvalCapability?: GuardApprovalCapabilityConfig;
}

export interface GuardApprovalTransportCapabilities {
  interactiveActions: boolean;
  cards: boolean;
}

export type GuardApprovalAction = {
  escalationId: string;
  action: "approve" | "reject";
  actorId?: string;
  notes?: string;
};

export type GuardTransportPendingEvent = {
  escalationId: string;
  input: GuardInput;
  decision: GuardDecision;
  payload: CreateEscalationInput;
  createResult: EscalationRequest;
};

export type GuardTransportResolvedEvent = {
  escalationId: string;
  input: GuardInput;
  decision: GuardDecision;
  resolution: GuardEscalationResolution;
};

export interface GuardApprovalTransport {
  platform: string;
  capabilities: GuardApprovalTransportCapabilities;
  sendPending(event: GuardTransportPendingEvent): Promise<void>;
  sendResolved(event: GuardTransportResolvedEvent): Promise<void>;
  parseApprovalAction?(payload: unknown): GuardApprovalAction | null;
}

export interface GuardHooks {
  onEscalationRequested(event: GuardEscalationRequestedEvent): Promise<void> | void;
  onEscalationResolved(event: GuardEscalationResolvedEvent): Promise<void> | void;
  onEscalationError(event: GuardEscalationErrorEvent): Promise<void> | void;
}

export interface GuardLogEvent {
  level: "debug" | "info" | "warn" | "error";
  message: string;
  data?: Record<string, unknown>;
}

export interface CoreaxGuardConfig {
  mode?: GuardMode;
  provider?: GuardProviderConfig;
  escalation?: GuardEscalationLifecycleConfig;
  hooks?: Partial<GuardHooks>;
  transport?: GuardApprovalTransport;
  logger?: (event: GuardLogEvent) => void;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
}

export interface GuardDecisionProviderInfo {
  mode: GuardMode;
  source: "local" | "custom" | "local-fallback";
  policyHash: string;
  fallbackReason?: string;
}

export interface GuardEscalationDescriptor {
  shouldEscalate: boolean;
  waitForResolution: boolean;
  escalationId?: string;
  status?: string;
  resolution?: GuardEscalationResolution;
}

export interface GuardDecision {
  outcome: GuardOutcome;
  shouldProceed: boolean;
  kind: GuardInputKind;
  reason: string | null;
  reasons: string[];
  violation?: string;
  findings?: AgentGuardFinding[];
  redactedContent?: string;
  provider: GuardDecisionProviderInfo;
  escalation?: GuardEscalationDescriptor;
}

export interface GuardExecutionResult<T> {
  decision: GuardDecision;
  value?: T;
  escalation?: GuardEscalationResolution;
}

export interface GuardEscalationResolution extends EscalationState {}

export interface GuardEscalationRequestedEvent {
  input: GuardInput;
  decision: GuardDecision;
  payload: CreateEscalationInput;
  created: EscalationRequest;
}

export interface GuardEscalationResolvedEvent {
  input: GuardInput;
  decision: GuardDecision;
  resolution: GuardEscalationResolution;
}

export interface GuardEscalationErrorEvent {
  input: GuardInput;
  decision: GuardDecision;
  error: Error;
}

export interface GuardExecuteHandlers<T> extends Partial<GuardHooks> {
  onBlock?: (decision: GuardDecision) => Promise<T> | T;
  onRedactInput?: (input: GuardInput, decision: GuardDecision) => Promise<GuardInput> | GuardInput;
  waitForEscalation?: boolean;
}

export interface GuardWaitForResolutionOptions {
  timeoutMs?: number;
  pollIntervalMs?: number;
  signal?: AbortSignal;
}

export interface GuardRuntimeContext {
  now: () => number;
  sleep: (ms: number) => Promise<void>;
  log: (event: GuardLogEvent) => void;
}

export interface GuardProviderSnapshot {
  policy: GuardPolicyInput;
  hash: string;
  source: "local" | "custom" | "local-fallback";
  fallbackReason?: string;
}

export interface GuardPolicyProvider {
  getPolicy(input: GuardInput): Promise<GuardProviderSnapshot>;
}

export interface CoreaxGuard {
  check(input: GuardInput): Promise<GuardDecision>;
  execute<T>(
    input: GuardInput,
    actionFn: (input: GuardInput, decision: GuardDecision) => Promise<T> | T,
    handlers?: GuardExecuteHandlers<T>,
  ): Promise<GuardExecutionResult<T>>;
  waitForResolution(escalationId: string, opts?: GuardWaitForResolutionOptions): Promise<GuardEscalationResolution>;
}
