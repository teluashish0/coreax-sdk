export {
  ApprovalCapabilityIssueError,
  CoreaxEscalationError,
  EscalationAbortError,
  EscalationApprovalRequiredError,
  EscalationConflictError,
  EscalationNotFoundError,
  EscalationReporterError,
  EscalationResolverError,
  EscalationStoreCorruptionError,
  EscalationStoreNotInitializedError,
  EscalationTimeoutError,
  EscalationValidationError,
} from "./errors";
export {
  assertEscalationApproved,
  digestApprovalScope,
  FileApprovalNonceStore,
  fingerprintApprovalKey,
  issueApprovalCapability,
  MemoryApprovalNonceStore,
  StaticApprovalKeyring,
  verifyApprovalCapability,
} from "./capability";
export {
  createLocalEscalationManager,
  escalationStatus,
  toEscalationState,
} from "./manager";
export {
  FileEscalationStore,
  MemoryEscalationStore,
} from "./store";
export { waitForEscalationResolution } from "./waiter";

export type {
  ApprovalKeyResolver,
  ApprovalSigningKey,
  ApprovalVerificationKey,
  ApprovedEscalationState,
  FileApprovalNonceStoreConfig,
  IssueApprovalCapabilityInput,
  VerifyApprovalCapabilityInput,
} from "./capability";
export type {
  FileEscalationStoreConfig,
  FileEscalationStorePaths,
} from "./store";
export type { WaitForEscalationResolutionInput } from "./waiter";
export type {
  ApprovalCapabilityClaims,
  ApprovalCapabilityFailureReason,
  ApprovalCapabilityVerification,
  ApprovalNonceStore,
  Awaitable,
  CreateEscalationInput,
  EscalationDecision,
  EscalationJsonObject,
  EscalationJsonPrimitive,
  EscalationJsonValue,
  EscalationReporter,
  EscalationRequest,
  EscalationResolution,
  EscalationResolutionStore,
  EscalationResolver,
  EscalationState,
  EscalationStatus,
  EscalationStore,
  EscalationWaitOptions,
  LocalEscalationManager,
  LocalEscalationManagerConfig,
  PendingEscalationStore,
  ResolveEscalationInput,
} from "./types";
