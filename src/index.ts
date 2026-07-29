export {
  matchesAllowlist,
  normalizeAllowlist,
  parsePolicyYaml,
  validatePolicy,
} from "./policy";
export type {
  CoreaxPolicy,
  PolicyEnforcementReason,
} from "./policy";

export {
  createRuntimeAdapter,
  LocalRuntimeAdapter,
  RUNTIME_PROTOCOL_VERSION,
} from "./runtime-adapter";
export type {
  RuntimeAdapter,
  RuntimeAdapterConfig,
  RuntimeDecisionInput,
  RuntimeDecisionOutput,
  RuntimeExecutionLayer,
} from "./runtime-adapter";

export { createCoreaxGuard } from "./guard";
export type {
  CoreaxGuard,
  CoreaxGuardConfig,
  GuardApprovalCapabilityConfig,
  GuardApprovalCapabilityContext,
  GuardDecision,
  GuardInput,
  GuardPolicy,
  GuardRule,
} from "./guard";

export {
  coreaxLocalMiddleware,
  coreaxSecurityMiddleware,
  createCoreaxAuditSink,
  getCoreaxMeta,
  withCoreaxMeta,
} from "./middleware";
export type {
  CoreaxMeta,
  McpServerLike,
  MiddlewareOptions,
  ToolHandler,
  ToolInvocationContext,
} from "./middleware";

export {
  CoreaxAppender,
  verifyAuditBundle,
  verifyAuditEnvelope,
  verifyAuditLog,
} from "./audit";
export type {
  AuditEnvelopeMinimal,
  AuditKeyResolver,
  AuditSigner,
  CoreaxAppenderOptions,
  CoreaxAuditConfig,
  SignedAuditEnvelope,
} from "./audit";

export {
  canonicalize,
  Ed25519Signer,
  Ed25519Verifier,
  sha256Hex,
} from "./signer";
export type { Signer, Verifier } from "./signer";

export {
  assertEscalationApproved,
  createLocalEscalationManager,
  FileEscalationStore,
  issueApprovalCapability,
  MemoryEscalationStore,
  verifyApprovalCapability,
} from "./escalation";
export type {
  CreateEscalationInput,
  EscalationState,
  LocalEscalationManager,
  LocalEscalationManagerConfig,
} from "./escalation";

export {
  FileGovernanceStore,
  LocalGovernanceClient,
  compactGovernanceEvidence,
  executeGovernedAction,
} from "./governance";
export type {
  GovernanceClient,
  GovernanceSubmission,
  GovernanceSubmissionResult,
} from "./governance";

export {
  createContextualEvaluatorManager,
  createLocalContextualEvaluator,
  evaluateContextualInputLocal,
} from "./evaluator";
export type {
  ContextualEvaluatorAdapter,
  EvaluatorDecision,
  EvaluatorInput,
  EvaluatorMode,
  EvaluatorOutput,
  EvaluatorPrinciple,
  EvaluatorSource,
  SemanticCalibrator,
} from "./evaluator";

export { assessRunRisk } from "./runtime-risk";
export type {
  RuntimeRiskAssessment,
  RuntimeRiskEvent,
} from "./runtime-risk";

export {
  AdaptivePolicyEngine,
  InMemoryAdaptivePolicyStore,
} from "./policy-learning";
export type {
  AdaptivePolicyEngineConfig,
  PolicyDocument,
  PolicyLearningMode,
} from "./policy-learning";

export {
  coreax,
  coreaxAgent,
  coreaxMiddleware,
  coreaxOrchestrator,
  coreaxServer,
  coreaxSkill,
  coreaxTool,
  initCoreax,
} from "./instrumentation";
export type {
  CoreaxInstrumentationConfig,
  CoreaxRunContext,
} from "./instrumentation";

export { createCustomAgentAdapter } from "./integrations/custom-agent";
export type {
  CustomAgentAdapter,
  CustomAgentAdapterConfig,
  CustomAgentContext,
} from "./integrations/custom-agent";

export type {
  ApprovalProvider,
  ApprovalProviderInput,
  AuditSink,
  PolicyContext,
  PolicyProvider,
  PolicySnapshot,
} from "./core";
