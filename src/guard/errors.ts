export type GuardErrorCode =
  | "COREAX_GUARD_CONFIG_INVALID"
  | "COREAX_GUARD_POLICY_UNAVAILABLE"
  | "COREAX_GUARD_POLICY_INVALID"
  | "COREAX_GUARD_PROVIDER_ERROR"
  | "COREAX_GUARD_BLOCKED"
  | "COREAX_GUARD_ESCALATION_FAILED"
  | "COREAX_GUARD_ESCALATION_TIMEOUT"
  | "COREAX_GUARD_ABORTED";

export class CoreaxGuardError extends Error {
  readonly code: GuardErrorCode;
  readonly details?: Record<string, unknown>;

  constructor(code: GuardErrorCode, message: string, details?: Record<string, unknown>) {
    super(message);
    this.code = code;
    this.details = details;
  }
}

export class GuardConfigError extends CoreaxGuardError {
  constructor(message: string, details?: Record<string, unknown>) {
    super("COREAX_GUARD_CONFIG_INVALID", message, details);
  }
}

export class GuardPolicyUnavailableError extends CoreaxGuardError {
  constructor(message: string, details?: Record<string, unknown>) {
    super("COREAX_GUARD_POLICY_UNAVAILABLE", message, details);
  }
}

export class GuardPolicyInvalidError extends CoreaxGuardError {
  constructor(message: string, details?: Record<string, unknown>) {
    super("COREAX_GUARD_POLICY_INVALID", message, details);
  }
}

export class GuardProviderError extends CoreaxGuardError {
  constructor(message: string, details?: Record<string, unknown>) {
    super("COREAX_GUARD_PROVIDER_ERROR", message, details);
  }
}

export class GuardBlockedError extends CoreaxGuardError {
  constructor(message: string, details?: Record<string, unknown>) {
    super("COREAX_GUARD_BLOCKED", message, details);
  }
}

export class GuardEscalationError extends CoreaxGuardError {
  constructor(message: string, details?: Record<string, unknown>) {
    super("COREAX_GUARD_ESCALATION_FAILED", message, details);
  }
}

export class GuardEscalationTimeoutError extends CoreaxGuardError {
  constructor(message: string, details?: Record<string, unknown>) {
    super("COREAX_GUARD_ESCALATION_TIMEOUT", message, details);
  }
}

export class GuardAbortError extends CoreaxGuardError {
  constructor(message: string, details?: Record<string, unknown>) {
    super("COREAX_GUARD_ABORTED", message, details);
  }
}
