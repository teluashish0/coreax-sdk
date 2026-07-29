export class CoreaxEscalationError extends Error {
  readonly details?: Readonly<Record<string, unknown>>;

  constructor(message: string, details?: Readonly<Record<string, unknown>>) {
    super(message);
    this.name = "CoreaxEscalationError";
    this.details = details;
  }
}

export class EscalationValidationError extends CoreaxEscalationError {
  constructor(message: string, details?: Readonly<Record<string, unknown>>) {
    super(message, details);
    this.name = "EscalationValidationError";
  }
}

export class EscalationNotFoundError extends CoreaxEscalationError {
  constructor(escalationId: string) {
    super(`Escalation "${escalationId}" was not found`, { escalationId });
    this.name = "EscalationNotFoundError";
  }
}

export class EscalationConflictError extends CoreaxEscalationError {
  constructor(message: string, details?: Readonly<Record<string, unknown>>) {
    super(message, details);
    this.name = "EscalationConflictError";
  }
}

export class EscalationStoreNotInitializedError extends CoreaxEscalationError {
  constructor() {
    super("File escalation state must be initialized before use");
    this.name = "EscalationStoreNotInitializedError";
  }
}

export class EscalationStoreCorruptionError extends CoreaxEscalationError {
  constructor(filePath: string, line: number, message: string) {
    super(`Invalid escalation log record at ${filePath}:${line}: ${message}`, {
      filePath,
      line,
    });
    this.name = "EscalationStoreCorruptionError";
  }
}

export class EscalationReporterError extends CoreaxEscalationError {
  constructor(message: string, escalationId: string) {
    super(message, { escalationId });
    this.name = "EscalationReporterError";
  }
}

export class EscalationResolverError extends CoreaxEscalationError {
  constructor(message: string, escalationId: string) {
    super(message, { escalationId });
    this.name = "EscalationResolverError";
  }
}

export class EscalationTimeoutError extends CoreaxEscalationError {
  constructor(escalationId: string, timeoutMs: number) {
    super(`Escalation "${escalationId}" was not resolved within ${timeoutMs}ms`, {
      escalationId,
      timeoutMs,
    });
    this.name = "EscalationTimeoutError";
  }
}

export class EscalationAbortError extends CoreaxEscalationError {
  constructor(escalationId: string) {
    super(`Waiting for escalation "${escalationId}" was aborted`, {
      escalationId,
    });
    this.name = "EscalationAbortError";
  }
}

export class EscalationApprovalRequiredError extends CoreaxEscalationError {
  constructor(escalationId: string, status: string) {
    super(
      `Escalation "${escalationId}" does not have a current approval`,
      { escalationId, status },
    );
    this.name = "EscalationApprovalRequiredError";
  }
}

export class ApprovalCapabilityIssueError extends CoreaxEscalationError {
  constructor(message: string, details?: Readonly<Record<string, unknown>>) {
    super(message, details);
    this.name = "ApprovalCapabilityIssueError";
  }
}
