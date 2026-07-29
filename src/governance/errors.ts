export class CoreaxGovernanceError extends Error {
  readonly details?: Readonly<Record<string, unknown>>;

  constructor(message: string, details?: Readonly<Record<string, unknown>>) {
    super(message);
    this.name = "CoreaxGovernanceError";
    this.details = details;
  }
}

export class GovernanceValidationError extends CoreaxGovernanceError {
  constructor(message: string, details?: Readonly<Record<string, unknown>>) {
    super(message, details);
    this.name = "GovernanceValidationError";
  }
}

export class GovernanceNotFoundError extends CoreaxGovernanceError {
  constructor(kind: string, id: string) {
    super(`${kind} "${id}" was not found`, { kind, id });
    this.name = "GovernanceNotFoundError";
  }
}

export class GovernanceConflictError extends CoreaxGovernanceError {
  constructor(message: string, details?: Readonly<Record<string, unknown>>) {
    super(message, details);
    this.name = "GovernanceConflictError";
  }
}

export class GovernanceStoreNotInitializedError extends CoreaxGovernanceError {
  constructor() {
    super("File governance state must be initialized before use");
    this.name = "GovernanceStoreNotInitializedError";
  }
}

export class GovernanceStoreCorruptionError extends CoreaxGovernanceError {
  constructor(filePath: string, line: number, message: string) {
    super(`Invalid governance log record at ${filePath}:${line}: ${message}`, {
      filePath,
      line,
    });
    this.name = "GovernanceStoreCorruptionError";
  }
}

export class GovernanceEvaluatorError extends CoreaxGovernanceError {
  constructor(message: string, submissionId: string) {
    super(message, { submissionId });
    this.name = "GovernanceEvaluatorError";
  }
}

export class GovernanceAbortError extends CoreaxGovernanceError {
  constructor(submissionId: string) {
    super(`Waiting for governance review "${submissionId}" was aborted`, {
      submissionId,
    });
    this.name = "GovernanceAbortError";
  }
}
