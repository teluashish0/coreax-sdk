import {
  assertEscalationApproved,
  CoreaxEscalationError,
  EscalationAbortError,
  EscalationTimeoutError,
  createLocalEscalationManager,
  escalationStatus,
  type CreateEscalationInput,
  type EscalationJsonObject,
  type EscalationReporter,
  type EscalationRequest,
  type EscalationResolver,
  type LocalEscalationManager,
} from "../escalation";
import {
  GuardAbortError,
  GuardEscalationError,
  GuardEscalationTimeoutError,
} from "./errors";
import { canonicalize, sha256Hex } from "../signer";
import type {
  GuardDecision,
  GuardEscalationLifecycleConfig,
  GuardEscalationResolution,
  GuardExecuteHandlers,
  GuardHooks,
  GuardInput,
  GuardRuntimeContext,
  GuardTransportResolvedEvent,
  GuardWaitForResolutionOptions,
} from "./types";

type ResolvedLifecycleConfig = {
  enabled: boolean;
  waitForResolutionByDefault: boolean;
  timeoutMs: number;
  pollIntervalMs: number;
  ttlMs: number;
  requestedBy?: string;
  manager?: LocalEscalationManager;
  reporter?: EscalationReporter;
  resolver?: EscalationResolver;
};

function positiveInt(value: unknown, fallback: number): number {
  const number = Number(value);
  return Number.isFinite(number) && number > 0
    ? Math.floor(number)
    : fallback;
}

function resolveConfig(
  config: GuardEscalationLifecycleConfig | undefined,
): ResolvedLifecycleConfig {
  const hasLocalApprovalPath = Boolean(
    config?.manager || config?.reporter || config?.resolver,
  );
  return {
    enabled:
      config?.enabled === true ||
      (config?.enabled !== false && hasLocalApprovalPath),
    waitForResolutionByDefault:
      config?.waitForResolutionByDefault !== false,
    timeoutMs: positiveInt(config?.timeoutMs, 10 * 60 * 1000),
    pollIntervalMs: positiveInt(config?.pollIntervalMs, 500),
    ttlMs: positiveInt(config?.ttlSeconds, 15 * 60) * 1000,
    ...(config?.requestedBy?.trim()
      ? { requestedBy: config.requestedBy.trim() }
      : {}),
    manager: config?.manager,
    reporter: config?.reporter,
    resolver: config?.resolver,
  };
}

function jsonValue(value: unknown): EscalationJsonObject[string] {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "number") {
    return Number.isFinite(value) ? value : String(value);
  }
  if (Array.isArray(value)) return value.map(jsonValue);
  if (value && typeof value === "object") {
    const output = Object.create(null) as EscalationJsonObject;
    for (const [key, item] of Object.entries(value)) output[key] = jsonValue(item);
    return output;
  }
  return String(value ?? "");
}

function assertCanonicalContent(
  value: unknown,
  path: string,
  ancestors: Set<object>,
): void {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError(`${path} contains a non-finite number`);
    }
    return;
  }
  if (!value || typeof value !== "object") {
    throw new TypeError(`${path} must contain only canonical JSON values`);
  }
  if (ancestors.has(value)) {
    throw new TypeError(`${path} must not contain cycles`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (
    !Array.isArray(value) &&
    prototype !== Object.prototype &&
    prototype !== null
  ) {
    throw new TypeError(`${path} must contain only plain objects`);
  }
  ancestors.add(value);
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      assertCanonicalContent(value[index], `${path}[${index}]`, ancestors);
    }
  } else {
    for (const [key, item] of Object.entries(value)) {
      assertCanonicalContent(item, `${path}.${key}`, ancestors);
    }
  }
  ancestors.delete(value);
}

function canonicalContentHash(content: unknown): string {
  const normalized = content === undefined ? null : content;
  assertCanonicalContent(normalized, "guard input.content", new Set<object>());
  return sha256Hex(canonicalize(normalized));
}

function toCreateInput(
  input: GuardInput,
  decision: GuardDecision,
  config: ResolvedLifecycleConfig,
): CreateEscalationInput {
  const target = input.target ?? input.context?.target;
  const scope: EscalationJsonObject = {
    kind: input.kind,
    ...(target ? { target } : {}),
    ...(input.context ? { context: jsonValue(input.context) } : {}),
    contentSha256: canonicalContentHash(input.content),
  };
  return {
    action: target || input.kind,
    scope,
    reason: decision.violation || decision.reason || "policy_review_required",
    ...(config.requestedBy ? { requestedBy: config.requestedBy } : {}),
    metadata: {
      policyHash: decision.provider.policyHash,
      policySource: decision.provider.source,
      reasons: jsonValue(decision.reasons),
    },
    ttlMs: config.ttlMs,
  };
}

export type GuardEscalationBinding = Readonly<{
  escalationId: string;
  action: string;
  scope: EscalationJsonObject;
  contentSha256: string;
  request: EscalationRequest;
  requestCanonical: string;
}>;

function deepFreeze<T>(value: T, seen = new Set<object>()): T {
  if (!value || typeof value !== "object" || seen.has(value)) return value;
  seen.add(value);
  for (const item of Object.values(value as Record<string, unknown>)) {
    deepFreeze(item, seen);
  }
  return Object.freeze(value);
}

function immutableSnapshot<T>(value: T, label: string): T {
  try {
    return deepFreeze(structuredClone(value));
  } catch {
    throw new GuardEscalationError(
      `${label} must be structured-cloneable canonical state`,
    );
  }
}

function requestPayloadCanonical(
  value: Pick<
    CreateEscalationInput | EscalationRequest,
    "action" | "scope" | "reason" | "requestedBy" | "metadata"
  >,
): string {
  return canonicalize({
    action: value.action,
    scope: value.scope,
    reason: value.reason,
    requestedBy: value.requestedBy ?? null,
    metadata: value.metadata ?? null,
  });
}

function timestamp(value: unknown, label: string): number {
  const milliseconds =
    typeof value === "string" && value.trim() ? Date.parse(value) : Number.NaN;
  if (!Number.isFinite(milliseconds)) {
    throw new GuardEscalationError(
      `Escalation manager returned an invalid ${label}`,
    );
  }
  return milliseconds;
}

function bindCreatedEscalation(
  payload: CreateEscalationInput,
  state: GuardEscalationResolution,
  now: number,
): GuardEscalationBinding {
  if (!Number.isFinite(now)) {
    throw new GuardEscalationError(
      "Escalation clock returned an invalid timestamp",
    );
  }
  const escalationId = state?.request?.id;
  if (
    typeof escalationId !== "string" ||
    !escalationId.trim() ||
    escalationId !== escalationId.trim()
  ) {
    throw new GuardEscalationError(
      "Escalation manager returned an invalid request ID",
    );
  }
  if (
    state.status !== "pending" ||
    state.resolution !== null ||
    (payload.id !== undefined && payload.id !== escalationId) ||
    requestPayloadCanonical(state.request) !==
      requestPayloadCanonical(payload)
  ) {
    throw new GuardEscalationError(
      "Escalation manager substituted the canonical approval request",
    );
  }

  const createdAt = timestamp(state.request.createdAt, "request.createdAt");
  const expiresAt = timestamp(state.request.expiresAt, "request.expiresAt");
  if (
    createdAt > now ||
    expiresAt <= now ||
    !Number.isFinite(payload.ttlMs) ||
    expiresAt - createdAt !== payload.ttlMs
  ) {
    throw new GuardEscalationError(
      "Escalation manager changed the canonical approval window",
    );
  }

  const scope = immutableSnapshot(payload.scope, "Escalation scope");
  const contentSha256 = scope.contentSha256;
  if (
    typeof contentSha256 !== "string" ||
    !/^[a-f0-9]{64}$/.test(contentSha256)
  ) {
    throw new GuardEscalationError(
      "Escalation scope is missing its canonical content digest",
    );
  }
  const request = immutableSnapshot(state.request, "Escalation request");
  return Object.freeze({
    escalationId,
    action: payload.action,
    scope,
    contentSha256,
    request,
    requestCanonical: canonicalize(request),
  });
}

function assertBoundResolution(
  resolution: GuardEscalationResolution,
  binding: GuardEscalationBinding,
  now: number,
): GuardEscalationResolution {
  const snapshot = immutableSnapshot(
    resolution,
    "Escalation resolution",
  );
  if (
    snapshot.request.id !== binding.escalationId ||
    canonicalize(snapshot.request) !== binding.requestCanonical ||
    snapshot.request.action !== binding.action ||
    canonicalize(snapshot.request.scope) !== canonicalize(binding.scope) ||
    snapshot.request.scope.contentSha256 !== binding.contentSha256 ||
    (snapshot.resolution !== null &&
      snapshot.resolution.escalationId !== binding.escalationId)
  ) {
    throw new GuardEscalationError(
      "Escalation manager substituted the bound approval request",
    );
  }

  let expectedStatus: GuardEscalationResolution["status"];
  try {
    expectedStatus = escalationStatus(
      snapshot.request,
      snapshot.resolution,
      now,
    );
    if (expectedStatus === "approved") {
      assertEscalationApproved(snapshot, now);
    }
  } catch {
    throw new GuardEscalationError(
      "Escalation manager returned an invalid approval state",
    );
  }
  if (snapshot.status !== expectedStatus) {
    throw new GuardEscalationError(
      "Escalation manager returned a contradictory approval status",
    );
  }
  return snapshot;
}

export class GuardEscalationLifecycle {
  private readonly config: ResolvedLifecycleConfig;
  private readonly manager: LocalEscalationManager;
  private initializePromise: Promise<void> | null = null;

  constructor(
    config: GuardEscalationLifecycleConfig | undefined,
    private readonly runtime: GuardRuntimeContext,
    private readonly hooks: Partial<GuardHooks>,
    private readonly transport?: {
      sendResolved(event: GuardTransportResolvedEvent): Promise<void>;
    },
  ) {
    this.config = resolveConfig(config);
    this.manager =
      this.config.manager ??
      createLocalEscalationManager({
        reporter: this.config.reporter,
        resolver: this.config.resolver,
        defaultTtlMs: this.config.ttlMs,
        now: runtime.now,
        sleep: runtime.sleep,
      });
  }

  get enabled(): boolean {
    return this.config.enabled;
  }

  private initialize(): Promise<void> {
    this.initializePromise ??= this.manager.initialize();
    return this.initializePromise;
  }

  buildEscalationPayload(
    input: GuardInput,
    decision: GuardDecision,
  ): CreateEscalationInput {
    return toCreateInput(input, decision, this.config);
  }

  async requestEscalation(input: GuardInput, decision: GuardDecision) {
    await this.initialize();
    const payload = immutableSnapshot(
      this.buildEscalationPayload(input, decision),
      "Escalation payload",
    );
    try {
      const created = await this.manager.create(structuredClone(payload));
      const state = immutableSnapshot(created, "Escalation state");
      const binding = bindCreatedEscalation(
        payload,
        state,
        this.runtime.now(),
      );
      return { payload, state, binding };
    } catch (error) {
      throw this.mapError(error);
    }
  }

  async waitForResolution(
    escalationId: string,
    options?: GuardWaitForResolutionOptions,
  ): Promise<GuardEscalationResolution> {
    await this.initialize();
    try {
      const resolution = await this.manager.waitForResolution(escalationId, {
        timeoutMs: options?.timeoutMs ?? this.config.timeoutMs,
        pollIntervalMs: options?.pollIntervalMs ?? this.config.pollIntervalMs,
        signal: options?.signal,
      });
      return immutableSnapshot(resolution, "Escalation resolution");
    } catch (error) {
      throw this.mapError(error);
    }
  }

  async maybeWaitForResolution(options: {
    input: GuardInput;
    decision: GuardDecision;
    escalationId: string;
    binding: GuardEscalationBinding;
    handlers?: GuardExecuteHandlers<unknown>;
  }): Promise<GuardEscalationResolution | null> {
    const shouldWait =
      options.handlers?.waitForEscalation ??
      this.config.waitForResolutionByDefault;
    if (!shouldWait) return null;

    const resolution = assertBoundResolution(
      await this.waitForResolution(options.escalationId),
      options.binding,
      this.runtime.now(),
    );
    await this.emitResolved(options.input, options.decision, resolution, options.handlers);
    return resolution;
  }

  private async emitResolved(
    input: GuardInput,
    decision: GuardDecision,
    resolution: GuardEscalationResolution,
    handlers?: GuardExecuteHandlers<unknown>,
  ): Promise<void> {
    try {
      await this.hooks.onEscalationResolved?.({
        input,
        decision,
        resolution: structuredClone(resolution),
      });
    } catch {}
    try {
      await handlers?.onEscalationResolved?.({
        input,
        decision,
        resolution: structuredClone(resolution),
      });
    } catch {}
    try {
      await this.transport?.sendResolved({
        escalationId: resolution.request.id,
        input,
        decision,
        resolution: structuredClone(resolution),
      });
    } catch {}
  }

  async emitEscalationError(
    input: GuardInput,
    decision: GuardDecision,
    error: Error,
    handlers?: GuardExecuteHandlers<unknown>,
  ): Promise<void> {
    try {
      await this.hooks.onEscalationError?.({ input, decision, error });
    } catch {}
    try {
      await handlers?.onEscalationError?.({ input, decision, error });
    } catch {}
  }

  private mapError(error: unknown): Error {
    if (error instanceof EscalationAbortError) {
      return new GuardAbortError(error.message);
    }
    if (error instanceof EscalationTimeoutError) {
      return new GuardEscalationTimeoutError(error.message);
    }
    if (error instanceof CoreaxEscalationError) {
      return new GuardEscalationError(error.message);
    }
    return new GuardEscalationError(
      error instanceof Error ? error.message : String(error),
    );
  }
}

export function isEscalationTerminal(status: string): boolean {
  return status === "approved" || status === "rejected" || status === "expired";
}
