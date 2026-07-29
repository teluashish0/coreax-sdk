import { randomUUID } from "node:crypto";

import {
  EscalationApprovalRequiredError,
  EscalationNotFoundError,
  EscalationReporterError,
  EscalationResolverError,
  EscalationValidationError,
} from "./errors";
import { MemoryEscalationStore } from "./store";
import type {
  CreateEscalationInput,
  EscalationRequest,
  EscalationResolution,
  EscalationState,
  EscalationStatus,
  EscalationWaitOptions,
  LocalEscalationManager,
  LocalEscalationManagerConfig,
  ResolveEscalationInput,
} from "./types";
import {
  canonicalJson,
  normalizeJsonObject,
  optionalString,
  requiredString,
  timestampMs,
  validateEscalationResolution,
} from "./validation";
import { waitForEscalationResolution } from "./waiter";

const DEFAULT_TTL_MS = 15 * 60 * 1000;

function clone<T>(value: T): T {
  return JSON.parse(canonicalJson(value)) as T;
}

function immutableClone<T>(value: T, seen = new Set<object>()): T {
  const cloned = seen.size === 0 ? clone(value) : value;
  if (!cloned || typeof cloned !== "object" || seen.has(cloned)) return cloned;
  seen.add(cloned);
  for (const item of Object.values(cloned as Record<string, unknown>)) {
    immutableClone(item, seen);
  }
  return Object.freeze(cloned);
}

function positiveMilliseconds(
  value: number | undefined,
  fallback: number,
  label: string,
): number {
  if (value === undefined) return fallback;
  if (!Number.isFinite(value) || value <= 0) {
    throw new EscalationValidationError(
      `${label} must be a positive finite number`,
    );
  }
  return Math.max(1, Math.floor(value));
}

function isoTimestamp(value: number, label: string): string {
  if (!Number.isFinite(value)) {
    throw new EscalationValidationError(`${label} is not a valid timestamp`);
  }
  try {
    return new Date(value).toISOString();
  } catch {
    throw new EscalationValidationError(`${label} is not a valid timestamp`);
  }
}

export function escalationStatus(
  request: EscalationRequest,
  resolution: EscalationResolution | null,
  now: number = Date.now(),
): EscalationStatus {
  if (!Number.isFinite(now)) {
    throw new EscalationValidationError("Clock returned an invalid timestamp");
  }
  if (resolution?.decision === "reject") return "rejected";
  if (now >= timestampMs(request.expiresAt, "request.expiresAt")) {
    return "expired";
  }
  return resolution?.decision === "approve" ? "approved" : "pending";
}

export function toEscalationState(
  request: EscalationRequest,
  resolution: EscalationResolution | null,
  now: number = Date.now(),
): EscalationState {
  return {
    request,
    resolution,
    status: escalationStatus(request, resolution, now),
  };
}

class DefaultLocalEscalationManager implements LocalEscalationManager {
  private readonly store;
  private readonly reporter;
  private readonly resolver;
  private readonly defaultTtlMs;
  private readonly now;
  private readonly sleep;
  private readonly idFactory;

  constructor(config: LocalEscalationManagerConfig = {}) {
    this.now = config.now ?? (() => Date.now());
    this.sleep =
      config.sleep ??
      ((milliseconds: number) =>
        new Promise<void>((resolve) => setTimeout(resolve, milliseconds)));
    this.store = config.store ?? new MemoryEscalationStore(this.now);
    this.reporter = config.reporter;
    this.resolver = config.resolver;
    this.defaultTtlMs = positiveMilliseconds(
      config.defaultTtlMs,
      DEFAULT_TTL_MS,
      "defaultTtlMs",
    );
    this.idFactory = config.idFactory ?? (() => randomUUID());
  }

  async initialize(): Promise<void> {
    await this.store.initialize?.();
  }

  async create(input: CreateEscalationInput): Promise<EscalationState> {
    const now = this.now();
    if (!Number.isFinite(now)) {
      throw new EscalationValidationError("Clock returned an invalid timestamp");
    }
    const ttlMs = positiveMilliseconds(input.ttlMs, this.defaultTtlMs, "ttlMs");
    const expiresAt = now + ttlMs;
    if (!Number.isFinite(expiresAt)) {
      throw new EscalationValidationError("ttlMs produces an invalid expiration");
    }
    const id = requiredString(input.id ?? this.idFactory(), "id");
    const requestedBy = optionalString(input.requestedBy, "requestedBy");
    const request: EscalationRequest = {
      id,
      action: requiredString(input.action, "action"),
      scope: normalizeJsonObject(input.scope, "scope"),
      reason: requiredString(input.reason, "reason"),
      ...(requestedBy ? { requestedBy } : {}),
      ...(input.metadata !== undefined
        ? { metadata: normalizeJsonObject(input.metadata, "metadata") }
        : {}),
      createdAt: isoTimestamp(now, "createdAt"),
      expiresAt: isoTimestamp(expiresAt, "expiresAt"),
    };

    const stored = await this.store.putPending(request);
    if (this.reporter) {
      try {
        await this.reporter.reportEscalation(immutableClone(stored));
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        throw new EscalationReporterError(
          `Escalation reporter failed: ${message}`,
          stored.id,
        );
      }
    }
    const canonicalRequest = await this.store.getPending(stored.id);
    if (!canonicalRequest) {
      throw new EscalationReporterError(
        "Escalation state disappeared after local persistence",
        stored.id,
      );
    }
    return toEscalationState(canonicalRequest, null, this.now());
  }

  async get(escalationId: string): Promise<EscalationState | null> {
    const id = requiredString(escalationId, "escalationId");
    const request = await this.store.getPending(id);
    if (!request) return null;

    let resolution = await this.store.getResolution(id);
    if (!resolution && this.resolver) {
      try {
        const candidate = await this.resolver.getResolution(
          immutableClone(request),
        );
        if (candidate) {
          validateEscalationResolution(candidate);
          if (candidate.escalationId !== id) {
            throw new EscalationValidationError(
              "Resolver returned a resolution for a different escalation",
            );
          }
          resolution = await this.store.putResolution(candidate);
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        throw new EscalationResolverError(
          `Escalation resolver failed closed: ${message}`,
          id,
        );
      }
    }

    const canonicalRequest = await this.store.getPending(id);
    if (!canonicalRequest) return null;
    return toEscalationState(canonicalRequest, resolution, this.now());
  }

  async listPending(): Promise<EscalationState[]> {
    const requests = await this.store.listPending();
    return requests
      .map((request) => toEscalationState(request, null, this.now()))
      .filter((state) => state.status === "pending");
  }

  async resolve(input: ResolveEscalationInput): Promise<EscalationState> {
    const escalationId = requiredString(input.escalationId, "escalationId");
    const request = await this.store.getPending(escalationId);
    if (!request) throw new EscalationNotFoundError(escalationId);
    if (input.decision !== "approve" && input.decision !== "reject") {
      throw new EscalationValidationError(
        'decision must be "approve" or "reject"',
      );
    }
    const now = this.now();
    if (!Number.isFinite(now)) {
      throw new EscalationValidationError("Clock returned an invalid timestamp");
    }
    const notes = optionalString(input.notes, "notes");
    const resolution: EscalationResolution = {
      id: requiredString(input.resolutionId ?? this.idFactory(), "resolutionId"),
      escalationId,
      decision: input.decision,
      resolvedBy: requiredString(input.resolvedBy, "resolvedBy"),
      ...(notes ? { notes } : {}),
      ...(input.metadata !== undefined
        ? { metadata: normalizeJsonObject(input.metadata, "metadata") }
        : {}),
      resolvedAt: isoTimestamp(now, "resolvedAt"),
    };
    const stored = await this.store.putResolution(resolution);
    return toEscalationState(request, stored, this.now());
  }

  waitForResolution(
    escalationId: string,
    options?: EscalationWaitOptions,
  ): Promise<EscalationState> {
    const id = requiredString(escalationId, "escalationId");
    return waitForEscalationResolution({
      escalationId: id,
      getState: (candidate) => this.get(candidate),
      options,
      now: this.now,
      sleep: this.sleep,
    });
  }

  async requireApproved(escalationId: string): Promise<EscalationState> {
    const id = requiredString(escalationId, "escalationId");
    const state = await this.get(id);
    if (!state || state.status !== "approved" || !state.resolution) {
      throw new EscalationApprovalRequiredError(
        id,
        state?.status ?? "missing",
      );
    }
    return state;
  }
}

export function createLocalEscalationManager(
  config: LocalEscalationManagerConfig = {},
): LocalEscalationManager {
  return new DefaultLocalEscalationManager(config);
}
