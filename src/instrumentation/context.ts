import { AsyncLocalStorage } from "node:async_hooks";
import { randomBytes } from "node:crypto";

import type { CoreaxNodeDefinition } from "./configuration";

export type CoreaxInvocationNode = Readonly<
  Required<Pick<CoreaxNodeDefinition, "kind" | "nodeId" | "name">> &
    Omit<CoreaxNodeDefinition, "kind" | "nodeId" | "name"> & { key: string }
>;

export type CoreaxRunContext = Readonly<{
  runId: string;
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  invocationId?: string;
  node?: CoreaxInvocationNode;
  metadata?: Readonly<Record<string, unknown>>;
}>;

export type SeedCoreaxRunOptions = {
  traceId?: string;
  spanId?: string;
  metadata?: Readonly<Record<string, unknown>>;
};

const contextStorage = new AsyncLocalStorage<CoreaxRunContext>();

function normalizedRequiredIdentifier(value: string, field: string): string {
  const normalized = value.trim();
  if (!normalized) throw new TypeError(`${field} must be a non-empty string`);
  return normalized;
}

function randomHex(bytes: number): string {
  return randomBytes(bytes).toString("hex");
}

export function generateRunRef(): string {
  return randomHex(16);
}

export function generateTraceId(): string {
  return randomHex(16);
}

export function generateSpanId(): string {
  return randomHex(8);
}

export function generateInvocationId(): string {
  return randomHex(16);
}

export function getCoreaxContext(): CoreaxRunContext | undefined {
  return contextStorage.getStore();
}

export function requireCoreaxContext(): CoreaxRunContext {
  const context = getCoreaxContext();
  if (!context) throw new Error("No active CoreAX run context");
  return context;
}

export function runWithCoreaxContext<T>(
  context: CoreaxRunContext,
  callback: () => T,
): T {
  const normalized: CoreaxRunContext = Object.freeze({
    ...context,
    runId: normalizedRequiredIdentifier(context.runId, "context.runId"),
    traceId: normalizedRequiredIdentifier(context.traceId, "context.traceId"),
    spanId: normalizedRequiredIdentifier(context.spanId, "context.spanId"),
    ...(context.metadata
      ? { metadata: Object.freeze({ ...context.metadata }) }
      : {}),
  });
  return contextStorage.run(normalized, callback);
}

export function seedCoreaxRun<T>(
  runId: string,
  callback: () => T,
  options: SeedCoreaxRunOptions = {},
): T {
  return runWithCoreaxContext(
    {
      runId: normalizedRequiredIdentifier(runId, "runId"),
      traceId: options.traceId?.trim() || generateTraceId(),
      spanId: options.spanId?.trim() || generateSpanId(),
      ...(options.metadata
        ? { metadata: Object.freeze({ ...options.metadata }) }
        : {}),
    },
    callback,
  );
}
