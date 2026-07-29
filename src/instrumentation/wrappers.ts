import { createHash } from "node:crypto";

import {
  requireCoreaxConfiguration,
  type CoreaxInstrumentationEvent,
  type CoreaxNodeDefinition,
  type CoreaxNodeKind,
  type ResolvedCoreaxInstrumentationConfig,
} from "./configuration";
import {
  generateInvocationId,
  generateRunRef,
  generateSpanId,
  generateTraceId,
  getCoreaxContext,
  runWithCoreaxContext,
  type CoreaxInvocationNode,
  type CoreaxRunContext,
} from "./context";

type AnyFunction = (...args: any[]) => any;

export type CoreaxWrapperOptions = Partial<
  Omit<CoreaxNodeDefinition, "kind">
> & {
  kind: CoreaxNodeKind;
  key?: string;
  runId?: string;
};

export type CoreaxSpecializedWrapperOptions = Omit<
  CoreaxWrapperOptions,
  "kind"
>;

function requiredIdentifier(value: string, field: string): string {
  const normalized = value.trim();
  if (!normalized) throw new TypeError(`${field} must be a non-empty string`);
  return normalized;
}

function generatedIdentifier(
  config: ResolvedCoreaxInstrumentationConfig,
  kind: "run" | "trace" | "span" | "invocation",
): string {
  const generated =
    config.idGenerator?.(kind) ??
    (kind === "run"
      ? generateRunRef()
      : kind === "trace"
        ? generateTraceId()
        : kind === "span"
          ? generateSpanId()
          : generateInvocationId());
  return requiredIdentifier(generated, `idGenerator(${kind})`);
}

function currentTime(config: ResolvedCoreaxInstrumentationConfig): number {
  const value = config.clock();
  if (!Number.isFinite(value)) {
    throw new TypeError("instrumentation clock must return epoch milliseconds");
  }
  return value;
}

function timestamp(milliseconds: number): string {
  return new Date(milliseconds).toISOString();
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function errorEvidence(error: unknown): NonNullable<
  CoreaxInstrumentationEvent["error"]
> {
  const name =
    error instanceof Error && error.name.trim() ? error.name.trim() : "Error";
  const message = error instanceof Error ? error.message : String(error);
  return { name, messageSha256: sha256(message) };
}

function resolveKey(
  callable: AnyFunction,
  options: CoreaxWrapperOptions,
): string {
  return requiredIdentifier(
    options.key?.trim() || callable.name.trim() || `${options.kind}:anonymous`,
    "wrapper key",
  );
}

function resolveNode(
  callable: AnyFunction,
  options: CoreaxWrapperOptions,
  config: ResolvedCoreaxInstrumentationConfig,
): CoreaxInvocationNode {
  const key = resolveKey(callable, options);
  const configured = config.nodes[key];
  if (configured && configured.kind !== options.kind) {
    throw new TypeError(
      `instrumentation node "${key}" is configured as ${configured.kind}, not ${options.kind}`,
    );
  }
  const name = requiredIdentifier(
    options.name?.trim() || configured?.name?.trim() || key,
    `instrumentation node "${key}" name`,
  );
  const nodeId = requiredIdentifier(
    options.nodeId?.trim() ||
      configured?.nodeId?.trim() ||
      `${options.kind}:${name}`,
    `instrumentation node "${key}" nodeId`,
  );
  const version = options.version?.trim() || configured?.version?.trim();
  const server = options.server?.trim() || configured?.server?.trim();
  const operation = options.operation?.trim() || configured?.operation?.trim();
  const metadata = {
    ...(configured?.metadata ?? {}),
    ...(options.metadata ?? {}),
  };
  return Object.freeze({
    key,
    kind: options.kind,
    nodeId,
    name,
    ...(version ? { version } : {}),
    ...(server ? { server } : {}),
    ...(operation ? { operation } : {}),
    ...(Object.keys(metadata).length > 0
      ? { metadata: Object.freeze(metadata) }
      : {}),
  });
}

function buildContext(
  node: CoreaxInvocationNode,
  options: CoreaxWrapperOptions,
  config: ResolvedCoreaxInstrumentationConfig,
): CoreaxRunContext {
  const parent = getCoreaxContext();
  const runId =
    options.runId?.trim() ||
    parent?.runId ||
    generatedIdentifier(config, "run");
  const traceId = parent?.traceId || generatedIdentifier(config, "trace");
  const spanId = generatedIdentifier(config, "span");
  const invocationId = generatedIdentifier(config, "invocation");
  const metadata = {
    ...(parent?.metadata ?? {}),
    ...(node.metadata ?? {}),
  };
  return Object.freeze({
    runId: requiredIdentifier(runId, "runId"),
    traceId,
    spanId,
    ...(parent?.spanId ? { parentSpanId: parent.spanId } : {}),
    invocationId,
    node,
    ...(Object.keys(metadata).length > 0
      ? { metadata: Object.freeze(metadata) }
      : {}),
  });
}

function emitEvent(
  config: ResolvedCoreaxInstrumentationConfig,
  event: CoreaxInstrumentationEvent,
): void {
  config.onEvent?.(Object.freeze(event));
}

function isPromiseLike(
  value: unknown,
): value is PromiseLike<unknown> {
  if (
    (typeof value !== "object" || value === null) &&
    typeof value !== "function"
  ) {
    return false;
  }
  return typeof (value as { then?: unknown }).then === "function";
}

export function wrapCoreaxFunction<T extends AnyFunction>(
  callable: T,
  options: CoreaxWrapperOptions,
): T {
  if (typeof callable !== "function") {
    throw new TypeError("wrapCoreaxFunction requires a function");
  }
  const wrapped = function (
    this: ThisParameterType<T>,
    ...args: Parameters<T>
  ): ReturnType<T> {
    const config = requireCoreaxConfiguration();
    const node = resolveNode(callable, options, config);
    const context = buildContext(node, options, config);
    return runWithCoreaxContext(context, () => {
      const startedAt = currentTime(config);
      const baseEvent = {
        invocationId: context.invocationId!,
        runId: context.runId,
        traceId: context.traceId,
        spanId: context.spanId,
        ...(context.parentSpanId
          ? { parentSpanId: context.parentSpanId }
          : {}),
        node,
      };
      emitEvent(config, {
        ...baseEvent,
        phase: "start",
        timestamp: timestamp(startedAt),
      });

      const complete = (
        phase: "success" | "error",
        error?: unknown,
      ): void => {
        const completedAt = currentTime(config);
        emitEvent(config, {
          ...baseEvent,
          phase,
          timestamp: timestamp(completedAt),
          durationMs: Math.max(0, completedAt - startedAt),
          ...(phase === "error" ? { error: errorEvidence(error) } : {}),
        });
      };

      let result: ReturnType<T>;
      try {
        result = callable.apply(this, args) as ReturnType<T>;
      } catch (error) {
        try {
          complete("error", error);
        } catch {
          // Preserve the original application failure.
        }
        throw error;
      }
      if (isPromiseLike(result)) {
        return Promise.resolve(result).then(
          (value) => {
            complete("success");
            return value;
          },
          (error: unknown) => {
            try {
              complete("error", error);
            } catch {
              // Preserve the original application failure.
            }
            throw error;
          },
        ) as ReturnType<T>;
      }
      complete("success");
      return result;
    });
  };
  Object.defineProperty(wrapped, "name", {
    value: callable.name || `coreax_${options.kind}`,
    configurable: true,
  });
  return wrapped as T;
}

function specializedWrapper(kind: CoreaxNodeKind) {
  return <T extends AnyFunction>(
    callable: T,
    options: CoreaxSpecializedWrapperOptions = {},
  ): T => wrapCoreaxFunction(callable, { ...options, kind });
}

export const wrapCoreaxAgent = specializedWrapper("agent");
export const wrapCoreaxOrchestrator = specializedWrapper("orchestrator");
export const wrapCoreaxServer = specializedWrapper("server");
export const wrapCoreaxMiddleware = specializedWrapper("middleware");
export const wrapCoreaxTool = specializedWrapper("tool");
export const wrapCoreaxSkill = specializedWrapper("skill");
