import { randomBytes, randomUUID } from "node:crypto";
import { serialize } from "node:v8";
import YAML from "yaml";

import { evaluateContextualInputLocalAsync } from "../evaluator";
import {
  GuardBlockedError,
  createCoreaxGuard,
  type GuardDecision,
  type GuardPolicyInput,
} from "../guard";
import { canonicalize, sha256Hex } from "../signer";
import { createCoreaxAuditSink } from "./adapters/auditSink";
import {
  PolicyDeniedError,
  type McpServerLike,
  type MiddlewareOptions,
  type ToolHandler,
  type ToolInvocationContext,
} from "./middlewareTypes";

export type {
  McpServerLike,
  MiddlewareAdapters,
  MiddlewareContextualEvaluatorOptions,
  MiddlewareOptions,
  PolicyViolation,
  ToolHandler,
  ToolInvocationContext,
} from "./middlewareTypes";
export {
  IdempotencyRequiredError,
  PolicyDeniedError,
  SigningFailedError,
  UnpinnedVersionError,
} from "./middlewareTypes";

export interface CoreaxMiddlewareController {
  flush(): Promise<void>;
}

function parsePolicy(value: GuardPolicyInput | string): GuardPolicyInput {
  if (typeof value !== "string") return value;
  const parsed = YAML.parse(value);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new TypeError("CoreAX policy must parse to an object");
  }
  return parsed as GuardPolicyInput;
}

function readHeader(
  headers: Record<string, string> | undefined,
  name: string,
): string | undefined {
  if (!headers) return undefined;
  const target = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === target && value.trim()) return value.trim();
  }
  return undefined;
}

function digest(value: unknown): string | null {
  if (value === undefined) return null;
  try {
    return sha256Hex(canonicalize(value));
  } catch {
    return sha256Hex(serialize(value));
  }
}

function policyViolation(decision?: GuardDecision): PolicyDeniedError {
  if (!decision) {
    return new PolicyDeniedError(
      "tool_not_in_allowlist",
      "CoreAX guard denied execution",
    );
  }
  const reason =
    decision.violation || decision.reason || "tool_not_in_allowlist";
  const supported = new Set([
    "tool_not_in_allowlist",
    "version_unpinned",
    "missing_idempotency_for_side_effect",
    "agent_guard_failed",
    "egress_violation",
    "fs_violation",
    "payload_too_large",
    "registry_mutation",
    "handler_swap",
    "server_code_changed",
    "tool_code_changed",
  ]);
  return new PolicyDeniedError(
    (supported.has(reason) ? reason : "tool_not_in_allowlist") as any,
    `CoreAX denied ${decision.kind}: ${reason}`,
  );
}

function auditPolicyDecision(
  decision: GuardDecision | undefined,
): "allow" | "deny" {
  if (
    decision?.outcome === "escalate" &&
    decision.escalation?.status === "approved"
  ) {
    return "allow";
  }
  return !decision ||
    decision.outcome === "block" ||
    decision.outcome === "escalate"
    ? "deny"
    : "allow";
}

function lockServerHook(
  server: McpServerLike,
  name: "tool" | "__getTools" | "__setTool",
  value: unknown,
): void {
  const current = Object.getOwnPropertyDescriptor(server, name);
  try {
    Object.defineProperty(server, name, {
      configurable: false,
      enumerable: current?.enumerable ?? true,
      value,
      writable: false,
    });
  } catch {
    throw new TypeError(
      `CoreAX could not secure the runtime ${name} hook`,
    );
  }
  const installed = Object.getOwnPropertyDescriptor(server, name);
  if (
    (server as unknown as Record<string, unknown>)[name] !== value ||
    !installed ||
    installed.configurable ||
    installed.writable
  ) {
    throw new TypeError(`CoreAX runtime rejected the secure ${name} hook`);
  }
}

function cloneInvocation(
  invocation: ToolInvocationContext,
): ToolInvocationContext {
  if (!invocation || typeof invocation !== "object") {
    throw new TypeError("CoreAX tool invocation must be an object");
  }
  try {
    return structuredClone(invocation);
  } catch {
    throw new TypeError(
      "CoreAX tool invocation must be structured-cloneable",
    );
  }
}

function isLikelySideEffect(tool: string): boolean {
  return /(?:^|[_./-])(create|update|delete|write|send|publish|execute|run|post|put|patch)(?:$|[_./-])/i.test(
    tool,
  );
}

/**
 * Wraps every registered tool with local deterministic enforcement and a
 * signed, hash-only audit trail. Construction never reads environment
 * variables and execution never performs an outbound request.
 */
export function coreaxSecurityMiddleware(options: MiddlewareOptions) {
  const policy = parsePolicy(options.policy);
  const guard =
    options.adapters?.guard ??
    createCoreaxGuard({
      ...options.guard,
      mode: options.mode ?? "enforce",
      provider: { local: { policy } },
    });
  const auditSink =
    options.adapters?.auditSink ??
    createCoreaxAuditSink({
      config: options.coreax,
      signer: options.signer,
    });
  const now = options.now ?? (() => Date.now());

  return (server: McpServerLike): CoreaxMiddlewareController => {
    auditSink.initialize?.();
    if (
      typeof server.__getTools !== "function" ||
      typeof server.__setTool !== "function"
    ) {
      throw new TypeError(
        "CoreAX middleware requires __getTools and __setTool hooks to prevent unwrapped tool execution",
      );
    }
    const getRegisteredTools = server.__getTools.bind(server);
    const setRegisteredTool = server.__setTool.bind(server);
    const registerTool = server.tool.bind(server);
    const readRegisteredTools = (): Map<string, ToolHandler> => {
      const registeredTools = getRegisteredTools();
      if (!(registeredTools instanceof Map)) {
        throw new TypeError("CoreAX __getTools must return a Map");
      }
      return registeredTools;
    };
    const tools = new Map(readRegisteredTools());
    const securedHandlers = new WeakMap<ToolHandler, string>();

    const wrapTool = (tool: string, original: ToolHandler): ToolHandler => {
      if (!tool.trim() || typeof original !== "function") {
        throw new TypeError(
          "CoreAX tool registrations require a name and handler function",
        );
      }
      if (securedHandlers.get(original) === tool) return original;
      const wrapped: ToolHandler = async (
        invocation: ToolInvocationContext,
      ) => {
        const invocationSnapshot = cloneInvocation(invocation);
        const startedAt = now();
        const traceId =
          readHeader(invocationSnapshot.headers, "x-trace-id") ??
          randomUUID().replace(/-/g, "");
        const spanId =
          readHeader(invocationSnapshot.headers, "x-span-id") ??
          randomBytes(8).toString("hex");
        const runId = readHeader(invocationSnapshot.headers, "x-agent-ref");
        const nodeId = readHeader(invocationSnapshot.headers, "x-node-id");
        const inputSha256 = digest(invocationSnapshot.args);
        let finalAuditAttempted = false;
        const appendFinalAudit = async (
          status: "ok" | "error",
          policyDecision: "allow" | "deny",
          output: unknown,
        ): Promise<void> => {
          finalAuditAttempted = true;
          await auditSink.append({
            ts: new Date(now()).toISOString(),
            trace_id: traceId,
            span_id: spanId,
            namespace: options.namespace ?? "default",
            server: `${server.name}@${server.version}`,
            tool,
            status,
            latency_ms: Math.max(0, now() - startedAt),
            retries: 0,
            input_sha256: inputSha256,
            output_sha256: status === "ok" ? digest(output) : null,
            policy: { decision: policyDecision },
            idempotency_key: invocationSnapshot.idempotencyKey ?? null,
            nodeId: nodeId ?? null,
            agentRef: runId ?? null,
          });
        };

        try {
          if (options.contextualEvaluator) {
            const evaluatorInput = await options.contextualEvaluator.buildInput({
              server: { name: server.name, version: server.version },
              tool,
              invocation: cloneInvocation(invocationSnapshot),
            });
            const evaluatorOutput = await evaluateContextualInputLocalAsync(
              evaluatorInput,
              {
                semanticCalibrator:
                  options.contextualEvaluator.semanticCalibrator,
                denyThreshold: options.contextualEvaluator.denyThreshold,
                escalateThreshold:
                  options.contextualEvaluator.escalateThreshold,
              },
            );
            if (evaluatorOutput && evaluatorOutput.decision !== "allow") {
              const violation =
                evaluatorOutput.decision === "clarify"
                  ? "contextual_evaluator_clarification_required"
                  : evaluatorOutput.decision === "escalate"
                    ? "contextual_evaluator_escalated"
                    : "contextual_evaluator_denied";
              await appendFinalAudit("error", "deny", undefined);
              throw new PolicyDeniedError(
                violation,
                `CoreAX contextual evaluator denied execution: ${violation}`,
              );
            }
          }
        } catch (error) {
          if (!finalAuditAttempted) {
            await appendFinalAudit("error", "deny", undefined);
          }
          throw error;
        }

        const guardInput = {
          kind: "tool_call" as const,
          target: `${server.name}/${tool}`,
          content: invocationSnapshot.args,
          context: {
            runId,
            nodeId,
            metadata: {
              serverVersion: server.version,
              idempotencyKey: invocationSnapshot.idempotencyKey ?? null,
              sideEffect: isLikelySideEffect(tool),
            },
          },
        };
        const deniedExecution = Symbol("coreax-denied-execution");
        let decision: GuardDecision | undefined;
        let decisionReported = false;
        let handlerInvoked = false;
        const reportDecision = async (
          nextDecision: GuardDecision,
        ): Promise<void> => {
          decision = nextDecision;
          if (decisionReported) return;
          decisionReported = true;
          await options.onDecision?.({
            server: { name: server.name, version: server.version },
            tool,
            decision: nextDecision,
          });
        };
        try {
          const execution = await guard.execute<unknown>(
            guardInput,
            async (guardedInput, guardedDecision) => {
              await reportDecision(guardedDecision);
              const handlerInvocation = {
                ...cloneInvocation(invocationSnapshot),
                args: guardedInput.content,
              };
              handlerInvoked = true;
              return original(handlerInvocation);
            },
            {
              async onBlock(blockedDecision) {
                await reportDecision(blockedDecision);
                return deniedExecution;
              },
            },
          );
          await reportDecision(execution.decision);
          if (
            execution.value === deniedExecution ||
            !handlerInvoked
          ) {
            await appendFinalAudit(
              "error",
              "deny",
              undefined,
            );
            throw policyViolation(execution.decision);
          }
          await appendFinalAudit(
            "ok",
            auditPolicyDecision(execution.decision),
            execution.value,
          );
          return execution.value;
        } catch (error) {
          if (!finalAuditAttempted) {
            await appendFinalAudit(
              "error",
              auditPolicyDecision(decision),
              undefined,
            );
          }
          if (error instanceof GuardBlockedError) {
            throw policyViolation(decision);
          }
          throw error;
        }
      };
      securedHandlers.set(wrapped, tool);
      return wrapped;
    };

    for (const [tool, original] of tools) {
      const wrapped = wrapTool(tool, original);
      setRegisteredTool(tool, wrapped);
      if (readRegisteredTools().get(tool) !== wrapped) {
        throw new TypeError(
          `CoreAX could not enforce the registered tool "${tool}"`,
        );
      }
    }

    const secureRegister: McpServerLike["tool"] = (tool, handler) => {
      const wrapped = wrapTool(tool, handler);
      registerTool(tool, wrapped);
      if (readRegisteredTools().get(tool) !== wrapped) {
        throw new TypeError(
          `CoreAX could not enforce the late-registered tool "${tool}"`,
        );
      }
    };
    const secureSetTool: NonNullable<McpServerLike["__setTool"]> = (
      tool,
      handler,
    ) => {
      const wrapped = wrapTool(tool, handler);
      setRegisteredTool(tool, wrapped);
      if (readRegisteredTools().get(tool) !== wrapped) {
        throw new TypeError(
          `CoreAX could not enforce the replaced tool "${tool}"`,
        );
      }
    };
    const secureGetTools: NonNullable<McpServerLike["__getTools"]> = () =>
      new Map(readRegisteredTools());

    lockServerHook(server, "tool", secureRegister);
    lockServerHook(server, "__setTool", secureSetTool);
    lockServerHook(server, "__getTools", secureGetTools);

    return {
      async flush() {
        await auditSink.flush?.();
      },
    };
  };
}

export const coreaxLocalMiddleware = coreaxSecurityMiddleware;
