import {
  GuardBlockedError,
  GuardConfigError,
  GuardEscalationError,
  GuardEscalationTimeoutError,
} from "./errors";
import { verifyApprovalCapability } from "../escalation";
import { GuardEscalationLifecycle } from "./escalation";
import { evaluateGuardDecision } from "./policy";
import { createGuardPolicyProvider } from "./providers";
import { createNoopApprovalTransport } from "./transport";
import type {
  CoreaxGuard,
  CoreaxGuardConfig,
  GuardDecision,
  GuardExecuteHandlers,
  GuardExecutionResult,
  GuardHooks,
  GuardInput,
  GuardLogEvent,
  GuardRuntimeContext,
  GuardWaitForResolutionOptions,
} from "./types";

function runtimeContext(config: CoreaxGuardConfig): GuardRuntimeContext {
  return {
    now: config.now ?? (() => Date.now()),
    sleep:
      config.sleep ??
      ((milliseconds) =>
        new Promise<void>((resolve) => setTimeout(resolve, milliseconds))),
    log(event: GuardLogEvent) {
      try {
        config.logger?.(event);
      } catch {}
    },
  };
}

function combinedHooks(
  globalHooks?: Partial<GuardHooks>,
  localHooks?: Partial<GuardHooks>,
): Partial<GuardHooks> {
  return {
    async onEscalationRequested(event) {
      await globalHooks?.onEscalationRequested?.(event);
      await localHooks?.onEscalationRequested?.(event);
    },
    async onEscalationResolved(event) {
      await globalHooks?.onEscalationResolved?.(event);
      await localHooks?.onEscalationResolved?.(event);
    },
    async onEscalationError(event) {
      await globalHooks?.onEscalationError?.(event);
      await localHooks?.onEscalationError?.(event);
    },
  };
}

function validateInput(input: GuardInput): void {
  const kinds = new Set(["message_outbound", "tool_call", "mcp_call", "api_call"]);
  if (!input || typeof input !== "object" || !kinds.has(input.kind)) {
    throw new GuardConfigError(
      "guard input.kind must be message_outbound, tool_call, mcp_call, or api_call",
    );
  }
}

function cloneGuardInput(input: GuardInput): GuardInput {
  try {
    return structuredClone(input);
  } catch {
    throw new GuardConfigError(
      "guard input must be structured-cloneable so policy checks and execution use the same snapshot",
    );
  }
}

function freezeSnapshot<T>(value: T, seen = new Set<object>()): T {
  if (!value || typeof value !== "object" || seen.has(value)) return value;
  if (ArrayBuffer.isView(value)) return value;
  seen.add(value);
  if (value instanceof Map) {
    for (const [key, item] of value) {
      freezeSnapshot(key, seen);
      freezeSnapshot(item, seen);
    }
  } else if (value instanceof Set) {
    for (const item of value) freezeSnapshot(item, seen);
  } else {
    for (const item of Object.values(value as Record<string, unknown>)) {
      freezeSnapshot(item, seen);
    }
  }
  return Object.freeze(value);
}

function snapshotGuardInput(input: GuardInput): GuardInput {
  const snapshot = cloneGuardInput(input);
  validateInput(snapshot);
  return freezeSnapshot(snapshot);
}

export function createCoreaxGuard(
  config: CoreaxGuardConfig = {},
): CoreaxGuard {
  const mode = config.mode === "observe" ? "observe" : "enforce";
  const runtime = runtimeContext(config);
  const provider = createGuardPolicyProvider({
    provider: config.provider,
    runtime,
  });
  const transport = config.transport ?? createNoopApprovalTransport();
  const lifecycle = new GuardEscalationLifecycle(
    config.escalation,
    runtime,
    config.hooks ?? {},
    transport,
  );

  async function checkSnapshot(input: GuardInput): Promise<GuardDecision> {
    return evaluateGuardDecision({
      snapshot: await provider.getPolicy(cloneGuardInput(input)),
      mode,
      input,
    });
  }

  async function check(input: GuardInput): Promise<GuardDecision> {
    return checkSnapshot(snapshotGuardInput(input));
  }

  async function execute<T>(
    input: GuardInput,
    action: (
      guardedInput: GuardInput,
      decision: GuardDecision,
    ) => Promise<T> | T,
    handlers?: GuardExecuteHandlers<T>,
  ): Promise<GuardExecutionResult<T>> {
    if (typeof action !== "function") {
      throw new GuardConfigError("guard.execute requires an action function");
    }
    const inputSnapshot = snapshotGuardInput(input);
    const decision = await checkSnapshot(inputSnapshot);

    if (mode === "observe" || decision.outcome === "allow") {
      return {
        decision,
        value: await action(cloneGuardInput(inputSnapshot), decision),
      };
    }
    if (decision.outcome === "redact") {
      const proposedInput = handlers?.onRedactInput
        ? await handlers.onRedactInput(
            cloneGuardInput(inputSnapshot),
            decision,
          )
        : {
            ...cloneGuardInput(inputSnapshot),
            content: decision.redactedContent ?? inputSnapshot.content,
          };
      const redactedInput = snapshotGuardInput(proposedInput);
      return {
        decision,
        value: await action(cloneGuardInput(redactedInput), decision),
      };
    }
    if (decision.outcome === "block") {
      if (handlers?.onBlock) {
        return { decision, value: await handlers.onBlock(decision) };
      }
      throw new GuardBlockedError(
        `Guard blocked execution (${decision.reason ?? "policy_denied"})`,
        { reasons: decision.reasons, provider: decision.provider },
      );
    }
    if (!lifecycle.enabled) {
      throw new GuardBlockedError("Escalation is disabled; execution failed closed");
    }

    const hooks = combinedHooks(config.hooks, handlers);
    try {
      const { payload, state, binding } = await lifecycle.requestEscalation(
        inputSnapshot,
        decision,
      );
      const escalationId = binding.escalationId;
      const pendingDecision: GuardDecision = {
        ...decision,
        escalation: {
          shouldEscalate: true,
          waitForResolution:
            handlers?.waitForEscalation ??
            config.escalation?.waitForResolutionByDefault ??
            true,
          escalationId,
          status: state.status,
        },
      };
      await hooks.onEscalationRequested?.({
        input: cloneGuardInput(inputSnapshot),
        decision: pendingDecision,
        payload,
        created: state.request,
      });
      try {
        await transport.sendPending({
          escalationId,
          input: cloneGuardInput(inputSnapshot),
          decision: pendingDecision,
          payload,
          createResult: state.request,
        });
      } catch (error) {
        runtime.log({
          level: "warn",
          message: "approval transport notification failed",
          data: { cause: error instanceof Error ? error.message : String(error) },
        });
      }

      const resolution = await lifecycle.maybeWaitForResolution({
        input: cloneGuardInput(inputSnapshot),
        decision: pendingDecision,
        escalationId,
        binding,
        handlers: handlers as GuardExecuteHandlers<unknown>,
      });
      if (!resolution) return { decision: pendingDecision };

      const resolvedDecision: GuardDecision = {
        ...pendingDecision,
        escalation: {
          ...pendingDecision.escalation!,
          status: resolution.status,
          resolution,
        },
      };
      if (resolution.status === "approved" && resolution.resolution) {
        const capabilityConfig =
          config.escalation?.approvalCapability;
        if (
          !capabilityConfig ||
          typeof capabilityConfig.getCapability !== "function"
        ) {
          throw new GuardBlockedError(
            "Approved escalation is missing approval capability verification",
            {
              escalationId,
              approvalId: resolution.resolution.id,
              reason: "missing",
            },
          );
        }

        let capability: string | null | undefined;
        try {
          capability = await capabilityConfig.getCapability({
            input: cloneGuardInput(inputSnapshot),
            decision: structuredClone(resolvedDecision),
            resolution: structuredClone(resolution),
          });
        } catch {
          throw new GuardBlockedError(
            "Approval capability could not be obtained",
            {
              escalationId,
              approvalId: resolution.resolution.id,
              reason: "capability_source_error",
            },
          );
        }

        const verification = await verifyApprovalCapability({
          token: capability,
          expected: {
            escalationId: binding.escalationId,
            approvalId: resolution.resolution.id,
            action: binding.action,
            scope: binding.scope,
          },
          nonceStore: capabilityConfig.nonceStore,
          publicKey: capabilityConfig.publicKey,
          expectedKeyId: capabilityConfig.expectedKeyId,
          keyResolver: capabilityConfig.keyResolver,
          now: runtime.now,
          clockSkewMs: capabilityConfig.clockSkewMs,
        });
        if (!verification.valid) {
          throw new GuardBlockedError(
            `Approval capability verification failed (${verification.reason})`,
            {
              escalationId,
              approvalId: resolution.resolution.id,
              reason: verification.reason,
            },
          );
        }

        return {
          decision: resolvedDecision,
          escalation: resolution,
          value: await action(
            cloneGuardInput(inputSnapshot),
            resolvedDecision,
          ),
        };
      }
      if (handlers?.onBlock) {
        return {
          decision: resolvedDecision,
          escalation: resolution,
          value: await handlers.onBlock(resolvedDecision),
        };
      }
      throw new GuardBlockedError(
        `Escalation resolved as ${resolution.status}`,
        { escalationId },
      );
    } catch (error) {
      const asError = error instanceof Error ? error : new Error(String(error));
      await lifecycle.emitEscalationError(
        cloneGuardInput(inputSnapshot),
        decision,
        asError,
        handlers as GuardExecuteHandlers<unknown>,
      );
      if (
        error instanceof GuardBlockedError ||
        error instanceof GuardEscalationTimeoutError
      ) {
        throw error;
      }
      throw new GuardEscalationError(asError.message);
    }
  }

  return {
    check,
    execute,
    waitForResolution(
      escalationId: string,
      options?: GuardWaitForResolutionOptions,
    ) {
      return lifecycle.waitForResolution(escalationId, options);
    },
  };
}

export * from "./errors";
export { isEscalationTerminal } from "./escalation";
export { createNoopApprovalTransport } from "./transport";
export * from "./types";
