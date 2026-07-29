import type {
  CoreaxGuard,
  GuardDecision,
  GuardExecutionResult,
  GuardInputContext,
} from "../../guard";

export type CustomAgentContext = Omit<
  GuardInputContext,
  "filesystemPaths"
> & {
  agentId?: string;
  sessionId?: string;
};

export interface CustomAgentToolCall<TArguments = unknown> {
  name: string;
  arguments: TArguments;
  context?: CustomAgentContext;
}

export interface CustomAgentOutboundMessage<TMessage = unknown> {
  message: TMessage;
  target?: string;
  context?: CustomAgentContext;
}

export interface CustomAgentToolFilesystemInput {
  readonly name: string;
  readonly target: string;
  readonly arguments: unknown;
}

export type CustomAgentFilesystemPathExtractor = (
  call: Readonly<CustomAgentToolFilesystemInput>,
) => readonly string[] | undefined;

export interface CustomAgentAdapterConfig {
  guard: CoreaxGuard;
  toolTarget?: (call: CustomAgentToolCall) => string;
  /**
   * Trusted harness callback that describes the paths the tool implementation
   * will access. Model-supplied context is intentionally not exposed here.
   */
  extractToolFilesystemPaths?: CustomAgentFilesystemPathExtractor;
  messageTarget?: (message: CustomAgentOutboundMessage) => string | undefined;
}

export interface CustomAgentAdapter {
  checkToolCall<TArguments>(call: CustomAgentToolCall<TArguments>): Promise<GuardDecision>;
  executeTool<TArguments, TResult>(
    call: CustomAgentToolCall<TArguments>,
    execute: (
      arguments_: TArguments,
      decision: GuardDecision,
    ) => Promise<TResult> | TResult,
  ): Promise<GuardExecutionResult<TResult>>;
  checkOutboundMessage<TMessage>(
    outbound: CustomAgentOutboundMessage<TMessage>,
  ): Promise<GuardDecision>;
  sendOutboundMessage<TMessage, TResult>(
    outbound: CustomAgentOutboundMessage<TMessage>,
    send: (
      message: TMessage,
      decision: GuardDecision,
    ) => Promise<TResult> | TResult,
  ): Promise<GuardExecutionResult<TResult>>;
}

function toGuardContext(
  context?: CustomAgentContext,
  trustedFilesystemPaths?: readonly string[],
): GuardInputContext | undefined {
  if (!context && trustedFilesystemPaths === undefined) return undefined;
  const {
    agentId,
    sessionId,
    filesystemPaths: _untrustedFilesystemPaths,
    ...guardContext
  } = (context ?? {}) as CustomAgentContext & {
    filesystemPaths?: unknown;
  };
  return {
    ...guardContext,
    ...(trustedFilesystemPaths !== undefined
      ? { filesystemPaths: [...trustedFilesystemPaths] }
      : {}),
    metadata: {
      ...(guardContext.metadata ?? {}),
      ...(agentId ? { agentId } : {}),
      ...(sessionId ? { sessionId } : {}),
    },
  };
}

function snapshotToolArguments<TArguments>(
  arguments_: TArguments,
): TArguments {
  try {
    return structuredClone(arguments_);
  } catch {
    throw new TypeError(
      "custom-agent tool arguments must be structured-cloneable",
    );
  }
}

/**
 * Adapts CoreAX to any agent framework without taking a dependency on that
 * framework. Callers retain control of tool execution, transport, and state.
 */
export function createCustomAgentAdapter(
  config: CustomAgentAdapterConfig,
): CustomAgentAdapter {
  const { guard } = config;
  if (!guard || typeof guard.check !== "function" || typeof guard.execute !== "function") {
    throw new TypeError("createCustomAgentAdapter requires a CoreaxGuard");
  }
  if (
    config.extractToolFilesystemPaths !== undefined &&
    typeof config.extractToolFilesystemPaths !== "function"
  ) {
    throw new TypeError(
      "extractToolFilesystemPaths must be a trusted caller-supplied function",
    );
  }

  function toolInput<TArguments>(call: CustomAgentToolCall<TArguments>) {
    const argumentsSnapshot = snapshotToolArguments(call.arguments);
    const snapshottedCall: CustomAgentToolCall<TArguments> = {
      name: call.name,
      arguments: argumentsSnapshot,
      ...(call.context ? { context: call.context } : {}),
    };
    const target =
      config.toolTarget?.(snapshottedCall) ?? snapshottedCall.name;
    const trustedFilesystemPaths =
      config.extractToolFilesystemPaths?.(
        Object.freeze({
          name: snapshottedCall.name,
          target,
          arguments: argumentsSnapshot,
        }),
      );
    return {
      kind: "tool_call" as const,
      content: argumentsSnapshot,
      target,
      context: toGuardContext(
        snapshottedCall.context,
        trustedFilesystemPaths,
      ),
    };
  }

  function messageInput<TMessage>(outbound: CustomAgentOutboundMessage<TMessage>) {
    return {
      kind: "message_outbound" as const,
      content: outbound.message,
      target: config.messageTarget?.(outbound) ?? outbound.target,
      context: toGuardContext(outbound.context),
    };
  }

  return {
    checkToolCall: (call) => guard.check(toolInput(call)),
    executeTool: (call, execute) =>
      guard.execute(toolInput(call), (input, decision) =>
        execute(input.content as typeof call.arguments, decision),
      ),
    checkOutboundMessage: (outbound) => guard.check(messageInput(outbound)),
    sendOutboundMessage: (outbound, send) =>
      guard.execute(messageInput(outbound), (input, decision) =>
        send(input.content as typeof outbound.message, decision),
      ),
  };
}
