import { sha256Hex } from "../signer";

export type ToolInvocationContext = {
  args: any;
  idempotencyKey?: string | null;
  headers?: Record<string, string>;
};

export type ToolHandler = (ctx: ToolInvocationContext) => Promise<any> | any;

type MutableToolHandler = ToolHandler & {
  __sec0_wrapper__?: boolean;
  __sec0_handler_hash?: string;
};

type ToolRegistry = Map<string, ToolHandler>;

type ToolRegistryMutationKind = "tool" | "setTool" | "map";

export type ToolRegistryMutation = {
  tool?: string;
  when: number;
  kind: ToolRegistryMutationKind;
} | null;

export interface ToolRegistrationServer {
  tool(nameAtVersion: string, handler: ToolHandler): void;
  __getTools?(): ToolRegistry;
  __setTool?(nameAtVersion: string, handler: ToolHandler): void;
}

type ToolRuntimeChanges = {
  handlerSwapDetected: boolean;
  toolCodeChanged: boolean;
  serverCodeChanged: boolean;
  registryMutation: boolean;
};

function getWrappedHandlerHash(handler: ToolHandler | undefined): string | undefined {
  if (!handler) return undefined;
  const tagged = handler as MutableToolHandler;
  return typeof tagged.__sec0_handler_hash === "string" && tagged.__sec0_handler_hash
    ? tagged.__sec0_handler_hash
    : undefined;
}

function snapshotHandlerIdentity(
  toolKey: string,
  handler: ToolHandler,
  codeHash: (value: unknown) => string,
): string {
  const tagged = handler as MutableToolHandler;
  if (tagged.__sec0_wrapper__ && tagged.__sec0_handler_hash) {
    return `${toolKey}:${tagged.__sec0_handler_hash}`;
  }
  return `${toolKey}:${codeHash(handler)}`;
}

function snapshotRegistryHash(
  registry: ToolRegistry,
  codeHash: (value: unknown) => string,
): string {
  const parts: string[] = [];
  for (const [toolKey, handler] of registry) {
    parts.push(snapshotHandlerIdentity(toolKey, handler, codeHash));
  }
  return sha256Hex(Buffer.from(parts.sort().join("|")));
}

function createFrozenRegistryError(): Error & { code: string } {
  const error = new Error("REGISTRY_FROZEN") as Error & { code: string };
  error.code = "REGISTRY_FROZEN";
  return error;
}

export function functionCodeHash(fn: unknown): string {
  try {
    const src = typeof fn === "function" ? Function.prototype.toString.call(fn) : String(fn);
    return sha256Hex(Buffer.from(src));
  } catch {
    return sha256Hex(Buffer.from("unknown"));
  }
}

export function createInvocationStats(windowSize = 100, now: () => number = () => Date.now()) {
  const recentByTool: Map<string, Array<{ ok: boolean; latency: number; ts: number }>> = new Map();

  const pushStat = (toolKey: string, ok: boolean, latency: number) => {
    const entries = recentByTool.get(toolKey) ?? [];
    entries.push({ ok, latency, ts: now() });
    if (entries.length > windowSize) entries.shift();
    recentByTool.set(toolKey, entries);
  };

  const calcErrorRate = (toolKey: string): number => {
    const entries = recentByTool.get(toolKey) ?? [];
    if (!entries.length) return 0;
    const errors = entries.filter((entry) => !entry.ok).length;
    return (errors / entries.length) * 100.0;
  };

  const calcP95 = (toolKey: string): number => {
    const entries = recentByTool.get(toolKey) ?? [];
    if (!entries.length) return 0;
    const latencies = entries.map((entry) => entry.latency).slice().sort((left, right) => left - right);
    const index = Math.max(0, Math.min(latencies.length - 1, Math.floor(latencies.length * 0.95) - 1));
    return latencies[index] ?? 0;
  };

  const getSampleCount = (toolKey: string): number => (recentByTool.get(toolKey) ?? []).length;

  return {
    pushStat,
    calcErrorRate,
    calcP95,
    getSampleCount,
  };
}

export function createRegistryState(opts: {
  server: ToolRegistrationServer;
  tools?: ToolRegistry;
  codeHash?: (value: unknown) => string;
  now?: () => number;
}) {
  const codeHash = opts.codeHash ?? functionCodeHash;
  const now = opts.now ?? (() => Date.now());
  const tools = opts.tools ?? opts.server.__getTools?.() ?? new Map<string, ToolHandler>();
  const initialOriginalHandlerHashByTool: Map<string, string> = new Map();

  for (const [toolKey, handler] of tools) {
    initialOriginalHandlerHashByTool.set(toolKey, codeHash(handler));
  }

  const initialServerSnapshotHash = snapshotRegistryHash(tools, codeHash);
  const originalToolRegister = opts.server.tool.bind(opts.server);
  const originalSetTool = opts.server.__setTool?.bind(opts.server);
  let registryFrozen = false;
  let installingWrapper = false;
  let registryMutationAttempted: ToolRegistryMutation = null;

  const recordMutationAttempt = (tool: string | undefined, kind: ToolRegistryMutationKind) => {
    registryMutationAttempted = { tool, when: now(), kind };
  };

  const throwFrozen = (tool: string | undefined, kind: ToolRegistryMutationKind): never => {
    recordMutationAttempt(tool, kind);
    throw createFrozenRegistryError();
  };

  (opts.server as ToolRegistrationServer & { tool: ToolRegistrationServer["tool"] }).tool = (
    nameAtVersion: string,
    handler: ToolHandler,
  ) => {
    if (registryFrozen && !installingWrapper) {
      throwFrozen(nameAtVersion, "tool");
    }
    return originalToolRegister(nameAtVersion, handler);
  };

  if (opts.server.__setTool) {
    (opts.server as ToolRegistrationServer & { __setTool: NonNullable<ToolRegistrationServer["__setTool"]> })
      .__setTool = (nameAtVersion: string, handler: ToolHandler) => {
        if (registryFrozen && !installingWrapper) {
          throwFrozen(nameAtVersion, "setTool");
        }
        return originalSetTool!(nameAtVersion, handler);
      };
  }

  try {
    if (typeof (tools as any).set === "function") {
      const originalSet = tools.set.bind(tools);
      (tools as any).set = (...args: any[]) => {
        if (registryFrozen && !installingWrapper) {
          throwFrozen(String(args[0]), "map");
        }
        return (originalSet as any)(...args);
      };
    }
    if (typeof (tools as any).delete === "function") {
      const originalDelete = tools.delete.bind(tools);
      (tools as any).delete = (...args: any[]) => {
        if (registryFrozen && !installingWrapper) {
          throwFrozen(String(args[0]), "map");
        }
        return (originalDelete as any)(...args);
      };
    }
    if (typeof (tools as any).clear === "function") {
      const originalClear = tools.clear.bind(tools);
      (tools as any).clear = (...args: any[]) => {
        if (registryFrozen && !installingWrapper) {
          throwFrozen(undefined, "map");
        }
        return (originalClear as any)(...args);
      };
    }
  } catch {}

  const markWrappedHandler = (wrappedHandler: ToolHandler, originalHandler: ToolHandler) => {
    const tagged = wrappedHandler as MutableToolHandler;
    tagged.__sec0_wrapper__ = true;
    tagged.__sec0_handler_hash = codeHash(originalHandler);
  };

  const getCurrentTools = (): ToolRegistry => opts.server.__getTools?.() ?? tools;

  return {
    initialServerSnapshotHash,
    freeze: () => {
      registryFrozen = true;
    },
    isFrozen: () => registryFrozen,
    getMutationAttempted: (): ToolRegistryMutation => registryMutationAttempted,
    markWrappedHandler,
    installWrappedTool: (nameAtVersion: string, wrappedHandler: ToolHandler, originalHandler: ToolHandler) => {
      installingWrapper = true;
      try {
        markWrappedHandler(wrappedHandler, originalHandler);
        if (originalSetTool) {
          originalSetTool(nameAtVersion, wrappedHandler);
          return;
        }
        tools.set(nameAtVersion, wrappedHandler);
      } finally {
        installingWrapper = false;
      }
    },
    detectToolRuntimeChanges: (
      nameAtVersion: string,
      expectedWrappedHandler: ToolHandler,
    ): ToolRuntimeChanges => {
      const currentTools = getCurrentTools();
      const currentHandler = currentTools.get(nameAtVersion);
      const currentHash = getWrappedHandlerHash(currentHandler) || codeHash(currentHandler);
      const initialHash = initialOriginalHandlerHashByTool.get(nameAtVersion);
      return {
        handlerSwapDetected: !currentHandler || currentHandler !== expectedWrappedHandler,
        toolCodeChanged: Boolean(initialHash && currentHash && currentHash !== initialHash),
        serverCodeChanged: snapshotRegistryHash(currentTools, codeHash) !== initialServerSnapshotHash,
        registryMutation: registryMutationAttempted !== null,
      };
    },
  };
}
