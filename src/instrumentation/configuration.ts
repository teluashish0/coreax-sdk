import * as fs from "node:fs";
import * as path from "node:path";

export type CoreaxNodeKind =
  | "agent"
  | "orchestrator"
  | "server"
  | "middleware"
  | "tool"
  | "skill";

export type CoreaxNodeDefinition = {
  kind: CoreaxNodeKind;
  nodeId?: string;
  name?: string;
  version?: string;
  server?: string;
  operation?: string;
  metadata?: Readonly<Record<string, unknown>>;
};

export type CoreaxInstrumentationEventPhase = "start" | "success" | "error";

export type CoreaxInstrumentationEvent = {
  phase: CoreaxInstrumentationEventPhase;
  invocationId: string;
  runId: string;
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  timestamp: string;
  durationMs?: number;
  node: Readonly<Required<Pick<CoreaxNodeDefinition, "kind" | "nodeId" | "name">> &
    Omit<CoreaxNodeDefinition, "kind" | "nodeId" | "name"> & { key: string }>;
  error?: {
    name: string;
    messageSha256: string;
  };
};

export type CoreaxInstrumentationConfig = {
  /** Local state root. No directory is created until `initCoreax` is called. */
  stateRoot?: string;
  directoryNames?: {
    state?: string;
    audit?: string;
  };
  application?: {
    name?: string;
    version?: string;
    environment?: string;
  };
  nodes?: Readonly<Record<string, CoreaxNodeDefinition>>;
  /** Synchronous local event sink. No network sink is provided by the SDK. */
  onEvent?: (event: CoreaxInstrumentationEvent) => void;
  /** Injectable sources make wrapper output reproducible in tests and replays. */
  clock?: () => number;
  idGenerator?: (kind: "run" | "trace" | "span" | "invocation") => string;
};

export type CoreaxDirectories = {
  rootDir: string;
  stateDir: string;
  auditDir: string;
};

export type ResolvedCoreaxInstrumentationConfig = Readonly<{
  stateRoot: string;
  directories: Readonly<CoreaxDirectories>;
  application: Readonly<{
    name?: string;
    version?: string;
    environment?: string;
  }>;
  nodes: Readonly<Record<string, Readonly<CoreaxNodeDefinition>>>;
  onEvent?: (event: CoreaxInstrumentationEvent) => void;
  clock: () => number;
  idGenerator?: (kind: "run" | "trace" | "span" | "invocation") => string;
}>;

const DEFAULT_STATE_ROOT = "./.coreax";
const DEFAULT_STATE_DIRECTORY = "state";
const DEFAULT_AUDIT_DIRECTORY = "audit";
const COREAX_NODE_KINDS = new Set<CoreaxNodeKind>([
  "agent",
  "orchestrator",
  "server",
  "middleware",
  "tool",
  "skill",
]);

let initializedConfig: ResolvedCoreaxInstrumentationConfig | null = null;

function validateDirectoryName(value: string, field: string): string {
  const normalized = value.trim();
  if (
    !normalized ||
    normalized === "." ||
    normalized === ".." ||
    path.isAbsolute(normalized) ||
    normalized.includes("/") ||
    normalized.includes("\\")
  ) {
    throw new TypeError(`${field} must be a single relative directory name`);
  }
  return normalized;
}

function resolveStateRoot(value: string | undefined): string {
  const configured = value?.trim() || DEFAULT_STATE_ROOT;
  return path.resolve(configured);
}

function resolveDirectories(
  config: Pick<CoreaxInstrumentationConfig, "stateRoot" | "directoryNames">,
): CoreaxDirectories {
  const rootDir = resolveStateRoot(config.stateRoot);
  const stateName = validateDirectoryName(
    config.directoryNames?.state ?? DEFAULT_STATE_DIRECTORY,
    "directoryNames.state",
  );
  const auditName = validateDirectoryName(
    config.directoryNames?.audit ?? DEFAULT_AUDIT_DIRECTORY,
    "directoryNames.audit",
  );
  const stateDir = path.join(rootDir, stateName);
  const auditDir = path.join(rootDir, auditName);
  return {
    rootDir,
    stateDir,
    auditDir,
  };
}

function optionalString(value: string | undefined): string | undefined {
  const normalized = value?.trim();
  return normalized || undefined;
}

function resolveNodes(
  nodes: CoreaxInstrumentationConfig["nodes"],
): Readonly<Record<string, Readonly<CoreaxNodeDefinition>>> {
  const output = Object.create(null) as Record<
    string,
    Readonly<CoreaxNodeDefinition>
  >;
  for (const [rawKey, definition] of Object.entries(nodes ?? {}).sort(
    ([left], [right]) => left.localeCompare(right),
  )) {
    const key = rawKey.trim();
    if (!key) throw new TypeError("instrumentation node keys cannot be empty");
    if (!definition || typeof definition !== "object") {
      throw new TypeError(`instrumentation node "${key}" must be an object`);
    }
    if (!COREAX_NODE_KINDS.has(definition.kind)) {
      throw new TypeError(
        `instrumentation node "${key}" has an unsupported kind`,
      );
    }
    output[key] = Object.freeze({
      kind: definition.kind,
      ...(optionalString(definition.nodeId)
        ? { nodeId: optionalString(definition.nodeId) }
        : {}),
      ...(optionalString(definition.name)
        ? { name: optionalString(definition.name) }
        : {}),
      ...(optionalString(definition.version)
        ? { version: optionalString(definition.version) }
        : {}),
      ...(optionalString(definition.server)
        ? { server: optionalString(definition.server) }
        : {}),
      ...(optionalString(definition.operation)
        ? { operation: optionalString(definition.operation) }
        : {}),
      ...(definition.metadata
        ? { metadata: Object.freeze({ ...definition.metadata }) }
        : {}),
    });
  }
  return Object.freeze(output);
}

export function resolveCoreaxConfiguration(
  config: CoreaxInstrumentationConfig,
): ResolvedCoreaxInstrumentationConfig {
  const directories = Object.freeze(resolveDirectories(config));
  const application = Object.freeze({
    ...(optionalString(config.application?.name)
      ? { name: optionalString(config.application?.name) }
      : {}),
    ...(optionalString(config.application?.version)
      ? { version: optionalString(config.application?.version) }
      : {}),
    ...(optionalString(config.application?.environment)
      ? { environment: optionalString(config.application?.environment) }
      : {}),
  });
  return Object.freeze({
    stateRoot: directories.rootDir,
    directories,
    application,
    nodes: resolveNodes(config.nodes),
    ...(config.onEvent ? { onEvent: config.onEvent } : {}),
    clock: config.clock ?? Date.now,
    ...(config.idGenerator ? { idGenerator: config.idGenerator } : {}),
  });
}

/**
 * Initialize local instrumentation and create its state directories.
 *
 * Merely importing instrumentation, resolving configuration, applying a
 * decorator, or querying paths never creates filesystem state.
 */
export function initCoreax(
  config: CoreaxInstrumentationConfig,
): ResolvedCoreaxInstrumentationConfig {
  const resolved = resolveCoreaxConfiguration(config);
  for (const directory of [
    resolved.directories.rootDir,
    resolved.directories.stateDir,
    resolved.directories.auditDir,
  ]) {
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    const stats = fs.lstatSync(directory);
    if (stats.isSymbolicLink() || !stats.isDirectory()) {
      throw new TypeError(
        "CoreAX state paths must be real directories, not symbolic links",
      );
    }
    fs.chmodSync(directory, 0o700);
  }
  const rootDir = fs.realpathSync(resolved.directories.rootDir);
  const stateDir = fs.realpathSync(resolved.directories.stateDir);
  const auditDir = fs.realpathSync(resolved.directories.auditDir);
  if (
    path.dirname(stateDir) !== rootDir ||
    path.dirname(auditDir) !== rootDir
  ) {
    throw new TypeError(
      "CoreAX state directories must remain inside the configured state root",
    );
  }
  initializedConfig = Object.freeze({
    ...resolved,
    stateRoot: rootDir,
    directories: Object.freeze({ rootDir, stateDir, auditDir }),
  });
  return initializedConfig;
}

export function isCoreaxInitialized(): boolean {
  return initializedConfig !== null;
}

export function getCoreaxConfiguration(): ResolvedCoreaxInstrumentationConfig | null {
  return initializedConfig;
}

export function requireCoreaxConfiguration(): ResolvedCoreaxInstrumentationConfig {
  const config = getCoreaxConfiguration();
  if (!config) {
    throw new Error("CoreAX instrumentation has not been initialized");
  }
  return config;
}

export function getCoreaxDirectories(
  config?: CoreaxInstrumentationConfig,
): CoreaxDirectories {
  if (config) return resolveDirectories(config);
  if (initializedConfig) return { ...initializedConfig.directories };
  return resolveDirectories({});
}
