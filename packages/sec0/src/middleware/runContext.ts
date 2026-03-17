import type { AgentStatePayload, AgentStateVariables } from "../agent-state";

type RunContextOptionInput = {
  run_context?: {
    enabled?: boolean;
    max_chars?: number;
    max_events?: number;
    max_event_chars?: number;
    max_runs?: number;
    ttl_ms?: number;
    include_objective?: boolean;
    include_metadata?: boolean;
  };
} | undefined;

export type RunContextConfig = {
  enabled: boolean;
  maxChars: number;
  maxEvents: number;
  maxEventChars: number;
  maxRuns: number;
  ttlMs: number;
  includeObjective: boolean;
  includeMetadata: boolean;
};

type RunContextState = {
  key: string;
  tenant?: string;
  nodeId?: string;
  runId?: string;
  createdAt: number;
  lastSeenAt: number;
  objective?: string;
  metadata?: Record<string, unknown>;
  events: string[];
  eventChars: number;
};

const RUN_CONTEXT_CACHE: Map<string, RunContextState> = new Map();

const DEFAULT_RUN_CONTEXT: RunContextConfig = {
  enabled: true,
  maxChars: 6000,
  maxEvents: 50,
  maxEventChars: 1200,
  maxRuns: 500,
  ttlMs: 30 * 60 * 1000,
  includeObjective: true,
  includeMetadata: false,
};

function clampPositiveInt(value: unknown, fallback: number): number {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  const v = Math.floor(n);
  return v > 0 ? v : fallback;
}

export function resolveRunContextConfig(
  opts: RunContextOptionInput,
  hasRunScanner: boolean,
): RunContextConfig | null {
  if (!hasRunScanner) return null;
  const raw = opts?.run_context || {};
  if (raw && raw.enabled === false) return null;
  return {
    ...DEFAULT_RUN_CONTEXT,
    maxChars: clampPositiveInt(raw?.max_chars, DEFAULT_RUN_CONTEXT.maxChars),
    maxEvents: clampPositiveInt(raw?.max_events, DEFAULT_RUN_CONTEXT.maxEvents),
    maxEventChars: clampPositiveInt(raw?.max_event_chars, DEFAULT_RUN_CONTEXT.maxEventChars),
    maxRuns: clampPositiveInt(raw?.max_runs, DEFAULT_RUN_CONTEXT.maxRuns),
    ttlMs: clampPositiveInt(raw?.ttl_ms, DEFAULT_RUN_CONTEXT.ttlMs),
    includeObjective: raw?.include_objective !== false,
    includeMetadata: raw?.include_metadata === true,
  };
}

function runContextKey(tenant?: string, nodeId?: string, runId?: string): string | null {
  const t = typeof tenant === "string" ? tenant.trim() : "";
  const n = typeof nodeId === "string" ? nodeId.trim() : "";
  const r = typeof runId === "string" ? runId.trim() : "";
  if (!n || !r) return null;
  return [t || "unknown", n, r].join("|");
}

function evictRunContexts(now: number, cfg: RunContextConfig) {
  if (!RUN_CONTEXT_CACHE.size) return;
  for (const [key, ctx] of RUN_CONTEXT_CACHE.entries()) {
    if (now - ctx.lastSeenAt > cfg.ttlMs) {
      RUN_CONTEXT_CACHE.delete(key);
    }
  }
  if (RUN_CONTEXT_CACHE.size <= cfg.maxRuns) return;
  const entries = Array.from(RUN_CONTEXT_CACHE.entries()).sort((a, b) => a[1].lastSeenAt - b[1].lastSeenAt);
  const overflow = entries.length - cfg.maxRuns;
  for (let i = 0; i < overflow; i += 1) {
    RUN_CONTEXT_CACHE.delete(entries[i][0]);
  }
}

export function ensureRunContextState(
  cfg: RunContextConfig,
  opts: { tenant?: string; nodeId?: string; runId?: string; now: number },
): RunContextState | null {
  const key = runContextKey(opts.tenant, opts.nodeId, opts.runId);
  if (!key) return null;
  evictRunContexts(opts.now, cfg);
  const existing = RUN_CONTEXT_CACHE.get(key);
  if (existing) {
    existing.lastSeenAt = opts.now;
    return existing;
  }
  const created: RunContextState = {
    key,
    tenant: opts.tenant,
    nodeId: opts.nodeId,
    runId: opts.runId,
    createdAt: opts.now,
    lastSeenAt: opts.now,
    events: [],
    eventChars: 0,
  };
  RUN_CONTEXT_CACHE.set(key, created);
  return created;
}

function stringifyForRunContext(value: unknown, maxChars: number): string {
  let raw = "";
  try {
    raw = JSON.stringify(value ?? null);
  } catch {
    raw = String(value ?? "");
  }
  const trimmed = raw.trim();
  if (!trimmed) return "";
  if (trimmed.length <= maxChars) return trimmed;
  return `${trimmed.slice(0, Math.max(0, maxChars - 1))}…`;
}

export function extractObjective(
  variables?: AgentStateVariables,
  incoming?: AgentStatePayload,
): string | null {
  const candidates = [
    (variables as any)?.AGENT?.objective,
    (variables as any)?.AGENT?.goal,
    (variables as any)?.AGENT?.task,
    (variables as any)?.ORCHESTRATOR?.objective,
    (incoming as any)?.metadata?.objective,
  ];
  for (const c of candidates) {
    const s = typeof c === "string" ? c.trim() : "";
    if (s) return s.slice(0, 480);
  }
  return null;
}

export function extractMetadata(incoming?: AgentStatePayload): Record<string, unknown> | null {
  const meta = incoming?.metadata;
  if (!meta || typeof meta !== "object") return null;
  try {
    return JSON.parse(JSON.stringify(meta));
  } catch {
    return null;
  }
}

function buildRunContextHeader(state: RunContextState, cfg: RunContextConfig): string {
  const parts: string[] = [];
  parts.push("# run_context");
  if (state.nodeId) parts.push(`node_id=${state.nodeId}`);
  if (state.runId) parts.push(`run_id=${state.runId}`);
  if (cfg.includeObjective && state.objective) parts.push(`objective=${state.objective}`);
  if (cfg.includeMetadata && state.metadata && Object.keys(state.metadata).length) {
    try {
      parts.push(`metadata=${JSON.stringify(state.metadata).slice(0, 480)}`);
    } catch {}
  }
  return parts.join("\n");
}

export function appendRunEvent(state: RunContextState, entry: string, cfg: RunContextConfig) {
  const trimmed = entry.trim();
  if (!trimmed) return;
  const safe = trimmed.length > cfg.maxEventChars ? `${trimmed.slice(0, cfg.maxEventChars - 1)}…` : trimmed;
  state.events.push(safe);
  state.eventChars += safe.length + 1;
  while (state.events.length > cfg.maxEvents) {
    const removed = state.events.shift();
    if (removed) state.eventChars -= removed.length + 1;
  }
  const headerLen = buildRunContextHeader(state, cfg).length + 1;
  const maxBody = Math.max(0, cfg.maxChars - headerLen);
  while (state.eventChars > maxBody && state.events.length > 1) {
    const removed = state.events.shift();
    if (removed) state.eventChars -= removed.length + 1;
  }
}

export function buildRunContextText(state: RunContextState, cfg: RunContextConfig): string {
  const header = buildRunContextHeader(state, cfg);
  const body = state.events.join("\n");
  if (!body) return header;
  const combined = `${header}\n${body}`;
  if (combined.length <= cfg.maxChars) return combined;
  return combined.slice(combined.length - cfg.maxChars);
}

export function buildRunEvent(
  direction: "input" | "output",
  tool: string,
  payload: unknown,
  cfg: RunContextConfig,
): string | null {
  const body = stringifyForRunContext(payload, cfg.maxEventChars);
  if (!body) return null;
  const ts = new Date().toISOString();
  return `[${ts}] ${direction.toUpperCase()} tool=${tool}\n${body}`;
}
