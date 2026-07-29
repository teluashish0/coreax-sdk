import { createHash } from "node:crypto";
import { lstatSync, readlinkSync, realpathSync } from "node:fs";
import path from "node:path";
import { matchesAllowlist, type CoreaxPolicy } from "../policy";
import { AgentGuard, type AgentGuardFinding } from "../middleware/agentGuard";
import type {
  GuardDecision,
  GuardInput,
  GuardInputContext,
  GuardInputKind,
  GuardMode,
  GuardOutcome,
  GuardPolicy,
  GuardPolicyInput,
  GuardProviderSnapshot,
} from "./types";

const BASIC_REDACTION_PATTERNS: RegExp[] = [
  /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi,
  /\b\d{3}-\d{2}-\d{4}\b/g,
  /\b(?:\d[ -]*?){13,16}\b/g,
  /\b\+?\d{1,3}[ -]?\(?\d{2,4}\)?[ -]?\d{3,4}[ -]?\d{3,4}\b/g,
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  /xox[baprs]-[A-Za-z0-9-]+/gi,
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g,
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/gi,
];

const AGENT_GUARD_CACHE = new Map<string, AgentGuard>();

type ParsedTarget = {
  serverName?: string;
  toolNameAtVersion?: string;
  raw: string;
};

function stableHash(value: unknown): string {
  const encoded = JSON.stringify(value ?? null);
  return createHash("sha256").update(encoded).digest("hex");
}

function normalizePolicyReasonArray(values: unknown): string[] {
  if (!Array.isArray(values)) return [];
  const seen = new Set<string>();
  for (const value of values) {
    const normalized = String(value || "").trim();
    if (!normalized) continue;
    seen.add(normalized);
  }
  return Array.from(seen.values());
}

function isCoreaxPolicy(policy: GuardPolicyInput): policy is CoreaxPolicy {
  const value = policy as CoreaxPolicy;
  return Boolean(
    value &&
      typeof value === "object" &&
      value.version === 1 &&
      Array.isArray(value.tools?.allow) &&
      Array.isArray(value.enforcement?.denyOn),
  );
}

function asString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function readTarget(input: GuardInput): string {
  return asString(input.target) || asString(input.context?.target);
}

function parseMcpTarget(target: string): ParsedTarget {
  const raw = String(target || "").trim();
  if (!raw) return { raw: "" };
  if (raw.startsWith("mcp://")) {
    const body = raw.slice("mcp://".length);
    const slash = body.indexOf("/");
    if (slash >= 0) {
      return {
        raw,
        serverName: body.slice(0, slash) || undefined,
        toolNameAtVersion: body.slice(slash + 1) || undefined,
      };
    }
  }
  if (raw.includes(":")) {
    const [serverName, rest] = raw.split(":", 2);
    if (rest) return { raw, serverName: serverName || undefined, toolNameAtVersion: rest || undefined };
  }
  if (raw.includes("/")) {
    const slash = raw.indexOf("/");
    return {
      raw,
      serverName: raw.slice(0, slash) || undefined,
      toolNameAtVersion: raw.slice(slash + 1) || undefined,
    };
  }
  return { raw, toolNameAtVersion: raw };
}

function wildcardMatch(value: string, patterns: string[]): boolean {
  if (!patterns.length) return true;
  return patterns.some((pattern) => {
    const p = String(pattern || "").trim();
    if (!p) return false;
    if (p === "*") return true;
    const escaped = p.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*?");
    return new RegExp(`^${escaped}$`, "i").test(value);
  });
}

function filesystemPathAllowed(
  candidate: string,
  allowlist: readonly string[],
): boolean {
  const resolvedCandidate = path.resolve(candidate);
  const entries = allowlist
    .map((value) => String(value || "").trim())
    .filter(Boolean);
  if (entries.includes("*")) return true;
  return entries.some((entry) => {
    if (entry.includes("*")) {
      const literalPrefix = entry.slice(0, entry.indexOf("*"));
      const prefixBoundary =
        literalPrefix.endsWith(path.sep) ||
        literalPrefix.endsWith("/") ||
        literalPrefix.endsWith("\\")
          ? literalPrefix
          : path.dirname(literalPrefix);
      if (
        !isWithinStablePhysicalRoot(
          candidate,
          path.resolve(
            prefixBoundary || path.parse(resolvedCandidate).root,
          ),
        )
      ) {
        return false;
      }
      const marker = "\u0000";
      const pattern = path
        .resolve(entry)
        .split(path.sep)
        .join("/")
        .replace(/\*\*/g, marker)
        .replace(/[.+^${}()|[\]\\]/g, "\\$&")
        .replace(/\*/g, "[^/]*")
        .replace(new RegExp(marker, "g"), ".*");
      return new RegExp(`^${pattern}$`).test(
        resolvedCandidate.split(path.sep).join("/"),
      );
    }
    return isWithinStablePhysicalRoot(
      candidate,
      entry,
    );
  });
}

function resolvePhysicalPath(candidate: string): string | null {
  const initial = pathComponents(candidate);
  let current = initial.root;
  let pending = initial.segments;
  let followedLinks = 0;

  while (pending.length > 0) {
    const segment = pending.shift()!;
    if (segment === ".") continue;
    if (segment === "..") {
      current = path.dirname(current);
      continue;
    }
    const next = path.join(current, segment);
    let stats: ReturnType<typeof lstatSync>;
    try {
      stats = lstatSync(next);
    } catch (error) {
      if (isErrno(error, "ENOENT")) {
        if (pending.includes("..")) return null;
        return path.resolve(
          current,
          segment,
          ...pending.filter((part) => part !== "."),
        );
      }
      return null;
    }

    if (!stats.isSymbolicLink()) {
      current = next;
      continue;
    }
    followedLinks += 1;
    if (followedLinks > 64) return null;

    let target: string;
    try {
      target = readlinkSync(next);
    } catch {
      return null;
    }
    if (path.isAbsolute(target)) {
      const targetComponents = pathComponents(target);
      current = targetComponents.root;
      pending = [...targetComponents.segments, ...pending];
    } else {
      pending = [...splitPathSegments(target), ...pending];
    }
  }

  try {
    return realpathSync(current);
  } catch (error) {
    return isErrno(error, "ENOENT") ? path.resolve(current) : null;
  }
}

function pathComponents(candidate: string): {
  root: string;
  segments: string[];
} {
  if (path.isAbsolute(candidate)) {
    const root = path.parse(candidate).root;
    return {
      root,
      segments: splitPathSegments(candidate.slice(root.length)),
    };
  }
  const workingDirectory = process.cwd();
  const root = path.parse(workingDirectory).root;
  return {
    root,
    segments: [
      ...splitPathSegments(workingDirectory.slice(root.length)),
      ...splitPathSegments(candidate),
    ],
  };
}

function splitPathSegments(value: string): string[] {
  return value
    .split(path.sep === "\\" ? /[\\/]+/ : /\/+/)
    .filter(Boolean);
}

function isErrno(error: unknown, code: string): boolean {
  return (
    error instanceof Error &&
    "code" in error &&
    (error as NodeJS.ErrnoException).code === code
  );
}

function isWithinStablePhysicalRoot(
  candidate: string,
  allowedRoot: string,
): boolean {
  const firstCandidate = resolvePhysicalPath(candidate);
  const firstRoot = resolvePhysicalPath(allowedRoot);
  if (!firstCandidate || !firstRoot) return false;

  // This cannot remove the executor's check/use boundary, but it fails closed
  // if either path changes while the policy decision itself is computed.
  const secondCandidate = resolvePhysicalPath(candidate);
  const secondRoot = resolvePhysicalPath(allowedRoot);
  if (
    secondCandidate !== firstCandidate ||
    secondRoot !== firstRoot
  ) {
    return false;
  }

  const relative = path.relative(secondRoot, secondCandidate);
  return (
    relative === "" ||
    (!relative.startsWith("..") && !path.isAbsolute(relative))
  );
}

function hasPinnedToolVersion(toolRef: string): boolean {
  const separator = toolRef.lastIndexOf("@");
  if (separator <= 0 || separator === toolRef.length - 1) return false;
  const toolName = toolRef.slice(0, separator);
  if (
    !toolName ||
    /\s/.test(toolName) ||
    (toolName.includes("@") &&
      !/^@[^/@\s]+\/[^@\s]+$/.test(toolName))
  ) {
    return false;
  }
  const version = toolRef.slice(separator + 1);
  return /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*))?(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/.test(
    version,
  );
}

function tagsMatch(input: GuardInputContext | undefined, expected: string[] | undefined): boolean {
  if (!expected || expected.length === 0) return true;
  const tags = Array.isArray(input?.tags) ? input!.tags.map((tag) => String(tag || "").trim()).filter(Boolean) : [];
  if (!tags.length) return false;
  const set = new Set(tags.map((tag) => tag.toLowerCase()));
  return expected.some((tag) => set.has(String(tag || "").trim().toLowerCase()));
}

function normalizeRuleKinds(raw: unknown): GuardInputKind[] | null {
  if (!raw || raw === "*") return null;
  const source = Array.isArray(raw) ? raw : [raw];
  const values = source.map((entry) => String(entry || "").trim()).filter(Boolean);
  return values.length ? (values as GuardInputKind[]) : null;
}

function isActionKind(
  kind: GuardInputKind,
): kind is "tool_call" | "mcp_call" | "api_call" {
  return kind === "tool_call" || kind === "mcp_call" || kind === "api_call";
}

function stringifyContent(content: unknown): string {
  if (typeof content === "string") return content;
  try {
    return JSON.stringify(content ?? null);
  } catch {
    return String(content ?? "");
  }
}

function redactContent(content: unknown, patterns?: string[], replacement = "[REDACTED]"): string {
  let text = stringifyContent(content);
  for (const re of BASIC_REDACTION_PATTERNS) {
    text = text.replace(re, replacement);
  }
  if (Array.isArray(patterns)) {
    for (const raw of patterns) {
      const source = String(raw || "").trim();
      if (!source) continue;
      try {
        text = text.replace(new RegExp(source, "gi"), replacement);
      } catch {
        continue;
      }
    }
  }
  return text;
}

function buildAgentGuard(policy: CoreaxPolicy, hash: string): AgentGuard {
  const cached = AGENT_GUARD_CACHE.get(hash);
  if (cached) return cached;
  const guardPolicy = policy.agentGuard ?? {};
  const guard = new AgentGuard({
    enabled: guardPolicy.enabled === true,
    block_on_severity: guardPolicy.blockOnSeverity,
    block_on_count: guardPolicy.blockOnCount,
  });
  AGENT_GUARD_CACHE.set(hash, guard);
  return guard;
}

function evaluateGuardPolicyRule(policy: GuardPolicy, input: GuardInput): {
  outcome: GuardOutcome;
  reason: string | null;
  reasons: string[];
  violation?: string;
  redactedContent?: string;
} {
  const rules = Array.isArray(policy.rules) ? policy.rules : [];
  if (!rules.length) {
    const defaultOutcome = policy.defaultOutcome === "allow" ? "allow" : "block";
    return {
      outcome: defaultOutcome,
      reason: defaultOutcome === "block" ? "policy_default_block" : null,
      reasons: defaultOutcome === "block" ? ["policy_default_block"] : [],
    };
  }

  const target = readTarget(input);
  for (const rule of rules) {
    const allowedKinds = normalizeRuleKinds(rule.kind);
    if (allowedKinds && !allowedKinds.includes(input.kind)) continue;
    if (rule.target) {
      const targets = Array.isArray(rule.target) ? rule.target : [rule.target];
      if (!wildcardMatch(target, targets.map((entry) => String(entry || "")))) continue;
    }
    if (!tagsMatch(input.context, rule.tagsAny)) continue;
    const outcome: GuardOutcome = rule.outcome;
    const reason = asString(rule.reason) || asString(rule.violation) || `rule_${asString(rule.id) || "matched"}`;
    return {
      outcome,
      reason: reason || null,
      reasons: reason ? [reason] : [],
      ...(asString(rule.violation) ? { violation: asString(rule.violation) } : {}),
      ...(outcome === "redact"
        ? {
            redactedContent: redactContent(
              input.content,
              rule.redact?.patterns,
              rule.redact?.replacement || "[REDACTED]",
            ),
          }
        : {}),
    };
  }

  const defaultOutcome = policy.defaultOutcome === "allow" ? "allow" : "block";
  return {
    outcome: defaultOutcome,
    reason: defaultOutcome === "block" ? "policy_default_block" : null,
    reasons: defaultOutcome === "block" ? ["policy_default_block"] : [],
  };
}

export async function evaluateGuardDecision(opts: {
  snapshot: GuardProviderSnapshot;
  mode: GuardMode;
  input: GuardInput;
}): Promise<GuardDecision> {
  const source = opts.snapshot.source;
  const policyHash = opts.snapshot.hash || stableHash(opts.snapshot.policy);
  if (isCoreaxPolicy(opts.snapshot.policy)) {
    const policy = opts.snapshot.policy;
    const kind = opts.input.kind;
    const target = readTarget(opts.input);
    const violations: string[] = [];
    const mandatoryDenies = new Set<string>();
    let findings: AgentGuardFinding[] = [];
    let redactedContent: string | undefined;

    const recordViolation = (reason: string, mandatoryDeny = false) => {
      if (!violations.includes(reason)) violations.push(reason);
      if (mandatoryDeny) mandatoryDenies.add(reason);
    };

    if (kind === "tool_call" || kind === "mcp_call") {
      const parsedTarget = parseMcpTarget(target);
      const allowlist = policy.tools.allow;
      const toolRef = parsedTarget.toolNameAtVersion || target;
      if (!toolRef) {
        recordViolation("tool_not_in_allowlist", true);
      } else if (
        !matchesAllowlist(allowlist, toolRef, {
          serverName: parsedTarget.serverName,
        })
      ) {
        recordViolation("tool_not_in_allowlist");
      }
      if (
        policy.tools.requirePinnedVersions === true &&
        toolRef &&
        !hasPinnedToolVersion(toolRef)
      ) {
        recordViolation("version_unpinned");
      }
      if (
        policy.security?.requireIdempotencyForSideEffects === true &&
        opts.input.context?.metadata?.sideEffect === true &&
        !opts.input.context?.metadata?.idempotencyKey
      ) {
        recordViolation("missing_idempotency_for_side_effect");
      }
    }

    if (kind === "api_call") {
      if (!target) {
        recordViolation("egress_violation", true);
      } else {
        const egressAllowlist = policy.security?.egressAllowlist ?? [];
        if (egressAllowlist.length && !wildcardMatch(target, egressAllowlist)) {
          try {
            const hostname = new URL(target).hostname;
            if (!wildcardMatch(hostname, egressAllowlist)) {
              recordViolation("egress_violation");
            }
          } catch {
            recordViolation("egress_violation");
          }
        }
      }
    }

    const filesystemAllowlist = policy.security?.filesystemAllowlist ?? [];
    if (isActionKind(kind) && filesystemAllowlist.length > 0) {
      const rawPaths = opts.input.context?.filesystemPaths;
      const proposedPaths = Array.isArray(rawPaths)
        ? rawPaths
            .filter(
              (value): value is string =>
                typeof value === "string" && value.trim().length > 0,
            )
            .map((value) => value.trim())
        : [];
      if (
        !Array.isArray(rawPaths) ||
        proposedPaths.length === 0 ||
        proposedPaths.length !== rawPaths.length
      ) {
        recordViolation("fs_violation", true);
      } else if (
        proposedPaths.some(
          (candidate) =>
            !filesystemPathAllowed(candidate, filesystemAllowlist),
        )
      ) {
        recordViolation("fs_violation");
      }
    }

    if (isActionKind(kind)) {
      const agentGuard = buildAgentGuard(policy, policyHash);
      findings = await agentGuard.scanInput({
        target,
        content: opts.input.content,
        context: opts.input.context,
      });
      const block = agentGuard.shouldBlock(findings);
      if (block.block) {
        recordViolation("agent_guard_failed");
      }
    } else if (kind === "message_outbound") {
      const agentGuard = buildAgentGuard(policy, policyHash);
      findings = await agentGuard.scanOutput({
        content: opts.input.content,
        context: opts.input.context,
      });
      const block = agentGuard.shouldBlock(findings);
      if (block.block) {
        recordViolation("agent_guard_failed");
      }
      if (policy.privacy?.redactOutputs === true && findings.length) {
        redactedContent = redactContent(opts.input.content, undefined, "[REDACTED]");
      }
    }

    if (
      typeof policy.security?.maxPayloadKb === "number" &&
      Buffer.byteLength(stringifyContent(opts.input.content), "utf8") >
        policy.security.maxPayloadKb * 1024
    ) {
      recordViolation("payload_too_large");
    }

    const denyOn = normalizePolicyReasonArray(policy.enforcement.denyOn);
    const escalateOn = normalizePolicyReasonArray([
      ...(policy.enforcement.escalateOn ?? []),
      ...(policy.security?.requireApprovalFor ?? []),
    ]);

    const hardDenyViolation = violations.find(
      (candidate) =>
        mandatoryDenies.has(candidate) || denyOn.includes(candidate),
    );
    const escalationViolation = violations.find((candidate) =>
      escalateOn.includes(candidate),
    );
    const violation =
      hardDenyViolation ?? escalationViolation ?? violations[0];
    let outcome: GuardOutcome = "allow";
    if (hardDenyViolation) {
      outcome = "block";
    } else if (escalationViolation) {
      outcome = "escalate";
    } else if (redactedContent) {
      outcome = "redact";
    }

    return {
      outcome,
      shouldProceed: outcome === "allow" || outcome === "redact",
      kind,
      reason: violation ?? null,
      reasons: violations,
      ...(violation ? { violation } : {}),
      ...(findings.length ? { findings } : {}),
      ...(redactedContent ? { redactedContent } : {}),
      provider: {
        mode: opts.mode,
        source,
        policyHash,
        ...(opts.snapshot.fallbackReason ? { fallbackReason: opts.snapshot.fallbackReason } : {}),
      },
      ...(outcome === "escalate"
        ? {
            escalation: {
              shouldEscalate: true,
              waitForResolution: true,
            },
          }
        : {}),
    };
  }

  const policy = opts.snapshot.policy as GuardPolicy;
  const decision = evaluateGuardPolicyRule(policy, opts.input);
  return {
    outcome: decision.outcome,
    shouldProceed: decision.outcome === "allow" || decision.outcome === "redact",
    kind: opts.input.kind,
    reason: decision.reason,
    reasons: decision.reasons,
    ...(decision.violation ? { violation: decision.violation } : {}),
    ...(decision.redactedContent ? { redactedContent: decision.redactedContent } : {}),
    provider: {
      mode: opts.mode,
      source,
      policyHash,
      ...(opts.snapshot.fallbackReason ? { fallbackReason: opts.snapshot.fallbackReason } : {}),
    },
    ...(decision.outcome === "escalate"
      ? {
          escalation: {
            shouldEscalate: true,
            waitForResolution: true,
          },
        }
      : {}),
  };
}
