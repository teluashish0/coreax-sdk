import fs from "node:fs";
import path from "node:path";
import YAML from "yaml";
import { createHash } from "node:crypto";
import { parsePolicyYaml, validatePolicy } from "../policy";
import { GuardConfigError, GuardPolicyInvalidError, GuardPolicyUnavailableError } from "./errors";
import type {
  GuardCustomPolicyProviderConfig,
  GuardInput,
  GuardLocalPolicyProviderConfig,
  GuardPolicyInput,
  GuardPolicyProvider,
  GuardProviderConfig,
  GuardProviderPrecedence,
  GuardProviderSnapshot,
  GuardRuntimeContext,
} from "./types";

type CachedPolicy = {
  snapshot: GuardProviderSnapshot;
  loadedAtMs: number;
  mtimeMs?: number;
};

function stableHash(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value ?? null)).digest("hex");
}

function validateGuardPolicyInput(policy: unknown): GuardPolicyInput {
  if (!policy || typeof policy !== "object" || Array.isArray(policy)) {
    throw new GuardPolicyInvalidError("Guard policy must be an object");
  }
  const record = policy as Record<string, unknown>;
  if (record.version === 1) {
    const result = validatePolicy(record);
    if (!result.valid || !result.policy) {
      throw new GuardPolicyInvalidError("Invalid CoreAX policy", {
        errors: result.errors ?? [],
      });
    }
    return result.policy;
  }
  if (
    record.defaultOutcome !== undefined &&
    record.defaultOutcome !== "allow" &&
    record.defaultOutcome !== "block"
  ) {
    throw new GuardPolicyInvalidError(
      "Guard defaultOutcome must be allow or block",
    );
  }
  if (record.rules !== undefined && !Array.isArray(record.rules)) {
    throw new GuardPolicyInvalidError("Guard rules must be an array");
  }
  for (const [index, value] of (
    Array.isArray(record.rules) ? record.rules : []
  ).entries()) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new GuardPolicyInvalidError(`Guard rule ${index} must be an object`);
    }
    const outcome = (value as Record<string, unknown>).outcome;
    if (
      outcome !== "allow" &&
      outcome !== "redact" &&
      outcome !== "block" &&
      outcome !== "escalate"
    ) {
      throw new GuardPolicyInvalidError(
        `Guard rule ${index} has an invalid outcome`,
      );
    }
  }
  return policy as GuardPolicyInput;
}

function asPositiveInt(value: unknown, fallback: number): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  const n = Math.floor(parsed);
  return n > 0 ? n : fallback;
}

function parsePolicyFile(filePath: string): GuardPolicyInput {
  const absolutePath = path.resolve(filePath);
  const raw = fs.readFileSync(absolutePath, "utf8");
  if (!raw.trim()) {
    throw new GuardPolicyInvalidError("Guard policy file is empty", { policyPath: absolutePath });
  }
  const ext = path.extname(absolutePath).toLowerCase();
  if (ext === ".json") {
    try {
      return validateGuardPolicyInput(JSON.parse(raw));
    } catch (error: any) {
      throw new GuardPolicyInvalidError("Failed to parse guard JSON policy", {
        policyPath: absolutePath,
        cause: error?.message || String(error),
      });
    }
  }

  try {
    return validateGuardPolicyInput(parsePolicyYaml(raw));
  } catch {
    try {
      const parsed = YAML.parse(raw);
      if (!parsed || typeof parsed !== "object") {
        throw new Error("yaml_did_not_parse_object");
      }
      return validateGuardPolicyInput(parsed);
    } catch (error: any) {
      throw new GuardPolicyInvalidError("Failed to parse guard YAML policy", {
        policyPath: absolutePath,
        cause: error?.message || String(error),
      });
    }
  }
}

function isSnapshot(value: unknown): value is GuardProviderSnapshot {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return typeof record.hash === "string" && "policy" in record;
}

class LocalPolicyProvider implements GuardPolicyProvider {
  private cache: CachedPolicy | null = null;
  private readonly cacheTtlMs: number;
  private readonly policyObject?: GuardPolicyInput;
  private readonly policyPath?: string;

  constructor(config: GuardLocalPolicyProviderConfig) {
    this.cacheTtlMs = asPositiveInt(config.cacheTtlMs, 1_000);
    this.policyObject = config.policy;
    this.policyPath = typeof config.policyPath === "string" && config.policyPath.trim()
      ? path.resolve(config.policyPath.trim())
      : undefined;
  }

  private loadFromPath(): GuardProviderSnapshot {
    if (!this.policyPath) {
      throw new GuardPolicyUnavailableError("Local guard policy path is not configured");
    }
    if (!fs.existsSync(this.policyPath)) {
      throw new GuardPolicyUnavailableError("Local guard policy file does not exist", {
        policyPath: this.policyPath,
      });
    }
    const stat = fs.statSync(this.policyPath);
    if (this.cache && this.cache.mtimeMs === stat.mtimeMs && Date.now() - this.cache.loadedAtMs < this.cacheTtlMs) {
      return this.cache.snapshot;
    }
    const policy = parsePolicyFile(this.policyPath);
    const snapshot: GuardProviderSnapshot = {
      policy,
      hash: stableHash(policy),
      source: "local",
    };
    this.cache = {
      snapshot,
      loadedAtMs: Date.now(),
      mtimeMs: stat.mtimeMs,
    };
    return snapshot;
  }

  private loadFromObject(): GuardProviderSnapshot {
    if (!this.policyObject) {
      throw new GuardPolicyUnavailableError("Local guard policy object is not configured");
    }
    if (this.cache && Date.now() - this.cache.loadedAtMs < this.cacheTtlMs) {
      return this.cache.snapshot;
    }
    const policy = validateGuardPolicyInput(this.policyObject);
    const snapshot: GuardProviderSnapshot = {
      policy,
      hash: stableHash(policy),
      source: "local",
    };
    this.cache = {
      snapshot,
      loadedAtMs: Date.now(),
    };
    return snapshot;
  }

  async getPolicy(): Promise<GuardProviderSnapshot> {
    if (this.policyPath) return this.loadFromPath();
    return this.loadFromObject();
  }
}

class CustomPolicyProvider implements GuardPolicyProvider {
  constructor(private readonly config: GuardCustomPolicyProviderConfig) {}
  async getPolicy(input: GuardInput): Promise<GuardProviderSnapshot> {
    const result = await this.config.getPolicy(input);
    if (isSnapshot(result)) {
      const policy = validateGuardPolicyInput(result.policy);
      return {
        ...result,
        policy,
        hash: result.hash || stableHash(policy),
        source: "custom",
      };
    }
    const policy = validateGuardPolicyInput(result);
    return {
      policy,
      hash: stableHash(policy),
      source: "custom",
    };
  }
}

class CompositePolicyProvider implements GuardPolicyProvider {
  constructor(private readonly config: {
    precedence: GuardProviderPrecedence;
    local?: GuardPolicyProvider;
    custom?: GuardPolicyProvider;
    runtime: GuardRuntimeContext;
  }) {}

  private async readCustom(input: GuardInput): Promise<GuardProviderSnapshot> {
    if (!this.config.custom) throw new GuardPolicyUnavailableError("Custom guard provider is not configured");
    return this.config.custom.getPolicy(input);
  }

  private async readLocal(input: GuardInput): Promise<GuardProviderSnapshot> {
    if (!this.config.local) throw new GuardPolicyUnavailableError("Local guard provider is not configured");
    return this.config.local.getPolicy(input);
  }

  async getPolicy(input: GuardInput): Promise<GuardProviderSnapshot> {
    if (this.config.precedence === "local-first") {
      try {
        return await this.readLocal(input);
      } catch (localError: any) {
        const custom = await this.readCustom(input);
        return {
          ...custom,
          source: "custom",
          fallbackReason: `local_unavailable:${localError?.message || "unknown"}`,
        };
      }
    }

    try {
      return await this.readCustom(input);
    } catch (customError: any) {
      try {
        const local = await this.readLocal(input);
        return {
          ...local,
          source: "local-fallback",
          fallbackReason: `custom_failed_using_local:${customError?.message || "unknown"}`,
        };
      } catch (localError: any) {
        this.config.runtime.log({
          level: "error",
          message: "guard policy resolution failed",
          data: {
            customError: customError?.message || String(customError),
            localError: localError?.message || String(localError),
          },
        });
        throw new GuardPolicyUnavailableError("Unable to resolve guard policy from custom or local provider", {
          customError: customError?.message || String(customError),
          localError: localError?.message || String(localError),
        });
      }
    }
  }
}

export function validateProviderConfig(provider: GuardProviderConfig | undefined): {
  precedence: GuardProviderPrecedence;
  local?: GuardLocalPolicyProviderConfig;
  custom?: GuardCustomPolicyProviderConfig;
} {
  const precedence: GuardProviderPrecedence =
    provider?.precedence === "local-first" || provider?.precedence === "custom-first"
      ? provider.precedence
      : "local-first";
  const hasLocal = Boolean(provider?.local?.policy || provider?.local?.policyPath);
  const hasCustom = Boolean(provider?.custom);
  if (!hasLocal && !hasCustom) {
    throw new GuardConfigError(
      "guard requires provider.local.policy, provider.local.policyPath, or provider.custom",
    );
  }
  return {
    precedence,
    ...(hasLocal ? { local: provider!.local } : {}),
    ...(hasCustom ? { custom: provider!.custom } : {}),
  };
}

export function createGuardPolicyProvider(opts: {
  provider?: GuardProviderConfig;
  runtime: GuardRuntimeContext;
}): GuardPolicyProvider {
  const resolved = validateProviderConfig(opts.provider);
  const local = resolved.local ? new LocalPolicyProvider(resolved.local) : undefined;
  const custom = resolved.custom ? new CustomPolicyProvider(resolved.custom) : undefined;
  if (local && !custom) return local;
  if (custom && !local) return custom;

  return new CompositePolicyProvider({
    precedence: resolved.precedence,
    local,
    custom,
    runtime: opts.runtime,
  });
}
