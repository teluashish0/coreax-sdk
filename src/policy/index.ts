import Ajv2020, { type ErrorObject } from "ajv/dist/2020";
import { parse as parseYaml } from "yaml";

import { policySchema } from "./schema";
import type { CoreaxPolicy, ValidationResult } from "./types";

export type {
  CoreaxPolicy,
  PolicyEnforcementReason,
  Severity,
} from "./types";

const ajv = new Ajv2020({ allErrors: true, strict: true });
const validate = ajv.compile(policySchema);

export function validatePolicy(
  policy: unknown,
): ValidationResult & { policy?: CoreaxPolicy } {
  if (validate(policy)) return { valid: true, policy: policy as CoreaxPolicy };
  return {
    valid: false,
    errors: (validate.errors ?? []).map(formatAjvError),
  };
}

export function parsePolicyYaml(source: string): CoreaxPolicy {
  const parsed = parseYaml(source);
  const result = validatePolicy(parsed);
  if (!result.valid || !result.policy) {
    throw new Error(`Invalid CoreAX policy: ${(result.errors ?? []).join("; ")}`);
  }
  return result.policy;
}

export function normalizeAllowlist(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  return raw.map((entry) => String(entry).trim()).filter(Boolean);
}

export function matchesAllowlist(
  allowlist: unknown,
  toolName: string,
  options: { serverName?: string } = {},
): boolean {
  const list = normalizeAllowlist(allowlist);
  if (list.includes("*")) return true;
  const rawTool = String(toolName || "").trim();
  if (!rawTool) return false;
  const [toolBase, toolVersion] = rawTool.split("@", 2);

  return list.some((entry) => {
    if (entry === rawTool || entry === toolBase) return true;
    if (entry.endsWith("@*") && entry.slice(0, -2) === toolBase) return true;
    if (!entry.startsWith("mcp://")) return false;
    const [server = "", tool = "*"] = entry.slice(6).split("/", 2);
    if (server !== "*" && server !== options.serverName) return false;
    if (tool === "*") return true;
    const [allowedTool, allowedVersion] = tool.split("@", 2);
    return (
      allowedTool === toolBase &&
      (!allowedVersion || allowedVersion === "*" || allowedVersion === toolVersion)
    );
  });
}

function formatAjvError(error: ErrorObject): string {
  const path = error.instancePath || "(root)";
  if (error.keyword === "enum") {
    return `${path} must be one of ${(error.params as any).allowedValues.join(", ")}`;
  }
  return `${path} ${error.message ?? error.keyword}`;
}
