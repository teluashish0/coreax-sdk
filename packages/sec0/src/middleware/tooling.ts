import { randomBytes } from "node:crypto";

export const readHeaderCaseInsensitive = (
  headers: Record<string, any> | undefined,
  name: string,
): string | undefined => {
  if (!headers) return undefined;
  const direct = headers[name];
  const lowered = headers[name.toLowerCase()];
  const raw = direct ?? lowered;
  if (Array.isArray(raw)) {
    const first = raw[0];
    return typeof first === "string" ? first.trim() || undefined : undefined;
  }
  if (typeof raw === "string") {
    const trimmed = raw.trim();
    return trimmed || undefined;
  }
  return undefined;
};

export function normalizeTraceId(value?: string | null): string | undefined {
  if (!value) return undefined;
  const hex = value.trim().toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(hex)) return undefined;
  if (/^0+$/.test(hex)) return undefined;
  return hex;
}

export function normalizeSpanId(value?: string | null): string | undefined {
  if (!value) return undefined;
  const hex = value.trim().toLowerCase();
  if (!/^[0-9a-f]{16}$/.test(hex)) return undefined;
  if (/^0+$/.test(hex)) return undefined;
  return hex;
}

export function generateTraceId(): string {
  return randomBytes(16).toString("hex");
}

export function generateSpanId(): string {
  return randomBytes(8).toString("hex");
}

export function isPinned(nameAtVersion: string): boolean {
  return /@\d+/.test(nameAtVersion);
}

export function isSideEffecting(toolNameAtVersion: string, args: any): boolean {
  try {
    const name = toolNameAtVersion.toLowerCase();
    if (/(write|delete|put|post|patch|create|update)/.test(name)) return true;
    if (name.includes("filesystem") && /write|delete|remove|mkdir|rmdir/.test(name)) return true;
    if (name.includes("fetch") && typeof args?.method === "string" && args.method.toUpperCase() !== "GET") return true;
    return false;
  } catch {
    return false;
  }
}

export function inferOp(toolNameAtVersion: string, args: any): "read" | "create" | "update" | "delete" {
  const name = String(toolNameAtVersion || "").toLowerCase();
  const method = typeof args?.method === "string" ? args.method.trim().toUpperCase() : "";
  if (method === "DELETE" || name.includes("delete") || name.includes("remove")) return "delete";
  if (method === "POST" || name.includes("create")) return "create";
  if (method === "PUT" || method === "PATCH" || name.includes("update") || name.includes("write")) return "update";
  if (method === "GET" || name.includes("read") || name.includes(".get") || name.includes("get@")) return "read";
  return isSideEffecting(toolNameAtVersion, args) ? "update" : "read";
}

export function normalizePolicyReasonToken(value: unknown): string {
  const normalized = String(value || "").trim();
  if (normalized === "idempotency_missing") return "missing_idempotency_for_side_effect";
  return normalized;
}

export function normalizePolicyReasonArray(values: unknown): string[] {
  if (!Array.isArray(values)) return [];
  const seen = new Set<string>();
  for (const value of values) {
    const normalized = normalizePolicyReasonToken(value);
    if (!normalized) continue;
    seen.add(normalized);
  }
  return Array.from(seen.values());
}

export type ToolDescriptor = { name: string; version: string };

export function parseToolDescriptor(toolNameAtVersion: string): ToolDescriptor {
  const [rawName, rawVersion] = String(toolNameAtVersion ?? "").split("@");
  const name = rawName?.trim();
  const version = rawVersion?.trim();
  if (!name) {
    throw new Error(`[sec0-middleware] tool name is required (${toolNameAtVersion || "unknown"})`);
  }
  if (!version) {
    throw new Error(`[sec0-middleware] tool version is required (${toolNameAtVersion || "unknown"})`);
  }
  return { name, version };
}

export function toolUri(serverName: string, toolNameAtVersion: string): string {
  const { name, version } = parseToolDescriptor(toolNameAtVersion);
  return `mcp://${serverName}/${name}@${version}`;
}

export function toolUriNoVersion(serverName: string, toolNameAtVersion: string): string {
  const { name } = parseToolDescriptor(toolNameAtVersion);
  return `mcp://${serverName}/${name}`;
}

export function matchesToolPattern(pattern: string, serverName: string, toolNameAtVersion: string): boolean {
  const pat = String(pattern || "").trim().toLowerCase();
  if (!pat) return false;
  const descriptor = parseToolDescriptor(toolNameAtVersion);
  const normalizedWithVersion = `${descriptor.name}@${descriptor.version}`;
  const toolRefFull = `${serverName}:${normalizedWithVersion}`.toLowerCase();
  const toolRefNoVersion = `${serverName}:${descriptor.name}`.toLowerCase();
  const toolWithVersion = normalizedWithVersion.toLowerCase();
  const toolOnly = descriptor.name.toLowerCase();
  const serverOnly = serverName.toLowerCase();
  if (pat.includes("*")) {
    const esc = pat.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*?");
    const re = new RegExp(`^${esc}$`, "i");
    return (
      re.test(toolRefFull) ||
      re.test(toolRefNoVersion) ||
      re.test(toolWithVersion) ||
      re.test(toolOnly) ||
      re.test(serverOnly)
    );
  }
  return (
    pat === toolRefFull ||
    pat === toolRefNoVersion ||
    pat === toolWithVersion ||
    pat === toolOnly ||
    pat === serverOnly
  );
}

export type AllowMatchKind = "exact" | "versionless" | "wildcard" | null;

export function matchAllowlist(
  allowlist: string[],
  serverName: string,
  toolNameAtVersion: string,
): { allowed: boolean; kind: AllowMatchKind } {
  const descriptor = parseToolDescriptor(toolNameAtVersion);
  const withVer = toolUri(serverName, toolNameAtVersion);
  if (allowlist.includes(withVer)) return { allowed: true, kind: "exact" };
  const noVer = toolUriNoVersion(serverName, toolNameAtVersion);
  if (allowlist.includes(noVer)) return { allowed: true, kind: "versionless" };
  const wildcard = `mcp://${serverName}/${descriptor.name}@*`;
  if (allowlist.includes(wildcard)) return { allowed: true, kind: "wildcard" };
  if (allowlist.includes("*") || allowlist.includes("mcp://*") || allowlist.includes("mcp://*/*@*")) {
    return { allowed: true, kind: "wildcard" };
  }
  return { allowed: false, kind: null };
}
