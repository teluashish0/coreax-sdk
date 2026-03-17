import { sha256Hex } from "../signer";
import { parseIdentityContextHeader } from "./identity";
import {
  generateSpanId,
  generateTraceId,
  normalizeSpanId,
  normalizeTraceId,
} from "./tooling";

export type AuditArtifacts = {
  traceId: string;
  spanId: string;
  causeTraceId?: string;
  causeSpanId?: string;
};

export function deriveTraceContext(input: {
  headers?: Record<string, string>;
  spanTraceId?: string;
  spanSpanId?: string;
}): AuditArtifacts {
  const headers = input.headers || {};
  const currentTraceId = normalizeTraceId(input.spanTraceId);
  const inferredParent = (() => {
    try {
      const traceparent = String((headers as any).traceparent || "").trim();
      if (!traceparent) return null;
      const match = traceparent.match(/^\s*([\da-fA-F]{2})-([\da-fA-F]{32})-([\da-fA-F]{16})-([\da-fA-F]{2})/);
      if (!match) return null;
      const traceId = match[2].toLowerCase();
      const spanId = match[3].toLowerCase();
      if (!/^0+$/.test(traceId) && traceId !== currentTraceId) {
        return { traceId, spanId };
      }
    } catch {}
    return null;
  })();

  return {
    traceId: currentTraceId || generateTraceId(),
    spanId: normalizeSpanId(input.spanSpanId) || generateSpanId(),
    causeTraceId: normalizeTraceId(headers["x-cause-trace"]) ?? normalizeTraceId(inferredParent?.traceId),
    causeSpanId: normalizeSpanId(headers["x-cause-span"]) ?? normalizeSpanId(inferredParent?.spanId),
  };
}

export function extractAuthObject(headers?: Record<string, string>): Record<string, unknown> | undefined {
  try {
    const contextHeader = (headers?.["x-auth-context"] as string) || undefined;
    const parsed = parseIdentityContextHeader(contextHeader);
    if (parsed) return { ...parsed };
    const authorization = (headers?.authorization as string) || (headers?.Authorization as string);
    if (typeof authorization !== "string" || !authorization.length) return undefined;
    const parts = authorization.split(/\s+/);
    const scheme = (parts[0] || "").toLowerCase();
    const token = parts.slice(1).join(" ");
    const tokenSha256 = token ? sha256Hex(Buffer.from(token)) : undefined;
    let jwt: any;
    if (token && token.split(".").length >= 2) {
      try {
        const payload = token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
        jwt = JSON.parse(Buffer.from(payload, "base64").toString("utf8"));
      } catch {}
    }
    return {
      scheme,
      ...(tokenSha256 ? { token_sha256: tokenSha256 } : {}),
      ...(jwt
        ? {
            jwt: {
              sub: jwt.sub,
              iss: jwt.iss,
              aud: jwt.aud,
              exp: jwt.exp,
              iat: jwt.iat,
              email: jwt.email,
              tenant: jwt.tenant,
            },
          }
        : {}),
    };
  } catch {
    return undefined;
  }
}

export function deriveComplianceMetadata(params: {
  sastFindings?: Array<Record<string, any>>;
  dastFindings?: Array<Record<string, any>>;
}) {
  const nistTags = new Set<string>();
  const owaspTags = new Set<string>();
  const cweTags = new Set<string>();
  const cveTags = new Set<string>();
  const addNist = (...codes: (string | undefined)[]) => codes.filter(Boolean).forEach((code) => nistTags.add(String(code)));
  const addOwasp = (...codes: (string | undefined)[]) => codes.filter(Boolean).forEach((code) => owaspTags.add(String(code)));
  const addCwe = (...codes: (string | undefined)[]) => codes.filter(Boolean).forEach((code) => cweTags.add(String(code)));
  try {
    const findings = [...(params.sastFindings || []), ...(params.dastFindings || [])];
    for (const finding of findings) {
      const tags = Array.isArray((finding as any)?.tags) ? (finding as any).tags : [];
      for (const tag of tags) {
        const value = String(tag);
        if (/^nist\b/i.test(value) || /SP\s*800-53/i.test(value)) addNist(value);
        if (/OWASP/i.test(value)) addOwasp(value);
        if (/^CWE[-_ ]?\d+/i.test(value)) addCwe(value.toUpperCase());
        if (/^CVE-\d{4}-\d{4,}$/i.test(value)) cveTags.add(value.toUpperCase());
      }
      const cwe = (finding as any)?.cwe;
      const owasp = (finding as any)?.owasp;
      const nist = (finding as any)?.nist;
      if (cwe) (Array.isArray(cwe) ? cwe : [cwe]).forEach((value: any) => addCwe(String(value)));
      if (owasp) (Array.isArray(owasp) ? owasp : [owasp]).forEach((value: any) => addOwasp(String(value)));
      if (nist) (Array.isArray(nist) ? nist : [nist]).forEach((value: any) => addNist(String(value)));
      const code = (finding as any)?.code;
      if (typeof code === "string" && /^CVE-\d{4}-\d{4,}$/i.test(code)) cveTags.add(code.toUpperCase());
    }
  } catch {}
  return {
    compliance: {
      nist: Array.from(nistTags),
      owasp: Array.from(owaspTags),
      cwe: Array.from(cweTags),
    },
    vulnRefs: {
      cve: Array.from(cveTags),
      cwe: Array.from(cweTags),
      owasp: Array.from(owaspTags),
      nist: Array.from(nistTags),
    },
  };
}
