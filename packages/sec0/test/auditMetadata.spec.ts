import { describe, expect, it } from "vitest";
import {
  deriveComplianceMetadata,
  deriveTraceContext,
  extractAuthObject,
} from "../src/middleware/auditMetadata";

describe("auditMetadata", () => {
  it("derives trace context from inbound headers and preserves parent linkage", () => {
    const result = deriveTraceContext({
      headers: {
        traceparent: "00-1234567890abcdef1234567890abcdef-1234567890abcdef-01",
      },
      spanTraceId: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      spanSpanId: "bbbbbbbbbbbbbbbb",
    });

    expect(result).toEqual({
      traceId: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      spanId: "bbbbbbbbbbbbbbbb",
      causeTraceId: "1234567890abcdef1234567890abcdef",
      causeSpanId: "1234567890abcdef",
    });
  });

  it("prefers the structured auth header over raw authorization parsing", () => {
    const result = extractAuthObject({
      "x-auth-context": JSON.stringify({
        scheme: "prehashed",
        user_hash: "user-hash",
        tenant: "tenant-a",
        roles: ["admin"],
      }),
      authorization: "Bearer ignored.token.value",
    });

    expect(result).toEqual({
      scheme: "prehashed",
      user_hash: "user-hash",
      tenant: "tenant-a",
      roles: ["admin"],
    });
  });

  it("collects compliance and vulnerability references from findings", () => {
    const result = deriveComplianceMetadata({
      sastFindings: [
        {
          tags: ["OWASP-A01", "nist SP 800-53 AC-3", "cwe-79"],
          code: "CVE-2025-1234",
        },
      ],
      dastFindings: [
        {
          cwe: ["CWE-89"],
          owasp: ["OWASP-API1"],
          nist: ["AC-4"],
        },
      ],
    });

    expect(result.compliance).toEqual({
      nist: expect.arrayContaining(["nist SP 800-53 AC-3", "AC-4"]),
      owasp: expect.arrayContaining(["OWASP-A01", "OWASP-API1"]),
      cwe: expect.arrayContaining(["CWE-79", "CWE-89"]),
    });
    expect(result.vulnRefs).toEqual({
      cve: ["CVE-2025-1234"],
      cwe: expect.arrayContaining(["CWE-79", "CWE-89"]),
      owasp: expect.arrayContaining(["OWASP-A01", "OWASP-API1"]),
      nist: expect.arrayContaining(["nist SP 800-53 AC-3", "AC-4"]),
    });
  });
});
