import { describe, expect, it, vi } from "vitest";
import {
  captureRawPayloads,
  resolveDenialType,
  stampResultTracing,
} from "../src/middleware/auditEnvelope";
import { createMiddlewareInvocationState } from "../src/middleware/invocationState";

describe("auditEnvelope", () => {
  it("stamps trace and span identifiers across all supported result keys", () => {
    const result: Record<string, unknown> = {};
    stampResultTracing(result, "trace-123", "span-456");

    expect(result).toMatchObject({
      trace: "trace-123",
      traceId: "trace-123",
      trace_id: "trace-123",
      span: "span-456",
      spanId: "span-456",
      span_id: "span-456",
    });
  });

  it("maps denial reasons to stable audit denial types", () => {
    expect(resolveDenialType("fs_violation")).toBe("rasp");
    expect(resolveDenialType("custom_sast_block")).toBe("sast");
    expect(resolveDenialType("custom_dast_block")).toBe("dast");
    expect(resolveDenialType("other")).toBeUndefined();
  });

  it("skips raw payload capture unless enabled and requires an agent run id when enabled", async () => {
    const appendRawPayload = vi.fn(async () => undefined);
    const sink = { append: vi.fn(async () => undefined), appendRawPayload } as any;
    const state = createMiddlewareInvocationState();
    state.result = { ok: true };
    state.riskTags = ["safe"];

    await captureRawPayloads({
      auditSink: sink,
      tenant: "tenant-a",
      environment: "dev",
      client: "client-a",
      clientVersion: "1.0.0",
      state,
      traceId: "trace-1",
      spanId: "span-1",
      tool: "read@1.0",
      ctx: { args: { query: "ok" } },
    });
    expect(appendRawPayload).not.toHaveBeenCalled();

    await expect(
      captureRawPayloads({
        rawPayloadConfig: { enabled: true },
        auditSink: sink,
        tenant: "tenant-a",
        environment: "dev",
        client: "client-a",
        clientVersion: "1.0.0",
        state,
        traceId: "trace-1",
        spanId: "span-1",
        tool: "read@1.0",
        ctx: { args: { query: "ok" } },
      }),
    ).rejects.toThrow("agent runId is required");
  });
});
