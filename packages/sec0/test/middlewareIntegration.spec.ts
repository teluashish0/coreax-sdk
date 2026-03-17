import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { encodeAgentStateHeaders, sec0SecurityMiddleware } from "../src/middleware";

const tempDirs: string[] = [];

afterEach(() => {
  while (tempDirs.length) {
    const dir = tempDirs.pop();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  }
});

function makeTempDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sec0-middleware-test-"));
  tempDirs.push(dir);
  return dir;
}

function createServer() {
  const tools = new Map<string, any>();
  return {
    server: {
      name: "demo-server",
      version: "1.0.0",
      tool(nameAtVersion: string, handler: any) {
        tools.set(nameAtVersion, handler);
      },
      __getTools() {
        return tools;
      },
      __setTool(nameAtVersion: string, handler: any) {
        tools.set(nameAtVersion, handler);
      },
    },
    tools,
  };
}

function createBaseOptions(overrides: Record<string, unknown> = {}) {
  return {
    policy: {
      default_retention: "default",
      tools: { allowlist: ["*"] },
      enforcement: { deny_on: [] },
    },
    signer: {
      keyId: "test-key",
      sign: () => new Uint8Array([1, 2, 3]),
    },
    otel: {
      endpoint: "http://127.0.0.1:4318",
      serviceName: "sec0-test",
      environment: "test",
    },
    sec0: {
      dir: makeTempDir(),
    },
    telemetry: { enabled: false },
    adapters: {
      policyProvider: {
        getPolicy: vi.fn(async () => ({
          policy: (overrides.policy as any) || {
            default_retention: "default",
            tools: { allowlist: ["*"] },
            enforcement: { deny_on: [] },
          },
          hash: "static",
          tenant: "tenant-a",
          env: "test",
          clientName: "client-a",
          clientVersion: "1.0.0",
        })),
      },
      approvalVerifier: {
        verify: vi.fn(async () => null),
      },
      runtimeInvoker: {
        evaluate: vi.fn(async () => ({
          decision: "allow",
          reasons: [],
          obligations: [],
          auditRefs: [],
          evaluationSource: "local",
          adapterMode: "local",
        })),
      },
      auditSink: {
        append: vi.fn(async () => undefined),
      },
      escalationReporter: {
        create: vi.fn(async () => ({ id: "esc-1", status: "pending" })),
      },
    },
    ...overrides,
  } as any;
}

describe("middleware integration", () => {
  it("keeps the allow path stable with a passing DAST scan and stamped result traces", async () => {
    const { server, tools } = createServer();
    server.tool("echo@1.0", async ({ args }: any) => ({ ok: true, args }));
    const opts = createBaseOptions({
      dast: {
        enabled: true,
        sandbox_url: "https://sandbox.example.com",
        rule_ttl_ms: 60_000,
        mode: "sync",
        onScan: vi.fn(async () => ({
          status: "pass",
          findings: [],
          scanId: "dast-pass",
        })),
      },
    });

    sec0SecurityMiddleware(opts)(server as any);
    const wrapped = tools.get("echo@1.0");
    const result = await wrapped({
      args: { message: "hello" },
      headers: encodeAgentStateHeaders({ nodeId: "node-allow", runId: "run-allow" }),
    });

    expect(result.ok).toBe(true);
    expect(typeof result.traceId).toBe("string");
    expect(typeof result.spanId).toBe("string");
    expect(opts.adapters.auditSink.append).toHaveBeenCalledTimes(1);
    expect(opts.adapters.escalationReporter.create).not.toHaveBeenCalled();
  });

  it("propagates deny + escalation behavior when a DAST scan blocks execution", async () => {
    const { server, tools } = createServer();
    server.tool("write@1.0", async () => ({ ok: true }));
    const opts = createBaseOptions({
      policy: {
        default_retention: "default",
        tools: { allowlist: ["*"] },
        enforcement: { deny_on: ["tool_code_changed"] },
        security: { side_effects: { approve_high_risk: true } },
      },
      dast: {
        enabled: true,
        sandbox_url: "https://sandbox.example.com",
        rule_ttl_ms: 60_000,
        mode: "sync",
        block_on_severity: "low",
        onScan: vi.fn(async () => ({
          status: "fail",
          findings: [
            {
              code: "DAST-1",
              title: "DAST issue",
              severity: "low",
              message: "blocked",
            },
          ],
          scanId: "dast-fail",
        })),
      },
    });

    sec0SecurityMiddleware(opts)(server as any);
    const wrapped = tools.get("write@1.0");

    await expect(
      wrapped({
        args: { value: "blocked" },
        headers: encodeAgentStateHeaders({ nodeId: "node-deny", runId: "run-deny" }),
      }),
    ).rejects.toMatchObject({
      code: "POLICY_DENIED",
      escalation_id: "esc-1",
      escalation_status: "pending",
    });
    expect(opts.adapters.escalationReporter.create).toHaveBeenCalledTimes(1);
    expect(opts.adapters.auditSink.append).toHaveBeenCalledTimes(1);
  });
});
