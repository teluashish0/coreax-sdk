import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { DastManager } from "../src/middleware/dast";
import { createMiddlewareInvocationState } from "../src/middleware/invocationState";
import { createScanPipeline } from "../src/middleware/scanPipeline";
import { SastManager } from "../src/middleware/sast";

const tempDirs: string[] = [];

afterEach(() => {
  while (tempDirs.length) {
    const dir = tempDirs.pop();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  }
});

function makeTempToolFile(source: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sec0-scan-pipeline-"));
  tempDirs.push(dir);
  const filePath = path.join(dir, "tool.ts");
  fs.writeFileSync(filePath, source, "utf8");
  return filePath;
}

describe("scanPipeline", () => {
  it("attributes file-path SAST findings to the wrapped tool span only", async () => {
    const filePath = makeTempToolFile(`
tool('alpha@1.0', withSec0Meta(async () => {
  const safe = true;
  return safe;
}));
tool('beta@1.0', withSec0Meta(async () => {
  const alsoSafe = true;
  return alsoSafe;
}));
`);
    const semgrepFallbackScan = vi.fn(async () => ({
      status: "fail" as const,
      scanId: "scan-1",
      findings: [
        { code: "A", title: "A", severity: "medium" as const, message: "alpha", file: filePath, startLine: 3 },
        { code: "B", title: "B", severity: "medium" as const, message: "beta", file: filePath, startLine: 7 },
      ],
    }));
    const pipeline = createScanPipeline({
      server: { name: "demo", version: "1.0.0" },
      tenant: "tenant-a",
      registrySnapshotHash: "snapshot-1",
      requireUploadConfig: () => ({ baseUrl: "https://api.example.com", apiKey: "key" }),
      semgrepFallbackScan,
    });
    const state = createMiddlewareInvocationState();
    state.toolCodeChanged = true;
    const manager = new SastManager({
      cache_ttl_ms: 60_000,
      onScan: semgrepFallbackScan,
    });

    const result = await pipeline.runSast({
      tool: "alpha@1.0",
      handler: async () => ({}),
      currentHandler: async () => ({}),
      toolFilePath: filePath,
      manager,
      state,
      addAttrs: vi.fn(),
      runOnChangeOnly: true,
      blockOnSeverity: "critical",
    });

    expect(result.didRun).toBe(true);
    expect(result.findings).toHaveLength(1);
    expect(result.findings?.[0].message).toBe("alpha");
  });

  it("uploads raw SAST evidence once and preserves the cached raw key", async () => {
    const filePath = makeTempToolFile(`
tool('alpha@1.0', withSec0Meta(async () => {
  return true;
}));
`);
    const semgrepFallbackScan = vi.fn(async () => ({
      status: "fail" as const,
      scanId: "scan-raw",
      findings: [{ code: "A", title: "A", severity: "low" as const, message: "alpha", file: filePath, startLine: 3 }],
      raw: { original: true },
    }));
    const persistRaw = vi.fn(async () => "raw-key-1");
    const pipeline = createScanPipeline({
      server: { name: "demo", version: "1.0.0" },
      tenant: "tenant-a",
      registrySnapshotHash: "snapshot-1",
      requireUploadConfig: () => ({ baseUrl: "https://api.example.com", apiKey: "key" }),
      semgrepFallbackScan,
      persistRaw,
    });
    const manager = new SastManager({
      cache_ttl_ms: 60_000,
      onScan: semgrepFallbackScan,
    });

    const firstState = createMiddlewareInvocationState();
    firstState.toolCodeChanged = true;
    const first = await pipeline.runSast({
      tool: "alpha@1.0",
      handler: async () => ({}),
      currentHandler: async () => ({}),
      toolFilePath: filePath,
      manager,
      state: firstState,
      addAttrs: vi.fn(),
      runOnChangeOnly: true,
      blockOnSeverity: "critical",
    });

    const secondState = createMiddlewareInvocationState();
    secondState.toolCodeChanged = true;
    const second = await pipeline.runSast({
      tool: "alpha@1.0",
      handler: async () => ({}),
      currentHandler: async () => ({}),
      toolFilePath: filePath,
      manager,
      state: secondState,
      addAttrs: vi.fn(),
      runOnChangeOnly: true,
      blockOnSeverity: "critical",
    });

    expect(first.rawKey).toBe("raw-key-1");
    expect(second.rawKey).toBe("raw-key-1");
    expect(persistRaw).toHaveBeenCalledTimes(1);
  });

  it("uses the registry snapshot hash for server-scope DAST runs", async () => {
    const onScan = vi.fn(async (info: any) => ({
      status: "pass" as const,
      findings: [],
      scanId: "dast-1",
      raw: null,
      received: info,
    }));
    const pipeline = createScanPipeline({
      server: { name: "demo", version: "1.0.0" },
      tenant: "tenant-a",
      registrySnapshotHash: "server-snapshot-hash",
      requireUploadConfig: () => ({ baseUrl: "https://api.example.com", apiKey: "key" }),
      semgrepFallbackScan: vi.fn(async () => ({ status: "pass" as const, findings: [] })),
    });
    const manager = new DastManager({
      sandbox_url: "https://sandbox.example.com",
      rule_ttl_ms: 60_000,
      mode: "sync",
      onScan,
    });
    const currentHandler = async () => ({});
    (currentHandler as any).__sec0_handler_hash = "tool-handler-hash";
    const state = createMiddlewareInvocationState();
    state.serverCodeChanged = true;

    const result = await pipeline.runDast({
      tool: "alpha@1.0",
      currentHandler,
      manager,
      state,
      mode: "sync",
      scope: "server",
      sandboxUrl: "https://sandbox.example.com",
      runOnChangeOnly: true,
      blockOnSeverity: "critical",
    });

    expect(result.scopeKey).toBe("server-snapshot-hash");
    expect(onScan).toHaveBeenCalledWith(
      expect.objectContaining({
        handlerHash: "server-snapshot-hash",
      }),
    );
  });
});
