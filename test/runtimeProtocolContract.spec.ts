import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createRuntimeAdapter,
  LocalRuntimeAdapter,
  mapRuntimeDecisionRequest,
  resolveRuntimeAdapterConfig,
  RUNTIME_PROTOCOL_VERSION,
  type RuntimeDecisionInput,
} from "../src/runtime-adapter";

function decisionInput(
  enforcement: RuntimeDecisionInput["enforcement"],
): RuntimeDecisionInput {
  return {
    context: {
      integrationSurface: "coreax",
      executionLayer: "middleware",
      server: "local-test-server",
      tool: "write_file",
    },
    enforcement,
    input: {
      reasons: ["boundary-crossing-side-effect"],
      riskTags: ["filesystem-write"],
      attributes: {
        path: "./workspace/report.txt",
      },
    },
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("local runtime adapter contract", () => {
  it("resolves only the explicit local runtime mode", () => {
    expect(resolveRuntimeAdapterConfig()).toEqual({
      mode: "local",
      protocolVersion: RUNTIME_PROTOCOL_VERSION,
    });

    expect(
      resolveRuntimeAdapterConfig({
        protocolVersion: "local-protocol-v1",
      }),
    ).toEqual({
      mode: "local",
      protocolVersion: "local-protocol-v1",
    });

    expect(createRuntimeAdapter()).toBeInstanceOf(LocalRuntimeAdapter);
  });

  it("evaluates deterministically when fetch is unavailable", async () => {
    vi.stubGlobal("fetch", undefined);
    const adapter = createRuntimeAdapter();
    const input = decisionInput({
      mode: "enforce",
      strategy: "deny_on_match",
      denyOn: ["boundary-crossing-side-effect"],
    });

    const first = await adapter.evaluate(input);
    const replay = await adapter.evaluate(input);

    expect(first).toEqual({
      protocolVersion: RUNTIME_PROTOCOL_VERSION,
      adapterMode: "local",
      evaluationSource: "local",
      decision: "deny",
      reason: "boundary-crossing-side-effect",
      reasons: ["boundary-crossing-side-effect"],
      obligations: [],
      auditRefs: [],
    });
    expect(replay).toEqual(first);
    expect(globalThis.fetch).toBeUndefined();
  });

  it("keeps observation local without turning findings into a denial", async () => {
    const outbound = vi.fn(() => {
      throw new Error("unexpected outbound request");
    });
    vi.stubGlobal("fetch", outbound);

    const result = await createRuntimeAdapter({
      protocolVersion: "caller-selected-local-version",
    }).evaluate(
      decisionInput({
        mode: "observe",
        strategy: "deny_on_any",
      }),
    );

    expect(result).toMatchObject({
      protocolVersion: "caller-selected-local-version",
      adapterMode: "local",
      evaluationSource: "local",
      decision: "allow",
      reasons: ["boundary-crossing-side-effect"],
    });
    expect(outbound).not.toHaveBeenCalled();
  });

  it("defaults mapped enforcement to fail closed and honors forceDeny without reasons", async () => {
    const mapped = mapRuntimeDecisionRequest({
      executionLayer: "custom-agent",
      server: "local-test-server",
      tool: "unknown-action",
    });
    expect(mapped.enforcement.mode).toBe("enforce");

    await expect(
      createRuntimeAdapter().evaluate({
        ...mapped,
        enforcement: {
          ...mapped.enforcement,
          forceDeny: true,
        },
      }),
    ).resolves.toMatchObject({
      decision: "deny",
      reasons: [],
    });
  });
});
