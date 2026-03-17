import { describe, expect, it } from "vitest";
import {
  createInvocationStats,
  createRegistryState,
  type ToolHandler,
  type ToolRegistrationServer,
} from "../src/middleware/registryState";

function createServer() {
  const tools = new Map<string, ToolHandler>();
  const server: ToolRegistrationServer & { name: string; version: string } = {
    name: "demo-server",
    version: "1.0.0",
    tool(nameAtVersion, handler) {
      tools.set(nameAtVersion, handler);
    },
    __getTools() {
      return tools;
    },
    __setTool(nameAtVersion, handler) {
      tools.set(nameAtVersion, handler);
    },
  };
  return { server, tools };
}

describe("registryState", () => {
  it("freezes external registry mutation while allowing wrapper installation", () => {
    const { server, tools } = createServer();
    const originalHandler: ToolHandler = async () => ({ ok: true });
    server.tool("echo@1.0", originalHandler);

    const registry = createRegistryState({ server, tools, now: () => 42 });
    const wrappedHandler: ToolHandler = async () => ({ wrapped: true });

    registry.installWrappedTool("echo@1.0", wrappedHandler, originalHandler);

    const installed = tools.get("echo@1.0") as ToolHandler & {
      __sec0_wrapper__?: boolean;
      __sec0_handler_hash?: string;
    };
    expect(installed).toBe(wrappedHandler);
    expect(installed.__sec0_wrapper__).toBe(true);
    expect(typeof installed.__sec0_handler_hash).toBe("string");

    registry.freeze();

    expect(() => server.tool("beta@1.0", async () => ({ ok: false }))).toThrow(/REGISTRY_FROZEN/);
    expect(() => tools.set("beta@1.0", async () => ({ ok: false }))).toThrow(/REGISTRY_FROZEN/);
    expect(registry.getMutationAttempted()).toEqual({
      tool: "beta@1.0",
      when: 42,
      kind: "map",
    });
  });

  it("detects wrapped handler drift against the initial registry snapshot", () => {
    const { server, tools } = createServer();
    const originalHandler: ToolHandler = async () => ({ ok: true });
    server.tool("echo@1.0", originalHandler);

    const registry = createRegistryState({ server, tools });
    const wrappedHandler: ToolHandler = async () => ({ wrapped: true });

    registry.installWrappedTool("echo@1.0", wrappedHandler, originalHandler);

    const hijackedHandler: ToolHandler = async () => ({ hijacked: true });
    tools.set("echo@1.0", hijackedHandler);

    expect(registry.detectToolRuntimeChanges("echo@1.0", wrappedHandler)).toEqual({
      handlerSwapDetected: true,
      toolCodeChanged: true,
      serverCodeChanged: true,
      registryMutation: false,
    });
  });

  it("tracks invocation stats with a bounded sliding window", () => {
    const stats = createInvocationStats(5, () => 100);

    stats.pushStat("echo@1.0", true, 10);
    stats.pushStat("echo@1.0", true, 20);
    stats.pushStat("echo@1.0", false, 30);
    stats.pushStat("echo@1.0", true, 40);
    stats.pushStat("echo@1.0", true, 50);
    stats.pushStat("echo@1.0", true, 60);

    expect(stats.getSampleCount("echo@1.0")).toBe(5);
    expect(stats.calcErrorRate("echo@1.0")).toBe(20);
    expect(stats.calcP95("echo@1.0")).toBe(50);
  });
});
