import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import type { CoreaxInstrumentationEvent } from "../src/instrumentation";

const temporaryDirectories: string[] = [];

function temporaryRoot(): { base: string; root: string } {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "coreax-instrumentation-"));
  temporaryDirectories.push(base);
  return { base, root: path.join(base, "nested", ".coreax") };
}

async function loadInstrumentation() {
  vi.resetModules();
  return import("../src/instrumentation");
}

afterEach(() => {
  vi.unstubAllGlobals();
  while (temporaryDirectories.length > 0) {
    fs.rmSync(temporaryDirectories.pop()!, {
      force: true,
      recursive: true,
    });
  }
});

describe("local instrumentation", () => {
  it("creates state only during explicit initialization", async () => {
    const instrumentation = await loadInstrumentation();
    const { root } = temporaryRoot();

    const resolved = instrumentation.resolveCoreaxConfiguration({
      stateRoot: root,
    });
    const paths = instrumentation.getCoreaxDirectories({ stateRoot: root });
    instrumentation.coreaxTool({ key: "Worker.execute" });
    instrumentation.wrapCoreaxTool(() => "ready", {
      key: "Worker.execute",
    });

    expect(resolved.stateRoot).toBe(path.resolve(root));
    expect(instrumentation.getCoreaxConfiguration()).toBeNull();
    expect(fs.existsSync(paths.rootDir)).toBe(false);
    expect(Object.keys(paths).sort()).toEqual([
      "auditDir",
      "rootDir",
      "stateDir",
    ]);

    const initialized = instrumentation.initCoreax({ stateRoot: root });

    expect(instrumentation.getCoreaxConfiguration()).toBe(initialized);
    expect(fs.statSync(paths.rootDir).isDirectory()).toBe(true);
    expect(fs.statSync(paths.stateDir).isDirectory()).toBe(true);
    expect(fs.statSync(paths.auditDir).isDirectory()).toBe(true);
  });

  it.skipIf(process.platform === "win32")(
    "rejects symlinked roots and narrows existing directory permissions",
    async () => {
      const instrumentation = await loadInstrumentation();
      const { base } = temporaryRoot();
      const target = path.join(base, "target");
      const symlink = path.join(base, "linked-state");
      fs.mkdirSync(target, { mode: 0o700 });
      fs.symlinkSync(target, symlink, "dir");

      expect(() =>
        instrumentation.initCoreax({ stateRoot: symlink }),
      ).toThrow(/symbolic links/i);

      const realRoot = path.join(base, "real-state");
      fs.mkdirSync(realRoot, { mode: 0o777 });
      const initialized = instrumentation.initCoreax({
        stateRoot: realRoot,
      });
      for (const directory of Object.values(initialized.directories)) {
        expect(fs.statSync(directory).mode & 0o077).toBe(0);
      }
    },
  );

  it("propagates run context through asynchronous wrapped calls", async () => {
    const instrumentation = await loadInstrumentation();
    const { root } = temporaryRoot();
    const events: CoreaxInstrumentationEvent[] = [];
    let clock = 1_000;
    const identifierCounts = new Map<string, number>();

    instrumentation.initCoreax({
      stateRoot: root,
      clock: () => {
        const value = clock;
        clock += 8;
        return value;
      },
      idGenerator: (kind) => {
        const count = (identifierCounts.get(kind) ?? 0) + 1;
        identifierCounts.set(kind, count);
        return `${kind}-${count}`;
      },
      onEvent: (event) => events.push(event),
    });

    const privateArgument = "private-input-that-must-not-be-recorded";
    const wrapped = instrumentation.wrapCoreaxTool(
      async (value: string) => {
        const before = instrumentation.requireCoreaxContext();
        await Promise.resolve();
        const after = instrumentation.requireCoreaxContext();
        expect(after).toBe(before);
        return `${value}:complete`;
      },
      {
        key: "Worker.execute",
        nodeId: "worker-node",
        name: "execute",
      },
    );

    const result = await instrumentation.seedCoreaxRun(
      "run-explicit",
      async () => {
        const rootContext = instrumentation.requireCoreaxContext();
        const output = await wrapped(privateArgument);
        expect(instrumentation.requireCoreaxContext()).toBe(rootContext);
        return output;
      },
      { traceId: "trace-explicit", spanId: "root-span" },
    );

    expect(result).toBe(`${privateArgument}:complete`);
    expect(events.map((event) => event.phase)).toEqual(["start", "success"]);
    expect(events[0]).toMatchObject({
      runId: "run-explicit",
      traceId: "trace-explicit",
      parentSpanId: "root-span",
      node: {
        key: "Worker.execute",
        kind: "tool",
        nodeId: "worker-node",
      },
    });
    expect(events[1]?.durationMs).toBe(8);
    expect(JSON.stringify(events)).not.toContain(privateArgument);
  });

  it("applies native decorators and preserves method receiver behavior", async () => {
    const instrumentation = await loadInstrumentation();
    const { root } = temporaryRoot();
    const events: CoreaxInstrumentationEvent[] = [];
    let sequence = 0;

    instrumentation.initCoreax({
      stateRoot: root,
      nodes: {
        "Worker.execute": {
          kind: "tool",
          nodeId: "configured-worker",
          name: "configured-execute",
        },
      },
      clock: () => 5_000 + sequence++,
      idGenerator: (kind) => `${kind}-${sequence++}`,
      onEvent: (event) => events.push(event),
    });

    class Worker {
      private readonly prefix = "receiver";

      execute(value: string): string {
        const context = instrumentation.requireCoreaxContext();
        return `${this.prefix}:${value}:${context.node?.nodeId}`;
      }
    }

    const descriptor = Object.getOwnPropertyDescriptor(
      Worker.prototype,
      "execute",
    )!;
    const decorated =
      instrumentation.coreax.tool({ key: "Worker.execute" })(
        Worker.prototype,
        "execute",
        descriptor,
      ) ?? descriptor;
    Object.defineProperty(Worker.prototype, "execute", decorated);

    const result = instrumentation.seedCoreaxRun(
      "run-decorator",
      () => new Worker().execute("input"),
      { traceId: "trace-decorator", spanId: "span-decorator" },
    );

    expect(result).toBe("receiver:input:configured-worker");
    expect(events.map((event) => event.phase)).toEqual(["start", "success"]);
    expect(events[0]?.node).toMatchObject({
      kind: "tool",
      key: "Worker.execute",
      nodeId: "configured-worker",
      name: "configured-execute",
    });
    expect(instrumentation.coreax.tool).toBe(instrumentation.coreaxTool);
    expect(instrumentation.coreaxDecorators["coreax-tool"]).toBe(
      instrumentation.coreaxTool,
    );
    expect(Object.keys(instrumentation.coreax).sort()).toEqual([
      "agent",
      "middleware",
      "orchestrator",
      "server",
      "skill",
      "tool",
    ]);
  });

  it("records hashed failures without invoking implicit network or environment APIs", async () => {
    const instrumentation = await loadInstrumentation();
    const { root } = temporaryRoot();
    const events: CoreaxInstrumentationEvent[] = [];
    const fetchSpy = vi.fn(() => {
      throw new Error("unexpected network access");
    });
    vi.stubGlobal("fetch", fetchSpy);

    instrumentation.initCoreax({
      stateRoot: root,
      onEvent: (event) => events.push(event),
    });
    const privateMessage = "private failure detail";
    const wrapped = instrumentation.wrapCoreaxAgent(
      () => {
        throw new Error(privateMessage);
      },
      { key: "Worker.fail" },
    );

    expect(() => wrapped()).toThrow(privateMessage);
    expect(events.map((event) => event.phase)).toEqual(["start", "error"]);
    expect(events[1]?.error?.messageSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(JSON.stringify(events)).not.toContain(privateMessage);
    expect(fetchSpy).not.toHaveBeenCalled();

    const source = fs
      .readdirSync(path.resolve("src/instrumentation"))
      .filter((file) => file.endsWith(".ts"))
      .sort()
      .map((file) =>
        fs.readFileSync(path.resolve("src/instrumentation", file), "utf8"),
      )
      .join("\n");
    expect(source).not.toMatch(/\bprocess\s*\.\s*env\b/);
    expect(source).not.toMatch(/\bfetch\s*\(/);
    expect(source.toLowerCase()).not.toContain("gate" + "way");
  });
});
