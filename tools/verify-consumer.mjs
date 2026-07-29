import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: process.cwd(),
    encoding: "utf8",
    ...options,
  });
  if (result.status !== 0) {
    throw new Error(
      `${command} ${args.join(" ")} failed\n${result.stdout}\n${result.stderr}`,
    );
  }
  return result.stdout;
}

function runIsolatedNode(scriptPath, cwd) {
  const result = spawnSync(process.execPath, [scriptPath], {
    cwd,
    encoding: "utf8",
    env: {},
    shell: false,
  });
  if (result.status !== 0) {
    throw new Error(
      `isolated consumer probe failed\n${result.stdout}\n${result.stderr}`,
    );
  }
  return result.stdout;
}

function consumerProbeSource(packageJson, specifiers) {
  return `
const fs = require("node:fs");
const path = require("node:path");
const { generateKeyPairSync } = require("node:crypto");

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

// macOS may inject __CF_USER_TEXT_ENCODING even when spawn receives env: {}.
// Clear any platform-injected keys before the SDK is imported or exercised.
for (const key of Reflect.ownKeys(process.env)) delete process.env[key];
assert(
  Reflect.ownKeys(process.env).length === 0,
  "consumer environment was not cleared before SDK import",
);

function unexpectedNetwork() {
  throw new Error("unexpected outbound network request");
}

globalThis.fetch = unexpectedNetwork;
if ("WebSocket" in globalThis) {
  globalThis.WebSocket = class BlockedWebSocket {
    constructor() {
      unexpectedNetwork();
    }
  };
}
for (const [moduleName, methods] of [
  ["node:http", ["request", "get"]],
  ["node:https", ["request", "get"]],
  ["node:http2", ["connect"]],
  ["node:net", ["connect", "createConnection"]],
  ["node:tls", ["connect"]],
  ["node:dgram", ["createSocket"]],
]) {
  const networkModule = require(moduleName);
  for (const method of methods) networkModule[method] = unexpectedNetwork;
}

const packageName = ${JSON.stringify(packageJson.name)};
const expectedVersion = ${JSON.stringify(packageJson.version)};
const specifiers = ${JSON.stringify(specifiers)};
const loaded = new Map();
for (const specifier of specifiers) loaded.set(specifier, require(specifier));

const root = loaded.get(packageName);
const policy = loaded.get(packageName + "/policy");
const evaluator = loaded.get(packageName + "/evaluator");
const signerModule = loaded.get(packageName + "/signer");
const runtimeAdapter = loaded.get(packageName + "/runtime-adapter");
const audit = loaded.get(packageName + "/audit");
const middleware = loaded.get(packageName + "/middleware");
const escalation = loaded.get(packageName + "/escalation");
const guardModule = loaded.get(packageName + "/guard");
const governance = loaded.get(packageName + "/governance");
const runtimeRisk = loaded.get(packageName + "/runtime-risk");
const policyLearning = loaded.get(packageName + "/policy-learning");
const instrumentation = loaded.get(packageName + "/instrumentation");
const customAgent = loaded.get(packageName + "/integrations/custom-agent");
const packagedManifest = loaded.get(packageName + "/package.json");
const completed = [];
const mark = (name) => completed.push(name);

const stateRoot = path.join(__dirname, ".coreax-smoke-state");
assert(!fs.existsSync(stateRoot), "consumer smoke state already exists");
const fixedTime = Date.parse("2026-01-01T00:00:00.000Z");

(async () => {
  try {
    assert(packagedManifest.version === expectedVersion, "package manifest version mismatch");
    assert(
      root.createCoreaxGuard === guardModule.createCoreaxGuard,
      "root guard export does not match the guard subpath",
    );
    mark("public-entrypoints");

    const nativePolicy = policy.parsePolicyYaml([
      "version: 1",
      "tools:",
      "  allow:",
      "    - records.read@1.0",
      "  requirePinnedVersions: true",
      "enforcement:",
      "  denyOn:",
      "    - tool_not_in_allowlist",
      "    - version_unpinned",
    ].join("\\n"));
    assert(policy.validatePolicy(nativePolicy).valid, "native policy validation failed");
    assert(
      policy.matchesAllowlist(nativePolicy.tools.allow, "records.read@1.0"),
      "native policy allowlist failed",
    );
    mark("policy");

    const signer = signerModule.Ed25519Signer.fromSeed(
      new Uint8Array(32).fill(7),
    );
    const signedBytes = Buffer.from("coreax-consumer-smoke", "utf8");
    const signature = signer.sign(signedBytes);
    assert(signer.verify(signedBytes, signature), "Ed25519 signer round trip failed");
    mark("signer");

    const evaluatorOutput = evaluator.evaluateContextualInputLocal({
      action: {
        kind: "resource_read",
        operation: "read",
        summary: "Read a local record.",
        sideEffect: false,
        disclosure: false,
        crossesBoundary: false,
        target: {
          id: "record-1",
          type: "record",
          boundary: "local",
          classification: "internal",
        },
      },
      actor: {
        id: "agent-1",
        type: "agent",
        role: "support",
        boundary: "local",
      },
      purpose: {
        summary: "Answer a record lookup.",
        objective: "Read without mutation.",
        justification: "The caller requested this exact local read.",
      },
      authority: {
        grantedScopes: ["read"],
        allowedBoundaries: ["local"],
        approvals: [],
        delegations: [],
      },
      runtimeContext: {
        runId: "run-1",
        workflowState: {},
        conversationState: {},
        unresolvedPrerequisites: [],
      },
      sourceUse: { sources: [] },
      constraints: {
        hard: [],
        soft: [],
        requiredPrerequisites: [],
        requiredApprovals: [],
        forbiddenBoundaries: [],
        maxClassification: "internal",
      },
    });
    assert(evaluatorOutput.decision === "allow", "local evaluator smoke failed");
    mark("evaluator");

    const runtimeDecision = await runtimeAdapter.createRuntimeAdapter().evaluate({
      context: {
        integrationSurface: "coreax",
        executionLayer: "custom-agent",
        server: "smoke",
        tool: "records.read@1.0",
      },
      enforcement: {
        mode: "enforce",
        strategy: "deny_on_match",
        denyOn: ["blocked"],
      },
      input: { reasons: [] },
    });
    assert(runtimeDecision.decision === "allow", "runtime adapter smoke failed");
    mark("runtime-adapter");

    const guardPolicy = {
      defaultOutcome: "block",
      rules: [
        {
          id: "allow-smoke-read",
          kind: "tool_call",
          target: "records.read@1.0",
          outcome: "allow",
        },
      ],
    };
    const guard = guardModule.createCoreaxGuard({
      mode: "enforce",
      provider: { local: { policy: guardPolicy } },
    });
    const guarded = await guard.execute(
      {
        kind: "tool_call",
        target: "records.read@1.0",
        content: { id: "record-1" },
      },
      (input) => input.content.id,
    );
    assert(guarded.value === "record-1", "guarded execution smoke failed");
    mark("guard");

    const agent = customAgent.createCustomAgentAdapter({ guard });
    const agentResult = await agent.executeTool(
      {
        name: "records.read@1.0",
        arguments: { id: "record-2" },
      },
      (arguments_) => arguments_.id,
    );
    assert(agentResult.value === "record-2", "custom-agent smoke failed");
    mark("custom-agent");

    const auditDirectory = path.join(stateRoot, "audit");
    const appender = new audit.CoreaxAppender({
      config: { directory: auditDirectory },
      signer,
    });
    appender.initialize();
    await appender.append({
      ts: "2026-01-01T00:00:00.000Z",
      trace_id: "trace-smoke",
      span_id: "span-smoke",
      namespace: "consumer",
      server: "smoke@1.0.0",
      tool: "records.read@1.0",
      status: "ok",
      latency_ms: 1,
      retries: 0,
      input_sha256: signerModule.sha256Hex("input"),
      output_sha256: signerModule.sha256Hex("output"),
      policy: { decision: "allow" },
      idempotency_key: null,
    });
    await appender.flush();
    const auditVerification = await audit.verifyAuditLog(
      path.join(auditDirectory, "audit-2026-01-01.ndjson"),
      new Map([[signer.keyId, signer]]),
    );
    assert(auditVerification.valid, "audit append/verification smoke failed");
    mark("audit");

    let escalationId = 0;
    const escalationManager = escalation.createLocalEscalationManager({
      now: () => fixedTime,
      idFactory: () => "escalation-" + ++escalationId,
    });
    await escalationManager.initialize();
    const pending = await escalationManager.create({
      id: "escalation-smoke",
      action: "records.publish",
      scope: { recordId: "record-1" },
      reason: "approval required",
      ttlMs: 60_000,
    });
    const approved = await escalationManager.resolve({
      escalationId: pending.request.id,
      resolutionId: "approval-smoke",
      decision: "approve",
      resolvedBy: "local-reviewer",
    });
    const approvalKeys = generateKeyPairSync("ed25519");
    const capability = escalation.issueApprovalCapability({
      state: approved,
      privateKey: approvalKeys.privateKey,
      nonce: "consumer-smoke-nonce",
      ttlMs: 30_000,
      now: () => fixedTime,
    });
    const capabilityVerification = await escalation.verifyApprovalCapability({
      token: capability,
      expected: {
        escalationId: pending.request.id,
        approvalId: approved.resolution.id,
        action: pending.request.action,
        scope: pending.request.scope,
      },
      nonceStore: new escalation.MemoryApprovalNonceStore(
        () => fixedTime + 1,
      ),
      publicKey: approvalKeys.publicKey,
      now: () => fixedTime + 1,
    });
    assert(capabilityVerification.valid, "approval capability smoke failed");
    let signedGuardId = 0;
    const signedGuardManager = escalation.createLocalEscalationManager({
      now: () => fixedTime,
      idFactory: () => "signed-guard-" + ++signedGuardId,
      resolver: {
        getResolution(request) {
          return {
            id: "signed-guard-resolution",
            escalationId: request.id,
            decision: "approve",
            resolvedBy: "consumer-smoke",
            resolvedAt: new Date(fixedTime).toISOString(),
          };
        },
      },
    });
    const signedGuard = guardModule.createCoreaxGuard({
      now: () => fixedTime,
      provider: {
        local: {
          policy: {
            defaultOutcome: "block",
            rules: [
              {
                kind: "tool_call",
                target: "records.publish@1.0",
                outcome: "escalate",
              },
            ],
          },
        },
      },
      escalation: {
        enabled: true,
        manager: signedGuardManager,
        approvalCapability: {
          publicKey: approvalKeys.publicKey,
          nonceStore: new escalation.MemoryApprovalNonceStore(
            () => fixedTime,
          ),
          getCapability({ resolution }) {
            return escalation.issueApprovalCapability({
              state: resolution,
              privateKey: approvalKeys.privateKey,
              nonce: "consumer-guard-capability",
              now: () => fixedTime,
            });
          },
        },
      },
    });
    const signedGuardResult = await signedGuard.execute(
      {
        kind: "tool_call",
        target: "records.publish@1.0",
        content: { recordId: "record-1" },
      },
      () => "published",
    );
    assert(
      signedGuardResult.value === "published",
      "signed guard approval smoke failed",
    );
    mark("escalation");

    let governanceId = 0;
    const governanceClient = new governance.LocalGovernanceClient({
      rootDir: path.join(stateRoot, "governance"),
      now: () => fixedTime,
      idFactory: () => "governance-" + ++governanceId,
    });
    await governanceClient.initialize();
    const governanceResult = await governanceClient.submitSubmission({
      submission: {
        submission_id: "submission-smoke",
        namespace: "consumer",
        workflow_id: "workflow-smoke",
        node_id: "node-smoke",
        run_id: "run-smoke",
        event_kind: "selected_action",
        actor: { actor_id: "agent-smoke", actor_type: "agent" },
        target: {
          action_type: "tool_call",
          action_name: "read_record",
          side_effect: false,
        },
        authority: {},
        payload: { record_id: "record-1" },
        state_slice: {},
        provenance: {},
        metadata: {},
        created_at: "2026-01-01T00:00:00.000Z",
      },
    });
    assert(governanceResult.allow_execution, "local governance smoke failed");
    mark("governance");

    const risk = runtimeRisk.assessRunRisk({
      runId: "risk-run",
      events: [
        {
          id: "risk-event-1",
          timestamp: "2026-01-01T00:00:00.000Z",
          runId: "risk-run",
          nodeId: "node-smoke",
          tool: "records.read@1.0",
          decision: "allow",
        },
      ],
    });
    assert(risk.runId === "risk-run" && risk.eventCount === 1, "runtime-risk smoke failed");
    mark("runtime-risk");

    const learningEngine = new policyLearning.AdaptivePolicyEngine({
      initialVersion: "policy-v1",
      initialCreatedAt: "2026-01-01T00:00:00.000Z",
      initialPolicy: {
        permissions: [
          {
            id: "read-records",
            actions: ["read"],
            resources: ["records"],
          },
        ],
        denyRules: [
          {
            id: "deny-delete",
            actions: ["delete"],
            resources: ["records"],
            required: true,
          },
        ],
      },
      clock: () => new Date(fixedTime),
    });
    assert(
      learningEngine.getActiveVersion().version === "policy-v1",
      "policy-learning smoke failed",
    );
    mark("policy-learning");

    const instrumentationEvents = [];
    instrumentation.initCoreax({
      stateRoot: path.join(stateRoot, "instrumentation"),
      nodes: {
        "smoke-tool": { kind: "tool", name: "Smoke tool" },
      },
      onEvent: (event) => instrumentationEvents.push(event),
      clock: (() => {
        let now = fixedTime;
        return () => now++;
      })(),
      idGenerator: (kind) => kind + "-smoke",
    });
    const wrappedTool = instrumentation.wrapCoreaxTool(
      (value) => value + 1,
      { key: "smoke-tool" },
    );
    assert(wrappedTool(1) === 2, "instrumentation wrapper smoke failed");
    assert(instrumentationEvents.length === 2, "instrumentation events were not emitted");
    mark("instrumentation");

    const toolHandlers = new Map([
      ["records.read@1.0", async (invocation) => invocation.args.id],
    ]);
    const server = {
      name: "smoke-server",
      version: "1.0.0",
      tool(name, handler) {
        toolHandlers.set(name, handler);
      },
      __getTools() {
        return toolHandlers;
      },
      __setTool(name, handler) {
        toolHandlers.set(name, handler);
      },
    };
    const auditRows = [];
    assert(
      middleware.coreaxLocalMiddleware === middleware.coreaxSecurityMiddleware,
      "local middleware export does not match the security middleware",
    );
    const controller = middleware.coreaxSecurityMiddleware({
      policy: {
        defaultOutcome: "block",
        rules: [
          {
            kind: "tool_call",
            target: "smoke-server/records.read@1.0",
            outcome: "allow",
          },
        ],
      },
      signer,
      adapters: {
        auditSink: {
          initialize() {},
          async append(row) {
            auditRows.push(row);
          },
          async flush() {},
        },
      },
    })(server);
    const middlewareResult = await toolHandlers.get("records.read@1.0")({
      args: { id: "record-3" },
      headers: {
        "x-trace-id": "trace-smoke",
        "x-span-id": "span-smoke",
      },
    });
    await controller.flush();
    assert(middlewareResult === "record-3", "middleware execution smoke failed");
    assert(auditRows.length === 1, "middleware audit smoke failed");
    mark("middleware");

    assert(
      Reflect.ownKeys(process.env).length === 0,
      "SDK mutated the empty consumer environment",
    );
    assert(completed.length === 14, "primary API smoke matrix is incomplete");
    process.stdout.write(
      "CoreAX consumer smoke passed (" + completed.join(", ") + ").\\n",
    );
  } finally {
    fs.rmSync(stateRoot, { recursive: true, force: true });
  }
})().catch((error) => {
  console.error(error && error.stack ? error.stack : error);
  process.exitCode = 1;
});
`;
}

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "coreax-consumer-"));
try {
  const npmCli = process.env.npm_execpath;
  if (!npmCli) throw new Error("npm_execpath is unavailable");
  const packageJson = JSON.parse(fs.readFileSync("package.json", "utf8"));
  const packOutput = run(process.execPath, [
    npmCli,
    "pack",
    "--json",
    "--ignore-scripts",
    "--pack-destination",
    temporary,
  ]);
  const tarballName = JSON.parse(packOutput)[0].filename;
  const consumer = path.join(temporary, "consumer");
  fs.mkdirSync(consumer);
  fs.writeFileSync(
    path.join(consumer, "package.json"),
    JSON.stringify({ name: "coreax-empty-consumer", private: true }),
  );
  run(
    process.execPath,
    [
      npmCli,
      "install",
      path.join(temporary, tarballName),
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
    ],
    { cwd: consumer },
  );

  const specifiers = Object.keys(packageJson.exports).map((subpath) =>
    subpath === "."
      ? packageJson.name
      : `${packageJson.name}/${subpath.slice(2)}`,
  );
  const probePath = path.join(consumer, "smoke.cjs");
  fs.writeFileSync(
    probePath,
    consumerProbeSource(packageJson, specifiers),
    "utf8",
  );
  const smokeOutput = runIsolatedNode(probePath, consumer).trim();
  for (const statePath of [".coreax", ".coreax-smoke-state"]) {
    if (fs.existsSync(path.join(consumer, statePath))) {
      throw new Error(`Consumer smoke left local state behind: ${statePath}`);
    }
  }
  console.log(
    `Empty consumer imported ${specifiers.length} public entrypoints and executed the primary API matrix with no environment variables or network access.`,
  );
  if (smokeOutput) console.log(smokeOutput);
} finally {
  fs.rmSync(temporary, { recursive: true, force: true });
}
