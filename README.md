<p align="center">
  <img src="https://raw.githubusercontent.com/teluashish0/coreax-sdk/main/public/coreax-logo-adaptive.svg" alt="CoreAX logo" width="70">
</p>

<h1 align="center">CoreAX</h1>

<h3 align="center"><strong>Open-source Runtime Assurance SDK for any AI agent in production.</strong></h3>
<p align="center"><em></em></p>
<p align="center"><em>The safest way to monitor, enforce context-aware guardrails, and improve your AI agents as conditions change.</em></p>

<p align="center">
  <a href="https://www.npmjs.com/package/@coreax/sdk"><img src="https://img.shields.io/npm/v/%40coreax%2Fsdk" alt="npm version"></a>
  <a href="https://www.npmjs.com/package/@coreax/sdk"><img src="https://img.shields.io/npm/dm/%40coreax%2Fsdk" alt="npm downloads"></a>
  <a href="https://github.com/teluashish0/coreax-sdk/blob/main/LICENSE"><img src="https://img.shields.io/github/license/teluashish0/coreax-sdk" alt="license"></a>
</p>

<p align="center">
  <a href="https://github.com/teluashish0/coreax-sdk">Repository</a> •
  <a href="#implementation-flows">Implementation flows</a> •
  <a href="#modules">Modules</a> •
  <a href="#security-guarantees">Security guarantees</a>
</p>

---

<p align="center">
  <img width="600" alt="Context-aware, self-correcting security boundary for AI agents as they evolve" src="./public/coreax-image.png" />
</p>

---

## What is CoreAX?

CoreAX, or Core Agent Experience, is an open-source SDK for governing AI
workflows with context-aware guardrails that evolve alongside your agents. It
provides local primitives to capture and curate high-quality trajectory data
from orchestrator decisions, agent actions, tool calls, policy outcomes, and
human-in-the-loop interventions to support safe, continuous agent improvement.

Models change, prompts evolve, tools are added, and attack techniques adapt.
CoreAX provides a self-correcting security boundary that observes behavior,
enforces deterministic constraints before side effects, preserves verifiable
evidence, and proposes constrained improvements without granting itself new
permissions.

The SDK is standalone and offline-capable. It evaluates untrusted AI and agent
actions before caller-owned code executes them, and every external integration
remains explicit and caller-controlled.

CoreAX requires Node.js 20 or newer.

## Installation

```sh
npm install @coreax/sdk
```

Each module can be imported through its documented package subpath.

## What you can build

| Goal | Start with | Result |
| --- | --- | --- |
| Guard an application-owned tool, API, or message side effect | `@coreax/sdk/guard` | Deterministic allow, redact, block, or escalation before execution |
| Integrate an agent framework without a framework dependency | `@coreax/sdk/integrations/custom-agent` | Tool and outbound-message proposals normalized through one guard |
| Review evidence-rich context | `@coreax/sdk/evaluator` | Local reasoning over authority, boundaries, missing facts, contradictions, retries, and recovery |
| Secure a compatible tool-server registry | `@coreax/sdk/middleware` | Existing and late-registered tools wrapped with enforcement and signed audit evidence |
| Require a human decision for a sensitive action | `@coreax/sdk/escalation` | Scoped, expiring, signed, single-use approval capabilities |
| Capture and assess execution trajectories | `@coreax/sdk/instrumentation`, `@coreax/sdk/governance`, and `@coreax/sdk/runtime-risk` | Local events, governed records, drift signals, state-propagation findings, and exposure risk |
| Improve policy without silent permission growth | `@coreax/sdk/policy-learning` | Shadow proposals followed by explicit signed promotion or rollback |

## Architecture

CoreAX sits between an untrusted proposal and the code that can cause a side
effect:

1. An agent proposes a tool call, API call, or outbound message.
2. A guard, middleware function, or runtime adapter evaluates it against an
   explicit policy.
3. Deterministic rules allow, redact, block, or require approval.
4. Caller-owned code performs an allowed action.
5. The caller can record the result with audit or governance and assess
   normalized events with runtime risk.
6. Policy learning can produce a constrained proposal; the caller explicitly
   decides whether and how to apply a signed promotion.

The evaluator can combine evidence, graph context, retries, recovery,
contradictions, and orchestration state. A caller-supplied semantic calibrator
is advisory: it cannot override a deterministic hard deny or approval
requirement.

The modules are deliberately composable rather than implicitly connected. This
keeps the trusted execution harness, storage, key custody, and any external
transport under application control.

## Implementation flows

### 1. Guard a model-proposed action

Create an enforcing guard with an explicit policy and place the side effect
inside `execute`. CoreAX snapshots the proposal and calls the callback only
after the action is allowed, redacted, or covered by a verified approval.

```ts
import { createCoreaxGuard } from "@coreax/sdk/guard";
import type { CoreaxPolicy } from "@coreax/sdk/policy";

const policy: CoreaxPolicy = {
  version: 1,
  tools: {
    allow: ["records.read@1.0"],
    requirePinnedVersions: true,
  },
  enforcement: {
    denyOn: [
      "tool_not_in_allowlist",
      "version_unpinned",
      "agent_guard_failed",
    ],
  },
  agentGuard: {
    enabled: true,
    blockOnSeverity: "high",
  },
};

const guard = createCoreaxGuard({
  mode: "enforce",
  provider: { local: { policy } },
});

const records = new Map([
  ["42", { id: "42", status: "open" }],
]);

const result = await guard.execute(
  {
    kind: "tool_call",
    target: "records.read@1.0",
    content: { id: "42" },
    context: { runId: "run-001", nodeId: "support-agent" },
  },
  async (guardedInput) => {
    const { id } = guardedInput.content as { id: string };
    return records.get(id) ?? null;
  },
);

console.log(result.decision.outcome, result.value);
```

A blocked action throws `GuardBlockedError` before the callback unless the
caller deliberately supplies an `onBlock` fallback. Do not call `check()` and
then execute the original mutable proposal later. Use `execute()` to keep the
decision and action in one guarded execution path.

`mode: "observe"` records what the policy would decide but still runs the
callback, including for blocked or escalated proposals. Use `mode: "enforce"`
for a security boundary.

Policies may also be loaded from an explicit JSON or YAML `policyPath`. CoreAX
does not discover configuration or read environment variables.

### 2. Integrate any agent framework

The custom-agent adapter is framework-neutral. It maps tool calls and outbound
messages into guard inputs while execution, transport, and agent state remain
owned by the application.

```ts
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { createCoreaxGuard } from "@coreax/sdk/guard";
import { createCustomAgentAdapter } from "@coreax/sdk/integrations/custom-agent";

const allowedRoot = resolve("./agent-data");

const guard = createCoreaxGuard({
  mode: "enforce",
  provider: {
    local: {
      policy: {
        version: 1,
        tools: {
          allow: ["files.read@1.0"],
          requirePinnedVersions: true,
        },
        enforcement: {
          denyOn: [
            "tool_not_in_allowlist",
            "version_unpinned",
            "fs_violation",
          ],
        },
        security: {
          filesystemAllowlist: [allowedRoot],
        },
      },
    },
  },
});

const agent = createCustomAgentAdapter({
  guard,
  extractToolFilesystemPaths({ arguments: input }) {
    return [(input as { path: string }).path];
  },
});

const toolResult = await agent.executeTool(
  {
    name: "files.read@1.0",
    arguments: { path: join(allowedRoot, "record.json") },
    context: { agentId: "support-agent", sessionId: "session-001" },
  },
  ({ path }) => readFile(path, "utf8"),
);

console.log(toolResult.decision.outcome, toolResult.value);
```

`extractToolFilesystemPaths` is part of the trusted harness. It receives a
structured-cloned snapshot containing the tool name, resolved target, and
arguments. Never copy model-authored metadata directly into
`context.filesystemPaths`.

Filesystem allowlisting validates the proposal at decision time; it cannot
eliminate the executor's check/use race. Keep allowlisted roots outside
untrusted write control, and safely open or revalidate paths inside the executor
when race resistance is required.

Outbound messages use the same boundary:

```ts
const messageGuard = createCoreaxGuard({
  mode: "enforce",
  provider: {
    local: {
      policy: {
        defaultOutcome: "block",
        rules: [
          {
            kind: "message_outbound",
            target: "customer",
            outcome: "allow",
          },
        ],
      },
    },
  },
});
const messagingAgent = createCustomAgentAdapter({ guard: messageGuard });

const messageResult = await messagingAgent.sendOutboundMessage(
  {
    target: "customer",
    message: "Your request is complete.",
    context: { runId: "run-001" },
  },
  (message) => sendMessage(message),
);

console.log(messageResult.decision.outcome);
```

This target-specific policy must explicitly permit or redact the corresponding
`message_outbound` action before the callback can run.

### 3. Review context before a side effect

Use the local contextual evaluator when a decision depends on more than a
target allowlist. Its input describes the proposed action, purpose, authority,
runtime state, evidence, and constraints.

```ts
import {
  EvaluatorInputSchema,
  evaluateContextualInputLocal,
} from "@coreax/sdk/evaluator";

const input = EvaluatorInputSchema.parse({
  action: {
    kind: "external_send",
    operation: "send",
    summary: "Send the approved delivery update to the carrier.",
    sideEffect: true,
    crossesBoundary: true,
    target: {
      boundary: "carrier",
      classification: "internal",
    },
  },
  actor: {
    id: "support-agent",
    type: "agent",
    boundary: "local",
  },
  purpose: {
    summary: "Notify the carrier of the requested delivery update.",
    justification: "The user approved this exact update.",
  },
  authority: {
    grantedScopes: ["write", "cross_boundary"],
    allowedBoundaries: ["carrier"],
    approvals: [],
    delegations: [],
  },
  runtimeContext: {
    runId: "run-001",
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

const evaluation = evaluateContextualInputLocal(input);

console.log({
  decision: evaluation.decision,
  principles: evaluation.principles,
  missingFacts: evaluation.missingFacts,
});
```

This example escalates because the action crosses a boundary and causes a side
effect. The evaluator returns a decision; it does not execute or independently
enforce the action. To use it in middleware, provide the `EvaluatorInput`
through `contextualEvaluator.buildInput`; elsewhere, explicitly map the output
into the application's guard or governance contract and enforce it before the
side effect. An optional caller-supplied semantic calibrator can make evaluation
more conservative, but cannot weaken a deterministic deny or approval
requirement.

### 4. Wrap a tool server and verify its audit log

The middleware wraps a compatible tool registry, applies the same guard
semantics to existing and late registrations, and appends one signed audit row
with input and output digests per completed invocation.

```ts
import {
  coreaxSecurityMiddleware,
  type McpServerLike,
  type ToolHandler,
} from "@coreax/sdk/middleware";
import { verifyAuditLog } from "@coreax/sdk/audit";
import { Ed25519Signer } from "@coreax/sdk/signer";

const tools = new Map<string, ToolHandler>();
const server: McpServerLike = {
  name: "records",
  version: "1.0.0",
  tool(name, handler) {
    tools.set(name, handler);
  },
  __getTools() {
    return tools;
  },
  __setTool(name, handler) {
    tools.set(name, handler);
  },
};

const signer = Ed25519Signer.fromFile("./.coreax/keys/audit.seed", {
  allowedDirectories: ["./.coreax/keys"],
});
const now = Date.now();

const controller = coreaxSecurityMiddleware({
  signer,
  coreax: { directory: "./.coreax/audit" },
  namespace: "support",
  now: () => now,
  policy: {
    version: 1,
    tools: {
      allow: ["mcp://records/read@1.0"],
      requirePinnedVersions: true,
    },
    enforcement: {
      denyOn: ["tool_not_in_allowlist", "version_unpinned"],
    },
  },
})(server);

server.tool("read@1.0", async ({ args }) => {
  const { id } = args as { id: string };
  return { id, status: "open" };
});

const handler = server.__getTools?.().get("read@1.0");
if (!handler) throw new Error("read tool was not registered");

const output = await handler({ args: { id: "42" } });
await controller.flush();

const day = new Date(now).toISOString().slice(0, 10);
const verification = await verifyAuditLog(
  `./.coreax/audit/audit-${day}.ndjson`,
  new Map([[signer.keyId, signer]]),
);

if (!verification.valid) {
  throw new Error(`Audit verification failed: ${verification.reason}`);
}

console.log(output);
```

The server must implement both `__getTools()` and `__setTool()`. Middleware
policy entries use `mcp://<server-name>/<tool@version>`. Applying the middleware
initializes its owned audit sink and performs no implicit network request.

Provision `audit.seed` before startup as a stable base64-encoded 32-byte
Ed25519 seed or 64-byte secret key. Keep it in a private, non-symlink regular
file outside untrusted agent control. Reuse the same signing identity to retain
one verifiable daily chain.

For an application-owned execution path, use `CoreaxAppender` directly:
construct it with an explicit directory and signer, call `initialize()`, append
hashes rather than raw sensitive payloads, then `flush()` and verify the log.

### 5. Require a signed human approval

Treat review and execution as separate trust domains. The private approval key
belongs only in the trusted reviewer path; the agent or execution process gets
the public key and the returned capability.

In the trusted reviewer process, resolve the pending request and issue a short
lived capability bound to that exact approval, action, scope, and nonce:

```ts
import { randomUUID } from "node:crypto";
import { issueApprovalCapability } from "@coreax/sdk/escalation";

const approvedState = await reviewerManager.resolve({
  escalationId,
  decision: "approve",
  resolvedBy: "security-reviewer",
});

const capability = issueApprovalCapability({
  state: approvedState,
  privateKey: reviewerPrivateKey,
  nonce: randomUUID(),
  ttlMs: 5 * 60_000,
});

await approvalTokenOutbox.put(approvedState.request.id, capability);
```

`reviewerManager`, `reviewerPrivateKey`, and `approvalTokenOutbox` are
application-owned components in the trusted review path.

In the execution process, configure durable pending state and replay
protection, then retrieve the returned token without exposing the private key:

```ts
import { createCoreaxGuard } from "@coreax/sdk/guard";
import {
  createLocalEscalationManager,
  FileApprovalNonceStore,
  FileEscalationStore,
} from "@coreax/sdk/escalation";

const escalationRoot = "./.coreax/escalation";
const manager = createLocalEscalationManager({
  store: new FileEscalationStore({ rootDir: escalationRoot }),
});
const nonceStore = new FileApprovalNonceStore({
  rootDir: `${escalationRoot}/consumed-nonces`,
});

await manager.initialize();
await nonceStore.initialize();

const guard = createCoreaxGuard({
  mode: "enforce",
  provider: {
    local: {
      policy: {
        defaultOutcome: "block",
        rules: [
          {
            kind: "tool_call",
            target: "records.publish@1.0",
            outcome: "escalate",
            reason: "human_approval_required",
          },
        ],
      },
    },
  },
  escalation: {
    enabled: true,
    waitForResolutionByDefault: true,
    manager,
    approvalCapability: {
      publicKey: reviewerPublicKey,
      nonceStore,
      getCapability: ({ resolution }) =>
        approvalTokenInbox.take(resolution.request.id),
    },
  },
});

const result = await guard.execute(
  {
    kind: "tool_call",
    target: "records.publish@1.0",
    content: { recordId: "42" },
  },
  () => publishRecord("42"),
);

console.log(result.value);
```

`reviewerPublicKey` and `approvalTokenInbox` are application-owned inputs to the
trusted execution harness. Missing, rejected, expired, replayed, incorrectly
scoped, or wrongly signed capabilities block before `publishRecord` runs. An
approved resolver result by itself is not enough.

### 6. Record a local execution trajectory

Use instrumentation for lightweight start, success, and error events around
nested agent, orchestrator, server, tool, or skill calls:

```ts
import {
  initCoreax,
  seedCoreaxRun,
  wrapCoreaxAgent,
  wrapCoreaxTool,
  type CoreaxInstrumentationEvent,
} from "@coreax/sdk/instrumentation";

const events: CoreaxInstrumentationEvent[] = [];

initCoreax({
  stateRoot: "./.coreax",
  application: {
    name: "support-agent",
    version: "1.0.0",
    environment: "production",
  },
  onEvent(event) {
    events.push(event);
  },
});

const readRecord = wrapCoreaxTool(
  async (id: string) => ({ id, status: "open" }),
  {
    key: "records.read",
    nodeId: "records-read",
    name: "Read record",
  },
);

const answerQuestion = wrapCoreaxAgent(
  async (id: string) => {
    const record = await readRecord(id);
    return `Record ${record.id} is ${record.status}.`;
  },
  {
    key: "support.answer",
    nodeId: "support-agent",
    name: "Support agent",
  },
);

const answer = await seedCoreaxRun(
  "run-001",
  () => answerQuestion("42"),
  { traceId: "trace-001", spanId: "root-span" },
);

console.log(answer, events.map((event) => event.phase));
```

Instrumentation carries async run context but is not an enforcement boundary.
It does not capture arguments or results, and hashes error messages before
emitting them.

Use governance when the trajectory also needs a persisted decision, execution
record, reflection, and outcome:

```ts
import {
  executeGovernedAction,
  LocalGovernanceClient,
  normalizeGovernanceSubmission,
} from "@coreax/sdk/governance";

const governance = new LocalGovernanceClient({
  rootDir: "./.coreax/governance",
});
await governance.initialize();

const submission = normalizeGovernanceSubmission({
  namespace: "support",
  workflow_id: "record-lookup",
  node_id: "records-agent",
  run_id: "run-001",
  event_kind: "selected_action",
  actor: {
    actor_id: "support-agent",
    actor_type: "agent",
  },
  target: {
    action_type: "tool_call",
    action_name: "records.read",
    side_effect: false,
  },
  authority: {},
  payload: { record_id: "42" },
  provenance: {},
  metadata: {},
});

const execution = await executeGovernedAction({
  client: governance,
  submission,
  execute: async (payload) => ({
    id: String(payload.record_id),
    status: "open",
  }),
  summarizeResult: () => ({
    status: "succeeded",
    result_summary: "Record lookup completed.",
  }),
});

await governance.reportReflection({
  submission_id: submission.submission_id,
  run_id: submission.run_id,
  workflow_id: submission.workflow_id,
  node_id: submission.node_id,
  actor: submission.actor,
  status: "completed",
  provenance: {},
  created_at: new Date().toISOString(),
});

await governance.reportOutcome({
  submission_id: submission.submission_id,
  run_id: submission.run_id,
  workflow_id: submission.workflow_id,
  task_success: execution.execution_record.executed,
  outcome_success: execution.execution_record.executed,
  created_at: new Date().toISOString(),
});
```

A side effect without sufficient authority becomes pending review and its
execution callback is not called. File governance persists hash-only
projections of payloads, result text, and errors.

### 7. Assess behavior, path, state, and exposure risk

`assessRunRisk` is a pure deterministic function over caller-normalized events.
The following run propagates a sensitive state key across nodes and records an
egress exposure:

```ts
import {
  assessRunRisk,
  type RuntimeRiskEvent,
} from "@coreax/sdk/runtime-risk";

const sessionToken = "example-only-token";
const events: RuntimeRiskEvent[] = [
  {
    id: "event-001",
    timestamp: "2026-07-30T10:00:00.000Z",
    runId: "run-001",
    nodeId: "planner",
    tool: "records.read@1.0",
    operation: "read",
    decision: "allow",
    state: {
      AGENT: { sessionToken },
    },
  },
  {
    id: "event-002",
    timestamp: "2026-07-30T10:00:01.000Z",
    runId: "run-001",
    nodeId: "sender",
    tool: "messages.send@1.0",
    operation: "send",
    decision: "allow",
    state: {
      AGENT: { sessionToken },
    },
    exposures: [
      {
        sink: "egress",
        detector: "rule",
        classification: "secret",
        severity: "high",
        ruleId: "secret-egress",
      },
    ],
  },
];

const assessment = assessRunRisk({
  runId: "run-001",
  events,
  sensitiveStateRules: [
    { scope: "AGENT", key: "sessionToken", maxHops: 1 },
  ],
});

console.log({
  score: assessment.overallScore,
  signals: assessment.signals.map(({ code, severity }) => ({
    code,
    severity,
  })),
});
```

Pass prior complete runs through `baselineEvents` to enable behavior and
golden-path drift. An insufficient baseline reports itself as unready rather
than treating missing history as drift. Evidence contains hashes and
classifications instead of raw sensitive values.

Instrumentation events are not automatically runtime-risk events. The
application maps and enriches them with trusted tool, decision, state,
exposure, and mandate information, then decides how the resulting score affects
later runs.

### 8. Learn in shadow mode and promote explicitly

The learning engine ranks constrained candidate policies. It defaults to
shadow mode, so producing a proposal never changes the active policy.

```ts
import { generateKeyPairSync, randomUUID } from "node:crypto";
import {
  AdaptivePolicyEngine,
  signPolicyOperationAuthorization,
  type PolicyCandidate,
  type PolicyDocument,
  type PolicyLearningState,
} from "@coreax/sdk/policy-learning";

const initialPolicy: PolicyDocument = {
  permissions: [
    {
      id: "read-orders",
      actions: ["read"],
      resources: ["orders"],
    },
  ],
  denyRules: [
    {
      id: "deny-sensitive-export",
      actions: ["export"],
      resources: ["sensitive-records"],
      required: true,
    },
  ],
};

const tightenedPolicy: PolicyDocument = {
  ...initialPolicy,
  denyRules: [
    ...initialPolicy.denyRules,
    {
      id: "deny-unreviewed-write",
      actions: ["write"],
      resources: ["orders"],
    },
  ],
};

const operatorKeys = generateKeyPairSync("ed25519");
const engine = new AdaptivePolicyEngine<string, PolicyDocument>({
  initialPolicy,
  initialVersion: "policy-v1",
  mode: "shadow",
  constraints: {
    requiredDenyRuleIds: ["deny-sensitive-export"],
  },
  trustedPublicKeys: {
    "operator-key": operatorKeys.publicKey,
  },
});

const state: PolicyLearningState = {
  key: "high-risk-write",
  features: {
    risk_score: 0.85,
    repeated_failures: 2,
  },
  severity: "high",
  baseline: {
    incidentCount: 12,
    sensitiveIncidentCount: 3,
    falsePositiveRatePct: 8,
    latencyMs: 100,
  },
};

engine.train({
  modelVersion: "model-v1",
  observations: [
    {
      id: "outcome-run-000",
      state,
      actionKey: "tighten",
      rewardComponents: {
        incident_reduction: 0.7,
        sensitive_exposure_prevention: 0.8,
        false_positive_reduction: 0,
        latency_reduction: -0.05,
        human_acceptance: 0.5,
        evaluator_score: 0.8,
      },
    },
  ],
});

const candidates: PolicyCandidate<string, PolicyDocument>[] = [
  {
    key: "tighten",
    action: "add-deny",
    targetPolicy: tightenedPolicy,
    simulation: {
      incidentMultiplier: 0.5,
      sensitiveIncidentMultiplier: 0.2,
      latencyMultiplier: 1.05,
      evaluatorScore0to100: 90,
    },
  },
];

const { proposal } = engine.propose({
  state,
  candidates,
  idempotencyKey: "run-001",
});

if (!proposal) throw new Error("No safe policy proposal was produced");
console.log(proposal.status); // "shadow"; policy-v1 is still active
```

Promotion requires a short-lived authorization signed by a trusted operator:

```ts
const issuedAt = new Date();
const expiresAt = new Date(issuedAt.getTime() + 5 * 60_000);

const authorization = signPolicyOperationAuthorization({
  authorization: {
    format: "coreax_policy_operation_v1",
    operation: "promote",
    subject: proposal.proposalId,
    targetVersion: "policy-v2",
    policyDigest: proposal.targetDigest,
    expectedActiveVersion: proposal.baseVersion,
    nonce: randomUUID(),
    keyId: "operator-key",
    issuedAt: issuedAt.toISOString(),
    expiresAt: expiresAt.toISOString(),
  },
  privateKey: operatorKeys.privateKey,
});

const promoted = engine.promote({
  proposalId: proposal.proposalId,
  version: "policy-v2",
  authorization,
});

console.log(promoted.version);
```

Generated keys keep the example self-contained. In production, keep operator
private keys outside the SDK's writable state and untrusted execution process.
The default policy-learning store is in memory; inject an
`AdaptivePolicyStore` when durable state is required.

The learning `PolicyDocument` is intentionally generic and is not the guard's
`CoreaxPolicy`. After a signed promotion, the application must explicitly map
the approved document into its enforcement policy. Proposals cannot silently
broaden permissions or remove mandatory denies.

## Composition rules

- Guard and custom-agent execution do not automatically write audit or
  governance records. Add the sink appropriate for the application.
- Middleware initializes and writes only its own audit sink.
- The contextual evaluator assesses a proposal but is not itself an execution
  boundary.
- Instrumentation events require caller mapping and enrichment before
  `assessRunRisk`.
- Runtime risk is deterministic and side-effect free; the application decides
  how a score changes later enforcement.
- Policy learning never directly mutates guard configuration. Mapping and
  activation remain explicit caller operations.

## Modules

| Import | Purpose |
| --- | --- |
| `@coreax/sdk` | Primary CoreAX exports |
| `@coreax/sdk/guard` | `createCoreaxGuard`, guard policies, and guarded execution |
| `@coreax/sdk/middleware` | Local security middleware and request metadata |
| `@coreax/sdk/evaluator` | Deterministic contextual evaluation |
| `@coreax/sdk/policy` | Policy parsing, validation, and allowlist matching |
| `@coreax/sdk/runtime-adapter` | Caller-configured runtime enforcement |
| `@coreax/sdk/audit` | Signed append-only audit logs and verification |
| `@coreax/sdk/signer` | Canonicalization, hashing, and keyed Ed25519 signing |
| `@coreax/sdk/escalation` | Memory/file review state and scoped approval capabilities |
| `@coreax/sdk/governance` | Local governance records, evidence compaction, and execution reporting |
| `@coreax/sdk/runtime-risk` | Deterministic behavior, path, state, exposure, and mandate risk |
| `@coreax/sdk/policy-learning` | Shadow learning, simulation, safety checks, promotion, and rollback |
| `@coreax/sdk/instrumentation` | CoreAX configuration, context, decorators, and wrappers |
| `@coreax/sdk/integrations/custom-agent` | Framework-neutral tool and message adapter |
| `@coreax/sdk/core` | Interfaces for caller-supplied policy, audit, and approval components |

## Local configuration and state

Configuration is supplied directly to each API. CoreAX does not search for
configuration, read environment variables, select endpoints, or make implicit
network requests. `./.coreax` is the conventional local state root, but every
file-backed path is configurable.

Importing a module creates no state:

| Component | State-creation boundary |
| --- | --- |
| Instrumentation | `initCoreax()` |
| `CoreaxAppender` | `appender.initialize()` |
| Tool middleware | Applying middleware to a compatible server initializes its owned audit sink |
| `LocalGovernanceClient` | `client.initialize()` |
| `FileEscalationStore` through a manager | `manager.initialize()` |
| `FileApprovalNonceStore` | `nonceStore.initialize()` |
| Policy learning | In-memory by default; caller-supplied store for persistence |

File-backed components use serialized, recovery-safe local writes. Keep audit,
approval, and policy signing keys outside any directory writable by an
untrusted agent.

Interfaces such as `PolicyProvider`, `RuntimeAdapter`, `AuditSink`,
`ApprovalProvider`, and `SemanticCalibrator` are available for integrations
owned and configured by the caller. CoreAX does not select an endpoint,
credential, transport, or storage service for them.

## Security guarantees

- No account, database, service credential, or implicit outbound request is
  required.
- Enforcement is deterministic and local unless the caller explicitly supplies
  an integration.
- Missing, expired, replayed, incorrectly scoped, or wrongly signed approval
  capabilities fail closed.
- Approval capabilities are keyed Ed25519 signatures with explicit action,
  scope, expiry, and nonce claims.
- Audit verification detects modified records, truncated logs, and unexpected
  signers relative to the signed local head.
- Detecting restoration of an entire older-but-valid state tree requires the
  caller to retain the latest signed head or policy version outside that
  writable state root.
- Learned policy changes remain proposals by default, and promotion is an
  explicit, signed operation.
- Default learning constraints reject permission expansion. Exact non-wildcard
  expansion requires an explicit `allowExactPermissionExpansion` opt-in and a
  signed promotion; wildcard expansion and mandatory-deny removal remain
  forbidden.
- Signed rollback may explicitly restore exact non-wildcard permissions from a
  prior version. Wildcard expansion and mandatory-deny removal remain forbidden.
- The application retains control of side effects and should place every
  untrusted action behind a CoreAX enforcement boundary.
