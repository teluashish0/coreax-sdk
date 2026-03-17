import { context, propagation, trace } from "@opentelemetry/api";
import type { PolicyObject } from "../policy";
import { sha256Hex } from "../signer";
import {
  extractAgentStateFromHeaders,
  mergeAgentVariables,
  ensureRunId,
  type AgentStatePayload,
  type AgentStateVariables,
} from "../agent-state";
import {
  verifyAp2MandatesFromHeaders,
  AP2_CART_DIGEST_HEADER,
  AP2_CONSTRAINTS_DIGEST_HEADER,
  compareArgsToDigest,
  type Ap2Config,
} from "../mandate-ap2";
import { DastManager, type DastFinding } from "./dast";
import { type AgentGuard, type AgentGuardFinding } from "./agentGuard";
import { dedupeFindings } from "./evaluatorUtils";
import { getSec0Meta } from "./meta";
import { runContextualEvaluation } from "./contextualEvaluatorFlow";
import { parseIdentityContextHeader } from "./identity";
import {
  buildAuditEnvelope,
  captureRawPayloads,
  stampResultTracing,
} from "./auditEnvelope";
import {
  deriveComplianceMetadata,
  deriveTraceContext,
  extractAuthObject,
} from "./auditMetadata";
import {
  annotateApprovedFindings,
  createDecisionFlow,
} from "./decisionFlow";
import { createEscalationFromState } from "./escalationAssembly";
import {
  createMiddlewareInvocationState,
} from "./invocationState";
import {
  appendRunEvent,
  buildRunContextText,
  buildRunEvent,
  ensureRunContextState,
  extractMetadata,
  extractObjective,
  type RunContextConfig,
} from "./runContext";
import {
  persistScanRawIfConfigured,
  type RawPayloadCaptureConfig,
  type UploadApiConfig,
} from "./rawPayloads";
import { createInvocationStats, createRegistryState } from "./registryState";
import { createScanPipeline } from "./scanPipeline";
import { SastManager, type SastFinding } from "./sast";
import { estimateSizeKb, withGuardedIO, type SecurityConfigLike } from "./securityGuards";
import {
  PolicyDeniedError,
  SigningFailedError,
} from "./middlewareTypes";
import type {
  McpServerLike,
  MiddlewareOptions,
  PolicyViolation,
} from "./middlewareTypes";
import type {
  ApprovalVerifier,
  AuditSink,
  EscalationReporter,
  PolicyProvider,
  RuntimeInvoker,
} from "../core/contracts";
import { fireAndForgetPolicyWebhookEvent } from "./adapters/webhookNotifier";
import { endSpanErr, endSpanOk, extractContextFromHeaders, setSpanAttributes, startInvokeSpan } from "../otel";
import { createContextualEvaluatorManager } from "../evaluator";
import {
  type AllowMatchKind,
  generateTraceId,
  inferOp,
  isPinned,
  isSideEffecting,
  matchAllowlist,
  matchesToolPattern,
  normalizeTraceId,
  parseToolDescriptor,
  readHeaderCaseInsensitive,
  toolUri,
  toolUriNoVersion,
} from "./tooling";

type ToolContext = {
  args: any;
  idempotencyKey?: string | null;
  headers?: Record<string, string>;
};

type ToolHandler = (ctx: ToolContext) => Promise<any> | any;
type ContextualEvaluatorManager = ReturnType<typeof createContextualEvaluatorManager>;

export type CreateWrappedToolHandlerInput = {
  sdkVersion: string;
  opts: MiddlewareOptions;
  server: McpServerLike;
  nameAtVersion: string;
  handler: ToolHandler;
  telemetryEnabled: boolean;
  includeServerAgentState: boolean;
  includeToolAgentState: boolean;
  policyProvider: PolicyProvider;
  approvalVerifier: ApprovalVerifier;
  escalationReporter: EscalationReporter;
  auditSink: AuditSink;
  runtimeInvoker: RuntimeInvoker;
  contextualEvaluatorManager: ContextualEvaluatorManager | null;
  rawPayloadConfig?: RawPayloadCaptureConfig;
  policyWebhookUrl?: string;
  forceDastRawUpload: boolean;
  computedSandboxUrl?: string;
  sastEnabled: boolean;
  sast: SastManager;
  policySast: any;
  dastEnabled: boolean;
  dast: DastManager | null;
  policyDast: any;
  toolFilePathByKey: Map<string, string>;
  lastVersionByToolBase: Map<string, string>;
  registryState: ReturnType<typeof createRegistryState>;
  invocationStats: ReturnType<typeof createInvocationStats>;
  scanPipeline: ReturnType<typeof createScanPipeline>;
  getAgentGuardForCurrentPolicy: () => AgentGuard;
  getRunContextConfigForCurrentPolicy: () => RunContextConfig | null;
  getPolicy: () => PolicyObject;
  onPolicyResolved: (resolved: Awaited<ReturnType<PolicyProvider["getPolicy"]>>) => void;
  requireUploadConfig: () => UploadApiConfig;
};

export function createWrappedToolHandler(input: CreateWrappedToolHandlerInput): ToolHandler {
  return async (ctx) => {
    input.registryState.freeze();
    const start = Date.now();
    const { name: toolBaseName, version: toolVersion } = parseToolDescriptor(input.nameAtVersion);
    let policyObj = input.getPolicy();

    // Some transports only forward the idempotency key via headers; normalize it
    // into the context shape once so every downstream check sees a consistent field.
    if (ctx && (ctx.idempotencyKey === undefined || ctx.idempotencyKey === null || ctx.idempotencyKey === "")) {
      const headerIdempotencyKey =
        readHeaderCaseInsensitive(ctx.headers as any, "x-idempotency-key") ||
        readHeaderCaseInsensitive(ctx.headers as any, "x-idempotency");
      if (headerIdempotencyKey) {
        ctx.idempotencyKey = headerIdempotencyKey;
      }
    }

    let span: any;
    let activeCtx = context.active();
    if (input.telemetryEnabled) {
      const parentCtx = extractContextFromHeaders(ctx.headers);
      const serviceName = (input.opts.otel.serviceName || "").trim();
      if (!serviceName) {
        throw new Error("[sec0-middleware] opts.otel.serviceName is required when telemetry is enabled");
      }
      const environment = (input.opts.otel.environment || "").trim();
      if (!environment) {
        throw new Error("[sec0-middleware] opts.otel.environment is required when telemetry is enabled");
      }
      const invokeSpanName = `${serviceName}.invoke`;
      span = startInvokeSpan(
        invokeSpanName,
        {
          "mcp.server": input.server.name,
          "mcp.tool": toolBaseName,
          "mcp.tool.name": input.nameAtVersion,
          "mcp.version": toolVersion,
          "deployment.env": environment,
        },
        parentCtx,
      );
      const activeWithSpan = trace.setSpan(context.active(), span);
      const carrier: Record<string, string> = {};
      carrier.baggage = "mcp.audit.parent=1";
      activeCtx = propagation.extract(activeWithSpan, carrier);
    } else {
      span = { spanContext: () => ({ traceId: "0".repeat(32), spanId: "0".repeat(16) }) };
    }
    const addAttrs = (attrs: Record<string, any>) => {
      if (input.telemetryEnabled) setSpanAttributes(span, attrs);
    };
    const spanCtx = typeof span?.spanContext === "function" ? span.spanContext() : undefined;
    const incomingAgentState: AgentStatePayload = extractAgentStateFromHeaders(ctx.headers as any);
    const nodeId = incomingAgentState.nodeId;
    const agentRunId = ensureRunId(incomingAgentState);
    let agentVariables: AgentStateVariables | undefined = incomingAgentState.variables;
    const identityContext = parseIdentityContextHeader(
      readHeaderCaseInsensitive(ctx.headers as any, "x-auth-context"),
    );

    let effectiveTenant: string | undefined = input.opts.otel?.tenant;
    let effectiveEnv: string | undefined = input.opts.otel?.environment || (input.opts.sec0 as any)?.presign?.environment;
    let effectiveClientName: string | undefined = (input.opts.sec0 as any)?.presign?.clientName;
    let effectiveClientVersion: string | undefined = (input.opts.sec0 as any)?.presign?.clientVersion;

    let decision: "allow" | "deny" = "allow";
    let violation: PolicyViolation | null = null;
    let result: any = null;
    let error: Error | null = null;
    let escalationFailure: string | null = null;
    let inputHash: string | null = null;
    let outputHash: string | null = null;
    let handlerSwapDetected = false;
    let serverCodeChanged = false;
    let registryMutation = false;
    let toolCodeChanged = false;
    let sastStatus: "pass" | "fail" | "pending" | undefined = undefined;
    let sastFindings: SastFinding[] | undefined = undefined;
    let sastScanId: string | undefined = undefined;
    let dastStatus: "pass" | "fail" | "pending" | undefined = undefined;
    let dastFindings: DastFinding[] | undefined = undefined;
    let dastScanId: string | undefined = undefined;
    let sastRawKey: string | undefined = undefined;
    let dastRawKey: string | undefined = undefined;
    let agentFindings: AgentGuardFinding[] | undefined = undefined;
    let agentGuardRawKey: string | undefined = undefined;
    let contextualEvaluatorFinding: any = null;
    let contextualEvaluatorViolation: PolicyViolation | null = null;
    let contextualAgentFindings: AgentGuardFinding[] = [];
    let didSast = false;
    let didDast = false;
    const toolBaseUri = toolUriNoVersion(input.server.name, input.nameAtVersion);
    const currentVersion = toolVersion;
    let versionChanged = false;
    let previousVersion: string | undefined = undefined;
    const getPolicyDenyOn = (): string[] => {
      const raw = (policyObj as any)?.enforcement?.deny_on;
      if (!Array.isArray(raw)) return [];
      return raw.map((entry: unknown) => String(entry ?? "").trim()).filter(Boolean);
    };
    const decisionFlow = createDecisionFlow({
      ctx,
      tenant: () => effectiveTenant,
      server: { name: input.server.name, version: input.server.version },
      tool: input.nameAtVersion,
      nodeId: nodeId || undefined,
      agentRunId: agentRunId || undefined,
      approvalVerifier: input.approvalVerifier,
      runtimeInvoker: input.runtimeInvoker,
      getPolicyDenyOn,
    });
    const { verifyApprovalIfAny, shouldRuntimeDeny, policyDeniesReason } = decisionFlow;
    const invocationState = createMiddlewareInvocationState();
    // The invocation state is the audit/escalation contract; keep it synchronized
    // with the local mutable variables so downstream helpers operate on one shape.
    const syncInvocationState = () => {
      invocationState.decision = decision;
      invocationState.violation = violation;
      invocationState.result = result;
      invocationState.error = error;
      invocationState.escalationFailure = escalationFailure;
      invocationState.inputHash = inputHash;
      invocationState.outputHash = outputHash;
      invocationState.handlerSwapDetected = handlerSwapDetected;
      invocationState.serverCodeChanged = serverCodeChanged;
      invocationState.registryMutation = registryMutation;
      invocationState.toolCodeChanged = toolCodeChanged;
      invocationState.versionChanged = versionChanged;
      invocationState.previousVersion = previousVersion;
      invocationState.contextualEvaluatorFinding = contextualEvaluatorFinding;
      invocationState.contextualEvaluatorViolation = contextualEvaluatorViolation;
      invocationState.contextualAgentFindings = contextualAgentFindings;
      invocationState.agentFindings = agentFindings;
      invocationState.agentGuardRawKey = agentGuardRawKey;
      invocationState.sast.status = sastStatus;
      invocationState.sast.findings = sastFindings as any;
      invocationState.sast.scanId = sastScanId;
      invocationState.sast.rawKey = sastRawKey;
      invocationState.sast.didRun = didSast;
      invocationState.dast.status = dastStatus;
      invocationState.dast.findings = dastFindings as any;
      invocationState.dast.scanId = dastScanId;
      invocationState.dast.rawKey = dastRawKey;
      invocationState.dast.didRun = didDast;
    };
    const syncLocalsFromInvocationState = () => {
      decision = invocationState.decision;
      violation = invocationState.violation as PolicyViolation | null;
      result = invocationState.result;
      error = invocationState.error;
      escalationFailure = invocationState.escalationFailure;
      inputHash = invocationState.inputHash;
      outputHash = invocationState.outputHash;
      handlerSwapDetected = invocationState.handlerSwapDetected;
      serverCodeChanged = invocationState.serverCodeChanged;
      registryMutation = invocationState.registryMutation;
      toolCodeChanged = invocationState.toolCodeChanged;
      versionChanged = invocationState.versionChanged;
      previousVersion = invocationState.previousVersion;
      contextualEvaluatorFinding = invocationState.contextualEvaluatorFinding;
      contextualEvaluatorViolation = invocationState.contextualEvaluatorViolation as PolicyViolation | null;
      contextualAgentFindings = invocationState.contextualAgentFindings;
      agentFindings = invocationState.agentFindings;
      agentGuardRawKey = invocationState.agentGuardRawKey;
      sastStatus = invocationState.sast.status;
      sastFindings = invocationState.sast.findings;
      sastScanId = invocationState.sast.scanId;
      sastRawKey = invocationState.sast.rawKey;
      didSast = invocationState.sast.didRun;
      dastStatus = invocationState.dast.status;
      dastFindings = invocationState.dast.findings;
      dastScanId = invocationState.dast.scanId;
      dastRawKey = invocationState.dast.rawKey;
      didDast = invocationState.dast.didRun;
    };

    try {
      const registrySignals = input.registryState.detectToolRuntimeChanges(input.nameAtVersion, input.handler as any);
      handlerSwapDetected = registrySignals.handlerSwapDetected;
      toolCodeChanged = registrySignals.toolCodeChanged;
    } catch {}

    if (!error) {
      try {
        const resolved = await input.policyProvider.getPolicy({ nodeId });
        input.onPolicyResolved(resolved);
        policyObj = input.getPolicy();
        if (!effectiveTenant) effectiveTenant = resolved.tenant;
        if (!effectiveEnv) effectiveEnv = resolved.env;
        if (!effectiveClientName) effectiveClientName = resolved.clientName;
        if (!effectiveClientVersion) effectiveClientVersion = resolved.clientVersion;
      } catch (e: any) {
        decision = "deny";
        violation = "policy_fetch_failed";
        error = new PolicyDeniedError("policy_fetch_failed", e?.message || "policy_fetch_failed");
      }
    }

    let allowMatch: { allowed: boolean; kind: AllowMatchKind } = { allowed: false, kind: null };
    if (!error && !violation) {
      const toolsCfgRaw: any = (policyObj as any)?.tools;
      const toolsCfg: any = toolsCfgRaw && typeof toolsCfgRaw === "object" ? toolsCfgRaw : {};
      const allowlist: string[] =
        toolsCfgRaw == null
          ? ["*"]
          : (Array.isArray(toolsCfg.allowlist) ? toolsCfg.allowlist.map(String).filter(Boolean) : []);
      allowMatch = matchAllowlist(allowlist, input.server.name, input.nameAtVersion);
      const denyIfUnpinned = !!toolsCfg.deny_if_unpinned_version;
      if (denyIfUnpinned && !isPinned(input.nameAtVersion)) {
        const relax = allowMatch.allowed && (allowMatch.kind === "versionless" || allowMatch.kind === "wildcard");
        if (!relax) violation = "version_unpinned";
      }
      if (!allowMatch.allowed) {
        violation = "tool_not_in_allowlist";
      }
    }
    if (allowMatch.allowed) {
      const prev = input.lastVersionByToolBase.get(toolBaseUri);
      if (prev && prev !== currentVersion) {
        versionChanged = true;
        previousVersion = prev;
      }
    }

    const agentGuard = input.getAgentGuardForCurrentPolicy();
    const runContextConfig = input.getRunContextConfigForCurrentPolicy();
    const runContextState =
      runContextConfig
        ? ensureRunContextState(runContextConfig, {
            tenant: effectiveTenant,
            nodeId,
            runId: agentRunId,
            now: Date.now(),
          })
        : null;
    if (runContextState && runContextConfig) {
      const objective = extractObjective(agentVariables, incomingAgentState);
      if (objective) runContextState.objective = objective;
      if (runContextConfig.includeMetadata && !runContextState.metadata) {
        const meta = extractMetadata(incomingAgentState);
        if (meta) runContextState.metadata = meta;
      }
    }

    if (policyObj.side_effects?.require_idempotency_key && isSideEffecting(input.nameAtVersion, ctx.args) && !ctx.idempotencyKey) {
      violation = "missing_idempotency_for_side_effect";
    }

    let ap2IntentId: string | undefined;
    let ap2CartId: string | undefined;
    let ap2ConstraintsSha256: string | undefined;
    let ap2CartSha256: string | undefined;
    let ap2IssuerDid: string | undefined;
    let ap2SubjectDid: string | undefined;
    try {
      const ap2 = (input.opts as any)?.ap2 || {};
      const isWrite = isSideEffecting(input.nameAtVersion, ctx.args);
      if (ap2.enabled && ap2.requireForSideEffects && isWrite) {
        // AP2 can arrive either as dedicated headers or bundled JSON/JWS payloads.
        // Normalize both forms into the same digest checks and audit fields.
        const getHeader = (name: string) => (ctx.headers?.[name] as string) || (ctx.headers?.[name.toLowerCase()] as string) || "";
        const intentRaw = getHeader(ap2.headers?.intent || "x-ap2-intent-mandate");
        const cartRaw = getHeader(ap2.headers?.cart || "x-ap2-cart-mandate");
        const bundleRaw = getHeader(ap2.headers?.bundle || "x-ap2-bundle");
        const rawIntent = intentRaw || (() => {
          try {
            const bundle = JSON.parse(bundleRaw || "{}");
            return String(bundle.intent || bundle.intentMandate || "");
          } catch {
            return "";
          }
        })();
        const rawCart = cartRaw || (() => {
          try {
            const bundle = JSON.parse(bundleRaw || "{}");
            return String(bundle.cart || bundle.cartMandate || "");
          } catch {
            return "";
          }
        })();
        const decodePayload = (value?: string): any | undefined => {
          try {
            if (!value) return undefined;
            return JSON.parse(value);
          } catch {}
          try {
            if (!value || value.split(".").length < 2) return undefined;
            const b64 = value.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
            const pad = b64.length % 4 === 2 ? "==" : (b64.length % 4 === 3 ? "=" : "");
            return JSON.parse(Buffer.from(b64 + pad, "base64").toString("utf8"));
          } catch {
            return undefined;
          }
        };
        const canon = (value: any): string => {
          const seen = new WeakSet();
          const sort = (next: any): any => {
            if (next === null || typeof next !== "object") return next;
            if (seen.has(next)) return null;
            seen.add(next);
            if (Array.isArray(next)) return next.map(sort);
            const out: any = {};
            Object.keys(next).sort().forEach((key) => {
              out[key] = sort(next[key]);
            });
            return out;
          };
          return JSON.stringify(sort(value));
        };
        const sha256HexLocal = (buffer: Buffer) => {
          try {
            return require("node:crypto").createHash("sha256").update(buffer).digest("hex");
          } catch {
            return "";
          }
        };
        const intent = decodePayload(rawIntent);
        const cart = decodePayload(rawCart);
        if (!cart) {
          violation = (violation as any) || "ap2_mandate_missing";
        } else {
          ap2IntentId = (intent?.jti || intent?.id) ? String(intent.jti || intent.id) : undefined;
          ap2CartId = (cart?.jti || cart?.id) ? String(cart.jti || cart.id) : undefined;
          ap2IssuerDid = (cart?.iss || cart?.issuer) ? String(cart.iss || cart.issuer) : undefined;
          ap2SubjectDid = (cart?.sub || cart?.subject) ? String(cart.sub || cart.subject) : undefined;
          ap2ConstraintsSha256 = intent?.constraints ? sha256HexLocal(Buffer.from(canon(intent.constraints))) : undefined;
          ap2CartSha256 = sha256HexLocal(Buffer.from(canon(cart)));
          const idempotencyKey = String(ctx.idempotencyKey || "");
          if (!idempotencyKey) {
            violation = (violation as any) || "ap2_idempotency_missing";
          } else if (ap2CartSha256 && idempotencyKey !== ap2CartSha256) {
            violation = (violation as any) || "ap2_idempotency_mismatch";
          }
        }
      }
    } catch {}

    const sec: SecurityConfigLike = (policyObj as any).security || {};
    if (sec?.limits?.max_payload_kb && estimateSizeKb((ctx as any)?.args) > sec.limits.max_payload_kb) {
      violation = "payload_too_large";
    }

    try {
      const errPct = input.invocationStats.calcErrorRate(input.nameAtVersion);
      const p95 = input.invocationStats.calcP95(input.nameAtVersion);
      const breakerConfig = policyObj.enforcement?.circuit_breakers;
      const samples = input.invocationStats.getSampleCount(input.nameAtVersion);
      const minSamplesRaw = (breakerConfig as any)?.min_samples ?? (breakerConfig as any)?.minSamples;
      const minSamples =
        typeof minSamplesRaw === "number" && Number.isFinite(minSamplesRaw) && minSamplesRaw > 0
          ? Math.floor(minSamplesRaw)
          : 20;
      const openByErr = (breakerConfig as any)?.error_rate_pct !== undefined && errPct >= (breakerConfig as any)?.error_rate_pct;
      const openByP95 = (breakerConfig as any)?.p95_latency_ms !== undefined && p95 >= (breakerConfig as any)?.p95_latency_ms;
      if (breakerConfig && samples >= minSamples && (openByErr || openByP95)) {
        addAttrs({ "circuit.open": true, "circuit.err_pct": errPct, "circuit.p95_ms": p95 });
        const circuitError = new Error("CIRCUIT_OPEN");
        (circuitError as any).code = "CIRCUIT_OPEN";
        throw circuitError;
      }
    } catch (preErr: any) {
      if (!error) {
        error = preErr instanceof Error ? preErr : new Error(String(preErr));
      }
    }

    // Run the pre-handler decision path inside the active tracing context so any
    // downstream spans from the tool call inherit the middleware invocation span.
    await context.with(activeCtx, async () => {
      try {
        inputHash = ctx?.args ? sha256Hex(Buffer.from(JSON.stringify(ctx.args))) : null;
        const registrySignals = input.registryState.detectToolRuntimeChanges(input.nameAtVersion, input.handler as any);
        registryMutation = registrySignals.registryMutation;
        handlerSwapDetected = handlerSwapDetected || registrySignals.handlerSwapDetected;
        toolCodeChanged = toolCodeChanged || registrySignals.toolCodeChanged;
        serverCodeChanged = registrySignals.serverCodeChanged;
        if (violation) {
          decision = "deny";
          if (await shouldRuntimeDeny([violation], { requestIdSuffix: "pre-handler-violation" })) {
            if (input.policyWebhookUrl) {
              try {
                fireAndForgetPolicyWebhookEvent(input.policyWebhookUrl, {
                  event: "policy.denied",
                  tenant: input.opts.otel.tenant,
                  server: input.server.name,
                  tool: input.nameAtVersion,
                  violation,
                  timestamp: new Date().toISOString(),
                });
              } catch {}
            }
            throw new PolicyDeniedError(violation);
          }
        }

        if (
          !error &&
          input.contextualEvaluatorManager?.enabled &&
          (!violation || violation === "agent_guard_failed")
        ) {
          const contextualResult = await runContextualEvaluation({
            manager: input.contextualEvaluatorManager,
            options: input.opts.contextualEvaluator,
            tenant: effectiveTenant,
            server: { name: input.server.name, version: input.server.version },
            tool: input.nameAtVersion,
            ctx,
            nodeId: nodeId || undefined,
            agentRunId: agentRunId || undefined,
            policy: policyObj as PolicyObject,
            agentVariables,
            incomingAgentState,
            identity: identityContext,
            violation,
            findings: agentFindings,
            content: (ctx as any)?.args,
            addAttrs,
          });
          agentFindings = contextualResult.findings;
          violation = contextualResult.violation;
          contextualEvaluatorFinding = contextualResult.contextualFinding;
          contextualEvaluatorViolation = contextualResult.contextualViolation;
          contextualAgentFindings = contextualResult.contextualAgentFindings;
          if (
            contextualResult.contextualViolation &&
            await shouldRuntimeDeny(
              [
                violation &&
                (violation !== contextualResult.contextualViolation || policyDeniesReason(violation))
                  ? violation
                  : null,
                contextualResult.contextualViolation &&
                policyDeniesReason(contextualResult.contextualViolation) &&
                contextualResult.contextualViolation !== violation
                  ? contextualResult.contextualViolation
                  : null,
              ].filter(Boolean) as string[],
              {
                requestIdSuffix: "contextual-evaluator",
              },
            )
          ) {
            violation = violation || contextualResult.contextualViolation;
            decision = "deny";
            error = new PolicyDeniedError(
              (violation || contextualResult.contextualViolation) as PolicyViolation,
            );
          }
        }

        if (
          !error &&
          violation === "agent_guard_failed" &&
          (await shouldRuntimeDeny(["agent_guard_failed"], { requestIdSuffix: "agent-guard-input" }))
        ) {
          const approval = await verifyApprovalIfAny();
          if (approval && approval.valid) {
            try {
              addAttrs({ "agent_guard.approved": true, "agent_guard.approval_id": approval?.approval?.id || "" });
            } catch {}
          } else {
            decision = "deny";
            error = new PolicyDeniedError("agent_guard_failed");
          }
        }

        if (!error) {
          result = await withGuardedIO(sec, async () => Promise.resolve(input.handler(ctx)));
          outputHash = result != null ? sha256Hex(Buffer.from(JSON.stringify(result))) : null;
          if (allowMatch.allowed) {
            input.lastVersionByToolBase.set(toolBaseUri, currentVersion);
          }
        }
      } catch (executionError: any) {
        const code = executionError && typeof executionError === "object" ? (executionError as any).code : undefined;
        if (code === "egress_violation" || code === "fs_violation" || code === "subprocess_blocked") {
          violation = code as PolicyViolation;
          decision = "deny";
          if (await shouldRuntimeDeny([violation], { requestIdSuffix: "guard-violation" })) {
            error = new PolicyDeniedError(violation);
          } else {
            error = executionError;
          }
        } else {
          error = executionError;
        }
      }
    });

    // Post-handler processing is intentionally centralized here so risk tags,
    // scans, escalation, and audit reflect the final invocation outcome in one place.
    const latency = Date.now() - start;
    const riskTags: string[] = [];
    let decisionReason: string | undefined = undefined;
    let egressDomain: string | undefined = undefined;
    let fsPath: string | undefined = undefined;

    if (violation) {
      decisionReason = violation;
      riskTags.push(violation);
    } else if (contextualEvaluatorViolation) {
      riskTags.push(contextualEvaluatorViolation);
    }

    const postSecurity = (policyObj as any).security || {};
    const ap2Policy = (policyObj as any).security?.ap2;
    const matchAny = (value: string, patterns?: string[]): boolean => {
      if (!patterns || patterns.length === 0) return true;
      return patterns.some((pattern) => {
        const escaped = pattern.replace(/[.+^${}()|\[\]\\]/g, "\\$&").replace(/\*/g, ".*?");
        try {
          return new RegExp(`^${escaped}$`, "i").test(value);
        } catch {
          return true;
        }
      });
    };
    const estimateKb = (obj: unknown): number => {
      try {
        return Math.ceil(Buffer.byteLength(JSON.stringify(obj || {}), "utf8") / 1024);
      } catch {
        return 0;
      }
    };
    const urlStr = typeof (ctx as any)?.args?.url === "string" ? (ctx as any).args.url : undefined;
    try {
      if (urlStr) {
        const url = new URL(urlStr);
        egressDomain = url.hostname;
      }
    } catch {}
    if (urlStr && postSecurity.egress_allowlist && !matchAny(urlStr, postSecurity.egress_allowlist)) {
      riskTags.push("egress_violation");
    }
    fsPath = typeof (ctx as any)?.args?.path === "string" ? (ctx as any).args.path : undefined;
    if (fsPath && postSecurity.fs_allowlist && !matchAny(fsPath, postSecurity.fs_allowlist)) {
      riskTags.push("fs_violation");
    }
    if (postSecurity?.limits?.max_payload_kb && estimateKb((ctx as any)?.args) > postSecurity.limits.max_payload_kb) {
      riskTags.push("payload_too_large");
    }

    const ap2Allow = Array.isArray(ap2Policy?.tools?.allow) ? ap2Policy.tools.allow : [];
    const legacyRequireFlag = (ap2Policy as any)?.require_for_side_effects;
    const requireForSideEffects = ap2Policy?.requireForSideEffects ?? legacyRequireFlag;
    const shouldEnforcePolicyAp2 = (() => {
      if (!ap2Policy || ap2Policy.enabled === false) return false;
      if (ap2Allow.length) return ap2Allow.some((pattern: string) => matchesToolPattern(pattern, input.server.name, input.nameAtVersion));
      return requireForSideEffects !== false && isSideEffecting(input.nameAtVersion, ctx.args);
    })();

    const forwardedCartDigest = readHeaderCaseInsensitive(ctx.headers as any, AP2_CART_DIGEST_HEADER);
    const forwardedIntentMandate = readHeaderCaseInsensitive(ctx.headers as any, (ap2Policy?.headers?.intent) || "x-ap2-intent-mandate");
    const forwardedCartMandate = readHeaderCaseInsensitive(ctx.headers as any, (ap2Policy?.headers?.cart) || "x-ap2-cart-mandate");
    const forwardedBundle = readHeaderCaseInsensitive(ctx.headers as any, (ap2Policy?.headers?.bundle) || "x-ap2-bundle");
    const shouldVerifyAp2Hop = Boolean(
      forwardedCartDigest ||
      forwardedIntentMandate ||
      forwardedCartMandate ||
      forwardedBundle ||
      shouldEnforcePolicyAp2,
    );

    if (shouldVerifyAp2Hop) {
      let ap2HopViolation: string | undefined;
      if (forwardedCartDigest) {
        const digestCheck = compareArgsToDigest(forwardedCartDigest, (ctx as any)?.args);
        if (!digestCheck.ok) {
          ap2HopViolation = digestCheck.reason || "ap2_cart_mismatch";
        }
      }
      if (!ap2HopViolation) {
        const verification = await verifyAp2MandatesFromHeaders(ap2Policy as Ap2Config | undefined, ctx.headers as any, ctx.args);
        if (!verification.ok) {
          ap2HopViolation = verification.reason || "ap2_verification_error";
        } else {
          if (verification.constraintsDigest) {
            if (!ctx.headers) ctx.headers = {};
            ctx.headers[AP2_CONSTRAINTS_DIGEST_HEADER] = verification.constraintsDigest;
          }
          if (verification.cartDigest) {
            if (!ctx.headers) ctx.headers = {};
            ctx.headers[AP2_CART_DIGEST_HEADER] = verification.cartDigest;
          }
        }
      }
      if (ap2HopViolation) {
        riskTags.push(ap2HopViolation);
        violation = (violation as any) || ap2HopViolation;
      }
    }

    if (versionChanged) {
      riskTags.push("tool_version_changed");
      addAttrs({ "tool.version.prev": previousVersion ?? "", "tool.version.new": currentVersion });
      if (input.policyWebhookUrl) {
        try {
          fireAndForgetPolicyWebhookEvent(input.policyWebhookUrl, {
            event: "tool.version_changed",
            tenant: input.opts.otel.tenant,
            server: input.server.name,
            tool_base: toolBaseUri,
            previous_version: previousVersion,
            new_version: currentVersion,
            timestamp: new Date().toISOString(),
          });
        } catch {}
      }
    }
    if (serverCodeChanged) {
      riskTags.push("server_code_changed");
      if (await shouldRuntimeDeny(["server_code_changed"], { requestIdSuffix: "server-code-changed" })) {
        decision = "deny";
        error = new PolicyDeniedError("server_code_changed");
      }
    }
    if (toolCodeChanged) {
      riskTags.push("tool_code_changed");
      if (await shouldRuntimeDeny(["tool_code_changed"], { requestIdSuffix: "tool-code-changed" })) {
        decision = "deny";
        error = new PolicyDeniedError("tool_code_changed");
      }
    }
    if (registryMutation) {
      riskTags.push("registry_mutation");
      if (await shouldRuntimeDeny(["registry_mutation"], { requestIdSuffix: "registry-mutation" })) {
        decision = "deny";
        error = new PolicyDeniedError("registry_mutation");
      }
    }
    if (handlerSwapDetected) {
      riskTags.push("handler_swap");
      if (await shouldRuntimeDeny(["handler_swap"], { requestIdSuffix: "handler-swap" })) {
        decision = "deny";
        error = new PolicyDeniedError("handler_swap");
      }
    }

    try {
      agentFindings = await agentGuard.scanInput((ctx as any)?.args);
      if (contextualAgentFindings.length) {
        agentFindings = [...contextualAgentFindings, ...(agentFindings || [])];
      }
      if (runContextState && runContextConfig) {
        const entry = buildRunEvent("input", input.nameAtVersion, (ctx as any)?.args, runContextConfig);
        if (entry) appendRunEvent(runContextState, entry, runContextConfig);
        const runText = buildRunContextText(runContextState, runContextConfig);
        const runFindings = await agentGuard.scanRun(runText);
        if (runFindings && runFindings.length) {
          agentFindings = [...(agentFindings || []), ...runFindings];
        }
      }
      if (agentFindings && agentFindings.length) {
        agentFindings = dedupeFindings(agentFindings);
      }
      const agBlock = agentGuard.shouldBlock(agentFindings || []);
      const deferInputAgentGuardDecision = agBlock.block && input.contextualEvaluatorManager?.enabled;
      if (!violation && agBlock.block) {
        violation = "agent_guard_failed";
      }
      if (
        agBlock.block &&
        !deferInputAgentGuardDecision &&
        (await shouldRuntimeDeny(["agent_guard_failed"], { requestIdSuffix: "agent-guard-input" }))
      ) {
        const approval = await verifyApprovalIfAny();
        if (approval && approval.valid) {
          try {
            addAttrs({ "agent_guard.approved": true, "agent_guard.approval_id": approval?.approval?.id || "" });
          } catch {}
          riskTags.push("agent_guard_approved");
          agentFindings = annotateApprovedFindings(agentFindings, approval) as AgentGuardFinding[] | undefined;
        } else {
          decision = "deny";
          error = new PolicyDeniedError("agent_guard_failed");
          riskTags.push("agent_guard_failed");
          violation = "agent_guard_failed";
          if (!decisionReason) decisionReason = "agent_guard_failed";
        }
      }
    } catch {}

    if (input.sastEnabled) {
      try {
        const currentFn = input.server.__getTools?.().get(input.nameAtVersion) || input.handler;
        const filePath = input.toolFilePathByKey.get(input.nameAtVersion) || getSec0Meta(currentFn)?.filePath || getSec0Meta(input.handler)?.filePath;
        syncInvocationState();
        const sastExecution = await input.scanPipeline.runSast({
          tool: input.nameAtVersion,
          handler: input.handler,
          currentHandler: currentFn,
          toolFilePath: filePath,
          manager: input.sast,
          state: invocationState,
          addAttrs,
          runOnChangeOnly: !!(input.policySast as any)?.scan_on_change_only,
          blockOnChange: input.opts.sast?.block_on_change,
          blockOnSeverity: input.opts.sast?.block_on_severity,
        });
        syncLocalsFromInvocationState();
        if (sastExecution.block.block) {
          decision = "deny";
          error = new PolicyDeniedError("tool_code_changed");
          riskTags.push(sastExecution.block.reason || "sast_block");
        }
      } catch {}
    }

    if (input.dastEnabled) {
      try {
        const activeDast = input.dast;
        if (!activeDast) throw new Error("[sec0-middleware] DAST manager not initialized");
        const currentFn = input.server.__getTools?.().get(input.nameAtVersion) || input.handler;
        syncInvocationState();
        const dastExecution = await input.scanPipeline.runDast({
          tool: input.nameAtVersion,
          currentHandler: currentFn,
          manager: activeDast,
          state: invocationState,
          mode: ((input.opts.dast as any)?.mode) || ((input.policyDast as any)?.mode),
          scope: ((input.opts.dast as any)?.scope) || ((input.policyDast as any)?.scope) || "tool",
          sandboxUrl: input.computedSandboxUrl,
          runOnChangeOnly: !!(input.policyDast as any)?.scan_on_change_only,
          blockOnChange: input.opts.dast?.block_on_change,
          blockOnSeverity: input.opts.dast?.block_on_severity,
          blockOnCount: input.opts.dast?.block_on_count,
          forceRawUpload: input.forceDastRawUpload,
          enableDynamicBlockTtl: !!input.opts.dast?.rule_ttl_ms,
        });
        syncLocalsFromInvocationState();
        if (dastExecution.block.block) {
          decision = "deny";
          error = new PolicyDeniedError("tool_code_changed");
          riskTags.push(dastExecution.block.reason || "dast_block");
        }
      } catch {}
    }

    if (input.dastEnabled && input.dast?.isDynamicallyBlocked(input.nameAtVersion)) {
      decision = "deny";
      error = new PolicyDeniedError("tool_code_changed");
      riskTags.push("dast_dynamic_rule");
    }

    try {
      const postFindings = await agentGuard.scanOutput(result);
      agentFindings = [...(agentFindings || []), ...(postFindings || [])];
      if (runContextState && runContextConfig) {
        const entry = buildRunEvent("output", input.nameAtVersion, result, runContextConfig);
        if (entry) appendRunEvent(runContextState, entry, runContextConfig);
        const runText = buildRunContextText(runContextState, runContextConfig);
        const runFindings = await agentGuard.scanRun(runText);
        if (runFindings && runFindings.length) {
          agentFindings = [...(agentFindings || []), ...runFindings];
        }
      }
      if (agentFindings && agentFindings.length) {
        agentFindings = dedupeFindings(agentFindings);
      }
      const agBlock = agentGuard.shouldBlock(agentFindings || []);
      let outputViolation: PolicyViolation | null = agBlock.block ? "agent_guard_failed" : null;
      if (
        input.contextualEvaluatorManager?.enabled &&
        agentFindings &&
        agentFindings.length > 0 &&
        (!violation || violation === "agent_guard_failed")
      ) {
        const contextualResult = await runContextualEvaluation({
          manager: input.contextualEvaluatorManager,
          options: input.opts.contextualEvaluator,
          tenant: effectiveTenant,
          server: { name: input.server.name, version: input.server.version },
          tool: input.nameAtVersion,
          ctx,
          nodeId: nodeId || undefined,
          agentRunId: agentRunId || undefined,
          policy: policyObj as PolicyObject,
          agentVariables,
          incomingAgentState,
          identity: identityContext,
          violation: outputViolation,
          findings: agentFindings,
          content: result,
          addAttrs,
          includeContextualFindingInAgentFindings: true,
        });
        agentFindings = contextualResult.findings;
        outputViolation = contextualResult.violation;
        contextualEvaluatorViolation = contextualResult.contextualViolation || contextualEvaluatorViolation;
        contextualEvaluatorFinding = contextualResult.contextualFinding;
        contextualAgentFindings = contextualResult.contextualAgentFindings;
      }
      if (!violation && outputViolation) {
        violation = outputViolation;
      }
      const outputEnforcementReasons = [
        outputViolation &&
        (outputViolation !== contextualEvaluatorViolation || policyDeniesReason(outputViolation))
          ? outputViolation
          : null,
        contextualEvaluatorViolation &&
        policyDeniesReason(contextualEvaluatorViolation) &&
        contextualEvaluatorViolation !== outputViolation
          ? contextualEvaluatorViolation
          : null,
      ].filter(Boolean) as string[];
      if (
        outputEnforcementReasons.length > 0 &&
        (await shouldRuntimeDeny(outputEnforcementReasons, { requestIdSuffix: "agent-guard-output" }))
      ) {
        const approval = await verifyApprovalIfAny();
        if (approval && approval.valid) {
          try {
            addAttrs({ "agent_guard.approved": true, "agent_guard.approval_id": approval?.approval?.id || "" });
          } catch {}
          riskTags.push("agent_guard_approved");
          agentFindings = annotateApprovedFindings(agentFindings, approval) as AgentGuardFinding[] | undefined;
        } else {
          const finalViolation = (outputViolation || contextualEvaluatorViolation || "agent_guard_failed") as PolicyViolation;
          decision = "deny";
          error = new PolicyDeniedError(finalViolation);
          riskTags.push(finalViolation);
          violation = finalViolation;
          if (!decisionReason) decisionReason = finalViolation;
        }
      }
    } finally {
      if (!agentFindings && contextualAgentFindings.length) {
        agentFindings = [...contextualAgentFindings];
      }
    }

    if (agentFindings && agentFindings.length) {
      const agScanId = (() => {
        try {
          return normalizeTraceId(spanCtx?.traceId) || generateTraceId();
        } catch {
          return generateTraceId();
        }
      })();
      const key = await persistScanRawIfConfigured({
        tenant: input.opts.otel?.tenant,
        level: "middleware",
        kind: "agent_guard_findings",
        scanId: agScanId,
        raw: {
          tenant: input.opts.otel?.tenant,
          server: { name: input.server.name, version: input.server.version },
          tool: input.nameAtVersion,
          input_sha256: inputHash,
          output_sha256: outputHash,
          findings: agentFindings,
        },
        uploadConfig: input.requireUploadConfig(),
      });
      if (key) agentGuardRawKey = key;
    }

    const checkLevel = "middleware";
    const checkKind = (versionChanged || serverCodeChanged || handlerSwapDetected || registryMutation) ? "dynamic" : "static";
    const authObj = extractAuthObject(ctx.headers as any);
    const { compliance, vulnRefs: vulnRefs } = deriveComplianceMetadata({
      sastFindings: sastFindings as any,
      dastFindings: dastFindings as any,
    });
    const testsPerformed = [didSast ? "sast" : undefined, didDast ? "dast" : undefined].filter(Boolean) as string[];
    const testSummary: any = {
      ...(didSast ? { sast: { performed: true, status: sastStatus } } : {}),
      ...(didDast ? { dast: { performed: true, status: dastStatus } } : {}),
    };

    if (nodeId) {
      if (incomingAgentState.metadata) {
        agentVariables = mergeAgentVariables(agentVariables, "AGENT", { metadata: incomingAgentState.metadata });
      }
      if (input.includeServerAgentState) {
        agentVariables = mergeAgentVariables(agentVariables, "SERVER", {
          server: input.server.name,
          server_version: input.server.version,
          check_level: checkLevel,
          decision,
          status: error ? "error" : "ok",
          latency_ms: latency,
          risk_tags: riskTags,
          ...(ap2IntentId ? { ap2_intent_id: ap2IntentId } : {}),
          ...(ap2CartId ? { ap2_cart_id: ap2CartId } : {}),
          ...(ctx.headers?.["x-ap2-intent-id"] ? { header_ap2_intent: ctx.headers["x-ap2-intent-id"] } : {}),
          ...(ctx.headers?.["x-ap2-cart-id"] ? { header_ap2_cart: ctx.headers["x-ap2-cart-id"] } : {}),
        });
      }
      if (input.includeToolAgentState) {
        const toolVars: Record<string, unknown> = {
          tool: input.nameAtVersion,
          tool_name: toolBaseName,
          tool_version: currentVersion,
          decision,
          status: error ? "error" : "ok",
          latency_ms: latency,
          risk_tags: riskTags,
          ...(authObj?.scheme ? { auth_scheme: authObj.scheme } : {}),
          ...(authObj?.token_sha256 ? { auth_token_sha256: authObj.token_sha256 } : {}),
          ...(agentFindings && agentFindings.length ? { agent_guard_findings: agentFindings.length } : {}),
          ...(sastStatus ? { sast_status: sastStatus } : {}),
          ...(dastStatus ? { dast_status: dastStatus } : {}),
        };
        agentVariables = mergeAgentVariables(agentVariables, "TOOL", toolVars);
      }
    }
    const agentVariablesPayload = nodeId && agentVariables && Object.keys(agentVariables).length ? agentVariables : undefined;
    const agentRefValue = agentRunId;

    const { traceId, spanId, causeTraceId, causeSpanId } = deriveTraceContext({
      headers: ctx.headers,
      spanTraceId: spanCtx?.traceId,
      spanSpanId: spanCtx?.spanId,
    });
    invocationState.riskTags = [...riskTags];
    invocationState.decisionReason = decisionReason;
    invocationState.egressDomain = egressDomain;
    invocationState.fsPath = fsPath;
    invocationState.authObj = authObj;
    syncInvocationState();
    const escalation = await createEscalationFromState({
      state: invocationState,
      policy: policyObj as PolicyObject,
      escalationReporter: input.escalationReporter,
      tenant: effectiveTenant,
      server: { name: input.server.name, version: input.server.version },
      tool: input.nameAtVersion,
      ctx,
      nodeId: nodeId || undefined,
      agentRef: agentRefValue || undefined,
      traceId,
      spanId,
    });
    invocationState.escalationResult = escalation.escalationResult;
    invocationState.escalationFailure = escalation.escalationFailure;
    syncLocalsFromInvocationState();
    stampResultTracing(result, traceId, spanId);
    syncInvocationState();
    await captureRawPayloads({
      rawPayloadConfig: input.rawPayloadConfig,
      auditSink: input.auditSink,
      tenant: effectiveTenant,
      environment: effectiveEnv,
      client: effectiveClientName,
      clientVersion: effectiveClientVersion,
      state: invocationState,
      nodeId: nodeId || undefined,
      agentRef: agentRefValue || undefined,
      traceId,
      spanId,
      tool: input.nameAtVersion,
      ctx,
      agentVariables: agentVariablesPayload,
    });
    const envelope: any = buildAuditEnvelope({
      sdkVersion: input.sdkVersion,
      middlewareHop: input.opts.middlewareHop,
      state: invocationState,
      startedAt: start,
      server: { name: input.server.name, version: input.server.version },
      tool: input.nameAtVersion,
      currentVersion,
      ctx,
      latency,
      tenant: effectiveTenant,
      environment: effectiveEnv,
      client: effectiveClientName,
      clientVersion: effectiveClientVersion,
      traceId,
      spanId,
      causeTraceId,
      causeSpanId,
      retention: policyObj.default_retention,
      registryFrozen: input.registryState.isFrozen(),
      registrySnapshotHash: input.registryState.initialServerSnapshotHash,
      checkLevel,
      checkKind,
      nodeId: nodeId || undefined,
      agentRef: agentRefValue || undefined,
      agentVariables: agentVariablesPayload,
      testsPerformed,
      testSummary,
      compliance,
      vulnRefs,
      ap2: {
        intentId: ap2IntentId,
        cartId: ap2CartId,
        constraintsSha256: ap2ConstraintsSha256,
        cartSha256: ap2CartSha256,
        issuerDid: ap2IssuerDid,
        subjectDid: ap2SubjectDid,
      },
    });
    try {
      if (input.opts.augment) {
        const extra = await Promise.resolve(
          input.opts.augment({
            tenant: input.opts.otel.tenant ?? "unknown",
            server: { name: input.server.name, version: input.server.version },
            tool: input.nameAtVersion,
            ctx,
          }),
        );
        if (extra?.envelope) Object.assign(envelope, extra.envelope);
        if (extra?.span) addAttrs(extra.span);
      }
    } catch {}
    try {
      await input.auditSink.append(envelope as any);
    } catch (signErr: any) {
      if (await shouldRuntimeDeny(["missing_audit_signature"], { requestIdSuffix: "audit-signature" })) {
        error = new SigningFailedError(signErr?.message);
      }
    }

    addAttrs({
      "policy.decision": decision,
      "audit.input_sha256": inputHash ?? "",
      "audit.output_sha256": outputHash ?? "",
      "retention.class": policyObj.default_retention,
      "idempotency.key": ctx.idempotencyKey ?? "",
      ...(invocationState.escalationResult?.id ? { "escalation.id": invocationState.escalationResult.id } : {}),
      ...(invocationState.escalationResult?.status ? { "escalation.status": invocationState.escalationResult.status } : {}),
      ...(invocationState.escalationFailure ? { "escalation.error": invocationState.escalationFailure } : {}),
      "status.code": error ? 2 : 1,
      "latency_ms": latency,
    });
    input.invocationStats.pushStat(input.nameAtVersion, !error, latency);
    if (input.telemetryEnabled) {
      if (error) endSpanErr(span, error, latency); else endSpanOk(span, latency);
    }

    if (error) {
      if (invocationState.escalationResult?.id) {
        try {
          (error as any).escalation = invocationState.escalationResult;
          (error as any).escalation_id = invocationState.escalationResult.id;
          (error as any).escalation_status = invocationState.escalationResult.status;
        } catch {}
      }
      throw error;
    }
    return result;
  };
}
