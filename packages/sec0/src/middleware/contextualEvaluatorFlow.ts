import type { ContextualEvaluationExecution } from "../evaluator";
import type { PolicyObject } from "../policy";
import { buildDetectorContextEvaluatorPatch, createContextualEvaluatorManager, defaultContextualEvaluatorEligible, mergeEvaluatorInput } from "../evaluator";
import type { AgentStatePayload } from "../agent-state";
import type { AgentGuardFinding } from "./agentGuard";
import {
  buildDefaultMiddlewareEvaluatorInput,
  extractInlineEvaluatorContext,
  mapContextualEvaluatorFindingToAgentFinding,
} from "./evaluatorUtils";
import type { IdentityContext } from "./identity";
import type { PolicyViolation, MiddlewareOptions } from "./middlewareTypes";
import { extractObjective } from "./runContext";
import { inferOp, toolUri } from "./tooling";
import { resolveDetectorContextualViolation } from "../evaluator";

type ContextualEvaluatorManager = ReturnType<typeof createContextualEvaluatorManager>;
type ContextualBuildContext = NonNullable<NonNullable<MiddlewareOptions["contextualEvaluator"]>["buildContext"]>;

export type RunContextualEvaluationInput = {
  manager: ContextualEvaluatorManager;
  options?: MiddlewareOptions["contextualEvaluator"];
  tenant?: string;
  server: { name: string; version: string };
  tool: string;
  ctx: { args: any; idempotencyKey?: string | null; headers?: Record<string, string> };
  nodeId?: string;
  agentRunId?: string;
  policy: PolicyObject;
  agentVariables?: Record<string, unknown>;
  incomingAgentState: AgentStatePayload;
  identity?: IdentityContext;
  violation: PolicyViolation | null;
  findings?: AgentGuardFinding[];
  content: unknown;
  addAttrs: (attrs: Record<string, unknown>) => void;
  includeContextualFindingInAgentFindings?: boolean;
};

export type RunContextualEvaluationResult = {
  findings?: AgentGuardFinding[];
  violation: PolicyViolation | null;
  contextualViolation: PolicyViolation | null;
  contextualFinding: ContextualEvaluationExecution["finding"] | null;
  contextualAgentFindings: AgentGuardFinding[];
};

export async function runContextualEvaluation(
  input: RunContextualEvaluationInput,
): Promise<RunContextualEvaluationResult> {
  if (!input.manager.enabled) {
    return {
      findings: input.findings,
      violation: input.violation,
      contextualViolation: null,
      contextualFinding: null,
      contextualAgentFindings: [],
    };
  }

  const op = inferOp(input.tool, input.ctx.args);
  const objective = extractObjective(input.agentVariables, input.incomingAgentState);
  const defaultEvaluatorInput = buildDefaultMiddlewareEvaluatorInput({
    tenant: input.tenant,
    server: input.server,
    tool: input.tool,
    toolRef: toolUri(input.server.name, input.tool),
    op,
    ctx: input.ctx,
    nodeId: input.nodeId,
    agentRunId: input.agentRunId,
    objective,
    identity: input.identity,
  });
  const detectorPatch = buildDetectorContextEvaluatorPatch({
    findings: input.findings,
    violation: input.violation,
    content: input.content,
  });
  const inlineOverride = extractInlineEvaluatorContext(input.ctx);
  let callbackOverride = null as Awaited<ReturnType<ContextualBuildContext>> | null | undefined;
  if (input.options?.buildContext) {
    try {
      callbackOverride = await Promise.resolve(
        input.options.buildContext({
          tenant: input.tenant,
          server: input.server,
          tool: input.tool,
          toolRef: toolUri(input.server.name, input.tool),
          op,
          ctx: input.ctx,
          nodeId: input.nodeId,
          agentRunId: input.agentRunId,
          policy: input.policy,
          objective,
          identity: input.identity,
          explicitReasons: input.violation ? [input.violation] : [],
          defaultInput: defaultEvaluatorInput,
        }),
      );
    } catch (builderError: any) {
      console.warn(
        "[sec0-evaluator] middleware buildContext failed",
        builderError instanceof Error ? builderError.message : String(builderError || "unknown"),
      );
    }
  }

  // Build the final evaluator payload in precedence order: default context,
  // detector-derived signals, inline overrides, then caller-provided overrides.
  const evaluatorInput = mergeEvaluatorInput(
    mergeEvaluatorInput(
      mergeEvaluatorInput(defaultEvaluatorInput, detectorPatch),
      inlineOverride,
    ),
    callbackOverride,
  );
  const eligible = input.options?.eligible
    ? input.options.eligible({
        server: input.server,
        tool: input.tool,
        toolRef: toolUri(input.server.name, input.tool),
        op,
        ctx: input.ctx,
        nodeId: input.nodeId,
        agentRunId: input.agentRunId,
        policy: input.policy,
        explicitReasons: input.violation ? [input.violation] : [],
        input: evaluatorInput,
      })
    : defaultContextualEvaluatorEligible(evaluatorInput);
  input.addAttrs({
    "evaluator.source": input.manager.source,
    "evaluator.mode": input.manager.mode,
    "evaluator.eligible": eligible,
  });
  if (!eligible) {
    return {
      findings: input.findings,
      violation: input.violation,
      contextualViolation: null,
      contextualFinding: null,
      contextualAgentFindings: [],
    };
  }

  let evaluation = null as ContextualEvaluationExecution | null;
  if (input.manager.mode === "async") {
    input.manager.schedule(evaluatorInput);
  } else {
    evaluation = await input.manager.evaluate(evaluatorInput);
  }

  if (!evaluation) {
    return {
      findings: input.findings,
      violation: input.violation,
      contextualViolation: null,
      contextualFinding: null,
      contextualAgentFindings: [],
    };
  }

  input.addAttrs({
    "evaluator.decision": evaluation.output.decision,
    "evaluator.confidence": evaluation.output.confidence,
    "evaluator.principles": evaluation.output.principles.join(","),
  });

  const contextualViolation =
    evaluation.output.decision === "deny"
      ? "contextual_evaluator_denied"
      : evaluation.output.decision === "escalate"
        ? "contextual_evaluator_escalated"
        : null;
  const adjudicated = resolveDetectorContextualViolation({
    violation: input.violation,
    findings: input.findings,
    contextualDecision: evaluation.output.decision,
    contextualFingerprint: evaluation.finding.fingerprint,
  });
  const contextualAgentFindings =
    evaluation.output.decision === "allow"
      ? []
      : [mapContextualEvaluatorFindingToAgentFinding(evaluation.finding, "run")];
  let findings = adjudicated.findings.length ? adjudicated.findings : input.findings;
  if (input.includeContextualFindingInAgentFindings && contextualAgentFindings.length) {
    findings = [...(findings || []), ...contextualAgentFindings];
  }

  // Hybrid control-plane mode blocks on the current decision and still schedules
  // an asynchronous follow-up so the remote evaluator can observe the full stream.
  if (input.manager.mode === "hybrid" && input.manager.source === "control-plane") {
    input.manager.schedule(evaluatorInput);
  }

  return {
    findings,
    violation: adjudicated.violation as PolicyViolation | null,
    contextualViolation,
    contextualFinding: evaluation.finding,
    contextualAgentFindings,
  };
}
