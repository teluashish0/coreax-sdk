import {
  createLocalContextualEvaluator,
  type LocalContextualEvaluatorOptions,
} from "./local";
import {
  EvaluatorInputSchema,
  EvaluatorModeSchema,
  EvaluatorOutputSchema,
  EvaluatorSourceSchema,
  type EvaluatorInput,
  type EvaluatorMode,
  type EvaluatorOutput,
  type EvaluatorPrinciple,
  type EvaluatorSeverity,
  type EvaluatorSource,
} from "./types";
import { compactText, hashFingerprint } from "./classification";

export interface ContextualEvaluatorAdapter {
  evaluate(input: EvaluatorInput): Promise<EvaluatorOutput | null>;
}
export type ContextualEvaluatorFinding = {
  source: "evaluator";
  code: "contextual_evaluator";
  severity: EvaluatorSeverity;
  message: string;
  evidence?: string;
  confidence: number;
  principles: EvaluatorPrinciple[];
  fingerprint: string;
  summary: string;
  reasoning: string;
  snapshot: {
    inputSha256: string;
    outputSha256: string;
  };
};

export type ContextualEvaluatorManagerConfig = {
  evaluatorSource: EvaluatorSource;
  evaluatorMode: EvaluatorMode;
  debug?: boolean;
  logger?: (event: {
    level: "debug" | "warn";
    message: string;
    data?: Record<string, unknown>;
  }) => void;
  local?: LocalContextualEvaluatorOptions;
  custom?: {
    adapter: ContextualEvaluatorAdapter;
  };
};

export type ContextualEvaluationExecution = {
  source: Exclude<EvaluatorSource, "disabled">;
  mode: EvaluatorMode;
  output: EvaluatorOutput;
  finding: ContextualEvaluatorFinding;
};

export type ContextualEvaluationScheduleHooks = {
  onResult?: (
    result: ContextualEvaluationExecution | null,
  ) => Promise<void> | void;
};

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function logEvent(
  config: ContextualEvaluatorManagerConfig,
  level: "debug" | "warn",
  message: string,
  data?: Record<string, unknown>,
) {
  config.logger?.({ level, message, ...(data ? { data } : {}) });
  if (!config.debug) return;
  const printer = level === "warn" ? console.warn : console.log;
  printer("[coreax-evaluator]", message, data ?? "");
}

export function buildContextualEvaluatorFinding(
  input: EvaluatorInput,
  output: EvaluatorOutput,
): ContextualEvaluatorFinding {
  const evidenceHash =
    output.evidence.length > 0
      ? `sha256:${hashFingerprint(output.evidence)}`
      : undefined;
  const decisionSummary = `Contextual evaluator decision: ${output.decision}.`;
  return {
    source: "evaluator",
    code: "contextual_evaluator",
    severity: output.suggestedSeverity,
    message: decisionSummary,
    ...(evidenceHash ? { evidence: evidenceHash } : {}),
    confidence: output.confidence,
    principles: [...output.principles],
    fingerprint: hashFingerprint(output.normalizedFingerprint),
    summary: decisionSummary,
    reasoning: `Evaluator detail sha256:${hashFingerprint({
      summary: output.summary,
      reasoning: output.reasoning,
      evidence: output.evidence,
    })}.`,
    snapshot: {
      inputSha256: hashFingerprint(input),
      outputSha256: hashFingerprint(output),
    },
  };
}

const DECISION_RANK: Record<EvaluatorOutput["decision"], number> = {
  allow: 0,
  clarify: 1,
  escalate: 2,
  deny: 3,
};
const SEVERITY_RANK: Record<EvaluatorSeverity, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

function selectMonotonicOutput(
  deterministic: EvaluatorOutput,
  custom: EvaluatorOutput,
): { output: EvaluatorOutput; source: "local" | "custom" } {
  if (
    DECISION_RANK[custom.decision] <= DECISION_RANK[deterministic.decision]
  ) {
    return { output: deterministic, source: "local" };
  }
  const principles = Array.from(
    new Set([...deterministic.principles, ...custom.principles]),
  ).sort();
  const suggestedSeverity =
    SEVERITY_RANK[custom.suggestedSeverity] >=
    SEVERITY_RANK[deterministic.suggestedSeverity]
      ? custom.suggestedSeverity
      : deterministic.suggestedSeverity;
  return {
    source: "custom",
    output: EvaluatorOutputSchema.parse({
      ...custom,
      confidence: Math.max(deterministic.confidence, custom.confidence),
      principles,
      reasoning: compactText(
        `${deterministic.reasoning} ${custom.reasoning}`,
        4000,
      ),
      evidence: [...deterministic.evidence, ...custom.evidence].slice(0, 50),
      evidenceRefs: Array.from(
        new Set([
          ...deterministic.evidenceRefs,
          ...custom.evidenceRefs,
        ]),
      ).slice(0, 100),
      suggestedSeverity,
      suggestedRemediation: {
        summary: custom.suggestedRemediation.summary,
        steps: Array.from(
          new Set([
            ...deterministic.suggestedRemediation.steps,
            ...custom.suggestedRemediation.steps,
          ]),
        ).slice(0, 20),
      },
      normalizedFingerprint: hashFingerprint({
        deterministic: deterministic.normalizedFingerprint,
        custom: custom.normalizedFingerprint,
        decision: custom.decision,
      }),
      missingFacts: Array.from(
        new Set([...deterministic.missingFacts, ...custom.missingFacts]),
      ).slice(0, 100),
      questions: Array.from(
        new Set([...deterministic.questions, ...custom.questions]),
      ).slice(0, 100),
      suggestedSources: Array.from(
        new Set([
          ...deterministic.suggestedSources,
          ...custom.suggestedSources,
        ]),
      ).slice(0, 100),
      resumeConditions: Array.from(
        new Set([
          ...deterministic.resumeConditions,
          ...custom.resumeConditions,
        ]),
      ).slice(0, 100),
    }),
  };
}

export function createContextualEvaluatorManager(
  config: ContextualEvaluatorManagerConfig,
) {
  const evaluatorSource = EvaluatorSourceSchema.parse(config.evaluatorSource);
  const evaluatorMode = EvaluatorModeSchema.parse(config.evaluatorMode);

  const localAdapter =
    evaluatorSource === "disabled"
      ? null
      : createLocalContextualEvaluator(config.local);
  let customAdapter: ContextualEvaluatorAdapter | null = null;
  if (evaluatorSource === "custom") {
    customAdapter = config.custom?.adapter ?? null;
    if (!customAdapter) {
      throw new Error(
        '[coreax-evaluator] evaluatorSource="custom" requires custom.adapter',
      );
    }
  }

  logEvent(config, "debug", "configured", {
    evaluatorSource,
    evaluatorMode,
  });

  const runOnce = async (
    rawInput: EvaluatorInput,
  ): Promise<ContextualEvaluationExecution | null> => {
    if (!localAdapter || evaluatorSource === "disabled") return null;
    const input = EvaluatorInputSchema.parse(rawInput);
    const deterministicRaw = await localAdapter.evaluate(input);
    if (!deterministicRaw) {
      throw new Error("Local contextual evaluator returned no decision");
    }
    const deterministic = EvaluatorOutputSchema.parse(deterministicRaw);
    let source: "local" | "custom" = "local";
    let output = deterministic;
    if (customAdapter && deterministic.decision !== "deny") {
      const customRaw = await customAdapter.evaluate(input);
      if (!customRaw) {
        throw new Error("Custom contextual evaluator returned no decision");
      }
      const selected = selectMonotonicOutput(
        deterministic,
        EvaluatorOutputSchema.parse(customRaw),
      );
      source = selected.source;
      output = selected.output;
    }
    return {
      source,
      mode: evaluatorMode,
      output,
      finding: buildContextualEvaluatorFinding(input, output),
    };
  };

  return {
    source: evaluatorSource,
    mode: evaluatorMode,
    enabled: evaluatorSource !== "disabled",
    async evaluate(
      input: EvaluatorInput,
    ): Promise<ContextualEvaluationExecution | null> {
      try {
        return await runOnce(input);
      } catch (error: unknown) {
        logEvent(config, "warn", "evaluation_failed", {
          evaluatorSource,
          evaluatorMode,
          errorSha256: hashFingerprint(errorMessage(error)),
        });
        throw error;
      }
    },
    schedule(
      input: EvaluatorInput,
      hooks?: ContextualEvaluationScheduleHooks,
    ): void {
      if (!localAdapter || evaluatorSource === "disabled") return;
      void runOnce(input)
        .then((result) => hooks?.onResult?.(result))
        .catch((error: unknown) => {
          logEvent(config, "warn", "evaluation_failed", {
            evaluatorSource,
            evaluatorMode,
            errorSha256: hashFingerprint(errorMessage(error)),
          });
          return hooks?.onResult?.(null);
        })
        .catch((error: unknown) => {
          logEvent(config, "warn", "schedule_callback_failed", {
            evaluatorSource,
            evaluatorMode,
            errorSha256: hashFingerprint(errorMessage(error)),
          });
        });
    },
  };
}
