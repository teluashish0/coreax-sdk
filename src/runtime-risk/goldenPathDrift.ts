import type {
  GoldenPathEvidence,
  RiskComputationResult,
  RuntimeRiskEvent,
  RuntimeRiskSignal,
} from "./types";
import {
  baselineReadiness,
  assertUniqueEventIds,
  clamp,
  finiteConfigNumber,
  safeIdentifier,
  safeModelVersion,
  severityFromScore,
  sortedEvents,
  stripToolVersion,
  toHop,
} from "./util";

export type GoldenPathDriftConfig = {
  modelVersion: string;
  minimumBaselineEvents: number;
  minimumBaselineRuns: number;
  smoothingAlpha: number;
  nllMaximum: number;
  transitionSignalNll: number;
  aggregateSignalThreshold: number;
};

export const DEFAULT_GOLDEN_PATH_DRIFT_CONFIG: GoldenPathDriftConfig =
  Object.freeze({
    modelVersion: "coreax-runtime-risk-v1",
    minimumBaselineEvents: 5,
    minimumBaselineRuns: 3,
    smoothingAlpha: 0.5,
    nllMaximum: 4,
    transitionSignalNll: 3,
    aggregateSignalThreshold: 60,
  });

export type GoldenPathDriftInput = {
  nodeId: string;
  events: readonly RuntimeRiskEvent[];
  baselineEvents: readonly RuntimeRiskEvent[];
  /** Include node identity when learning an entire run's cross-node path. */
  includeNodeIdInToken?: boolean;
  config?: Partial<GoldenPathDriftConfig>;
};

export type GoldenPathStepScore = {
  eventId: string;
  timestamp: string;
  token: string;
  previousToken: string;
  probability: number;
  negativeLogLikelihood: number;
  observedCount: number;
  novelToken: boolean;
  sourceObserved: boolean;
  score: number;
};

type TransitionModel = Map<string, Map<string, number>>;

const START_TOKEN = "__START__";
const END_TOKEN = "__END__";

export function goldenPathToken(
  event: RuntimeRiskEvent,
  includeNodeId = false,
): string {
  const parts = [
    safeIdentifier(event.nodeType ?? "unknown"),
    safeIdentifier(event.server ?? "unknown"),
    safeIdentifier(stripToolVersion(event.tool ?? "unknown")),
  ];
  if (includeNodeId) parts.unshift(safeIdentifier(event.nodeId));
  return parts.join(":");
}

function sequence(
  events: readonly RuntimeRiskEvent[],
  includeNodeId: boolean,
): {
  events: RuntimeRiskEvent[];
  tokens: string[];
} {
  const ordered = sortedEvents(events);
  return {
    events: ordered,
    tokens: ordered.map((event) => goldenPathToken(event, includeNodeId)),
  };
}

function increment(
  model: TransitionModel,
  from: string,
  to: string,
): void {
  const transitions = model.get(from) ?? new Map<string, number>();
  transitions.set(to, (transitions.get(to) ?? 0) + 1);
  model.set(from, transitions);
}

function buildModel(
  events: readonly RuntimeRiskEvent[],
  includeNodeId: boolean,
): {
  model: TransitionModel;
  vocabularySize: number;
  vocabulary: Set<string>;
} {
  const byRun = new Map<string, RuntimeRiskEvent[]>();
  for (const event of events) {
    const runEvents = byRun.get(event.runId) ?? [];
    runEvents.push(event);
    byRun.set(event.runId, runEvents);
  }
  const model: TransitionModel = new Map();
  const vocabulary = new Set<string>([END_TOKEN]);
  for (const runEvents of [...byRun.entries()].sort(([left], [right]) =>
    left.localeCompare(right),
  ).map(([, value]) => value)) {
    let previous = START_TOKEN;
    for (const token of sequence(runEvents, includeNodeId).tokens) {
      vocabulary.add(token);
      increment(model, previous, token);
      previous = token;
    }
    increment(model, previous, END_TOKEN);
  }
  // Reserve one bucket for an unseen token.
  return {
    model,
    vocabularySize: Math.max(1, vocabulary.size + 1),
    vocabulary,
  };
}

function transitionProbability(
  model: TransitionModel,
  from: string,
  to: string,
  alpha: number,
  vocabularySize: number,
): { probability: number; observedCount: number } {
  const transitions = model.get(from);
  const total = transitions
    ? [...transitions.values()].reduce((sum, count) => sum + count, 0)
    : 0;
  const observedCount = transitions?.get(to) ?? 0;
  const smoothing = Math.max(0.000001, alpha);
  return {
    probability:
      (observedCount + smoothing) /
      (total + smoothing * Math.max(1, vocabularySize)),
    observedCount,
  };
}

function resolvedConfig(
  overrides: Partial<GoldenPathDriftConfig> | undefined,
): GoldenPathDriftConfig {
  const merged = { ...DEFAULT_GOLDEN_PATH_DRIFT_CONFIG, ...overrides };
  return {
    ...merged,
    modelVersion: safeModelVersion(merged.modelVersion),
    minimumBaselineEvents: finiteConfigNumber(
      merged.minimumBaselineEvents,
      "goldenPathDrift.minimumBaselineEvents",
      { minimum: 1, maximum: 1_000_000, integer: true },
    ),
    minimumBaselineRuns: finiteConfigNumber(
      merged.minimumBaselineRuns,
      "goldenPathDrift.minimumBaselineRuns",
      { minimum: 1, maximum: 1_000_000, integer: true },
    ),
    smoothingAlpha: finiteConfigNumber(
      merged.smoothingAlpha,
      "goldenPathDrift.smoothingAlpha",
      { minimum: 0, maximum: 100, exclusiveMinimum: true },
    ),
    nllMaximum: finiteConfigNumber(
      merged.nllMaximum,
      "goldenPathDrift.nllMaximum",
      { minimum: 0, maximum: 1_000, exclusiveMinimum: true },
    ),
    transitionSignalNll: finiteConfigNumber(
      merged.transitionSignalNll,
      "goldenPathDrift.transitionSignalNll",
      { minimum: 0, maximum: 1_000 },
    ),
    aggregateSignalThreshold: finiteConfigNumber(
      merged.aggregateSignalThreshold,
      "goldenPathDrift.aggregateSignalThreshold",
      { minimum: 0, maximum: 100 },
    ),
  };
}

export function computeGoldenPathStepScores(
  input: GoldenPathDriftInput,
): {
  steps: GoldenPathStepScore[];
  baseline: ReturnType<typeof baselineReadiness>;
  modelVersion: string;
} {
  const config = resolvedConfig(input.config);
  assertUniqueEventIds([...input.events, ...input.baselineEvents]);
  // Validate current event chronology even when the historical baseline is not
  // yet large enough to produce a score.
  sortedEvents(input.events);
  const baselineEvents = sortedEvents(input.baselineEvents);
  const readiness = baselineReadiness(
    baselineEvents,
    config.minimumBaselineEvents,
    config.minimumBaselineRuns,
  );
  if (!readiness.ready) {
    return { steps: [], baseline: readiness, modelVersion: config.modelVersion };
  }
  const current = sequence(input.events, input.includeNodeIdInToken === true);
  const { model, vocabularySize, vocabulary } = buildModel(
    baselineEvents,
    input.includeNodeIdInToken === true,
  );
  const steps: GoldenPathStepScore[] = [];
  let previous = START_TOKEN;
  const appendStep = (token: string, event: RuntimeRiskEvent): void => {
    const sourceObserved = model.has(previous);
    const { probability, observedCount } = transitionProbability(
      model,
      previous,
      token,
      config.smoothingAlpha,
      vocabularySize,
    );
    const negativeLogLikelihood = -Math.log(Math.max(1e-12, probability));
    const novelToken = !vocabulary.has(token);
    const likelihoodScore = clamp(
      (negativeLogLikelihood / Math.max(0.0001, config.nllMaximum)) * 100,
      0,
      100,
    );
    steps.push({
      eventId: safeIdentifier(event.id),
      timestamp: toHop(event).timestamp,
      token,
      previousToken: previous,
      probability,
      negativeLogLikelihood,
      observedCount,
      novelToken,
      sourceObserved,
      score:
        novelToken || observedCount === 0
          ? Math.max(60, likelihoodScore)
          : likelihoodScore,
    });
    previous = token;
  };
  for (let index = 0; index < current.tokens.length; index += 1) {
    appendStep(current.tokens[index], current.events[index]);
  }
  if (current.events.length > 0) {
    appendStep(END_TOKEN, current.events[current.events.length - 1]);
  }
  return { steps, baseline: readiness, modelVersion: config.modelVersion };
}

export function computeGoldenPathDrift(
  input: GoldenPathDriftInput,
): RiskComputationResult<GoldenPathEvidence> {
  const config = resolvedConfig(input.config);
  const current = sequence(input.events, input.includeNodeIdInToken === true);
  const result = computeGoldenPathStepScores(input);
  if (!result.baseline.ready || current.events.length === 0) {
    return {
      score: 0,
      evidence: {
        baseline: result.baseline,
        expected: { source: "none" },
        observed: {
          tokens: current.tokens,
          hopsInOrder: current.events.map(toHop),
        },
        deviations: [],
      },
      signals: [],
      modelVersion: config.modelVersion,
    };
  }

  const deviations: GoldenPathEvidence["deviations"] = [];
  for (let index = 0; index < result.steps.length; index += 1) {
    const step = result.steps[index];
    if (step.token === END_TOKEN && !step.sourceObserved) continue;
    if (
      !step.novelToken &&
      step.observedCount > 0 &&
      step.negativeLogLikelihood < config.transitionSignalNll
    ) {
      continue;
    }
    deviations.push({
      kind: step.novelToken ? "unexpected_token" : "unexpected_transition",
      atIndex: index,
      hop: toHop(
        current.events[Math.min(index, current.events.length - 1)],
      ),
      details: {
        from: step.previousToken,
        to: step.token,
        probability: step.probability,
        observedCount: step.observedCount,
      },
    });
  }
  const averageNegativeLogLikelihood =
    result.steps.reduce(
      (sum, step) => sum + step.negativeLogLikelihood,
      0,
    ) / Math.max(1, result.steps.length);
  const averageScore = clamp(
    (averageNegativeLogLikelihood / Math.max(0.0001, config.nllMaximum)) *
      100,
    0,
    100,
  );
  const deviationIndexes = new Set(
    deviations
      .map((deviation) => deviation.atIndex)
      .filter((index): index is number => index !== undefined),
  );
  const score = Math.max(
    averageScore,
    ...result.steps
      .filter((_, index) => deviationIndexes.has(index))
      .map((step) => step.score),
  );
  const evidence: GoldenPathEvidence = {
    baseline: result.baseline,
    expected: {
      source: "learned",
      modelId: `markov1:${safeIdentifier(input.nodeId)}`,
    },
    observed: {
      tokens: current.tokens,
      hopsInOrder: current.events.map(toHop),
    },
    deviations,
  };
  const signals: RuntimeRiskSignal[] = [];
  if (score >= config.aggregateSignalThreshold) {
    signals.push({
      code: "golden_path_drift:aggregate",
      subtype: "golden_path_drift",
      severity: severityFromScore(score),
      score,
      title: "Golden path drift detected",
      message: `Sequence drift score ${Math.round(score)} for node ${safeIdentifier(input.nodeId)}`,
      evidence: {
        averageNegativeLogLikelihood,
        deviationCount: deviations.length,
      },
      hop: toHop(current.events[current.events.length - 1]),
    });
  }
  for (const deviation of deviations.slice(0, 3)) {
    signals.push({
      code:
        deviation.kind === "unexpected_token"
          ? "golden_path_drift:novel_token"
          : "golden_path_drift:transition",
      subtype: "golden_path_drift",
      severity: "high",
      score: 60,
      title:
        deviation.kind === "unexpected_token"
          ? "Novel golden-path token"
          : "Unexpected transition",
      evidence: deviation.details,
      hop: deviation.hop,
    });
  }
  return {
    score,
    evidence,
    signals,
    modelVersion: config.modelVersion,
  };
}
