import {
  DEFAULT_CHARACTER_NGRAM_VECTORIZER_CONFIG,
  addVectorInPlace,
  cosineDistance,
  cosineSimilarity,
  validateCharacterNgramVectorizerConfig,
  vectorizeCharacterNgrams,
  type CharacterNgramVectorizerConfig,
} from "./stringVectorizer";
import type {
  BehaviorDriftEvidence,
  CategoricalDriftFeature,
  NumericDriftFeature,
  RiskComputationResult,
  RuntimeRiskEvent,
  RuntimeRiskSignal,
  RuntimeStateScope,
  StringDriftFeature,
} from "./types";
import {
  baselineReadiness,
  assertUniqueEventIds,
  clamp,
  clamp01,
  extractRiskTags,
  finiteConfigNumber,
  flattenStringValues,
  mean,
  safeIdentifier,
  safeModelVersion,
  severityFromScore,
  sha256Hex,
  sortedEvents,
  standardDeviation,
  stripToolVersion,
  toHop,
} from "./util";

export type BehaviorDriftWeights = {
  latencyMs: number;
  denyRate: number;
  tool: number;
  operation: number;
  reasonCode: number;
  riskTag: number;
  stringState: number;
};

export type BehaviorDriftConfig = {
  modelVersion: string;
  minimumBaselineEvents: number;
  minimumBaselineRuns: number;
  weights: BehaviorDriftWeights;
  aggregateSignalThreshold: number;
  featureSignalThreshold: number;
  numericZMaximum: number;
  categoricalSurpriseMaximum: number;
  string: {
    vectorizer: CharacterNgramVectorizerConfig;
    distanceMaximum: number;
    zMaximum: number;
    maximumFeatures: number;
    maximumBaselineSamplesPerFeature: number;
    includeScopes: RuntimeStateScope[];
    allowlistKeys?: ReadonlySet<string>;
    excludeLeafKeys?: ReadonlySet<string>;
  };
};

export type BehaviorDriftConfigOverrides = Partial<
  Omit<BehaviorDriftConfig, "weights" | "string">
> & {
  weights?: Partial<BehaviorDriftWeights>;
  string?: Partial<Omit<BehaviorDriftConfig["string"], "vectorizer">> & {
    vectorizer?: Partial<CharacterNgramVectorizerConfig>;
  };
};

export const DEFAULT_BEHAVIOR_DRIFT_CONFIG: BehaviorDriftConfig = {
  modelVersion: "coreax-runtime-risk-v1",
  minimumBaselineEvents: 5,
  minimumBaselineRuns: 3,
  weights: {
    latencyMs: 0.2,
    denyRate: 0.15,
    tool: 0.15,
    operation: 0.05,
    reasonCode: 0.15,
    riskTag: 0.1,
    stringState: 0.2,
  },
  aggregateSignalThreshold: 60,
  featureSignalThreshold: 30,
  numericZMaximum: 4,
  categoricalSurpriseMaximum: 4,
  string: {
    vectorizer: DEFAULT_CHARACTER_NGRAM_VECTORIZER_CONFIG,
    distanceMaximum: 0.6,
    zMaximum: 4,
    maximumFeatures: 10,
    maximumBaselineSamplesPerFeature: 40,
    includeScopes: ["AGENT", "ORCHESTRATOR"],
  },
};

export type BehaviorDriftInput = {
  nodeId: string;
  events: readonly RuntimeRiskEvent[];
  baselineEvents: readonly RuntimeRiskEvent[];
  config?: BehaviorDriftConfigOverrides;
};

type CategoryStats = {
  counts: Map<string, number>;
  total: number;
};

function mergeConfig(
  overrides: BehaviorDriftConfigOverrides | undefined,
): BehaviorDriftConfig {
  const merged: BehaviorDriftConfig = {
    ...DEFAULT_BEHAVIOR_DRIFT_CONFIG,
    ...overrides,
    weights: {
      ...DEFAULT_BEHAVIOR_DRIFT_CONFIG.weights,
      ...overrides?.weights,
    },
    string: {
      ...DEFAULT_BEHAVIOR_DRIFT_CONFIG.string,
      ...overrides?.string,
      vectorizer: {
        ...DEFAULT_BEHAVIOR_DRIFT_CONFIG.string.vectorizer,
        ...overrides?.string?.vectorizer,
        method: "character_ngram_hash",
      },
    },
  };
  const weightKeys = new Set<keyof BehaviorDriftWeights>([
    "latencyMs",
    "denyRate",
    "tool",
    "operation",
    "reasonCode",
    "riskTag",
    "stringState",
  ]);
  if (
    Object.keys(merged.weights).some(
      (key) => !weightKeys.has(key as keyof BehaviorDriftWeights),
    )
  ) {
    throw new TypeError("behaviorDrift.weights contains an unknown key");
  }
  const validatedWeights = Object.fromEntries(
    Object.entries(merged.weights).map(([key, weight]) => [
      key,
      finiteConfigNumber(weight, `behaviorDrift.weights.${key}`, {
        minimum: 0,
        maximum: 1_000_000,
      }),
    ]),
  ) as unknown as BehaviorDriftWeights;
  const total = Object.values(validatedWeights).reduce(
    (sum, weight) => sum + weight,
    0,
  );
  if (total <= 0) {
    throw new RangeError(
      "behaviorDrift.weights must include at least one positive weight",
    );
  }
  return {
    ...merged,
    modelVersion: safeModelVersion(merged.modelVersion),
    minimumBaselineEvents: finiteConfigNumber(
      merged.minimumBaselineEvents,
      "behaviorDrift.minimumBaselineEvents",
      { minimum: 1, maximum: 1_000_000, integer: true },
    ),
    minimumBaselineRuns: finiteConfigNumber(
      merged.minimumBaselineRuns,
      "behaviorDrift.minimumBaselineRuns",
      { minimum: 1, maximum: 1_000_000, integer: true },
    ),
    weights: Object.fromEntries(
      Object.entries(validatedWeights).map(([key, weight]) => [
        key,
        weight / total,
      ]),
    ) as unknown as BehaviorDriftWeights,
    aggregateSignalThreshold: finiteConfigNumber(
      merged.aggregateSignalThreshold,
      "behaviorDrift.aggregateSignalThreshold",
      { minimum: 0, maximum: 100 },
    ),
    featureSignalThreshold: finiteConfigNumber(
      merged.featureSignalThreshold,
      "behaviorDrift.featureSignalThreshold",
      { minimum: 0, maximum: 100 },
    ),
    numericZMaximum: finiteConfigNumber(
      merged.numericZMaximum,
      "behaviorDrift.numericZMaximum",
      { minimum: 0, maximum: 1_000, exclusiveMinimum: true },
    ),
    categoricalSurpriseMaximum: finiteConfigNumber(
      merged.categoricalSurpriseMaximum,
      "behaviorDrift.categoricalSurpriseMaximum",
      { minimum: 0, maximum: 1_000, exclusiveMinimum: true },
    ),
    string: {
      ...merged.string,
      vectorizer: validateCharacterNgramVectorizerConfig(
        merged.string.vectorizer,
      ),
      distanceMaximum: finiteConfigNumber(
        merged.string.distanceMaximum,
        "behaviorDrift.string.distanceMaximum",
        { minimum: 0, maximum: 2, exclusiveMinimum: true },
      ),
      zMaximum: finiteConfigNumber(
        merged.string.zMaximum,
        "behaviorDrift.string.zMaximum",
        { minimum: 0, maximum: 1_000, exclusiveMinimum: true },
      ),
      maximumFeatures: finiteConfigNumber(
        merged.string.maximumFeatures,
        "behaviorDrift.string.maximumFeatures",
        { minimum: 1, maximum: 10_000, integer: true },
      ),
      maximumBaselineSamplesPerFeature: finiteConfigNumber(
        merged.string.maximumBaselineSamplesPerFeature,
        "behaviorDrift.string.maximumBaselineSamplesPerFeature",
        { minimum: 3, maximum: 1_000_000, integer: true },
      ),
    },
  };
}

function categoryStats(values: readonly string[]): CategoryStats {
  const counts = new Map<string, number>();
  for (const value of values) {
    const normalized = value.trim();
    if (normalized) counts.set(normalized, (counts.get(normalized) ?? 0) + 1);
  }
  return {
    counts,
    total: [...counts.values()].reduce((sum, count) => sum + count, 0),
  };
}

function categoryMode(stats: CategoryStats): string {
  return (
    [...stats.counts.entries()].sort(
      ([leftValue, leftCount], [rightValue, rightCount]) =>
        rightCount - leftCount || leftValue.localeCompare(rightValue),
    )[0]?.[0] ?? ""
  );
}

function categoryProbability(stats: CategoryStats, value: string): number {
  return stats.total > 0 ? (stats.counts.get(value) ?? 0) / stats.total : 0;
}

function topCategoryValues(
  stats: CategoryStats,
): Array<{ value: string; percentage: number }> {
  const denominator = stats.total || 1;
  return [...stats.counts.entries()]
    .sort(
      ([leftValue, leftCount], [rightValue, rightCount]) =>
        rightCount - leftCount || leftValue.localeCompare(rightValue),
    )
    .slice(0, 5)
    .map(([value, count]) => ({
      value: safeIdentifier(value),
      percentage: (count / denominator) * 100,
    }));
}

function contribution(raw: number, weight: number): number {
  return clamp01(raw) * 100 * Math.max(0, weight);
}

function deviationWithZeroVariance(
  current: number,
  baseline: number,
  standardDeviationValue: number,
  maximum: number,
): number {
  if (standardDeviationValue > 0) {
    return (current - baseline) / standardDeviationValue;
  }
  return current === baseline ? 0 : Math.sign(current - baseline) * maximum;
}

function numericFeature(
  key: string,
  currentValues: readonly number[],
  baselineValues: readonly number[],
  weight: number,
  zMaximum: number,
): NumericDriftFeature | undefined {
  if (currentValues.length === 0 || baselineValues.length === 0) return undefined;
  const currentValue = mean(currentValues);
  const baselineMean = mean(baselineValues);
  const baselineDeviation = standardDeviation(baselineValues, baselineMean);
  const zScore = deviationWithZeroVariance(
    currentValue,
    baselineMean,
    baselineDeviation,
    zMaximum,
  );
  const absoluteZScore = Math.abs(zScore);
  return {
    key,
    kind: "number",
    currentValue,
    baseline: {
      mean: baselineMean,
      standardDeviation: baselineDeviation,
      sampleCount: baselineValues.length,
    },
    distance: { zScore, absoluteZScore },
    weight,
    contribution: contribution(absoluteZScore / Math.max(zMaximum, 0.0001), weight),
  };
}

function categoricalFeature(
  key: string,
  currentValues: readonly string[],
  baselineValues: readonly string[],
  weight: number,
  surpriseMaximum: number,
): CategoricalDriftFeature | undefined {
  const currentStats = categoryStats(currentValues);
  const baselineStats = categoryStats(baselineValues);
  if (currentStats.total === 0 || baselineStats.total === 0) return undefined;
  const currentValue = categoryMode(currentStats);
  const probability = categoryProbability(baselineStats, currentValue);
  const surprise = -Math.log(Math.max(0.000001, Math.min(1, probability)));
  return {
    key,
    kind: "categorical",
    currentValue: safeIdentifier(currentValue),
    baseline: {
      topValues: topCategoryValues(baselineStats),
      sampleCount: baselineStats.total,
    },
    distance: { surprise },
    weight,
    contribution: contribution(
      surprise / Math.max(surpriseMaximum, 0.0001),
      weight,
    ),
  };
}

function emptyEvidence(
  nodeId: string,
  readiness: ReturnType<typeof baselineReadiness>,
): BehaviorDriftEvidence {
  return {
    baseline: { ...readiness, nodeId: safeIdentifier(nodeId) },
    features: [],
    aggregate: { driftScore: 0, primaryFeatureKeys: [] },
  };
}

export function computeBehaviorDrift(
  input: BehaviorDriftInput,
): RiskComputationResult<BehaviorDriftEvidence> & {
  vectorizer: CharacterNgramVectorizerConfig;
} {
  const config = mergeConfig(input.config);
  assertUniqueEventIds([...input.events, ...input.baselineEvents]);
  const events = sortedEvents(input.events);
  const baseline = sortedEvents(input.baselineEvents);
  const readiness = baselineReadiness(
    baseline,
    config.minimumBaselineEvents,
    config.minimumBaselineRuns,
  );
  if (!readiness.ready || events.length === 0) {
    return {
      score: 0,
      evidence: emptyEvidence(input.nodeId, readiness),
      signals: [],
      modelVersion: config.modelVersion,
      vectorizer: config.string.vectorizer,
    };
  }

  const features: BehaviorDriftEvidence["features"] = [];

  const latency = numericFeature(
    "SERVER:latency_ms",
    events
      .map((event) => event.latencyMs)
      .filter((value): value is number => Number.isFinite(value)),
    baseline
      .map((event) => event.latencyMs)
      .filter((value): value is number => Number.isFinite(value)),
    config.weights.latencyMs,
    config.numericZMaximum,
  );
  if (latency) features.push(latency);

  const runDenyRate =
    events.filter((event) => event.decision?.toLowerCase() === "deny").length /
    events.length;
  const baselineDenyRate =
    baseline.filter((event) => event.decision?.toLowerCase() === "deny").length /
    baseline.length;
  const denyStandardDeviation = Math.sqrt(
    (baselineDenyRate * (1 - baselineDenyRate)) / baseline.length,
  );
  const denyZScore = deviationWithZeroVariance(
    runDenyRate,
    baselineDenyRate,
    denyStandardDeviation,
    config.numericZMaximum,
  );
  const denyAbsoluteZScore = Math.abs(denyZScore);
  features.push({
    key: "SERVER:deny_rate",
    kind: "number",
    currentValue: runDenyRate,
    baseline: {
      mean: baselineDenyRate,
      standardDeviation: denyStandardDeviation,
      sampleCount: baseline.length,
    },
    distance: { zScore: denyZScore, absoluteZScore: denyAbsoluteZScore },
    weight: config.weights.denyRate,
    contribution: contribution(
      denyAbsoluteZScore / Math.max(config.numericZMaximum, 0.0001),
      config.weights.denyRate,
    ),
  });

  const categoryInputs: Array<{
    key: string;
    current: string[];
    baseline: string[];
    weight: number;
  }> = [
    {
      key: "TOOL:tool",
      current: events.map((event) => stripToolVersion(event.tool ?? "")),
      baseline: baseline.map((event) => stripToolVersion(event.tool ?? "")),
      weight: config.weights.tool,
    },
    {
      key: "SERVER:operation",
      current: events.map((event) => event.operation ?? "unknown"),
      baseline: baseline.map((event) => event.operation ?? "unknown"),
      weight: config.weights.operation,
    },
    {
      key: "SERVER:reason_code",
      current: events.map((event) => event.reasonCode ?? "none"),
      baseline: baseline.map((event) => event.reasonCode ?? "none"),
      weight: config.weights.reasonCode,
    },
    {
      key: "SERVER:risk_tag",
      current: events.flatMap(extractRiskTags),
      baseline: baseline.flatMap(extractRiskTags),
      weight: config.weights.riskTag,
    },
  ];
  for (const category of categoryInputs) {
    const feature = categoricalFeature(
      category.key,
      category.current,
      category.baseline,
      category.weight,
      config.categoricalSurpriseMaximum,
    );
    if (feature) features.push(feature);
  }

  const defaultExcludedLeaves = new Set([
    "token",
    "access_token",
    "refresh_token",
    "authorization",
    "auth",
    "secret",
    "password",
    "api_key",
    "apikey",
    "key",
    ...(config.string.excludeLeafKeys ?? []),
  ]);
  const flattenOptions = {
    maxDepth: 4,
    maxKeys: config.string.maximumFeatures,
    maxCharacters: config.string.vectorizer.maximumCharacters,
    includeScopes: config.string.includeScopes,
    allowlistKeys: config.string.allowlistKeys,
    excludeLeafKeys: defaultExcludedLeaves,
  };
  const currentByKey = new Map<
    string,
    { value: string; characterLength: number }
  >();
  for (let index = events.length - 1; index >= 0; index -= 1) {
    for (const [key, value] of flattenStringValues(
      events[index].state,
      flattenOptions,
    )) {
      if (!currentByKey.has(key)) currentByKey.set(key, value);
      if (currentByKey.size >= config.string.maximumFeatures) break;
    }
  }

  const baselineSamples = new Map<string, string[]>(
    [...currentByKey.keys()].map((key) => [key, []]),
  );
  for (const event of baseline) {
    const values = flattenStringValues(event.state, {
      ...flattenOptions,
      maxKeys: Math.max(config.string.maximumFeatures * 4, 80),
    });
    for (const [key, value] of values) {
      const samples = baselineSamples.get(key);
      if (
        samples &&
        samples.length < config.string.maximumBaselineSamplesPerFeature
      ) {
        samples.push(value.value);
      }
    }
  }

  const pendingStringFeatures: Array<
    Omit<StringDriftFeature, "weight" | "contribution"> & {
      rawDistance: number;
    }
  > = [];
  for (const [key, current] of currentByKey) {
    const samples = baselineSamples.get(key) ?? [];
    if (samples.length < 3) continue;
    const currentVector = vectorizeCharacterNgrams(
      current.value,
      config.string.vectorizer,
    );
    const centroid = new Float32Array(
      Math.max(8, Math.floor(config.string.vectorizer.dimensions)),
    );
    const sampleVectors = samples.map((sample) => {
      const vector = vectorizeCharacterNgrams(
        sample,
        config.string.vectorizer,
      );
      addVectorInPlace(centroid, vector);
      return vector;
    });
    const similarity = cosineSimilarity(currentVector, centroid);
    const distance = cosineDistance(currentVector, centroid);
    const distances = sampleVectors.map((vector) =>
      cosineDistance(vector, centroid),
    );
    const distanceMean = mean(distances);
    const distanceDeviation = standardDeviation(distances, distanceMean);
    const zScore =
      distanceDeviation > 0
        ? (distance - distanceMean) / distanceDeviation
        : distance === distanceMean
          ? 0
          : config.string.zMaximum;
    const rawDistance = Math.max(
      distance / Math.max(config.string.distanceMaximum, 0.0001),
      Math.abs(zScore) / Math.max(config.string.zMaximum, 0.0001),
    );
    pendingStringFeatures.push({
      key,
      kind: "string",
      current: {
        valueSha256: sha256Hex(current.value),
        characterLength: current.characterLength,
      },
      baseline: {
        sampleCount: samples.length,
        meanCosineDistance: distanceMean,
        ...(distanceDeviation > 0
          ? { standardDeviation: distanceDeviation }
          : {}),
      },
      distance: {
        cosineSimilarity: similarity,
        cosineDistance: distance,
        ...(Number.isFinite(zScore) ? { zScore } : {}),
      },
      rawDistance,
    });
  }
  const perStringWeight =
    config.weights.stringState / Math.max(1, pendingStringFeatures.length);
  for (const pending of pendingStringFeatures) {
    const { rawDistance, ...feature } = pending;
    features.push({
      ...feature,
      weight: perStringWeight,
      contribution: contribution(rawDistance, perStringWeight),
    });
  }

  const score = clamp(
    features.reduce((sum, feature) => sum + feature.contribution, 0),
    0,
    100,
  );
  const sortedFeatures = [...features].sort(
    (left, right) =>
      right.contribution - left.contribution ||
      left.key.localeCompare(right.key),
  );
  const primaryFeatureKeys = sortedFeatures
    .slice(0, 5)
    .map((feature) => feature.key);
  const evidence: BehaviorDriftEvidence = {
    baseline: { ...readiness, nodeId: safeIdentifier(input.nodeId) },
    features,
    aggregate: { driftScore: score, primaryFeatureKeys },
  };

  const signals: RuntimeRiskSignal[] = [];
  if (score >= config.aggregateSignalThreshold) {
    signals.push({
      code: "behavior_drift:aggregate",
      subtype: "behavior_drift",
      severity: severityFromScore(score),
      score,
      title: "Behavior drift detected",
      message: `Behavior drift score ${Math.round(score)} for node ${safeIdentifier(input.nodeId)}`,
      evidence: { primaryFeatureKeys },
      hop: toHop(events.at(-1)!),
    });
  }
  for (const feature of sortedFeatures.slice(0, 3)) {
    if (feature.contribution < config.featureSignalThreshold) continue;
    signals.push({
      code: "behavior_drift:feature",
      subtype: "behavior_drift",
      severity: severityFromScore(feature.contribution),
      score: feature.contribution,
      title: "Behavior drift contributor",
      message: feature.key,
      evidence: { key: feature.key, contribution: feature.contribution },
      hop: toHop(events.at(-1)!),
    });
  }

  return {
    score,
    evidence,
    signals,
    modelVersion: config.modelVersion,
    vectorizer: config.string.vectorizer,
  };
}
