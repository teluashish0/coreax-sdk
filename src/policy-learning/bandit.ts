import {
  dot,
  finiteNumber,
  identityMatrix,
  invertMatrix,
  multiplyMatrixVector,
  quadraticForm,
} from "./math";
import type { RewardComponents, RewardWeights } from "./types";

export interface LinearActionStatistics {
  actionKey: string;
  weights: number[];
  inverseCovariance: number[][];
  observationCount: number;
}

export interface LinearComponentModel<TKey extends string = string> {
  component: TKey;
  actions: Record<string, LinearActionStatistics>;
}

export interface ContextualBanditModel<TKey extends string = string> {
  algorithm: "coreax_contextual_bandit_v1";
  featureNames: string[];
  actionKeys: string[];
  rewardKeys: TKey[];
  lambda: number;
  alpha: number;
  weights: RewardWeights<TKey>;
  trainingRows: number;
  componentModels: Record<TKey, LinearComponentModel<TKey>>;
}

export interface LinearPolicyModel<TKey extends string = string> {
  featureNames: string[];
  actionKeys: string[];
  rewardKeys: TKey[];
  weights: RewardWeights<TKey>;
  componentModels: Record<TKey, LinearComponentModel<TKey>>;
}

export interface BanditTrainingRow<TKey extends string = string> {
  x: readonly number[];
  actionKey: string;
  components: RewardComponents<TKey>;
}

function uniqueSorted(values: readonly string[]): string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))].sort(
    (left, right) => left.localeCompare(right),
  );
}

function alignVector(values: readonly number[], dimension: number): number[] {
  return Array.from(
    { length: dimension },
    (_, index) => finiteNumber(values[index], 0),
  );
}

export function trainRidgeComponent<TKey extends string>(input: {
  featureNames: readonly string[];
  actionKeys: readonly string[];
  component: TKey;
  rows: ReadonlyArray<{
    x: readonly number[];
    actionKey: string;
    y: number;
  }>;
  lambda: number;
}): LinearComponentModel<TKey> {
  const dimension = input.featureNames.length;
  const lambda =
    Number.isFinite(input.lambda) && input.lambda > 0 ? input.lambda : 1;
  const actionKeys = uniqueSorted(input.actionKeys);

  const buckets: Record<
    string,
    { covariance: number[][]; target: number[]; count: number }
  > = {};
  for (const actionKey of actionKeys) {
    buckets[actionKey] = {
      covariance: identityMatrix(dimension, lambda),
      target: new Array<number>(dimension).fill(0),
      count: 0,
    };
  }

  for (const row of input.rows) {
    const bucket = buckets[row.actionKey];
    if (!bucket) continue;
    const vector = alignVector(row.x, dimension);
    const target = finiteNumber(row.y, 0);

    for (let left = 0; left < dimension; left += 1) {
      bucket.target[left] += vector[left] * target;
      for (let right = 0; right < dimension; right += 1) {
        bucket.covariance[left][right] += vector[left] * vector[right];
      }
    }
    bucket.count += 1;
  }

  const actions: Record<string, LinearActionStatistics> = {};
  for (const actionKey of actionKeys) {
    const bucket = buckets[actionKey];
    const inverseCovariance =
      invertMatrix(bucket.covariance) ??
      identityMatrix(dimension, 1 / lambda);
    actions[actionKey] = {
      actionKey,
      weights: multiplyMatrixVector(inverseCovariance, bucket.target),
      inverseCovariance,
      observationCount: bucket.count,
    };
  }

  return { component: input.component, actions };
}

export function createInitialBanditModel<TKey extends string>(input: {
  featureNames: readonly string[];
  actionKeys: readonly string[];
  weights: Readonly<RewardWeights<TKey>>;
  lambda?: number;
  alpha?: number;
}): ContextualBanditModel<TKey> {
  return buildContextualBanditModel({
    ...input,
    rows: [],
  });
}

export function buildContextualBanditModel<TKey extends string>(input: {
  featureNames: readonly string[];
  actionKeys: readonly string[];
  rows: readonly BanditTrainingRow<TKey>[];
  weights: Readonly<RewardWeights<TKey>>;
  lambda?: number;
  alpha?: number;
}): ContextualBanditModel<TKey> {
  const featureNames = [...input.featureNames];
  if (
    featureNames.length === 0 ||
    new Set(featureNames).size !== featureNames.length
  ) {
    throw new Error("feature_names_must_be_nonempty_and_unique");
  }

  const actionKeys = uniqueSorted(input.actionKeys);
  if (actionKeys.length === 0) throw new Error("action_space_is_empty");

  const rewardKeys = (Object.keys(input.weights) as TKey[]).sort((left, right) =>
    left.localeCompare(right),
  );
  if (rewardKeys.length === 0) throw new Error("reward_space_is_empty");

  const lambda =
    Number.isFinite(input.lambda) && (input.lambda as number) > 0
      ? (input.lambda as number)
      : 1;
  const alpha =
    Number.isFinite(input.alpha) && (input.alpha as number) >= 0
      ? (input.alpha as number)
      : 0;

  const componentModels = {} as Record<TKey, LinearComponentModel<TKey>>;
  for (const component of rewardKeys) {
    componentModels[component] = trainRidgeComponent({
      featureNames,
      actionKeys,
      component,
      rows: input.rows.map((row) => ({
        x: row.x,
        actionKey: row.actionKey,
        y: finiteNumber(row.components[component], 0),
      })),
      lambda,
    });
  }

  return {
    algorithm: "coreax_contextual_bandit_v1",
    featureNames,
    actionKeys,
    rewardKeys,
    lambda,
    alpha,
    weights: { ...input.weights },
    trainingRows: input.rows.length,
    componentModels,
  };
}

export function estimateLinearAction<TKey extends string>(input: {
  x: readonly number[];
  model: LinearPolicyModel<TKey>;
  actionKey: string;
}): {
  expectedComponents: RewardComponents<TKey>;
  componentUncertainty: Record<TKey, number>;
} {
  const vector = alignVector(input.x, input.model.featureNames.length);
  const expectedComponents = {} as RewardComponents<TKey>;
  const componentUncertainty = {} as Record<TKey, number>;

  for (const component of input.model.rewardKeys) {
    const statistics =
      input.model.componentModels[component]?.actions[input.actionKey];
    if (!statistics) {
      expectedComponents[component] = 0;
      componentUncertainty[component] = 1;
      continue;
    }

    const expected = dot(statistics.weights, vector);
    const variance = quadraticForm(
      statistics.inverseCovariance,
      vector,
    );
    const uncertainty = Math.sqrt(Math.max(0, variance));
    expectedComponents[component] = finiteNumber(expected, 0);
    componentUncertainty[component] = finiteNumber(uncertainty, 1);
  }

  return { expectedComponents, componentUncertainty };
}

export function combineComponentUncertainty(
  uncertainty: Readonly<Record<string, number>>,
): number {
  const values = Object.values(uncertainty).map((value) =>
    finiteNumber(value, 1),
  );
  if (values.length === 0) return 1;
  const meanSquare =
    values.reduce((total, value) => total + value * value, 0) /
    values.length;
  return Math.sqrt(meanSquare);
}
