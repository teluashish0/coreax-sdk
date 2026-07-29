import {
  estimateLinearAction,
  trainRidgeComponent,
  type LinearComponentModel,
  type LinearPolicyModel,
} from "./bandit";
import { collectFeatureNames, extractPolicyFeatureVector } from "./features";
import { clamp, finiteNumber } from "./math";
import { computeWeightedReward } from "./reward";
import type {
  PolicyTransition,
  RewardComponents,
  RewardWeights,
} from "./types";

export interface FittedQModel<TKey extends string = string>
  extends LinearPolicyModel<TKey> {
  algorithm: "coreax_fitted_q_v1";
  lambda: number;
  gamma: number;
  iterations: number;
  trainingRows: number;
}

function uniqueSorted(values: readonly string[]): string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))].sort(
    (left, right) => left.localeCompare(right),
  );
}

function initialQModel<TKey extends string>(input: {
  featureNames: readonly string[];
  actionKeys: readonly string[];
  weights: Readonly<RewardWeights<TKey>>;
  lambda: number;
  gamma: number;
  iterations: number;
}): FittedQModel<TKey> {
  const rewardKeys = (Object.keys(input.weights) as TKey[]).sort((left, right) =>
    left.localeCompare(right),
  );
  const componentModels = {} as Record<TKey, LinearComponentModel<TKey>>;
  for (const component of rewardKeys) {
    componentModels[component] = trainRidgeComponent({
      featureNames: input.featureNames,
      actionKeys: input.actionKeys,
      component,
      rows: [],
      lambda: input.lambda,
    });
  }

  return {
    algorithm: "coreax_fitted_q_v1",
    featureNames: [...input.featureNames],
    actionKeys: [...input.actionKeys],
    rewardKeys,
    weights: { ...input.weights },
    lambda: input.lambda,
    gamma: input.gamma,
    iterations: input.iterations,
    trainingRows: 0,
    componentModels,
  };
}

function bestNextAction<TKey extends string>(input: {
  model: FittedQModel<TKey>;
  x: readonly number[];
  actionKeys: readonly string[];
}): RewardComponents<TKey> {
  let bestComponents = {} as RewardComponents<TKey>;
  let bestScore = Number.NEGATIVE_INFINITY;

  for (const actionKey of uniqueSorted(input.actionKeys)) {
    const estimate = estimateLinearAction({
      x: input.x,
      model: input.model,
      actionKey,
    });
    const score = computeWeightedReward(
      estimate.expectedComponents,
      input.model.weights,
    );
    if (score > bestScore) {
      bestScore = score;
      bestComponents = estimate.expectedComponents;
    }
  }

  return bestComponents;
}

export function buildFittedQModel<TKey extends string>(input: {
  transitions: readonly PolicyTransition<TKey>[];
  actionKeys: readonly string[];
  weights: Readonly<RewardWeights<TKey>>;
  featureNames?: readonly string[];
  lambda?: number;
  gamma?: number;
  iterations?: number;
}): {
  model: FittedQModel<TKey>;
  metrics: {
    transitions: number;
    actions: number;
    meanAbsoluteTdError: number | null;
  };
} {
  const actionKeys = uniqueSorted(input.actionKeys);
  if (actionKeys.length < 2) throw new Error("action_space_too_small");

  const allStates = input.transitions.flatMap((transition) =>
    transition.nextState
      ? [transition.state, transition.nextState]
      : [transition.state],
  );
  const featureNames = input.featureNames
    ? [...input.featureNames]
    : collectFeatureNames(allStates);
  const lambda =
    Number.isFinite(input.lambda) && (input.lambda as number) > 0
      ? (input.lambda as number)
      : 1;
  const gamma = clamp(finiteNumber(input.gamma, 0.97), 0, 0.999);
  const iterations = Math.max(
    1,
    Math.min(20, Math.floor(finiteNumber(input.iterations, 6))),
  );

  let model = initialQModel({
    featureNames,
    actionKeys,
    weights: input.weights,
    lambda,
    gamma,
    iterations,
  });
  let totalAbsoluteTdError = 0;
  let tdCount = 0;

  for (let iteration = 0; iteration < iterations; iteration += 1) {
    const targets = {} as Record<
      TKey,
      Array<{ x: number[]; actionKey: string; y: number }>
    >;
    for (const component of model.rewardKeys) targets[component] = [];

    totalAbsoluteTdError = 0;
    tdCount = 0;

    for (const transition of input.transitions) {
      if (!actionKeys.includes(transition.actionKey)) continue;
      const vector = extractPolicyFeatureVector(
        transition.state,
        featureNames,
      ).values;
      const nextVector = transition.nextState
        ? extractPolicyFeatureVector(transition.nextState, featureNames).values
        : null;
      const nextComponents = nextVector
        ? bestNextAction({
            model,
            x: nextVector,
            actionKeys:
              transition.nextActionKeys?.length
                ? transition.nextActionKeys
                : actionKeys,
          })
        : null;

      for (const component of model.rewardKeys) {
        const reward = finiteNumber(
          transition.rewardComponents[component],
          0,
        );
        const nextValue = nextComponents
          ? finiteNumber(nextComponents[component], 0)
          : 0;
        targets[component].push({
          x: vector,
          actionKey: transition.actionKey,
          y: reward + gamma * nextValue,
        });
      }

      const currentEstimate = estimateLinearAction({
        x: vector,
        model,
        actionKey: transition.actionKey,
      });
      const currentTotal = computeWeightedReward(
        currentEstimate.expectedComponents,
        input.weights,
      );
      const rewardTotal = computeWeightedReward(
        transition.rewardComponents,
        input.weights,
      );
      const nextTotal = nextComponents
        ? computeWeightedReward(nextComponents, input.weights)
        : 0;
      totalAbsoluteTdError += Math.abs(
        rewardTotal + gamma * nextTotal - currentTotal,
      );
      tdCount += 1;
    }

    const componentModels = {} as Record<TKey, LinearComponentModel<TKey>>;
    for (const component of model.rewardKeys) {
      componentModels[component] = trainRidgeComponent({
        featureNames,
        actionKeys,
        component,
        rows: targets[component],
        lambda,
      });
    }
    model = {
      ...model,
      trainingRows: input.transitions.length,
      componentModels,
    };
  }

  return {
    model,
    metrics: {
      transitions: input.transitions.length,
      actions: actionKeys.length,
      meanAbsoluteTdError:
        tdCount > 0 ? totalAbsoluteTdError / tdCount : null,
    },
  };
}
