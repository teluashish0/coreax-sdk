import { clamp, finiteNumber } from "./math";
import type {
  PolicyRewardComponentKey,
  RewardComponents,
  RewardWeights,
} from "./types";

export const DEFAULT_POLICY_REWARD_WEIGHTS: Readonly<
  RewardWeights<PolicyRewardComponentKey>
> = Object.freeze({
  incident_reduction: 1,
  sensitive_exposure_prevention: 3,
  false_positive_reduction: 1,
  latency_reduction: 0.35,
  human_acceptance: 0.5,
  evaluator_score: 0.2,
});

export function emptyPolicyRewardComponents(): RewardComponents<PolicyRewardComponentKey> {
  return {
    incident_reduction: 0,
    sensitive_exposure_prevention: 0,
    false_positive_reduction: 0,
    latency_reduction: 0,
    human_acceptance: 0,
    evaluator_score: 0,
  };
}

export function normalizeEvaluatorScore(score0to100: number): number {
  const score = clamp(finiteNumber(score0to100), 0, 100);
  return clamp((score - 50) / 50, -1, 1);
}

export function computeWeightedReward<TKey extends string>(
  components: Readonly<RewardComponents<TKey>>,
  weights: Readonly<RewardWeights<TKey>>,
): number {
  return (Object.keys(weights) as TKey[]).reduce(
    (total, key) =>
      total +
      finiteNumber(weights[key], 0) * finiteNumber(components[key], 0),
    0,
  );
}
