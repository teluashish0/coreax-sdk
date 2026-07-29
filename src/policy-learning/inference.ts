import type { ContextualBanditModel } from "./bandit";
import {
  combineComponentUncertainty,
  estimateLinearAction,
} from "./bandit";
import { extractPolicyFeatureVector } from "./features";
import { clamp, finiteNumber, softmaxProbabilities } from "./math";
import {
  DEFAULT_POLICY_REWARD_WEIGHTS,
  computeWeightedReward,
  emptyPolicyRewardComponents,
} from "./reward";
import {
  assessPolicyCandidate,
  type PolicySafetyConstraints,
  type PolicySafetyReason,
} from "./safety";
import { simulatePolicyCandidate } from "./simulation";
import type {
  PolicyCandidate,
  PolicyDocument,
  PolicyLearningState,
  PolicyRewardComponentKey,
  RewardComponents,
  RewardWeights,
} from "./types";

export interface RankedPolicyAction {
  actionKey: string;
  expectedReward: number;
  selectionScore: number;
  expectedImpact: RewardComponents<PolicyRewardComponentKey>;
  uncertainty: number;
  confidence: number;
  source: "model" | "simulation" | "untrained";
  allowed: boolean;
  safetyReasons: PolicySafetyReason[];
  explanation: string;
}

export interface PolicyInferenceResult {
  modelVersion: string | null;
  rankedActions: RankedPolicyAction[];
  distribution: Record<string, number>;
  chosenActionKey: string | null;
  modelConfidence: number | null;
  modelUncertainty: number | null;
}

function confidenceFromUncertainty(uncertainty: number): number {
  return clamp(1 / (1 + finiteNumber(uncertainty, 1)), 0, 1);
}

function priorityOf(candidate: PolicyCandidate): number {
  return finiteNumber(candidate.priority, 0);
}

function assertUniqueCandidateKeys(
  candidates: readonly PolicyCandidate[],
): void {
  const keys = new Set<string>();
  for (const candidate of candidates) {
    const key = candidate.key.trim();
    if (!key) throw new Error("candidate_key_is_required");
    if (keys.has(key)) throw new Error(`duplicate_candidate_key:${key}`);
    keys.add(key);
  }
}

export function rankPolicyCandidates<
  TAction,
  TPolicy extends PolicyDocument,
  TContext = unknown,
>(input: {
  state: PolicyLearningState<TContext>;
  candidates: readonly PolicyCandidate<TAction, TPolicy>[];
  currentPolicy: TPolicy;
  model?: ContextualBanditModel<PolicyRewardComponentKey> | null;
  modelVersion?: string | null;
  weights?: Readonly<RewardWeights<PolicyRewardComponentKey>>;
  constraints?: PolicySafetyConstraints;
  chooseFromActionKeys?: readonly string[] | null;
  softmaxTemperature?: number;
}): PolicyInferenceResult {
  assertUniqueCandidateKeys(input.candidates as readonly PolicyCandidate[]);
  const weights = {
    ...DEFAULT_POLICY_REWARD_WEIGHTS,
    ...(input.weights ?? {}),
  };
  const model = input.model ?? null;
  const featureVector = model
    ? extractPolicyFeatureVector(input.state, model.featureNames)
    : null;
  const candidateByKey = new Map(
    input.candidates.map((candidate) => [candidate.key, candidate] as const),
  );

  const rankedActions: RankedPolicyAction[] = input.candidates.map(
    (candidate) => {
      const safety = assessPolicyCandidate({
        currentPolicy: input.currentPolicy,
        candidate,
        constraints: input.constraints,
      });

      let expectedImpact = emptyPolicyRewardComponents();
      let uncertainty = 1;
      let source: RankedPolicyAction["source"] = "untrained";

      if (
        model &&
        featureVector &&
        model.actionKeys.includes(candidate.key)
      ) {
        const estimate = estimateLinearAction({
          x: featureVector.values,
          model,
          actionKey: candidate.key,
        });
        expectedImpact = estimate.expectedComponents;
        uncertainty = combineComponentUncertainty(
          estimate.componentUncertainty,
        );
        source = "model";
      } else if (candidate.simulation && input.state.baseline) {
        expectedImpact = simulatePolicyCandidate(
          input.state,
          candidate,
        ).components;
        // A deterministic simulation is reproducible but remains an uncertain
        // proxy for an observed outcome.
        uncertainty = 1;
        source = "simulation";
      }

      const expectedReward = computeWeightedReward(expectedImpact, weights);
      const alpha = model?.alpha ?? 0;
      const selectionScore = expectedReward + alpha * uncertainty;
      const confidence = confidenceFromUncertainty(uncertainty);
      const explanation = safety.allowed
        ? `${candidate.key} has expected reward ${expectedReward.toFixed(3)} from ${source} evidence.`
        : `${candidate.key} is ineligible: ${safety.reasons
            .map((reason) => reason.code)
            .join(", ")}.`;

      return {
        actionKey: candidate.key,
        expectedReward,
        selectionScore,
        expectedImpact,
        uncertainty,
        confidence,
        source,
        allowed: safety.allowed,
        safetyReasons: safety.reasons,
        explanation,
      };
    },
  );

  rankedActions.sort((left, right) => {
    if (left.allowed !== right.allowed) return left.allowed ? -1 : 1;
    if (right.selectionScore !== left.selectionScore) {
      return right.selectionScore - left.selectionScore;
    }
    const priorityDifference =
      priorityOf(candidateByKey.get(right.actionKey) as PolicyCandidate) -
      priorityOf(candidateByKey.get(left.actionKey) as PolicyCandidate);
    if (priorityDifference !== 0) return priorityDifference;
    return left.actionKey.localeCompare(right.actionKey);
  });

  const chooseFrom =
    input.chooseFromActionKeys === undefined ||
    input.chooseFromActionKeys === null
      ? null
      : new Set(input.chooseFromActionKeys);
  const chosen =
    rankedActions.find(
      (action) =>
        action.allowed && (!chooseFrom || chooseFrom.has(action.actionKey)),
    ) ?? null;

  const allowedScores = Object.fromEntries(
    rankedActions
      .filter(
        (action) =>
          action.allowed &&
          (!chooseFrom || chooseFrom.has(action.actionKey)),
      )
      .map((action) => [action.actionKey, action.selectionScore]),
  );
  const allowedDistribution = softmaxProbabilities(
    allowedScores,
    input.softmaxTemperature,
  );
  const distribution = Object.fromEntries(
    rankedActions.map((action) => [
      action.actionKey,
      allowedDistribution[action.actionKey] ?? 0,
    ]),
  );

  return {
    modelVersion: input.modelVersion ?? null,
    rankedActions,
    distribution,
    chosenActionKey: chosen?.actionKey ?? null,
    modelConfidence: chosen?.confidence ?? null,
    modelUncertainty: chosen?.uncertainty ?? null,
  };
}
