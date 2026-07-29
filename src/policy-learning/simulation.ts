import { clamp, finiteNumber } from "./math";
import {
  emptyPolicyRewardComponents,
  normalizeEvaluatorScore,
} from "./reward";
import type {
  PolicyCandidate,
  PolicyLearningState,
  PolicyRewardComponentKey,
  RewardComponents,
} from "./types";

export interface PolicySimulationOutcome {
  actionKey: string;
  components: RewardComponents<PolicyRewardComponentKey>;
  projected: {
    incidentCount: number;
    sensitiveIncidentCount: number;
    falsePositiveRatePct: number;
    latencyMs: number;
  };
}

function safeCount(value: unknown): number {
  return Math.max(0, finiteNumber(value, 0));
}

/**
 * A deterministic local counterfactual. The candidate supplies its assumed
 * deltas explicitly, making the simulator useful for replay without hiding
 * vendor-specific heuristics or model calls.
 */
export function simulatePolicyCandidate(
  state: PolicyLearningState,
  candidate: Pick<PolicyCandidate, "key" | "simulation">,
): PolicySimulationOutcome {
  const baseline = state.baseline ?? {
    incidentCount: 0,
    sensitiveIncidentCount: 0,
    falsePositiveRatePct: 0,
    latencyMs: 0,
  };
  const profile = candidate.simulation ?? {};

  const baseIncidents = safeCount(baseline.incidentCount);
  const baseSensitive = safeCount(baseline.sensitiveIncidentCount);
  const baseFalsePositiveRate = clamp(
    finiteNumber(baseline.falsePositiveRatePct, 0),
    0,
    100,
  );
  const baseLatency = safeCount(baseline.latencyMs);

  const incidentMultiplier = clamp(
    finiteNumber(profile.incidentMultiplier, 1),
    0,
    2,
  );
  const sensitiveMultiplier = clamp(
    finiteNumber(profile.sensitiveIncidentMultiplier, incidentMultiplier),
    0,
    2,
  );
  const latencyMultiplier = clamp(
    finiteNumber(profile.latencyMultiplier, 1),
    0,
    3,
  );

  const projected = {
    incidentCount: baseIncidents * incidentMultiplier,
    sensitiveIncidentCount: baseSensitive * sensitiveMultiplier,
    falsePositiveRatePct: clamp(
      baseFalsePositiveRate +
        finiteNumber(profile.falsePositiveDeltaPct, 0),
      0,
      100,
    ),
    latencyMs: baseLatency * latencyMultiplier,
  };

  const components = emptyPolicyRewardComponents();
  components.incident_reduction =
    baseIncidents > 0
      ? clamp(
          (baseIncidents - projected.incidentCount) / baseIncidents,
          -1,
          1,
        )
      : 0;
  components.sensitive_exposure_prevention =
    baseSensitive > 0
      ? clamp(
          (baseSensitive - projected.sensitiveIncidentCount) / baseSensitive,
          -1,
          1,
        )
      : 0;
  components.false_positive_reduction = clamp(
    (baseFalsePositiveRate - projected.falsePositiveRatePct) / 100,
    -1,
    1,
  );
  components.latency_reduction =
    baseLatency > 0
      ? clamp((baseLatency - projected.latencyMs) / baseLatency, -1, 1)
      : 0;
  components.human_acceptance = clamp(
    finiteNumber(profile.humanAcceptance, 0),
    -1,
    1,
  );
  components.evaluator_score = normalizeEvaluatorScore(
    finiteNumber(profile.evaluatorScore0to100, 50),
  );

  return { actionKey: candidate.key, components, projected };
}

export function simulatePolicyCandidates(
  state: PolicyLearningState,
  candidates: readonly Pick<PolicyCandidate, "key" | "simulation">[],
): PolicySimulationOutcome[] {
  return [...candidates]
    .sort((left, right) => left.key.localeCompare(right.key))
    .map((candidate) => simulatePolicyCandidate(state, candidate));
}
