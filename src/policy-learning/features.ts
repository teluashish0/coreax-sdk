import { finiteNumber } from "./math";
import type {
  FeatureVector,
  PolicyFeatureValue,
  PolicyLearningState,
} from "./types";

function normalizeFeature(value: PolicyFeatureValue): number {
  if (typeof value === "boolean") return value ? 1 : 0;
  return finiteNumber(value, 0);
}

/**
 * Produces a stable feature order. Supplying `featureNames` aligns inference
 * with a previously trained model and fills unavailable features with zero.
 */
export function extractPolicyFeatureVector(
  state: PolicyLearningState,
  featureNames?: readonly string[],
): FeatureVector {
  const byName: Record<string, number> = { bias: 1 };
  for (const [name, value] of Object.entries(state.features)) {
    const normalizedName = name.trim();
    if (!normalizedName || normalizedName === "bias") continue;
    byName[normalizedName] = normalizeFeature(value);
  }

  const names = featureNames
    ? [...featureNames]
    : Object.keys(byName).sort((left, right) => left.localeCompare(right));

  if (new Set(names).size !== names.length) {
    throw new Error("feature_names_must_be_unique");
  }

  return {
    names,
    values: names.map((name) => (name === "bias" ? 1 : byName[name] ?? 0)),
    byName,
  };
}

export function collectFeatureNames(
  states: readonly PolicyLearningState[],
): string[] {
  const names = new Set<string>(["bias"]);
  for (const state of states) {
    for (const rawName of Object.keys(state.features)) {
      const name = rawName.trim();
      if (name) names.add(name);
    }
  }
  return [...names].sort((left, right) => left.localeCompare(right));
}
