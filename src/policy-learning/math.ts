import { createHash } from "node:crypto";

import type { PolicyJsonValue } from "./types";

export function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

export function finiteNumber(value: unknown, fallback = 0): number {
  const numberValue =
    typeof value === "number" ? value : Number(value);
  return Number.isFinite(numberValue) ? numberValue : fallback;
}

export function dot(left: readonly number[], right: readonly number[]): number {
  let sum = 0;
  const length = Math.min(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    sum += finiteNumber(left[index]) * finiteNumber(right[index]);
  }
  return sum;
}

export function identityMatrix(size: number, diagonal = 1): number[][] {
  const safeSize = Math.max(0, Math.floor(size));
  return Array.from({ length: safeSize }, (_, rowIndex) =>
    Array.from(
      { length: safeSize },
      (_, columnIndex) => (rowIndex === columnIndex ? diagonal : 0),
    ),
  );
}

export function multiplyMatrixVector(
  matrix: readonly (readonly number[])[],
  vector: readonly number[],
): number[] {
  return matrix.map((row) => dot(row, vector));
}

export function quadraticForm(
  matrix: readonly (readonly number[])[],
  vector: readonly number[],
): number {
  return dot(vector, multiplyMatrixVector(matrix, vector));
}

/**
 * Gaussian elimination with partial pivoting. Invalid or singular matrices
 * return `null`, allowing callers to fall back to their ridge prior.
 */
export function invertMatrix(
  matrix: readonly (readonly number[])[],
): number[][] | null {
  const size = matrix.length;
  if (size === 0) return [];
  if (
    matrix.some(
      (row) =>
        row.length !== size ||
        row.some((value) => !Number.isFinite(value)),
    )
  ) {
    return null;
  }

  const source = matrix.map((row) => [...row]);
  const inverse = identityMatrix(size);

  for (let column = 0; column < size; column += 1) {
    let pivotRow = column;
    let pivotMagnitude = Math.abs(source[column]?.[column] ?? 0);

    for (let row = column + 1; row < size; row += 1) {
      const magnitude = Math.abs(source[row]?.[column] ?? 0);
      if (magnitude > pivotMagnitude) {
        pivotMagnitude = magnitude;
        pivotRow = row;
      }
    }

    if (pivotMagnitude < 1e-12) return null;

    if (pivotRow !== column) {
      [source[column], source[pivotRow]] = [
        source[pivotRow],
        source[column],
      ];
      [inverse[column], inverse[pivotRow]] = [
        inverse[pivotRow],
        inverse[column],
      ];
    }

    const pivot = source[column][column];
    for (let index = 0; index < size; index += 1) {
      source[column][index] /= pivot;
      inverse[column][index] /= pivot;
    }

    for (let row = 0; row < size; row += 1) {
      if (row === column) continue;
      const factor = source[row][column];
      if (Math.abs(factor) < 1e-15) continue;
      for (let index = 0; index < size; index += 1) {
        source[row][index] -= factor * source[column][index];
        inverse[row][index] -= factor * inverse[column][index];
      }
    }
  }

  return inverse;
}

export function softmaxProbabilities(
  scores: Readonly<Record<string, number>>,
  temperature = 1,
): Record<string, number> {
  const entries = Object.entries(scores).sort(([left], [right]) =>
    left.localeCompare(right),
  );
  if (entries.length === 0) return {};

  const safeTemperature = clamp(finiteNumber(temperature, 1), 0.05, 50);
  const finiteEntries = entries.filter(([, score]) => Number.isFinite(score));
  if (finiteEntries.length === 0) {
    const uniform = 1 / entries.length;
    return Object.fromEntries(entries.map(([key]) => [key, uniform]));
  }

  const maximum = Math.max(...finiteEntries.map(([, score]) => score));
  const exponentials = entries.map(([key, score]) => {
    if (!Number.isFinite(score)) return [key, 0] as const;
    const exponent = clamp((score - maximum) / safeTemperature, -50, 50);
    return [key, Math.exp(exponent)] as const;
  });
  const total = exponentials.reduce((sum, [, value]) => sum + value, 0);

  if (!Number.isFinite(total) || total <= 0) {
    const uniform = 1 / entries.length;
    return Object.fromEntries(entries.map(([key]) => [key, uniform]));
  }

  return Object.fromEntries(
    exponentials.map(([key, value]) => [key, value / total]),
  );
}

function canonicalize(value: unknown): PolicyJsonValue {
  if (value === null) return null;
  if (typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  if (Array.isArray(value)) return value.map(canonicalize);
  if (typeof value !== "object") return String(value);

  const output = Object.create(null) as Record<string, PolicyJsonValue>;
  for (const key of Object.keys(value as Record<string, unknown>).sort()) {
    const entry = (value as Record<string, unknown>)[key];
    if (entry !== undefined) output[key] = canonicalize(entry);
  }
  return output;
}

export function stableSerialize(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

export function stableDigest(value: unknown): string {
  return createHash("sha256").update(stableSerialize(value)).digest("hex");
}
