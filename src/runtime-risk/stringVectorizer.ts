import { clamp, finiteConfigNumber } from "./util";

export type CharacterNgramVectorizerConfig = {
  method: "character_ngram_hash";
  ngramMinimum: number;
  ngramMaximum: number;
  dimensions: number;
  lowercase: boolean;
  normalizeWhitespace: boolean;
  maximumCharacters: number;
};

export const DEFAULT_CHARACTER_NGRAM_VECTORIZER_CONFIG: CharacterNgramVectorizerConfig =
  Object.freeze({
    method: "character_ngram_hash",
    ngramMinimum: 3,
    ngramMaximum: 5,
    dimensions: 2048,
    lowercase: true,
    normalizeWhitespace: true,
    maximumCharacters: 2048,
  });

export function validateCharacterNgramVectorizerConfig(
  config: CharacterNgramVectorizerConfig,
): CharacterNgramVectorizerConfig {
  if (config?.method !== "character_ngram_hash") {
    throw new TypeError(
      "stringVectorizer.method must be character_ngram_hash",
    );
  }
  if (
    typeof config.lowercase !== "boolean" ||
    typeof config.normalizeWhitespace !== "boolean"
  ) {
    throw new TypeError("stringVectorizer normalization flags must be boolean");
  }
  const ngramMinimum = finiteConfigNumber(
    config.ngramMinimum,
    "stringVectorizer.ngramMinimum",
    { minimum: 1, maximum: 128, integer: true },
  );
  const ngramMaximum = finiteConfigNumber(
    config.ngramMaximum,
    "stringVectorizer.ngramMaximum",
    { minimum: ngramMinimum, maximum: 128, integer: true },
  );
  return {
    method: "character_ngram_hash",
    ngramMinimum,
    ngramMaximum,
    lowercase: config.lowercase,
    normalizeWhitespace: config.normalizeWhitespace,
    dimensions: finiteConfigNumber(
      config.dimensions,
      "stringVectorizer.dimensions",
      { minimum: 8, maximum: 1_048_576, integer: true },
    ),
    maximumCharacters: finiteConfigNumber(
      config.maximumCharacters,
      "stringVectorizer.maximumCharacters",
      { minimum: 1, maximum: 1_000_000, integer: true },
    ),
  };
}

function normalizedVectorText(
  text: string,
  config: CharacterNgramVectorizerConfig,
): string {
  let normalized = String(text ?? "");
  if (config.lowercase) normalized = normalized.toLowerCase();
  if (config.normalizeWhitespace) {
    normalized = normalized.replace(/\s+/g, " ").trim();
  }
  return normalized.length > config.maximumCharacters
    ? normalized.slice(0, config.maximumCharacters)
    : normalized;
}

export function normalizeVectorText(
  text: string,
  config: CharacterNgramVectorizerConfig,
): string {
  return normalizedVectorText(
    text,
    validateCharacterNgramVectorizerConfig(config),
  );
}

function fnv1a32(value: string): number {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash =
      (hash +
        ((hash << 1) +
          (hash << 4) +
          (hash << 7) +
          (hash << 8) +
          (hash << 24))) >>>
      0;
  }
  return hash >>> 0;
}

export function vectorizeCharacterNgrams(
  text: string,
  config: CharacterNgramVectorizerConfig = DEFAULT_CHARACTER_NGRAM_VECTORIZER_CONFIG,
): Float32Array {
  const resolved = validateCharacterNgramVectorizerConfig(config);
  const normalized = normalizedVectorText(text, resolved);
  const vector = new Float32Array(resolved.dimensions);
  const minimum = resolved.ngramMinimum;
  const maximum = resolved.ngramMaximum;
  for (let size = minimum; size <= maximum; size += 1) {
    if (normalized.length < size) continue;
    for (let index = 0; index <= normalized.length - size; index += 1) {
      const ngram = normalized.slice(index, index + size);
      vector[fnv1a32(ngram) % resolved.dimensions] += 1;
    }
  }
  return vector;
}

export function vectorDot(
  left: Float32Array,
  right: Float32Array,
): number {
  const length = Math.min(left.length, right.length);
  let sum = 0;
  for (let index = 0; index < length; index += 1) {
    sum += left[index] * right[index];
  }
  return sum;
}

export function vectorNorm(vector: Float32Array): number {
  let sum = 0;
  for (const value of vector) sum += value * value;
  return Math.sqrt(sum);
}

export function cosineSimilarity(
  left: Float32Array,
  right: Float32Array,
): number {
  const denominator = vectorNorm(left) * vectorNorm(right);
  if (!Number.isFinite(denominator) || denominator <= 0) return 0;
  return clamp(vectorDot(left, right) / denominator, -1, 1);
}

export function cosineDistance(
  left: Float32Array,
  right: Float32Array,
): number {
  return clamp(1 - cosineSimilarity(left, right), 0, 2);
}

export function addVectorInPlace(
  target: Float32Array,
  source: Float32Array,
): void {
  const length = Math.min(target.length, source.length);
  for (let index = 0; index < length; index += 1) {
    target[index] += source[index];
  }
}
