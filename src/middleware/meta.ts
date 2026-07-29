export interface CoreaxMeta {
  filePath?: string;
  repositoryRoot?: string;
  language?: string;
  tags?: string[];
}

const COREAX_META = Symbol.for("@coreax/sdk/middleware-meta");

export function withCoreaxMeta<T extends Function>(fn: T, meta: CoreaxMeta): T {
  Object.defineProperty(fn, COREAX_META, {
    value: Object.freeze({ ...meta }),
    enumerable: false,
    configurable: false,
  });
  return fn;
}

export function getCoreaxMeta(value: unknown): CoreaxMeta | undefined {
  if (typeof value !== "function") return undefined;
  return (value as unknown as Record<PropertyKey, unknown>)[COREAX_META] as
    | CoreaxMeta
    | undefined;
}

export function requireNonEmptyString(value: unknown, label: string): string {
  const normalized = typeof value === "string" ? value.trim() : "";
  if (!normalized) throw new TypeError(`${label} must be a non-empty string`);
  return normalized;
}

export function requirePositiveNumber(value: unknown, label: string): number {
  const normalized = Number(value);
  if (!Number.isFinite(normalized) || normalized <= 0) {
    throw new TypeError(`${label} must be a positive finite number`);
  }
  return normalized;
}

export function requireNonEmptyArray<T>(
  value: T[] | undefined,
  label: string,
): T[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new TypeError(`${label} must be a non-empty array`);
  }
  return value;
}
