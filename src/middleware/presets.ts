import type { MiddlewareOptions } from "./middlewareTypes";

export type LocalCoreaxPresetOptions = MiddlewareOptions;

export function createLocalCoreaxPreset(
  options: LocalCoreaxPresetOptions,
): MiddlewareOptions {
  return {
    ...options,
    mode: options.mode ?? "enforce",
  };
}
