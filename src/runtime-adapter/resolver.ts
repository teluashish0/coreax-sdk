import {
  RUNTIME_PROTOCOL_VERSION,
  type RuntimeAdapterConfig,
  type ResolvedRuntimeAdapterConfig,
} from "./types";

export function resolveRuntimeAdapterConfig(config?: RuntimeAdapterConfig): ResolvedRuntimeAdapterConfig {
  const protocolVersion =
    typeof config?.protocolVersion === "string" && config.protocolVersion.trim()
      ? config.protocolVersion.trim()
      : RUNTIME_PROTOCOL_VERSION;
  return {
    mode: "local",
    protocolVersion,
  };
}
