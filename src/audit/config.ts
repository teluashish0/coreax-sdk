import path from "node:path";
import type { CoreaxAuditConfig } from "./types";

export function resolveAuditConfig(
  config: CoreaxAuditConfig = {},
): Required<Pick<CoreaxAuditConfig, "directory">> & CoreaxAuditConfig {
  const directory = path.resolve(
    String(config.directory || ".coreax/audit").trim() || ".coreax/audit",
  );
  return { ...config, directory };
}
