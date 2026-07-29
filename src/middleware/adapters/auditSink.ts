import {
  CoreaxAppender,
  type AuditSigner,
  type CoreaxAuditConfig,
} from "../../audit";
import type { AuditSink } from "../../core";

export function createCoreaxAuditSink(options: {
  config?: CoreaxAuditConfig;
  signer: AuditSigner;
}): AuditSink {
  const appender = new CoreaxAppender({
    config: options.config ?? {},
    signer: options.signer,
  });
  return {
    initialize: () => appender.initialize(),
    append: (envelope) => appender.append(envelope),
    flush: () => appender.flush(),
  };
}
