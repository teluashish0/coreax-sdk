import {
  canonicalize,
  Ed25519Verifier,
  sha256Hex,
  toBase64,
} from "../signer";
import type { Signer } from "../signer";
import type {
  AuditEnvelopeMinimal,
  CoreaxAppenderOptions,
  CoreaxAuditConfig,
} from "./types";
import { resolveAuditConfig } from "./config";
import { FileManager } from "./file-manager";
import { parseAuditSignature } from "./verification";

const auditQueues = new Map<string, Promise<void>>();
const RFC3339_WITH_ZONE =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(Z|[+-](\d{2}):(\d{2}))$/;

function enqueueAuditWrite(
  key: string,
  task: () => Promise<void>,
): Promise<void> {
  const previous = auditQueues.get(key) ?? Promise.resolve();
  const next = previous.then(task, task);
  auditQueues.set(key, next);
  void next.then(
    () => {
      if (auditQueues.get(key) === next) auditQueues.delete(key);
    },
    () => {
      if (auditQueues.get(key) === next) auditQueues.delete(key);
    },
  );
  return next;
}

/**
 * Append-only keyed Ed25519 NDJSON audit writer.
 */
export class CoreaxAppender {
  private readonly config: CoreaxAuditConfig & { directory: string };
  private readonly signer: CoreaxAppenderOptions["signer"];
  private readonly verifier: Ed25519Verifier;
  private readonly files: FileManager;
  private writeQueue: Promise<void> = Promise.resolve();

  constructor(opts: CoreaxAppenderOptions) {
    this.config = resolveAuditConfig(opts.config);
    this.signer = opts.signer;
    if (
      !(this.signer.publicKey instanceof Uint8Array) ||
      this.signer.publicKey.length !== 32
    ) {
      throw new TypeError(
        "CoreAX audit signing requires a 32-byte Ed25519 public key",
      );
    }
    this.verifier = new Ed25519Verifier(this.signer.publicKey);
    if (this.signer.keyId !== this.verifier.keyId) {
      throw new TypeError(
        "CoreAX audit signer keyId must be derived from its Ed25519 public key",
      );
    }

    this.files = new FileManager(this.config.directory);
  }

  /**
   * Creates the configured local audit directory. Construction and import are
   * side-effect free; append/flush fail until initialization completes.
   */
  initialize(): void {
    this.files.initialize();
  }

  // Sign and append an audit envelope to the daily log file.
  async append(envelope: AuditEnvelopeMinimal & { sig?: string }): Promise<void> {
    const normalized = normalizeAuditEnvelope(envelope);
    const date = normalized.ts.slice(0, 10);
    const task = () =>
      enqueueAuditWrite(this.files.auditFilePath(date), () =>
        this.files.withAuditLock(date, async () => {
          this.files.rotateAuditStream(date);
          const tail = this.files.readAuditTail(date);
          const needsRecovery = await verifyCurrentHead({
            date,
            tail,
            encodedHead: this.files.readAuditHead(date),
            signerKeyId: this.signer.keyId,
            verifier: this.verifier,
          });
          if (needsRecovery && tail) {
            const recoveredTail = JSON.parse(tail) as Record<string, unknown>;
            await this.writeHead(
              date,
              Number(recoveredTail.sequence) + 1,
              tail,
            );
          }

          const chain = nextChain(tail);
          const unsigned = {
            ...normalized,
            sequence: chain.sequence,
            previous_sha256: chain.previousSha256,
          };
          const signature = await signAuditValue(
            this.signer,
            this.verifier,
            unsigned,
          );
          const row = {
            ...unsigned,
            sig: `${this.signer.keyId}:${toBase64(signature)}`,
          };
          const encodedRow = JSON.stringify(row);
          this.files.writeAuditLine(`${encodedRow}\n`);
          await this.writeHead(date, chain.sequence + 1, encodedRow);
        }),
      );
    this.writeQueue = this.writeQueue.then(task, task);
    await this.writeQueue;
  }

  async flush(): Promise<void> {
    await this.writeQueue;
    await this.files.drainAuditStream();
  }

  private async writeHead(
    date: string,
    records: number,
    encodedTail: string,
  ): Promise<void> {
    const head = {
      format: "coreax-audit-head",
      version: 1,
      date,
      records,
      tail_sha256: sha256Hex(encodedTail),
    };
    const headSignature = await signAuditValue(
      this.signer,
      this.verifier,
      head,
    );
    this.files.writeAuditHead(
      date,
      `${JSON.stringify({
        ...head,
        sig: `${this.signer.keyId}:${toBase64(headSignature)}`,
      })}\n`,
    );
  }
}

async function verifyCurrentHead(input: {
  date: string;
  tail: string | null;
  encodedHead: string | null;
  signerKeyId: string;
  verifier: Ed25519Verifier;
}): Promise<boolean> {
  if (!input.tail) {
    if (input.encodedHead) {
      throw new Error("CoreAX audit head exists without an audit log");
    }
    return false;
  }
  let tail: Record<string, unknown>;
  try {
    tail = JSON.parse(input.tail) as Record<string, unknown>;
  } catch {
    throw new Error("CoreAX audit log is invalid JSON");
  }
  if (!input.encodedHead) {
    if (
      tail.sequence === 0 &&
      tail.previous_sha256 === null &&
      (await verifySignedValue(
        tail,
        input.signerKeyId,
        input.verifier,
      ))
    ) {
      return true;
    }
    throw new Error("CoreAX audit log is missing its signed head");
  }
  let head: Record<string, unknown>;
  try {
    head = JSON.parse(input.encodedHead) as Record<string, unknown>;
  } catch {
    throw new Error("CoreAX audit head is invalid JSON");
  }
  const parsedSignature = parseAuditSignature(head.sig);
  if (!parsedSignature || parsedSignature.keyId !== input.signerKeyId) {
    throw new Error("CoreAX audit head has an unexpected signer");
  }
  const unsignedHead = { ...head };
  delete unsignedHead.sig;
  const signatureValid = input.verifier.verify(
    Buffer.from(canonicalize(unsignedHead)),
    parsedSignature.signature,
  );
  if (
    !signatureValid ||
    head.format !== "coreax-audit-head" ||
    head.version !== 1 ||
    head.date !== input.date ||
    !Number.isInteger(head.records) ||
    Number(head.records) < 1 ||
    typeof head.tail_sha256 !== "string"
  ) {
    throw new Error("CoreAX audit log does not match its signed head");
  }
  if (
    head.records === Number(tail.sequence) + 1 &&
    head.tail_sha256 === sha256Hex(input.tail)
  ) {
    return false;
  }
  if (
    head.records === tail.sequence &&
    tail.previous_sha256 === head.tail_sha256 &&
    (await verifySignedValue(
      tail,
      input.signerKeyId,
      input.verifier,
    ))
  ) {
    return true;
  }
  throw new Error("CoreAX audit log does not match its signed head");
}

async function verifySignedValue(
  value: Record<string, unknown>,
  signerKeyId: string,
  verifier: Ed25519Verifier,
): Promise<boolean> {
  const parsed = parseAuditSignature(value.sig);
  if (!parsed || parsed.keyId !== signerKeyId) return false;
  const unsigned = { ...value };
  delete unsigned.sig;
  try {
    return await Promise.resolve(
      verifier.verify(
        Buffer.from(canonicalize(unsigned)),
        parsed.signature,
      ),
    );
  } catch {
    return false;
  }
}

async function signAuditValue(
  signer: Signer,
  verifier: Ed25519Verifier,
  value: unknown,
): Promise<Uint8Array> {
  const signature = await Promise.resolve(
    signer.sign(Buffer.from(canonicalize(value))),
  );
  if (signature.length !== 64) {
    throw new TypeError("Ed25519 audit signatures must be 64 bytes");
  }
  if (
    !verifier.verify(Buffer.from(canonicalize(value)), signature)
  ) {
    throw new TypeError(
      "CoreAX audit signer returned a signature that does not match its public key",
    );
  }
  return signature;
}

function nextChain(tail: string | null): {
  sequence: number;
  previousSha256: string | null;
} {
  if (!tail) return { sequence: 0, previousSha256: null };
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(tail) as Record<string, unknown>;
  } catch {
    throw new Error("CoreAX cannot append after an invalid audit record");
  }
  if (
    !Number.isInteger(parsed.sequence) ||
    Number(parsed.sequence) < 0 ||
    typeof parsed.sig !== "string"
  ) {
    throw new Error("CoreAX cannot append after an unchained audit record");
  }
  return {
    sequence: Number(parsed.sequence) + 1,
    previousSha256: sha256Hex(tail),
  };
}

function requiredString(value: unknown, field: string): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new TypeError(`CoreAX audit ${field} must be a non-empty string`);
  }
  return value.trim();
}

function optionalHash(value: unknown, field: string): string | null {
  if (value === null) return null;
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/i.test(value)) {
    throw new TypeError(
      `CoreAX audit ${field} must be a SHA-256 hex digest or null`,
    );
  }
  return value.toLowerCase();
}

function normalizeAuditEnvelope(
  envelope: AuditEnvelopeMinimal & { sig?: string },
): AuditEnvelopeMinimal {
  if (!envelope || typeof envelope !== "object") {
    throw new TypeError("CoreAX audit envelope must be an object");
  }
  const ts = requiredString(envelope.ts, "ts");
  const timestamp = RFC3339_WITH_ZONE.exec(ts);
  const year = Number(timestamp?.[1]);
  const month = Number(timestamp?.[2]);
  const day = Number(timestamp?.[3]);
  const hour = Number(timestamp?.[4]);
  const minute = Number(timestamp?.[5]);
  const second = Number(timestamp?.[6]);
  const offsetHour = timestamp?.[8] === undefined
    ? 0
    : Number(timestamp[8]);
  const offsetMinute = timestamp?.[9] === undefined
    ? 0
    : Number(timestamp[9]);
  const calendarCheck = new Date(Date.UTC(year, month - 1, day));
  if (
    !timestamp ||
    year < 1 ||
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > 31 ||
    hour > 23 ||
    minute > 59 ||
    second > 59 ||
    offsetHour > 23 ||
    offsetMinute > 59 ||
    calendarCheck.getUTCFullYear() !== year ||
    calendarCheck.getUTCMonth() !== month - 1 ||
    calendarCheck.getUTCDate() !== day ||
    !Number.isFinite(Date.parse(ts))
  ) {
    throw new TypeError(
      "CoreAX audit ts must be an RFC3339 timestamp with an explicit time zone",
    );
  }
  const status =
    envelope.status === "ok" || envelope.status === "error"
      ? envelope.status
      : null;
  if (!status) {
    throw new TypeError("CoreAX audit status must be ok or error");
  }
  const decision =
    envelope.policy?.decision === "allow" ||
    envelope.policy?.decision === "deny"
      ? envelope.policy.decision
      : null;
  if (!decision) {
    throw new TypeError("CoreAX audit policy.decision must be allow or deny");
  }
  const policyHash = envelope.policy?.policyHash;
  if (
    policyHash !== undefined &&
    !/^[0-9a-f]{64}$/i.test(policyHash)
  ) {
    throw new TypeError(
      "CoreAX audit policy.policyHash must be a SHA-256 hex digest",
    );
  }
  if (
    !Number.isFinite(envelope.latency_ms) ||
    envelope.latency_ms < 0 ||
    !Number.isInteger(envelope.retries) ||
    envelope.retries < 0
  ) {
    throw new TypeError(
      "CoreAX audit latency_ms and retries must be non-negative numbers",
    );
  }
  return {
    ts,
    trace_id: requiredString(envelope.trace_id, "trace_id"),
    span_id: requiredString(envelope.span_id, "span_id"),
    namespace: requiredString(envelope.namespace, "namespace"),
    server: requiredString(envelope.server, "server"),
    tool: requiredString(envelope.tool, "tool"),
    status,
    latency_ms: envelope.latency_ms,
    retries: envelope.retries,
    input_sha256: optionalHash(envelope.input_sha256, "input_sha256"),
    output_sha256: optionalHash(envelope.output_sha256, "output_sha256"),
    policy: {
      decision,
      ...(policyHash ? { policyHash: policyHash.toLowerCase() } : {}),
    },
    idempotency_key:
      envelope.idempotency_key === null
        ? null
        : requiredString(envelope.idempotency_key, "idempotency_key"),
    ...(envelope.nodeId === undefined
      ? {}
      : {
          nodeId:
            envelope.nodeId === null
              ? null
              : requiredString(envelope.nodeId, "nodeId"),
        }),
    ...(envelope.agentRef === undefined
      ? {}
      : {
          agentRef:
            envelope.agentRef === null
              ? null
              : requiredString(envelope.agentRef, "agentRef"),
        }),
  };
}
