import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  CoreaxAppender,
  verifyAuditEnvelope,
  verifyAuditLog,
  type AuditEnvelopeMinimal,
} from "../src/audit";
import {
  canonicalize,
  Ed25519Signer,
  Ed25519Verifier,
  sha256Hex,
  toBase64,
} from "../src/signer";

const temporaryDirectories: string[] = [];

function temporaryDirectory(): string {
  const directory = fs.mkdtempSync(
    path.join(os.tmpdir(), "coreax-audit-local-"),
  );
  temporaryDirectories.push(directory);
  return directory;
}

function initializedAppender(
  options: ConstructorParameters<typeof CoreaxAppender>[0],
): CoreaxAppender {
  const appender = new CoreaxAppender(options);
  appender.initialize();
  return appender;
}

function envelope(index = 1): AuditEnvelopeMinimal {
  return {
    ts: `2026-07-29T12:00:${String(index).padStart(2, "0")}.000Z`,
    trace_id: `trace-${index}`,
    span_id: `span-${index}`,
    namespace: "local",
    server: "test-server@1.0.0",
    tool: "read@1.0.0",
    status: "ok",
    latency_ms: index,
    retries: 0,
    input_sha256: "a".repeat(64),
    output_sha256: "b".repeat(64),
    policy: { decision: "allow", policyHash: "c".repeat(64) },
    idempotency_key: null,
    nodeId: "node-1",
    agentRef: "run-1",
  };
}

afterEach(() => {
  while (temporaryDirectories.length > 0) {
    const directory = temporaryDirectories.pop();
    if (directory) fs.rmSync(directory, { recursive: true, force: true });
  }
});

describe("local keyed audit verification", () => {
  it("creates audit state only during explicit initialization", async () => {
    const directory = path.join(temporaryDirectory(), "audit");
    const appender = new CoreaxAppender({
      config: { directory },
      signer: Ed25519Signer.fromSeed(new Uint8Array(32).fill(5)),
    });

    expect(fs.existsSync(directory)).toBe(false);
    await expect(appender.append(envelope())).rejects.toThrow(
      "initialized before use",
    );
    expect(fs.existsSync(directory)).toBe(false);
    appender.initialize();
    expect(fs.existsSync(directory)).toBe(true);
  });

  it("canonicalizes only unambiguous JSON data", () => {
    expect(canonicalize({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
    expect(
      canonicalize(JSON.parse('{"__proto__":{"polluted":true}}')),
    ).toBe('{"__proto__":{"polluted":true}}');
    expect(() => canonicalize({ omitted: undefined })).toThrow(
      "defined values",
    );
    expect(() => canonicalize({ value: Number.NaN })).toThrow("finite");
    const cyclic: { self?: unknown } = {};
    cyclic.self = cyclic;
    expect(() => canonicalize(cyclic)).toThrow("cyclic");
  });

  it("loads signing keys only from regular files in allowed directories", () => {
    const directory = temporaryDirectory();
    const keyFile = path.join(directory, "audit.seed");
    const linkFile = path.join(directory, "linked.seed");
    const seed = new Uint8Array(32).fill(6);
    fs.writeFileSync(keyFile, Buffer.from(seed).toString("base64"), {
      mode: 0o600,
    });
    const loaded = Ed25519Signer.fromFile(keyFile, {
      allowedDirectories: [directory],
    });
    expect(loaded.keyId).toBe(Ed25519Signer.fromSeed(seed).keyId);

    fs.symlinkSync(keyFile, linkFile);
    expect(() =>
      Ed25519Signer.fromFile(linkFile, {
        allowedDirectories: [directory],
      }),
    ).toThrow("not a symlink");
  });

  it("serializes concurrent appends into a verifiable log", async () => {
    const directory = temporaryDirectory();
    const signer = Ed25519Signer.fromSeed(new Uint8Array(32).fill(7));
    const appender = initializedAppender({
      config: { directory },
      signer,
    });

    await Promise.all(
      Array.from({ length: 20 }, (_, index) => appender.append(envelope(index))),
    );
    await appender.flush();

    const result = await verifyAuditLog(
      path.join(directory, "audit-2026-07-29.ndjson"),
      new Map([
        [signer.keyId, new Ed25519Verifier(signer.publicKey)],
      ]),
    );
    expect(result).toEqual({
      valid: true,
      keyId: signer.keyId,
      records: 20,
    });
  });

  it("rejects tampering, truncation, unknown keys, and wrong signers", async () => {
    const directory = temporaryDirectory();
    const signer = Ed25519Signer.fromSeed(new Uint8Array(32).fill(11));
    const wrongSigner = Ed25519Signer.fromSeed(new Uint8Array(32).fill(12));
    const appender = initializedAppender({
      config: { directory },
      signer,
    });
    await appender.append(envelope());
    await appender.flush();

    const file = path.join(directory, "audit-2026-07-29.ndjson");
    const original = fs.readFileSync(file, "utf8");
    const signed = JSON.parse(original) as Record<string, unknown>;

    await expect(
      verifyAuditEnvelope(signed, new Map()),
    ).resolves.toMatchObject({
      valid: false,
      reason: "unknown_key",
    });
    await expect(
      verifyAuditEnvelope(
        { ...signed, sig: `${signer.keyId}:AA==` },
        new Map([
          [signer.keyId, new Ed25519Verifier(signer.publicKey)],
        ]),
      ),
    ).resolves.toMatchObject({
      valid: false,
      reason: "unsupported_signature",
    });
    await expect(
      verifyAuditEnvelope(
        signed,
        new Map([
          [signer.keyId, new Ed25519Verifier(wrongSigner.publicKey)],
        ]),
      ),
    ).resolves.toMatchObject({
      valid: false,
      reason: "invalid_signature",
    });

    fs.writeFileSync(
      file,
      `${JSON.stringify({ ...signed, latency_ms: 999 })}\n`,
    );
    await expect(
      verifyAuditLog(
        file,
        new Map([
          [signer.keyId, new Ed25519Verifier(signer.publicKey)],
        ]),
      ),
    ).resolves.toMatchObject({
      valid: false,
      reason: "invalid_signature",
      line: 1,
    });

    fs.writeFileSync(file, original.trimEnd());
    await expect(
      verifyAuditLog(
        file,
        new Map([
          [signer.keyId, new Ed25519Verifier(signer.publicKey)],
        ]),
      ),
    ).resolves.toMatchObject({
      valid: false,
      reason: "truncated_log",
    });
  });

  it("rejects a log that changes signing keys mid-stream", async () => {
    const directory = temporaryDirectory();
    const first = Ed25519Signer.fromSeed(new Uint8Array(32).fill(21));
    const second = Ed25519Signer.fromSeed(new Uint8Array(32).fill(22));
    await initializedAppender({
      config: { directory },
      signer: first,
    }).append(envelope(1));
    await expect(
      initializedAppender({
        config: { directory },
        signer: second,
      }).append(envelope(2)),
    ).rejects.toThrow("unexpected signer");

    const file = path.join(directory, "audit-2026-07-29.ndjson");
    const firstLine = fs.readFileSync(file, "utf8").trimEnd();
    const unsignedSecond = {
      ...envelope(2),
      sequence: 1,
      previous_sha256: sha256Hex(firstLine),
    };
    const secondSignature = second.sign(
      Buffer.from(canonicalize(unsignedSecond)),
    );
    fs.appendFileSync(
      file,
      `${JSON.stringify({
        ...unsignedSecond,
        sig: `${second.keyId}:${toBase64(secondSignature)}`,
      })}\n`,
    );

    await expect(
      verifyAuditLog(
        file,
        new Map([
          [first.keyId, new Ed25519Verifier(first.publicKey)],
          [second.keyId, new Ed25519Verifier(second.publicKey)],
        ]),
      ),
    ).resolves.toMatchObject({
      valid: false,
      reason: "mixed_signers",
      line: 2,
    });
  });

  it("detects deletion, reordering, duplication, and signed-head rollback", async () => {
    const directory = temporaryDirectory();
    const signer = Ed25519Signer.fromSeed(new Uint8Array(32).fill(23));
    const appender = initializedAppender({
      config: { directory },
      signer,
    });
    await appender.append(envelope(1));
    await appender.append(envelope(2));
    await appender.append(envelope(3));

    const file = path.join(directory, "audit-2026-07-29.ndjson");
    const headFile = path.join(directory, "audit-2026-07-29.head.json");
    const original = fs.readFileSync(file, "utf8");
    const originalHead = fs.readFileSync(headFile, "utf8");
    const lines = original.trimEnd().split("\n");
    const verifiers = new Map([
      [signer.keyId, new Ed25519Verifier(signer.publicKey)],
    ]);

    fs.writeFileSync(file, `${lines[0]}\n${lines[2]}\n`);
    await expect(verifyAuditLog(file, verifiers)).resolves.toMatchObject({
      valid: false,
      reason: "invalid_sequence",
      line: 2,
    });

    fs.writeFileSync(file, `${lines[1]}\n${lines[0]}\n${lines[2]}\n`);
    await expect(verifyAuditLog(file, verifiers)).resolves.toMatchObject({
      valid: false,
      reason: "invalid_sequence",
      line: 1,
    });

    fs.writeFileSync(
      file,
      `${lines[0]}\n${lines[1]}\n${lines[1]}\n${lines[2]}\n`,
    );
    await expect(verifyAuditLog(file, verifiers)).resolves.toMatchObject({
      valid: false,
      reason: "invalid_sequence",
      line: 3,
    });

    fs.writeFileSync(file, `${lines[0]}\n${lines[1]}\n`);
    fs.writeFileSync(headFile, originalHead);
    await expect(verifyAuditLog(file, verifiers)).resolves.toMatchObject({
      valid: false,
      reason: "head_mismatch",
    });

    fs.writeFileSync(file, original);
    fs.writeFileSync(headFile, originalHead);
    await expect(verifyAuditLog(file, verifiers)).resolves.toMatchObject({
      valid: true,
      records: 3,
    });
  });

  it("recovers a single valid row written after the last signed head", async () => {
    const directory = temporaryDirectory();
    const signer = Ed25519Signer.fromSeed(new Uint8Array(32).fill(24));
    const appender = initializedAppender({
      config: { directory },
      signer,
    });
    await appender.append(envelope(1));

    const headFile = path.join(directory, "audit-2026-07-29.head.json");
    const previousHead = fs.readFileSync(headFile, "utf8");
    await appender.append(envelope(2));
    fs.writeFileSync(headFile, previousHead);

    await initializedAppender({
      config: { directory },
      signer,
    }).append(envelope(3));

    await expect(
      verifyAuditLog(
        path.join(directory, "audit-2026-07-29.ndjson"),
        new Map([
          [signer.keyId, new Ed25519Verifier(signer.publicKey)],
        ]),
      ),
    ).resolves.toMatchObject({
      valid: true,
      records: 3,
    });
  });

  it("rejects spoofed key IDs, ambiguous timestamps, and hostile verifiers", async () => {
    const directory = temporaryDirectory();
    const signer = Ed25519Signer.fromSeed(new Uint8Array(32).fill(25));
    expect(
      () =>
        initializedAppender({
          config: { directory },
          signer: {
            publicKey: signer.publicKey,
            keyId: `ed25519:${"f".repeat(64)}`,
            sign: (value) => signer.sign(value),
            verify: (value, signature) =>
              signer.verify(value, signature),
          },
        }),
    ).toThrow("must be derived");

    const appender = initializedAppender({
      config: { directory },
      signer,
    });
    await expect(
      appender.append({
        ...envelope(1),
        ts: "2026-07-29T12:00:01",
      }),
    ).rejects.toThrow("explicit time zone");
    await expect(
      appender.append({
        ...envelope(1),
        ts: "2026-02-31T12:00:01Z",
      }),
    ).rejects.toThrow("RFC3339");
    await expect(
      appender.append({
        ...envelope(1),
        ts: "2026-07-29T12:00:01+24:00",
      }),
    ).rejects.toThrow("RFC3339");

    await appender.append(envelope(1));
    const signed = JSON.parse(
      fs.readFileSync(
        path.join(directory, "audit-2026-07-29.ndjson"),
        "utf8",
      ),
    ) as Record<string, unknown>;
    await expect(
      verifyAuditEnvelope(signed, () => {
        throw new Error("resolver failure");
      }),
    ).resolves.toMatchObject({
      valid: false,
      reason: "unknown_key",
    });
    await expect(
      verifyAuditEnvelope(null as never, new Map()),
    ).resolves.toMatchObject({
      valid: false,
      reason: "invalid_json",
    });
  });
});
