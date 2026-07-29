import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
} from "node:fs";
import path from "node:path";
import nacl from "tweetnacl";

export interface Signer {
  readonly keyId: string;
  sign(data: Uint8Array): Promise<Uint8Array> | Uint8Array;
}

export interface Verifier {
  verify(
    data: Uint8Array,
    signature: Uint8Array,
  ): Promise<boolean> | boolean;
}

export interface Ed25519FileOptions {
  allowedDirectories?: string[];
}

export function sha256Hex(data: Uint8Array | string): string {
  return createHash("sha256")
    .update(typeof data === "string" ? Buffer.from(data) : Buffer.from(data))
    .digest("hex");
}

export function canonicalize(value: unknown): string {
  return JSON.stringify(sortJsonValue(value, new WeakSet<object>()));
}

function sortJsonValue(
  value: unknown,
  ancestors: WeakSet<object>,
): unknown {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError("Canonical JSON numbers must be finite");
    }
    return Object.is(value, -0) ? 0 : value;
  }
  if (!value || typeof value !== "object") {
    throw new TypeError(
      `Canonical JSON does not support ${typeof value} values`,
    );
  }
  if (ancestors.has(value)) {
    throw new TypeError("Canonical JSON does not support cyclic values");
  }
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return value.map((entry, index) => {
        if (!(index in value) || entry === undefined) {
          throw new TypeError(
            "Canonical JSON arrays cannot contain holes or undefined",
          );
        }
        return sortJsonValue(entry, ancestors);
      });
    }

    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError(
        "Canonical JSON objects must have a plain or null prototype",
      );
    }
    const ownKeys = Reflect.ownKeys(value);
    if (ownKeys.some((key) => typeof key !== "string")) {
      throw new TypeError("Canonical JSON does not support symbol keys");
    }
    const output = Object.create(null) as Record<string, unknown>;
    for (const key of (ownKeys as string[]).sort()) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (
        !descriptor ||
        !descriptor.enumerable ||
        !("value" in descriptor) ||
        descriptor.value === undefined
      ) {
        throw new TypeError(
          "Canonical JSON objects require enumerable data properties with defined values",
        );
      }
      output[key] = sortJsonValue(descriptor.value, ancestors);
    }
    return output;
  } finally {
    ancestors.delete(value);
  }
}

function decodeKey(value: Uint8Array | string): Uint8Array {
  return typeof value === "string"
    ? new Uint8Array(Buffer.from(value.trim(), "base64"))
    : new Uint8Array(value);
}

function keyId(publicKey: Uint8Array): string {
  return `ed25519:${sha256Hex(publicKey)}`;
}

function isWithin(candidate: string, directory: string): boolean {
  const relative = path.relative(directory, candidate);
  return (
    relative === "" ||
    (!relative.startsWith("..") && !path.isAbsolute(relative))
  );
}

export class Ed25519Signer implements Signer, Verifier {
  readonly publicKey: Uint8Array;
  readonly keyId: string;

  private constructor(private readonly secretKey: Uint8Array) {
    const pair = nacl.sign.keyPair.fromSecretKey(secretKey);
    this.publicKey = new Uint8Array(pair.publicKey);
    this.keyId = keyId(this.publicKey);
  }

  static generate(): Ed25519Signer {
    return new Ed25519Signer(nacl.sign.keyPair().secretKey);
  }

  static fromSeed(seed: Uint8Array | string): Ed25519Signer {
    const decoded = decodeKey(seed);
    if (decoded.length !== 32) {
      throw new TypeError("Ed25519 seed must be exactly 32 bytes");
    }
    return new Ed25519Signer(
      nacl.sign.keyPair.fromSeed(decoded).secretKey,
    );
  }

  static fromSecretKey(secretKey: Uint8Array | string): Ed25519Signer {
    const decoded = decodeKey(secretKey);
    if (decoded.length !== 64) {
      throw new TypeError("Ed25519 secret key must be exactly 64 bytes");
    }
    return new Ed25519Signer(decoded);
  }

  static fromFile(
    filePath: string,
    options: Ed25519FileOptions = {},
  ): Ed25519Signer {
    const resolved = path.resolve(filePath);
    const allowedDirectories = (
      options.allowedDirectories ?? [path.resolve(".coreax/keys")]
    )
      .map((directory) => path.resolve(directory))
      .filter((directory) => existsSync(directory))
      .map((directory) => realpathSync(directory));
    const entry = lstatSync(resolved);
    if (entry.isSymbolicLink() || !entry.isFile()) {
      throw new Error("Signing key path must be a regular file, not a symlink");
    }
    const canonicalPath = realpathSync(resolved);
    if (
      !allowedDirectories.some((directory) =>
        isWithin(canonicalPath, directory),
      )
    ) {
      throw new Error(
        `Signing key path is outside the explicitly allowed directories: ${canonicalPath}`,
      );
    }
    const descriptor = openSync(
      canonicalPath,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
    );
    let encoded: string;
    try {
      const stat = fstatSync(descriptor);
      if (!stat.isFile() || stat.size > 4_096) {
        throw new Error("Signing key file must be a small regular file");
      }
      encoded = readFileSync(descriptor, "utf8");
    } finally {
      closeSync(descriptor);
    }
    const decoded = decodeKey(encoded);
    return decoded.length === 32
      ? Ed25519Signer.fromSeed(decoded)
      : Ed25519Signer.fromSecretKey(decoded);
  }

  sign(data: Uint8Array): Uint8Array {
    return nacl.sign.detached(data, this.secretKey);
  }

  verify(data: Uint8Array, signature: Uint8Array): boolean {
    return nacl.sign.detached.verify(data, signature, this.publicKey);
  }
}

export class Ed25519Verifier implements Verifier {
  readonly publicKey: Uint8Array;
  readonly keyId: string;

  constructor(publicKey: Uint8Array | string) {
    const decoded = decodeKey(publicKey);
    if (decoded.length !== 32) {
      throw new TypeError("Ed25519 public key must be exactly 32 bytes");
    }
    this.publicKey = decoded;
    this.keyId = keyId(decoded);
  }

  verify(data: Uint8Array, signature: Uint8Array): boolean {
    return nacl.sign.detached.verify(data, signature, this.publicKey);
  }
}

export function toBase64(value: Uint8Array): string {
  return Buffer.from(value).toString("base64");
}

export function fromBase64(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, "base64"));
}
