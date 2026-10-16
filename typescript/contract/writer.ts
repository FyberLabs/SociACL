/**
 * Transport brand for AuthenticatedWriterChannel.
 *
 * s3r.ch copies docs/s3rch-check.d.ts and reimplements this class. It
 * does not import this file and it does not import the Rust crate.
 * The brand is the ECMAScript private field #channelBrand and the
 * module WeakSet filled by the constructor. writer and writerPub are
 * frozen. A copy is not in the set. This value is not a grant and it
 * is not a writer pub on the stored row.
 *
 * openWithPossession is the only mint. It verifies a signature over
 * the length-prefixed fields "s3rch-writer-channel-v1" and the writer
 * id under writerPub. The private constructor is not callable outside
 * this class. The reserved names are
 * vectors/encrypted-discovery/forbidden-names.json, the same list
 * hop_forbidden reads.
 */

import { createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { writerChannelBytes } from "./canonical.ts";

const writerChannelBrand = Symbol("s3rch-writer-channel");
const writerChannelInstances = new WeakSet<AuthenticatedWriterChannel>();

const P256_HALF_N =
  0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8n;

type ForbiddenNames = {
  exact: string[];
  contains: string[];
};

const forbiddenNames = JSON.parse(
  readFileSync(
    new URL("../../vectors/encrypted-discovery/forbidden-names.json", import.meta.url),
    "utf8",
  ),
) as ForbiddenNames;

function hopForbidden(name: string): boolean {
  const value = name.trim().toLowerCase();
  if (value.length === 0) {
    return false;
  }
  if (forbiddenNames.exact.includes(value)) {
    return true;
  }
  return forbiddenNames.contains.some((needle) => value.includes(needle));
}

function verifyPossession(writer: string, writerPub: string, signature: string): boolean {
  if (!/^[0-9a-f]{128}$/.test(signature)) {
    return false;
  }
  const s = BigInt(`0x${signature.slice(64)}`);
  if (s === 0n || s > P256_HALF_N) {
    return false;
  }
  const parts = writerPub.split(".");
  const x = parts[0];
  const y = parts[1];
  if (parts.length !== 2 || x === undefined || y === undefined || x.length !== 43 || y.length !== 43) {
    return false;
  }
  let key;
  try {
    key = createPublicKey({
      key: { kty: "EC", crv: "P-256", x, y },
      format: "jwk",
    });
  } catch {
    return false;
  }
  try {
    return verify(
      "sha256",
      writerChannelBytes(writer),
      { key, dsaEncoding: "ieee-p1363" },
      Buffer.from(signature, "hex"),
    );
  } catch {
    return false;
  }
}

export class AuthenticatedWriterChannel {
  readonly writer: string;
  readonly writerPub: string;
  readonly #channelBrand = writerChannelBrand;

  private constructor(writer: string, writerPub: string) {
    this.writer = writer;
    this.writerPub = writerPub;
    Object.freeze(this);
    writerChannelInstances.add(this);
  }

  /**
   * Mint only after `signature` verifies under `writerPub`.
   * Signed bytes, length-prefixed:
   * 1. "s3rch-writer-channel-v1"
   * 2. writer
   */
  static openWithPossession(
    writer: string,
    writerPub: string,
    signature: string,
  ): AuthenticatedWriterChannel {
    if (writer.length === 0 || writerPub.length === 0 || hopForbidden(writer)) {
      throw new Error("channel rejected");
    }
    if (!verifyPossession(writer, writerPub, signature)) {
      throw new Error("signature rejected");
    }
    return new AuthenticatedWriterChannel(writer, writerPub);
  }

  hasTransportBrand(): boolean {
    try {
      return (
        this.#channelBrand === writerChannelBrand &&
        writerChannelInstances.has(this)
      );
    } catch {
      return false;
    }
  }
}

/**
 * Runtime check for an append channel. An object literal fails
 * instanceof. A prototype copy fails the private field and the set.
 */
export function writerChannelMatches(
  channel: unknown,
  writer: string,
  enrolledPub: string,
): boolean {
  if (!(channel instanceof AuthenticatedWriterChannel)) {
    return false;
  }
  if (!channel.hasTransportBrand()) {
    return false;
  }
  return channel.writer === writer && channel.writerPub === enrolledPub;
}

/** Same predicate as Rust `hop_forbidden`. Exported for the vector test. */
export function writerNameForbidden(name: string): boolean {
  return hopForbidden(name);
}
