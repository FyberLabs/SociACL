/**
 * Authorization for a recovery-copy or wrap-store write.
 *
 * Every put, commit, and delete is a signed compare-and-swap by the
 * account's current chain-head key. The message is `sociacl-store-write-v1`,
 * the PrincipalId, the operation, the target sequence or wrap id, the
 * envelope hash, the published head sequence, the hash of the row being
 * replaced or `none`, the wrap class or `none`, and the per-principal write
 * generation.
 *
 * The store does not take that chain from the writer. It asks a resolver,
 * which an adapter fills from the published source. Panopticon reads the Gun
 * chain. It verifies and witnesses. It is never the authority. Session
 * authentication is not this check.
 *
 * A write whose resolved head is below the store's monotonic per-principal
 * floor is `store-rejected` and changes nothing. The floor records every
 * head the resolver reports, including a read or a rejected write, plus
 * every stored current recovery sequence. A pending sequence is not
 * included. The recovery store and the wrap store share one floor per
 * principal.
 */
import { p256 } from "@noble/curves/nist.js";
import type { PrincipalId } from "../ids/src/index.js";
import { canonicalDecimal, lengthPrefixed, sha256Hex } from "./canonical.ts";

export const DOMAIN_STORE_WRITE = "sociacl-store-write-v1";

/** Predecessor field when the row being replaced is absent. */
export const REPLACED_NONE = "none";

/** Class field for a recovery-store write. Wrap writes use `genesis` or `delivery`. */
export const STORE_CLASS_NONE = "none";

export const STORE_CLASS_GENESIS = "genesis";

export const STORE_CLASS_DELIVERY = "delivery";

const SEA_PUB = /^[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}$/u;

/** Monotonic per-principal head floor shared by the recovery and wrap stores. */
export class HeadFloor {
  readonly #values = new Map<string, number>();

  /** Record `head` when it is at least the floor. A smaller head is `store-rejected`. */
  observe(principal: string, head: number): void {
    const floor = this.#values.get(principal) ?? 0;
    if (head < floor) throw new Error("store-rejected");
    if (head > floor) this.#values.set(principal, head);
  }

  /** Raise the floor to a stored current sequence. A smaller sequence leaves it. */
  raise(principal: string, seq: number): void {
    const floor = this.#values.get(principal) ?? 0;
    if (seq > floor) this.#values.set(principal, seq);
  }
}

export type StoreWriteAccount = {
  readonly currentKey: PrincipalId;
  readonly currentEpub: PrincipalId | null;
  readonly rotations: readonly { readonly seq: number }[];
};

export function storeWriteMessage(
  principal: string,
  operation: string,
  target: string,
  envelopeHashHex: string,
  head: string,
  replaced: string,
  className: string,
  generation: string,
): Uint8Array {
  return lengthPrefixed([
    DOMAIN_STORE_WRITE,
    principal,
    operation,
    target,
    envelopeHashHex,
    head,
    replaced,
    className,
    generation,
  ]);
}

export function signStoreWrite(
  seaPriv: string,
  principal: PrincipalId,
  operation: string,
  target: string,
  envelopeHashHex: string,
  head: string,
  replaced: string,
  className: string,
  generation: string,
): string {
  const message = storeWriteMessage(
    principal,
    operation,
    target,
    envelopeHashHex,
    head,
    replaced,
    className,
    generation,
  );
  return bytesToHex(p256.sign(message, unb64(seaPriv), { lowS: true, prehash: true }));
}

/**
 * Verify `signature` under `account.currentKey`.
 *
 * The store has already resolved `account` from its own chain. A signature
 * that does not verify is `store-rejected`. The store must not mutate on
 * that error, or on any later rejection of the same call.
 */
export function verifyStoreWrite(
  principal: PrincipalId,
  operation: string,
  target: string,
  envelopeHashHex: string,
  head: string,
  replaced: string,
  className: string,
  generation: string,
  signature: string,
  account: StoreWriteAccount,
): void {
  const message = storeWriteMessage(
    principal,
    operation,
    target,
    envelopeHashHex,
    head,
    replaced,
    className,
    generation,
  );
  let ok = false;
  try {
    ok = p256.verify(hexToBytes(signature), message, uncompressedFromSea(account.currentKey), {
      lowS: true,
      prehash: true,
    });
  } catch {
    ok = false;
  }
  if (!ok) throw new Error("store-rejected");
}

/** SHA-256 of the wrap ciphertext bytes. The hex alphabet is not the hashed message. */
export function wrapCiphertextHash(ciphertextHex: string): string {
  return sha256Hex(hexToBytes(ciphertextHex));
}

export function recoveryEnvelopeHash(envelope: {
  principal: string;
  rotationSeq: number;
  signingPub: string;
  epub: string;
  bytes: Uint8Array;
}): string {
  return sha256Hex(
    lengthPrefixed([
      envelope.principal,
      canonicalDecimal(envelope.rotationSeq),
      envelope.signingPub,
      envelope.epub,
      bytesToHex(envelope.bytes),
    ]),
  );
}

function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/u.test(hex)) throw new Error("store-rejected");
  return Uint8Array.from(Buffer.from(hex, "hex"));
}

function unb64(text: string): Uint8Array {
  const pad = text.length % 4 === 0 ? "" : "=".repeat(4 - (text.length % 4));
  return Uint8Array.from(Buffer.from(text.replace(/-/g, "+").replace(/_/g, "/") + pad, "base64"));
}

function uncompressedFromSea(sea: string): Uint8Array {
  if (sea.length !== 87 || !SEA_PUB.test(sea)) throw new Error("store-rejected");
  const x = unb64(sea.slice(0, 43));
  const y = unb64(sea.slice(44));
  if (x.length !== 32 || y.length !== 32) throw new Error("store-rejected");
  const out = new Uint8Array(65);
  out[0] = 4;
  out.set(x, 1);
  out.set(y, 33);
  return out;
}
