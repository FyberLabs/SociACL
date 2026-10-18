/**
 * Authorization for a recovery-copy or wrap-store write.
 *
 * Every put, commit, and delete carries a signature by the account's current
 * chain-head key, over `sociacl-store-write-v1`, the PrincipalId, the
 * operation, the target sequence or wrap id, and the envelope hash. The store
 * verifies that signature against the resolved published chain. Session
 * authentication is not this check. Adapters, Panopticon included, must verify
 * before they write. Panopticon is a verifier and a witness. It is never the
 * authority.
 */
import { p256 } from "@noble/curves/nist.js";
import { resolveCurrentKey, type PrincipalId, type ResolutionContext } from "../ids/src/index.js";
import { canonicalDecimal, lengthPrefixed, sha256Hex } from "./canonical.ts";

export const DOMAIN_STORE_WRITE = "sociacl-store-write-v1";

const SEA_PUB = /^[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}$/u;

export function storeWriteMessage(
  principal: string,
  operation: string,
  target: string,
  envelopeHashHex: string,
): Uint8Array {
  return lengthPrefixed([DOMAIN_STORE_WRITE, principal, operation, target, envelopeHashHex]);
}

export function signStoreWrite(
  seaPriv: string,
  principal: PrincipalId,
  operation: string,
  target: string,
  envelopeHashHex: string,
): string {
  const message = storeWriteMessage(principal, operation, target, envelopeHashHex);
  return bytesToHex(p256.sign(message, unb64(seaPriv), { lowS: true, prehash: true }));
}

/** A chain that does not resolve, or a signature that does not verify, is `store-rejected`. */
export function verifyStoreWrite(
  principal: PrincipalId,
  operation: string,
  target: string,
  envelopeHashHex: string,
  signature: string,
  rotations: readonly unknown[],
  context: ResolutionContext,
): { currentKey: PrincipalId; currentEpub: PrincipalId | null; rotations: readonly { seq: number }[] } {
  const resolved = resolveCurrentKey(principal, rotations, context);
  if (!resolved.ok) throw new Error("store-rejected");
  const message = storeWriteMessage(principal, operation, target, envelopeHashHex);
  let ok = false;
  try {
    ok = p256.verify(hexToBytes(signature), message, uncompressedFromSea(resolved.value.currentKey), {
      lowS: true,
      prehash: true,
    });
  } catch {
    ok = false;
  }
  if (!ok) throw new Error("store-rejected");
  return resolved.value;
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
