/**
 * Device delivery of an account keyring through the #63 sealed wrap.
 * Caller-chosen ephemerals are wrapped for tests in
 * typescript/tests/support/recovery-deterministic.ts.
 */
import { createCipheriv, createDecipheriv } from "node:crypto";
import { p256 } from "@noble/curves/nist.js";
import { parseObjectId, parsePrincipalId, type ObjectId, type PrincipalId, type ResolutionContext } from "../ids/src/index.js";
import { currentSigningKey, type EncryptedAccountWrap, type KeyWrapStore } from "./account-key.ts";
import {
  backupAad,
  backupKdf,
  backupSignatureMessage,
  bytesToHex,
  hexToBytes,
  seaPoint,
  sharedX,
  unb64,
  uncompressedFromSea,
} from "./account-key-seal.ts";
import type { AccountKeyring } from "./account-keyring.ts";
import { AccountKeyring as Keyring } from "./account-keyring.ts";
import { decodeKeyring, encodeKeyring } from "./keyring-codec.ts";
import { DELIVERY_BLOB_MAX, KEYRING_SERIAL_MAX } from "./keyring-limits.ts";

const DOMAIN_DELIVERY_BIND = "sociacl-keyring-delivery-v1";
const DOMAIN_DELIVERY_SIG = "sociacl-keyring-delivery-sig-v1";

/** Caller-chosen ephemeral and nonce. Tests use this through the support wrapper. */
export function deliverKeyringWith(
  keyring: AccountKeyring,
  transportPub: string,
  ephemeral: Uint8Array,
  nonce: Uint8Array,
  wrapId: ObjectId,
  rotations: readonly unknown[],
  context: ResolutionContext,
  store: KeyWrapStore,
): EncryptedAccountWrap {
  if (ephemeral.length !== 32 || nonce.length !== 12) throw new Error("bad-key");
  const plain = encodeKeyring(keyring);
  let key: Uint8Array | undefined;
  try {
    if (plain.length > KEYRING_SERIAL_MAX) throw new Error("keyring-too-large");
    const current = currentSigningKey(keyring.principal, rotations, context);
    if (current !== keyring.pub) throw new Error("current-key");
    const peer = transportPeer(keyring, transportPub);
    const point = p256.getPublicKey(ephemeral, false);
    const ephemeralPub = seaPoint(ephemeral);
    const shared = sharedX(ephemeral, peer);
    key = backupKdf(shared, keyring.principal, wrapId, transportPub, ephemeralPub, DOMAIN_DELIVERY_BIND);
    shared.fill(0);
    const aad = backupAad(keyring.principal, wrapId, transportPub, ephemeralPub, DOMAIN_DELIVERY_BIND);
    const ciphertext = aesEncrypt(key, nonce, aad, plain);
    const blob = new Uint8Array(1 + point.length + nonce.length + ciphertext.length);
    blob[0] = 1;
    blob.set(point, 1);
    blob.set(nonce, 1 + point.length);
    blob.set(ciphertext, 1 + point.length + nonce.length);
    if (blob.length > DELIVERY_BLOB_MAX) throw new Error("keyring-too-large");
    const message = backupSignatureMessage(blob, transportPub, wrapId, DOMAIN_DELIVERY_SIG);
    const signature = bytesToHex(p256.sign(message, unb64(keyring.currentPriv()), { lowS: true, prehash: true }));
    const wrap: EncryptedAccountWrap = {
      principal: keyring.principal,
      wrapId,
      epub: keyring.epub,
      class: "delivery",
      ciphertextHex: bytesToHex(blob),
      signature,
    };
    store.put({ principal: wrap.principal, wrapId: wrap.wrapId, epub: wrap.epub }, wrap);
    return wrap;
  } finally {
    plain.fill(0);
    key?.fill(0);
  }
}

export function openDeliveredKeyring(
  transportScalarHex: string,
  wrap: EncryptedAccountWrap,
  expected: PrincipalId,
  expectedRotationSeq: number,
  rotations: readonly unknown[],
  context: ResolutionContext,
): AccountKeyring {
  if (wrap.ciphertextHex.length > DELIVERY_BLOB_MAX * 2) throw new Error("keyring-too-large");
  if (wrap.principal !== expected) throw new Error("wrap-rejected");
  if (wrap.signature.length !== 128 || !/^[0-9a-f]{128}$/u.test(wrap.signature)) throw new Error("wrap-rejected");
  const wrapId = parseObjectId(wrap.wrapId);
  if (!wrapId.ok) throw new Error(wrapId.reason);
  let blob: Uint8Array;
  try {
    blob = hexToBytes(wrap.ciphertextHex);
  } catch {
    throw new Error("wrap-rejected");
  }
  if (blob.length > DELIVERY_BLOB_MAX) throw new Error("keyring-too-large");
  if (blob[0] !== 1 || blob.length < 1 + 65 + 12 + 16) throw new Error("wrap-rejected");
  const transport = hexToBytes(transportScalarHex);
  if (transport.length !== 32) {
    transport.fill(0);
    throw new Error("bad-key");
  }
  let shared: Uint8Array | undefined;
  let key: Uint8Array | undefined;
  let plain: Uint8Array | undefined;
  try {
    const transportPub = seaPoint(transport);
    const message = backupSignatureMessage(blob, transportPub, wrapId.value, DOMAIN_DELIVERY_SIG);
    const current = currentSigningKey(expected, rotations, context);
    const currentOk = signatureOk(wrap.signature, message, current);
    const ephemeral = blob.subarray(1, 66);
    const nonce = blob.subarray(66, 78);
    let ephemeralPub: string;
    try {
      ephemeralPub = seaPoint(ephemeral);
      shared = sharedX(transport, ephemeral);
    } catch {
      throw new Error("wrap-rejected");
    }
    key = backupKdf(shared, expected, wrapId.value, transportPub, ephemeralPub, DOMAIN_DELIVERY_BIND);
    shared.fill(0);
    const aad = backupAad(expected, wrapId.value, transportPub, ephemeralPub, DOMAIN_DELIVERY_BIND);
    try {
      plain = aesDecrypt(key, nonce, aad, blob.subarray(78));
    } catch {
      throw new Error("wrap-rejected");
    }
    if (plain.length > KEYRING_SERIAL_MAX) throw new Error("keyring-too-large");
    if (currentOk) {
      let fields;
      try {
        fields = decodeKeyring(plain);
      } catch (error) {
        if (error instanceof Error && error.message === "keyring-too-large") throw error;
        throw new Error("wrap-rejected");
      }
      if (fields.rotationSeq !== expectedRotationSeq) {
        if (
          fields.rotationSeq < expectedRotationSeq &&
          signatureAtSeq(expected, rotations, context, fields.rotationSeq, message, wrap.signature)
        ) {
          throw new Error("recovery-stale");
        }
        throw new Error("wrap-rejected");
      }
      const parsed = parsePrincipalId(fields.principal);
      if (!parsed.ok || parsed.value !== fields.principal || parsed.value !== expected) throw new Error("wrap-rejected");
      const keyring = Keyring.import(
        fields.principal,
        fields.genesisEpub,
        fields.pub,
        fields.priv,
        fields.epub,
        fields.epriv,
        fields.retired,
        fields.laneId,
        fields.contentEpoch,
        fields.rotationSeq,
        rotations,
        context,
        fields.priorLanes,
      );
      if (keyring.epub !== wrap.epub) throw new Error("wrap-rejected");
      return keyring;
    }
    const seq = trailingRotationSeq(plain);
    if (
      seq !== undefined &&
      seq < expectedRotationSeq &&
      signatureAtSeq(expected, rotations, context, seq, message, wrap.signature)
    ) {
      throw new Error("recovery-stale");
    }
    throw new Error("wrap-rejected");
  } finally {
    shared?.fill(0);
    key?.fill(0);
    transport.fill(0);
    plain?.fill(0);
  }
}

function signatureOk(signature: string, message: Uint8Array, seaPub: string): boolean {
  try {
    return p256.verify(hexToBytes(signature), message, uncompressedFromSea(seaPub), { lowS: true, prehash: true });
  } catch {
    return false;
  }
}

/** Signing key valid at `seq`: the prefix `rotations.slice(0, seq)`. A resolution failure is not a choosable error. */
function signatureAtSeq(
  expected: PrincipalId,
  rotations: readonly unknown[],
  context: ResolutionContext,
  seq: number,
  message: Uint8Array,
  signature: string,
): boolean {
  try {
    const key = currentSigningKey(expected, rotations.slice(0, seq), context);
    return signatureOk(signature, message, key);
  } catch {
    return false;
  }
}

function trailingRotationSeq(bytes: Uint8Array): number | undefined {
  if (bytes.length === 0 || bytes.length > KEYRING_SERIAL_MAX) return undefined;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let offset = 0;
  let last = "";
  const text = new TextDecoder("utf-8", { fatal: true });
  try {
    while (offset < bytes.length) {
      if (bytes.length - offset < 4) return undefined;
      const len = view.getUint32(offset, true);
      offset += 4;
      if (bytes.length - offset < len) return undefined;
      last = text.decode(bytes.subarray(offset, offset + len));
      offset += len;
    }
  } catch {
    return undefined;
  }
  if (!/^(0|[1-9][0-9]*)$/u.test(last)) return undefined;
  const seq = Number(last);
  if (!Number.isSafeInteger(seq)) return undefined;
  return seq;
}

function transportPeer(keyring: AccountKeyring, transportPub: string): Uint8Array {
  const held = new Set<string>([keyring.principal, keyring.genesisEpub, keyring.pub, keyring.epub]);
  for (const row of keyring.retired()) held.add(row.epub);
  if (held.has(transportPub)) throw new Error("transport");
  try {
    const peer = uncompressedFromSea(transportPub);
    p256.Point.fromBytes(peer);
    return peer;
  } catch (error) {
    if (error instanceof Error && error.message === "transport") throw error;
    throw new Error("bad-key");
  }
}

function aesEncrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, plain: Uint8Array): Uint8Array {
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(aad);
  return new Uint8Array(Buffer.concat([cipher.update(plain), cipher.final(), cipher.getAuthTag()]));
}

function aesDecrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, body: Uint8Array): Uint8Array {
  const tag = body.subarray(body.length - 16);
  const data = body.subarray(0, body.length - 16);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return new Uint8Array(Buffer.concat([decipher.update(data), decipher.final()]));
}
