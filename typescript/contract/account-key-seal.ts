/**
 * Account-key cryptography. Not a package export, and not re-exported by
 * account-key.ts. Caller-chosen ephemerals are wrapped for tests in
 * typescript/tests/support/account-key-deterministic.ts.
 */
import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { p256 } from "@noble/curves/nist.js";
import { parseObjectId, resolveCurrentKey, type ObjectId, type PrincipalId, type ResolutionContext } from "../ids/src/index.js";
import type { EncryptedAccountWrap, GenesisAccount, KeyWrapStore } from "./account-key.ts";
import { canonicalDecimal, lengthPrefixed } from "./canonical.ts";
import { REPLACED_NONE, signStoreWrite, wrapRowHash } from "./store-write.ts";

const DOMAIN_ACCOUNT_WRAP = "sociacl-account-key-wrap-v1";
const DOMAIN_ACCOUNT_BIND = "sociacl-account-key-bind-v1";
const DOMAIN_ACCOUNT_SIG = "sociacl-account-key-wrap-sig-v1";
const DOMAIN_WRAPPED_KEY = "s3rch-wrapped-key-v1";
const MAX_BACKUP_BYTES = 8192;
/** SEA `base64url(x).base64url(y)`: 43 + 1 + 43. Checked before any decode. */
const SEA_PUB = /^[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}$/u;

export function currentSigningKey(
  genesis: PrincipalId,
  rotations: readonly unknown[],
  context: ResolutionContext,
): PrincipalId {
  const resolved = resolveCurrentKey(genesis, rotations, context);
  if (!resolved.ok) throw new Error(resolved.reason);
  return resolved.value.currentKey;
}

export function randomScalar(): Uint8Array {
  for (;;) {
    const bytes = randomBytes(32);
    try {
      p256.getPublicKey(bytes, false);
      return bytes;
    } catch {
      // A zero or out-of-range scalar is not a key. Draw again.
    }
  }
}

/** Encrypt with a caller-chosen ephemeral. Tests use this through the support wrapper. */
export function encryptAccountBackup(
  account: GenesisAccount,
  transportPub: string,
  ephemeral: Uint8Array,
  nonce: Uint8Array,
  wrapId: ObjectId,
  rotations: readonly unknown[],
  context: ResolutionContext,
  store: KeyWrapStore,
): EncryptedAccountWrap {
  if (ephemeral.length !== 32 || nonce.length !== 12) throw new Error("bad-key");
  const current = currentSigningKey(account.principal, rotations, context);
  if (current !== account.pub) throw new Error("current-key");
  const peer = transportPeer(account, transportPub);
  const point = p256.getPublicKey(ephemeral, false);
  const ephemeralPub = seaPoint(ephemeral);
  const plain = lengthPrefixed([
    DOMAIN_ACCOUNT_WRAP,
    account.principal,
    account.priv,
    account.epub,
    account.epriv,
    account.laneId,
  ]);
  const aad = backupAad(account.principal, wrapId, transportPub, ephemeralPub);
  const ct = aesEncrypt(backupKdf(sharedX(ephemeral, peer), account.principal, wrapId, transportPub, ephemeralPub), nonce, aad, plain);
  const blob = new Uint8Array(1 + point.length + nonce.length + ct.length);
  blob[0] = 1;
  blob.set(point, 1);
  blob.set(nonce, 1 + point.length);
  blob.set(ct, 1 + point.length + nonce.length);
  if (blob.length > MAX_BACKUP_BYTES) throw new Error("wrap-rejected");
  const ciphertextHex = bytesToHex(blob);
  const privHex = bytesToHex(unb64(account.priv));
  const eprivHex = bytesToHex(unb64(account.epriv));
  if (ciphertextHex.includes(privHex) || ciphertextHex.includes(eprivHex)) throw new Error("wrap-rejected");
  const message = backupSignatureMessage(blob, transportPub, wrapId);
  const signature = bytesToHex(p256.sign(message, unb64(account.priv), { lowS: true, prehash: true }));
  const wrap: EncryptedAccountWrap = {
    principal: account.principal,
    wrapId,
    epub: account.epub,
    class: "genesis",
    ciphertextHex,
    signature,
  };
  const hash = wrapRowHash(wrap);
  const accountHead = store.publishedAccount(wrap.principal);
  const existing = store.get(wrap.principal, wrap.wrapId);
  const storeSignature = signStoreWrite(
    account.priv,
    wrap.principal,
    "put",
    wrap.wrapId,
    hash,
    canonicalDecimal(accountHead.rotations.length),
    existing ? wrapRowHash(existing) : REPLACED_NONE,
    wrap.class,
    canonicalDecimal(store.writeGeneration(wrap.principal)),
  );
  store.put(
    { principal: wrap.principal, wrapId: wrap.wrapId, epub: wrap.epub },
    wrap,
    storeSignature,
  );
  const stored = store.get(wrap.principal, wrap.wrapId);
  if (!stored || wrapRowHash(stored) !== hash) throw new Error("store-rejected");
  return wrap;
}

/** Content wrap with a caller-chosen ephemeral. Tests use this through the support wrapper. */
export function wrapContent(
  account: GenesisAccount,
  dekHex: string,
  ephemeralScalarHex: string,
  nonceHex: string,
  epoch: number,
  objectId: string,
  revisionId: string,
): string {
  const parsed = parseObjectId(objectId);
  if (!parsed.ok) throw new Error(parsed.reason);
  if (!/^[0-9a-f]{64}$/u.test(revisionId)) throw new Error("bad-revision");
  const dek = hexToBytes(dekHex);
  const ephemeral = hexToBytes(ephemeralScalarHex);
  const nonce = hexToBytes(nonceHex);
  if (dek.length !== 32 || ephemeral.length !== 32 || nonce.length !== 12) throw new Error("bad-key");
  const plain = lengthPrefixed([
    DOMAIN_WRAPPED_KEY,
    "item-dek",
    canonicalDecimal(epoch),
    "reader-epub",
    account.epub,
    parsed.value,
    "",
    revisionId,
    bytesToHex(dek),
  ]);
  const peer = uncompressedFromSea(account.epub);
  const point = p256.getPublicKey(ephemeral, false);
  const ct = aesEncrypt(contentKdf(sharedX(ephemeral, peer)), nonce, new Uint8Array(), plain);
  const blob = new Uint8Array(1 + point.length + nonce.length + ct.length);
  blob[0] = 1;
  blob.set(point, 1);
  blob.set(nonce, 1 + point.length);
  blob.set(ct, 1 + point.length + nonce.length);
  return bytesToHex(blob);
}

export function openBackupParts(blob: Uint8Array): { ephemeral: Uint8Array; nonce: Uint8Array } {
  const first = blob[0];
  if (first !== 1 || blob.length < 1 + 65 + 12 + 16 || blob.length > MAX_BACKUP_BYTES) throw new Error("wrap-rejected");
  return { ephemeral: blob.slice(1, 66), nonce: blob.slice(66, 78) };
}

export function backupPlaintext(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  body: Uint8Array,
): Uint8Array {
  return aesDecrypt(key, nonce, aad, body);
}

export function backupKdf(
  x: Uint8Array,
  principal: string,
  wrapId: string,
  transportPub: string,
  ephemeralPub: string,
  domain = DOMAIN_ACCOUNT_BIND,
): Uint8Array {
  return kdf(domain, x, principal, wrapId, transportPub, ephemeralPub);
}

export function backupAad(
  principal: string,
  wrapId: string,
  transportPub: string,
  ephemeralPub: string,
  domain = DOMAIN_ACCOUNT_BIND,
): Uint8Array {
  return lengthPrefixed([domain, principal, wrapId, transportPub, ephemeralPub]);
}

export function backupSignatureMessage(
  blob: Uint8Array,
  transportPub: string,
  wrapId: string,
  domain = DOMAIN_ACCOUNT_SIG,
): Uint8Array {
  return lengthPrefixed([domain, sha256Hex(blob), transportPub, wrapId]);
}

export const MAX_BACKUP_HEX = MAX_BACKUP_BYTES * 2;

function transportPeer(account: GenesisAccount, transportPub: string): Uint8Array {
  if (transportPub === account.pub || transportPub === account.epub) throw new Error("transport");
  try {
    const peer = uncompressedFromSea(transportPub);
    p256.Point.fromBytes(peer);
    return peer;
  } catch {
    throw new Error("bad-key");
  }
}

function contentKdf(x: Uint8Array): Uint8Array {
  return sha256Bytes(lengthPrefixed(["s3rch-sea-secret-v1", bytesToHex(x)]));
}

function kdf(
  domain: string,
  x: Uint8Array,
  principal: string,
  wrapId: string,
  transportPub: string,
  ephemeralPub: string,
): Uint8Array {
  return sha256Bytes(lengthPrefixed([domain, bytesToHex(x), principal, wrapId, transportPub, ephemeralPub]));
}

export function sharedX(scalar: Uint8Array, peerUncompressed: Uint8Array): Uint8Array {
  return p256.getSharedSecret(scalar, peerUncompressed, false).slice(1, 33);
}

function aesEncrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, plain: Uint8Array): Uint8Array {
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(aad);
  return new Uint8Array(Buffer.concat([cipher.update(plain), cipher.final(), cipher.getAuthTag()]));
}

function aesDecrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, body: Uint8Array): Uint8Array {
  const tag = body.slice(body.length - 16);
  const data = body.slice(0, body.length - 16);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return new Uint8Array(Buffer.concat([decipher.update(data), decipher.final()]));
}

export function seaPoint(scalar: Uint8Array): string {
  const raw = scalar.length === 65 ? scalar : p256.getPublicKey(scalar, false);
  return `${b64(raw.slice(1, 33))}.${b64(raw.slice(33))}`;
}

export function uncompressedFromSea(sea: string): Uint8Array {
  if (sea.length !== 87 || !SEA_PUB.test(sea)) throw new Error("bad-key");
  const x = unb64(sea.slice(0, 43));
  const y = unb64(sea.slice(44));
  if (x.length !== 32 || y.length !== 32) throw new Error("bad-key");
  const out = new Uint8Array(65);
  out[0] = 4;
  out.set(x, 1);
  out.set(y, 33);
  return out;
}

export function decodeLengthPrefixed(bytes: Uint8Array): string[] {
  const out: string[] = [];
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let offset = 0;
  while (offset < bytes.length) {
    if (bytes.length - offset < 4) throw new Error("bad-encoding");
    const len = view.getUint32(offset, true);
    offset += 4;
    if (bytes.length - offset < len) throw new Error("bad-encoding");
    out.push(new TextDecoder().decode(bytes.slice(offset, offset + len)));
    offset += len;
  }
  return out;
}

function sha256Bytes(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(bytes).digest());
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function b64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

export function unb64(text: string): Uint8Array {
  if (text.length !== 43 || !/^[A-Za-z0-9_-]{43}$/u.test(text)) throw new Error("base64url");
  const bytes = Uint8Array.from(atob(text.replaceAll("-", "+").replaceAll("_", "/")), (c) => c.charCodeAt(0));
  if (b64(bytes) !== text) throw new Error("noncanonical base64url");
  return bytes;
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-f]+$/u.test(hex)) throw new Error("bad-key");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}
