/**
 * Genesis account key. The account is its sociacl-ids PrincipalId.
 * Devices inherit that one SEA keypair. priv and epriv stay off Gun.
 * The backup ciphertext goes to a KeyWrapStore, which is not an authority.
 */
import { createCipheriv, createDecipheriv, createHash } from "node:crypto";
import { p256 } from "@noble/curves/nist.js";
import {
  formatPrincipalKey,
  grantSoul,
  parseEip55,
  parseObjectId,
  parsePrincipalId,
  principalFromSec1,
  userSoul,
  type ObjectId,
  type PrincipalId,
} from "../ids/src/index.js";
import { lengthPrefixed } from "./canonical.ts";

const DOMAIN_ACCOUNT_WRAP = "sociacl-account-key-wrap-v1";
const DOMAIN_SEA_SECRET = "s3rch-sea-secret-v1";
const DOMAIN_WRAPPED_KEY = "s3rch-wrapped-key-v1";

export type GenesisAccount = {
  readonly principal: PrincipalId;
  readonly pub: string;
  readonly priv: string;
  readonly epub: string;
  readonly epriv: string;
  readonly laneId: string;
};

export type InheritedDevice = {
  readonly localId: string;
  readonly account: GenesisAccount;
  readonly grantsSee: false;
};

export type WrapIndex = {
  readonly principal: PrincipalId;
  readonly wrapId: ObjectId;
  readonly epub: string;
};

export type EncryptedAccountWrap = WrapIndex & { readonly ciphertextHex: string };

export type LinkedCredential = {
  readonly kind: "wallet" | "oidc";
  readonly principal: PrincipalId;
  readonly label: string;
};

/** Index plus ciphertext. Not an authority and not a grant minter. */
export class MemoryKeyWrapStore {
  readonly isAuthority = false;
  readonly mintsGrant = false;
  readonly #wraps = new Map<string, EncryptedAccountWrap>();

  put(index: WrapIndex, wrap: EncryptedAccountWrap): void {
    if (
      index.principal !== wrap.principal ||
      index.wrapId !== wrap.wrapId ||
      index.epub !== wrap.epub ||
      index.epub.length === 0 ||
      !/^[0-9a-f]+$/.test(wrap.ciphertextHex) ||
      wrap.ciphertextHex.length % 2 !== 0
    ) {
      throw new Error("store-rejected");
    }
    const existing = this.#wraps.get(index.principal);
    if (existing && existing.wrapId !== wrap.wrapId) throw new Error("store-rejected");
    this.#wraps.set(index.principal, wrap);
  }

  get(principal: PrincipalId): EncryptedAccountWrap | undefined {
    return this.#wraps.get(principal);
  }
}

export function importGenesis(
  laneId: string,
  seaPub: string,
  seaPriv: string,
  epub: string,
  epriv: string,
): GenesisAccount {
  if (!/^[0-9a-f]{64}$/.test(laneId)) throw new Error("bad-lane");
  const principal = principalFromSec1(uncompressedFromSea(seaPub));
  if (!principal.ok || principal.value !== seaPub || seaPoint(unb64(seaPriv)) !== seaPub) {
    throw new Error("pub-mismatch");
  }
  const parsed = parsePrincipalId(seaPub);
  if (!parsed.ok || parsed.value !== principal.value) throw new Error("pub-mismatch");
  const encryption = principalFromSec1(uncompressedFromSea(epub));
  if (!encryption.ok || encryption.value !== epub || seaPoint(unb64(epriv)) !== epub || epub === seaPub) {
    throw new Error("epub-mismatch");
  }
  return { principal: principal.value, pub: seaPub, priv: seaPriv, epub, epriv, laneId };
}

export function enroll(account: GenesisAccount, localId: string): InheritedDevice {
  if (localId.length === 0) throw new Error("empty-device");
  if (parsePrincipalId(localId).ok || parseEip55(localId).ok) throw new Error("device-id");
  return { localId, account, grantsSee: false };
}

export function gunDocument(account: GenesisAccount): string {
  const soul = userSoul(account.principal);
  return `{"soul":${jsonString(soul)},"account":${jsonString(account.principal)},"pub":${jsonString(account.pub)},"epub":${jsonString(account.epub)}}`;
}

export function principalKey(account: GenesisAccount): string {
  return formatPrincipalKey(account.principal);
}

export function accountIdFromLabel(label: string): { ok: true; value: PrincipalId } | { ok: false; reason: string } {
  return parsePrincipalId(label);
}

export function deliveryMintsGrant(kind: string): boolean {
  if (kind === "enrollment" || kind === "hop" || kind === "hint" || kind === "wrap" || kind === "request" || kind === "inbox") {
    return false;
  }
  throw new Error("unknown-delivery");
}

export function sameAccount(credential: LinkedCredential, account: PrincipalId): boolean {
  return credential.principal === account;
}

export function accountGrantSoul(owner: PrincipalId, object: ObjectId, accessor: PrincipalId): string {
  return grantSoul(owner, object, accessor);
}

export function parseWrapObject(text: string): ObjectId {
  const parsed = parseObjectId(text);
  if (!parsed.ok) throw new Error(parsed.reason);
  return parsed.value;
}

export function sealAccountBackup(
  account: GenesisAccount,
  transportScalarHex: string,
  ephemeralScalarHex: string,
  nonceHex: string,
  wrapId: ObjectId,
  store: MemoryKeyWrapStore,
): EncryptedAccountWrap {
  const transport = hexToBytes(transportScalarHex);
  const ephemeral = hexToBytes(ephemeralScalarHex);
  const nonce = hexToBytes(nonceHex);
  if (transport.length !== 32 || ephemeral.length !== 32 || nonce.length !== 12) throw new Error("bad-key");
  const transportPub = seaPoint(transport);
  if (transportPub === account.pub) throw new Error("transport");
  const plain = lengthPrefixed([
    DOMAIN_ACCOUNT_WRAP,
    account.principal,
    account.priv,
    account.epub,
    account.epriv,
    account.laneId,
  ]);
  const blob = sealBlob(ephemeral, p256.getPublicKey(transport, false), nonce, plain);
  const ciphertextHex = bytesToHex(blob);
  if (ciphertextHex.includes(account.priv) || ciphertextHex.includes(account.epriv)) throw new Error("wrap-rejected");
  const wrap: EncryptedAccountWrap = {
    principal: account.principal,
    wrapId,
    epub: account.epub,
    ciphertextHex,
  };
  store.put(wrap, wrap);
  return wrap;
}

export function openAccountBackup(transportScalarHex: string, wrap: EncryptedAccountWrap): GenesisAccount {
  const blob = hexToBytes(wrap.ciphertextHex);
  const first = blob[0];
  if (first !== 1 || blob.length < 1 + 65 + 12 + 16) throw new Error("wrap-rejected");
  const ephemeral = blob.slice(1, 66);
  const nonce = blob.slice(66, 78);
  const x = sharedX(hexToBytes(transportScalarHex), ephemeral);
  const plain = aesDecrypt(kdf(x), nonce, blob.slice(78));
  const fields = decodeLengthPrefixed(plain);
  if (fields.length !== 6 || fields[0] !== DOMAIN_ACCOUNT_WRAP) throw new Error("wrap-rejected");
  const account = importGenesis(fields[5] ?? "", fields[1] ?? "", fields[2] ?? "", fields[3] ?? "", fields[4] ?? "");
  if (account.principal !== wrap.principal || account.epub !== wrap.epub) throw new Error("wrap-rejected");
  return account;
}

export function contentWrapHex(
  account: GenesisAccount,
  dekHex: string,
  ephemeralScalarHex: string,
  nonceHex: string,
  epoch: number,
  objectId: string,
  revisionId: string,
): string {
  const dek = hexToBytes(dekHex);
  const ephemeral = hexToBytes(ephemeralScalarHex);
  const nonce = hexToBytes(nonceHex);
  if (dek.length !== 32 || ephemeral.length !== 32 || nonce.length !== 12) throw new Error("bad-key");
  const plain = lengthPrefixed([
    DOMAIN_WRAPPED_KEY,
    "item-dek",
    String(epoch),
    "reader-epub",
    account.epub,
    objectId,
    "",
    revisionId,
    bytesToHex(dek),
  ]);
  return bytesToHex(sealBlob(ephemeral, uncompressedFromSea(account.epub), nonce, plain));
}

function sealBlob(ephemeral: Uint8Array, peer: Uint8Array, nonce: Uint8Array, plain: Uint8Array): Uint8Array {
  const point = p256.getPublicKey(ephemeral, false);
  const ct = aesEncrypt(kdf(sharedX(ephemeral, peer)), nonce, plain);
  const blob = new Uint8Array(1 + point.length + nonce.length + ct.length);
  blob[0] = 1;
  blob.set(point, 1);
  blob.set(nonce, 1 + point.length);
  blob.set(ct, 1 + point.length + nonce.length);
  return blob;
}

function sharedX(scalar: Uint8Array, peerUncompressed: Uint8Array): Uint8Array {
  return p256.getSharedSecret(scalar, peerUncompressed, false).slice(1, 33);
}

function kdf(x: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(lengthPrefixed([DOMAIN_SEA_SECRET, bytesToHex(x)])).digest());
}

function aesEncrypt(key: Uint8Array, nonce: Uint8Array, plain: Uint8Array): Uint8Array {
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  return new Uint8Array(Buffer.concat([cipher.update(plain), cipher.final(), cipher.getAuthTag()]));
}

function aesDecrypt(key: Uint8Array, nonce: Uint8Array, body: Uint8Array): Uint8Array {
  const tag = body.slice(body.length - 16);
  const data = body.slice(0, body.length - 16);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAuthTag(tag);
  return new Uint8Array(Buffer.concat([decipher.update(data), decipher.final()]));
}

function seaPoint(scalar: Uint8Array): string {
  const raw = p256.getPublicKey(scalar, false);
  return `${b64(raw.slice(1, 33))}.${b64(raw.slice(33))}`;
}

function uncompressedFromSea(sea: string): Uint8Array {
  const dot = sea.indexOf(".");
  if (dot < 0 || sea.indexOf(".", dot + 1) !== -1) throw new Error("bad-key");
  const x = unb64(sea.slice(0, dot));
  const y = unb64(sea.slice(dot + 1));
  if (x.length !== 32 || y.length !== 32) throw new Error("bad-key");
  const out = new Uint8Array(65);
  out[0] = 4;
  out.set(x, 1);
  out.set(y, 33);
  return out;
}

function decodeLengthPrefixed(bytes: Uint8Array): string[] {
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

/** Canonical unpadded base64url, the same alphabet sociacl-ids uses for a SEA point. */
function b64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function unb64(text: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/u.test(text)) throw new Error("base64url");
  const bytes = Uint8Array.from(atob(text.replaceAll("-", "+").replaceAll("_", "/")), (c) => c.charCodeAt(0));
  if (b64(bytes) !== text) throw new Error("noncanonical base64url");
  return bytes;
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-f]+$/u.test(hex)) throw new Error("bad-key");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

function jsonString(value: string): string {
  return JSON.stringify(value);
}
