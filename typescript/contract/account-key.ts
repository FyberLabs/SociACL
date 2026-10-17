/**
 * Genesis account key. The account is its sociacl-ids PrincipalId.
 * Devices inherit that one SEA keypair. priv and epriv stay off Gun.
 * The backup ciphertext goes to a KeyWrapStore, which is not an authority.
 *
 * Seal takes the recipient's transport public key. The ephemeral key and
 * nonce are generated inside sealAccountBackup. That public key must arrive
 * out of band (a QR code, or a short-code comparison). Panopticon stores
 * the wrap and must not be the only channel for the transport public key.
 *
 * `rotations` and the resolution context passed to seal and open must be the
 * trusted latest-state checkpoint from sociacl-ids §4.6. Panopticon alone
 * does not supply that checkpoint.
 */
import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { p256 } from "@noble/curves/nist.js";
import {
  formatPrincipalKey,
  grantSoul,
  parseEip55,
  parseObjectId,
  parsePrincipalId,
  principalFromSec1,
  resolveCurrentKey,
  userSoul,
  verifyOidcLink,
  verifyWalletLink,
  type Jwks,
  type KeyState,
  type ObjectId,
  type PrincipalId,
  type ResolutionContext,
  type SiwePolicy,
} from "../ids/src/index.js";
import { canonicalDecimal, lengthPrefixed } from "./canonical.ts";

const DOMAIN_ACCOUNT_WRAP = "sociacl-account-key-wrap-v1";
const DOMAIN_ACCOUNT_BIND = "sociacl-account-key-bind-v1";
const DOMAIN_ACCOUNT_SIG = "sociacl-account-key-wrap-sig-v1";
const DOMAIN_WRAPPED_KEY = "s3rch-wrapped-key-v1";
const MAX_BACKUP_BYTES = 8192;

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

export type EncryptedAccountWrap = WrapIndex & {
  readonly ciphertextHex: string;
  readonly signature: string;
};

/** Index plus ciphertext. Not an authority and not a grant minter. */
export interface KeyWrapStore {
  readonly isAuthority: false;
  readonly mintsGrant: false;
  put(index: WrapIndex, wrap: EncryptedAccountWrap): void;
  get(principal: PrincipalId): EncryptedAccountWrap | undefined;
}

export class MemoryKeyWrapStore implements KeyWrapStore {
  readonly isAuthority = false as const;
  readonly mintsGrant = false as const;
  readonly #wraps = new Map<string, EncryptedAccountWrap>();

  put(index: WrapIndex, wrap: EncryptedAccountWrap): void {
    if (wrap.ciphertextHex.length > MAX_BACKUP_BYTES * 2 || wrap.signature.length !== 128) {
      throw new Error("store-rejected");
    }
    if (
      index.principal !== wrap.principal ||
      index.wrapId !== wrap.wrapId ||
      index.epub !== wrap.epub ||
      index.epub.length === 0 ||
      !/^[0-9a-f]+$/u.test(wrap.ciphertextHex) ||
      wrap.ciphertextHex.length % 2 !== 0 ||
      !/^[0-9a-f]{128}$/u.test(wrap.signature)
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

const linkedBrand = Symbol("verified-link");

/**
 * A wallet or OIDC record that `verifyWalletLink` / `verifyOidcLink` accepted.
 * The constructor is private. A forged record is not a credential.
 */
export class LinkedCredential {
  readonly kind: "wallet" | "oidc";
  readonly principal: PrincipalId;
  readonly label: string;
  readonly #brand = linkedBrand;

  private constructor(kind: "wallet" | "oidc", principal: PrincipalId, label: string) {
    this.kind = kind;
    this.principal = principal;
    this.label = label;
  }

  static fromWallet(raw: unknown, jwks: Jwks, policy: SiwePolicy, now: number, keyState: KeyState): LinkedCredential {
    const verified = verifyWalletLink(raw, jwks, policy, now, keyState);
    if (!verified.ok) throw new Error("unverified-credential");
    return new LinkedCredential("wallet", verified.value.principal, verified.value.address);
  }

  static fromOidc(
    raw: unknown,
    jwks: Jwks,
    pinnedIss: ReadonlySet<string>,
    now: number,
    keyState: KeyState,
  ): LinkedCredential {
    const verified = verifyOidcLink(raw, jwks, pinnedIss, now, keyState);
    if (!verified.ok) throw new Error("unverified-credential");
    return new LinkedCredential("oidc", verified.value.principal, verified.value.cred.sub);
  }
}

export function importGenesis(
  laneId: string,
  seaPub: string,
  seaPriv: string,
  epub: string,
  epriv: string,
): GenesisAccount {
  if (!/^[0-9a-f]{64}$/u.test(laneId)) throw new Error("bad-lane");
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
  if (!(credential instanceof LinkedCredential)) throw new Error("unverified-credential");
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

export function currentSigningKey(
  genesis: PrincipalId,
  rotations: readonly unknown[],
  context: ResolutionContext,
): PrincipalId {
  const resolved = resolveCurrentKey(genesis, rotations, context);
  if (!resolved.ok) throw new Error(resolved.reason);
  return resolved.value.currentKey;
}

/**
 * Seal to `transportPub`. Randomness stays inside this function.
 * `rotations` and `context` are the trusted latest-state checkpoint (sociacl-ids §4.6).
 */
export function sealAccountBackup(
  account: GenesisAccount,
  transportPub: string,
  wrapId: ObjectId,
  store: KeyWrapStore,
  rotations: readonly unknown[],
  context: ResolutionContext,
): EncryptedAccountWrap {
  return sealAccountBackupWith(account, transportPub, randomScalar(), randomBytes(12), wrapId, rotations, context, store);
}

/**
 * Open a wrap for `expected`.
 * `rotations` and `context` are the trusted latest-state checkpoint (sociacl-ids §4.6).
 */
export function openAccountBackup(
  transportScalarHex: string,
  wrap: EncryptedAccountWrap,
  expected: PrincipalId,
  rotations: readonly unknown[],
  context: ResolutionContext,
): GenesisAccount {
  if (wrap.signature.length !== 128 || !/^[0-9a-f]{128}$/u.test(wrap.signature)) throw new Error("wrap-rejected");
  if (wrap.ciphertextHex.length > MAX_BACKUP_BYTES * 2) throw new Error("wrap-rejected");
  const transport = hexToBytes(transportScalarHex);
  if (transport.length !== 32) throw new Error("bad-key");
  const transportPub = seaPoint(transport);
  const blob = hexToBytes(wrap.ciphertextHex);
  const first = blob[0];
  if (first !== 1 || blob.length < 1 + 65 + 12 + 16 || blob.length > MAX_BACKUP_BYTES) throw new Error("wrap-rejected");
  const ephemeral = blob.slice(1, 66);
  const nonce = blob.slice(66, 78);
  const current = currentSigningKey(expected, rotations, context);
  const message = lengthPrefixed([DOMAIN_ACCOUNT_SIG, sha256Hex(blob), transportPub, wrap.wrapId]);
  let signatureOk = false;
  try {
    signatureOk = p256.verify(hexToBytes(wrap.signature), message, uncompressedFromSea(current), { lowS: true, prehash: true });
  } catch {
    signatureOk = false;
  }
  if (!signatureOk) throw new Error("wrap-rejected");
  const ephemeralPub = seaPoint(ephemeral);
  const x = sharedX(transport, ephemeral);
  const aad = lengthPrefixed([DOMAIN_ACCOUNT_BIND, expected, wrap.wrapId, transportPub, ephemeralPub]);
  const plain = aesDecrypt(kdf(x, expected, wrap.wrapId, transportPub, ephemeralPub), nonce, aad, blob.slice(78));
  const fields = decodeLengthPrefixed(plain);
  if (fields.length !== 6 || fields[0] !== DOMAIN_ACCOUNT_WRAP) throw new Error("wrap-rejected");
  const account = importGenesis(fields[5] ?? "", fields[1] ?? "", fields[2] ?? "", fields[3] ?? "", fields[4] ?? "");
  if (account.principal !== expected || account.principal !== wrap.principal || account.epub !== wrap.epub) {
    throw new Error("wrap-rejected");
  }
  return account;
}

/** Wrap a DEK to the account `epub`. The ephemeral key and nonce are generated here. */
export function contentWrapHex(
  account: GenesisAccount,
  dekHex: string,
  epoch: number,
  objectId: string,
  revisionId: string,
): string {
  return contentWrapHexWith(account, dekHex, bytesToHex(randomScalar()), bytesToHex(randomBytes(12)), epoch, objectId, revisionId);
}

/** Deterministic content wrap. Not a production export. */
function contentWrapHexWith(
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

/**
 * Deterministic helpers for `node --test`.
 * Returns undefined unless `NODE_TEST_CONTEXT` is set. The helpers are not named exports.
 */
export function accountKeyTestApi():
  | {
      sealAccountBackupWith: (
        account: GenesisAccount,
        transportPub: string,
        ephemeralScalarHex: string,
        nonceHex: string,
        wrapId: ObjectId,
        rotations: readonly unknown[],
        context: ResolutionContext,
        store: KeyWrapStore,
      ) => EncryptedAccountWrap;
      contentWrapHexWith: (
        account: GenesisAccount,
        dekHex: string,
        ephemeralScalarHex: string,
        nonceHex: string,
        epoch: number,
        objectId: string,
        revisionId: string,
      ) => string;
    }
  | undefined {
  if (process.env.NODE_TEST_CONTEXT === undefined) return undefined;
  return {
    sealAccountBackupWith(account, transportPub, ephemeralScalarHex, nonceHex, wrapId, rotations, context, store) {
      return sealAccountBackupWith(
        account,
        transportPub,
        hexToBytes(ephemeralScalarHex),
        hexToBytes(nonceHex),
        wrapId,
        rotations,
        context,
        store,
      );
    },
    contentWrapHexWith,
  };
}

/** Deterministic enrollment seal. Not a production export. */
function sealAccountBackupWith(
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
  const aad = lengthPrefixed([DOMAIN_ACCOUNT_BIND, account.principal, wrapId, transportPub, ephemeralPub]);
  const ct = aesEncrypt(kdf(sharedX(ephemeral, peer), account.principal, wrapId, transportPub, ephemeralPub), nonce, aad, plain);
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
  const message = lengthPrefixed([DOMAIN_ACCOUNT_SIG, sha256Hex(blob), transportPub, wrapId]);
  const signature = bytesToHex(p256.sign(message, unb64(account.priv), { lowS: true, prehash: true }));
  const wrap: EncryptedAccountWrap = { principal: account.principal, wrapId, epub: account.epub, ciphertextHex, signature };
  store.put({ principal: wrap.principal, wrapId: wrap.wrapId, epub: wrap.epub }, wrap);
  return wrap;
}

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

function randomScalar(): Uint8Array {
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

function contentKdf(x: Uint8Array): Uint8Array {
  return sha256Bytes(lengthPrefixed(["s3rch-sea-secret-v1", bytesToHex(x)]));
}

function kdf(x: Uint8Array, principal: string, wrapId: string, transportPub: string, ephemeralPub: string): Uint8Array {
  return sha256Bytes(lengthPrefixed([DOMAIN_ACCOUNT_BIND, bytesToHex(x), principal, wrapId, transportPub, ephemeralPub]));
}

function sharedX(scalar: Uint8Array, peerUncompressed: Uint8Array): Uint8Array {
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

function seaPoint(scalar: Uint8Array): string {
  const raw = scalar.length === 65 ? scalar : p256.getPublicKey(scalar, false);
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

function sha256Bytes(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(bytes).digest());
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
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
