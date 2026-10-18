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
import { randomBytes } from "node:crypto";
import { p256 } from "@noble/curves/nist.js";
import {
  formatPrincipalKey,
  grantSoul,
  parseEip55,
  parseObjectId,
  parsePrincipalId,
  principalFromSec1,
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
import { DELIVERY_BLOB_MAX } from "./keyring-limits.ts";
import {
  MAX_BACKUP_HEX,
  backupAad,
  backupKdf,
  backupPlaintext,
  backupSignatureMessage,
  bytesToHex,
  decodeLengthPrefixed,
  currentSigningKey,
  encryptAccountBackup,
  hexToBytes,
  openBackupParts,
  randomScalar,
  seaPoint,
  sharedX,
  unb64,
  uncompressedFromSea,
  wrapContent,
} from "./account-key-seal.ts";

export { currentSigningKey };

const DOMAIN_ACCOUNT_WRAP = "sociacl-account-key-wrap-v1";

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
    // Genesis seal and open stay at MAX_BACKUP_HEX. A delivered keyring may
    // use the full DELIVERY_BLOB_MAX, so the adapter accepts that.
    if (wrap.ciphertextHex.length > DELIVERY_BLOB_MAX * 2 || wrap.signature.length !== 128) {
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
const ctorToken: unique symbol = Symbol("linked-credential-ctor");

/**
 * A wallet or OIDC record that `verifyWalletLink` / `verifyOidcLink` accepted.
 * `sameAccount` checks the private `#brand`, not `instanceof`. The constructor
 * accepts only this module's token. `principal` is a private field. The
 * instance, the prototype, and the constructor are frozen.
 */
export class LinkedCredential {
  readonly kind: "wallet" | "oidc";
  readonly label: string;
  readonly #brand = linkedBrand;
  readonly #principal: PrincipalId;

  private constructor(token: typeof ctorToken, kind: "wallet" | "oidc", principal: PrincipalId, label: string) {
    if (token !== ctorToken) throw new Error("unverified-credential");
    this.kind = kind;
    this.#principal = principal;
    this.label = label;
    Object.freeze(this);
  }

  get principal(): PrincipalId {
    return this.#principal;
  }

  /** True only for an instance this module constructed. */
  static isVerified(value: unknown): value is LinkedCredential {
    if (typeof value !== "object" || value === null) return false;
    try {
      return #brand in value;
    } catch {
      return false;
    }
  }

  static fromWallet(raw: unknown, jwks: Jwks, policy: SiwePolicy, now: number, keyState: KeyState): LinkedCredential {
    const verified = verifyWalletLink(raw, jwks, policy, now, keyState);
    if (!verified.ok) throw new Error("unverified-credential");
    return new LinkedCredential(ctorToken, "wallet", verified.value.principal, verified.value.address);
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
    return new LinkedCredential(ctorToken, "oidc", verified.value.principal, verified.value.cred.sub);
  }
}

Object.freeze(LinkedCredential.prototype);
Object.freeze(LinkedCredential);

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

export function sameAccount(credential: unknown, account: PrincipalId): boolean {
  if (!LinkedCredential.isVerified(credential)) throw new Error("unverified-credential");
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
  return encryptAccountBackup(account, transportPub, randomScalar(), randomBytes(12), wrapId, rotations, context, store);
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
  const wrapId = parseWrapObject(wrap.wrapId);
  if (wrap.signature.length !== 128 || !/^[0-9a-f]{128}$/u.test(wrap.signature)) throw new Error("wrap-rejected");
  if (wrap.ciphertextHex.length > MAX_BACKUP_HEX) throw new Error("wrap-rejected");
  if (transportScalarHex.length !== 64) throw new Error("bad-key");
  const transport = hexToBytes(transportScalarHex);
  if (transport.length !== 32) throw new Error("bad-key");
  const transportPub = seaPoint(transport);
  const blob = hexToBytes(wrap.ciphertextHex);
  const { ephemeral, nonce } = openBackupParts(blob);
  const current = currentSigningKey(expected, rotations, context);
  const message = backupSignatureMessage(blob, transportPub, wrapId);
  let signatureOk = false;
  try {
    signatureOk = p256.verify(hexToBytes(wrap.signature), message, uncompressedFromSea(current), { lowS: true, prehash: true });
  } catch {
    signatureOk = false;
  }
  if (!signatureOk) throw new Error("wrap-rejected");
  const ephemeralPub = seaPoint(ephemeral);
  const x = sharedX(transport, ephemeral);
  const aad = backupAad(expected, wrapId, transportPub, ephemeralPub);
  const plain = backupPlaintext(backupKdf(x, expected, wrapId, transportPub, ephemeralPub), nonce, aad, blob.slice(78));
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
  return wrapContent(account, dekHex, bytesToHex(randomScalar()), bytesToHex(randomBytes(12)), epoch, objectId, revisionId);
}

function jsonString(value: string): string {
  return JSON.stringify(value);
}
