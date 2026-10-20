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
import { DELIVERY_BLOB_MAX, MAX_WRAPS_PER_PRINCIPAL } from "./keyring-limits.ts";
import { canonicalDecimal } from "./canonical.ts";
import {
  HeadFloor,
  REPLACED_NONE,
  signStoreWrite,
  verifyStoreWrite,
  wrapCiphertextHash,
  type StoreWriteAccount,
} from "./store-write.ts";
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

/** Which seal produced a wrap. A wrap id stays in the class that first stored it.
 * The class is a field of the store-write signature. Openers ignore it. */
export type WrapClass = "genesis" | "delivery";

export type EncryptedAccountWrap = WrapIndex & {
  readonly class: WrapClass;
  readonly ciphertextHex: string;
  readonly signature: string;
};

/** Index plus ciphertext. Not an authority and not a grant minter.
 * Rows are keyed by `(principal, wrapId)`. The genesis backup and device
 * deliveries share the store. A delivery cannot replace the genesis backup's
 * wrap id. A principal holds at most `MAX_WRAPS_PER_PRINCIPAL` rows.
 * Replacing an existing id does not count as a new row. Every put and delete
 * carries a store-write signature by the current chain-head key. Adapters,
 * Panopticon included, must verify that signature before they write. Session
 * authentication is not this check. Panopticon is a verifier and a witness,
 * never the authority. The genesis backup can be replaced, never deleted. */
export interface KeyWrapStore {
  readonly isAuthority: false;
  readonly mintsGrant: false;
  publishedAccount(principal: PrincipalId): StoreWriteAccount;
  writeGeneration(principal: PrincipalId): number;
  put(index: WrapIndex, wrap: EncryptedAccountWrap, storeSignature: string): void;
  /** Delete a delivery row. A genesis row is `store-rejected` and stays. */
  delete(principal: PrincipalId, wrapId: ObjectId, storeSignature: string): void;
  get(principal: PrincipalId, wrapId: ObjectId): EncryptedAccountWrap | undefined;
  list(principal: PrincipalId): EncryptedAccountWrap[];
}

export class MemoryKeyWrapStore implements KeyWrapStore {
  readonly isAuthority = false as const;
  readonly mintsGrant = false as const;
  readonly #wraps = new Map<string, Map<string, EncryptedAccountWrap>>();
  readonly #floor: HeadFloor;
  readonly #generation = new Map<string, number>();
  readonly #chain: (principal: PrincipalId) => StoreWriteAccount;

  constructor(chain: (principal: PrincipalId) => StoreWriteAccount, floor: HeadFloor = new HeadFloor()) {
    this.#chain = chain;
    this.#floor = floor;
  }

  publishedAccount(principal: PrincipalId): StoreWriteAccount {
    const account = this.#chain(principal);
    this.#floor.observe(principal, account.rotations.length);
    return account;
  }

  writeGeneration(principal: PrincipalId): number {
    return this.#generation.get(principal) ?? 0;
  }

  put(index: WrapIndex, wrap: EncryptedAccountWrap, storeSignature: string): void {
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
    const account = this.#account(wrap.principal);
    const head = account.rotations.length;
    const rows = this.#wraps.get(index.principal) ?? new Map<string, EncryptedAccountWrap>();
    const existing = rows.get(index.wrapId);
    const replaced = existing ? wrapCiphertextHash(existing.ciphertextHex) : REPLACED_NONE;
    const hash = wrapCiphertextHash(wrap.ciphertextHex);
    const generation = this.writeGeneration(wrap.principal);
    verifyStoreWrite(
      wrap.principal,
      "put",
      wrap.wrapId,
      hash,
      canonicalDecimal(head),
      replaced,
      wrap.class,
      canonicalDecimal(generation),
      storeSignature,
      account,
    );
    if (existing) {
      if (existing.class !== wrap.class) throw new Error("store-rejected");
    } else if (rows.size >= MAX_WRAPS_PER_PRINCIPAL) {
      throw new Error("store-rejected");
    }
    rows.set(index.wrapId, copyWrap(wrap));
    this.#wraps.set(index.principal, rows);
    this.#floor.raise(wrap.principal, head);
    this.#generation.set(wrap.principal, generation + 1);
  }

  delete(principal: PrincipalId, wrapId: ObjectId, storeSignature: string): void {
    const account = this.#account(principal);
    const head = account.rotations.length;
    const row = this.#wraps.get(principal)?.get(wrapId);
    if (!row) throw new Error("store-rejected");
    const hash = wrapCiphertextHash(row.ciphertextHex);
    const generation = this.writeGeneration(principal);
    verifyStoreWrite(
      principal,
      "delete",
      wrapId,
      hash,
      canonicalDecimal(head),
      hash,
      row.class,
      canonicalDecimal(generation),
      storeSignature,
      account,
    );
    if (row.class === "genesis") throw new Error("store-rejected");
    const rows = this.#wraps.get(principal);
    rows?.delete(wrapId);
    if (rows && rows.size === 0) this.#wraps.delete(principal);
    this.#floor.raise(principal, head);
    this.#generation.set(principal, generation + 1);
  }

  #account(principal: PrincipalId): StoreWriteAccount {
    try {
      return this.publishedAccount(principal);
    } catch (error) {
      if (error instanceof Error && error.message === "store-rejected") throw error;
      throw new Error("store-rejected");
    }
  }

  get(principal: PrincipalId, wrapId: ObjectId): EncryptedAccountWrap | undefined {
    const row = this.#wraps.get(principal)?.get(wrapId);
    return row ? copyWrap(row) : undefined;
  }

  list(principal: PrincipalId): EncryptedAccountWrap[] {
    return [...(this.#wraps.get(principal)?.values() ?? [])].map(copyWrap);
  }
}

function copyWrap(wrap: EncryptedAccountWrap): EncryptedAccountWrap {
  return {
    principal: wrap.principal,
    wrapId: wrap.wrapId,
    epub: wrap.epub,
    class: wrap.class,
    ciphertextHex: wrap.ciphertextHex,
    signature: wrap.signature,
  };
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

export function parseWrapObject(text: string): ObjectId {
  const parsed = parseObjectId(text);
  if (!parsed.ok) throw new Error(parsed.reason);
  return parsed.value;
}

/**
 * Seal to `transportPub`. Randomness stays inside this function.
 * `rotations` and `context` are the trusted latest-state checkpoint (sociacl-ids §4.6).
 */
/** Delete a delivery row. The genesis backup can only be replaced. */
export function deleteAccountWrap(
  principal: PrincipalId,
  wrapId: ObjectId,
  signerPriv: string,
  store: KeyWrapStore,
): void {
  const row = store.get(principal, wrapId);
  if (!row) throw new Error("store-rejected");
  const hash = wrapCiphertextHash(row.ciphertextHex);
  const account = store.publishedAccount(principal);
  const signature = signStoreWrite(
    signerPriv,
    principal,
    "delete",
    wrapId,
    hash,
    canonicalDecimal(account.rotations.length),
    hash,
    row.class,
    canonicalDecimal(store.writeGeneration(principal)),
  );
  store.delete(principal, wrapId, signature);
}

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
