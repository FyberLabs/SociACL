/**
 * Account keyring. Holds the current signing key, the current encryption
 * key, the retired encryption keys, and the one lane id for this account.
 * The account id stays the genesis signing pub. Import checks that pair
 * against resolveCurrentKey. A null currentEpub is not a match and is not
 * Gun's user.epub. New rotations are v3 and mint a fresh epub.
 *
 * Argon2id recovery and HKDF per-contact lanes are not this module.
 */
import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { p256 } from "@noble/curves/nist.js";
import {
  parseEip55,
  parseObjectId,
  parsePrincipalId,
  resolveCurrentKey,
  userSoul,
  type ObjectId,
  type PrincipalId,
  type ResolutionContext,
} from "../ids/src/index.js";
import type { GenesisAccount } from "./account-key.ts";
import {
  bytesToHex,
  decodeLengthPrefixed,
  hexToBytes,
  seaPoint,
  sharedX,
  unb64,
  uncompressedFromSea,
} from "./account-key-seal.ts";
import { canonicalDecimal, lengthPrefixed } from "./canonical.ts";

const DOMAIN_WRAPPED_KEY = "s3rch-wrapped-key-v1";
const DOMAIN_SEA_SECRET = "s3rch-sea-secret-v1";

export type RetiredEpriv = {
  readonly epub: PrincipalId;
  readonly epriv: string;
};

export type RotationMint = {
  readonly signingPub: string;
  readonly signingPriv: string;
  readonly epub: string;
  readonly epriv: string;
  readonly laneId: string;
};

export type RotationDraft = {
  readonly v: 1;
  readonly kind: "rotate";
  readonly principal: PrincipalId;
  readonly seq: number;
  readonly prevKey: PrincipalId;
  readonly nextKey: PrincipalId;
  readonly nextEpub: PrincipalId;
  readonly version: 3;
};

export type KeyringDevice = {
  readonly localId: string;
  readonly keyring: AccountKeyring;
  readonly grantsSee: false;
  gunDocument(): string;
};

export type KeyringRotation = {
  readonly keyring: AccountKeyring;
  readonly devices: readonly KeyringDevice[];
  readonly draft: RotationDraft;
  readonly lostLocalId: string;
};

type RetiredSecret = { epub: PrincipalId; epriv: string };

export class AccountKeyring {
  readonly principal: PrincipalId;
  readonly genesisEpub: PrincipalId;
  readonly pub: PrincipalId;
  readonly epub: PrincipalId;
  readonly contentEpoch: number;
  readonly rotationSeq: number;
  readonly #priv: string;
  readonly #epriv: string;
  readonly #retired: readonly RetiredSecret[];
  readonly #laneId: string;

  /** Prefer {@link fromGenesis} or {@link import}. */
  constructor(
    principal: PrincipalId,
    genesisEpub: PrincipalId,
    currentPub: PrincipalId,
    currentPriv: string,
    currentEpub: PrincipalId,
    currentEpriv: string,
    retired: readonly RetiredSecret[],
    laneId: string,
    contentEpoch: number,
    rotationSeq: number,
  ) {
    this.principal = principal;
    this.genesisEpub = genesisEpub;
    this.pub = currentPub;
    this.#priv = currentPriv;
    this.epub = currentEpub;
    this.#epriv = currentEpriv;
    this.#retired = retired;
    this.#laneId = laneId;
    this.contentEpoch = contentEpoch;
    this.rotationSeq = rotationSeq;
  }

  /** Local constructor for a new account. Import is the witnessed check. */
  static fromGenesis(account: GenesisAccount): AccountKeyring {
    return hold(
      account.principal,
      account.epub,
      account.pub,
      account.priv,
      account.epub,
      account.epriv,
      [],
      account.laneId,
      0,
      0,
    );
  }

  /**
   * Device import. The current pub and epub must equal the witnessed pair.
   * A null currentEpub throws epub-unknown. It is not the bound genesis epub
   * and not a Gun user.epub.
   */
  static import(
    principal: string,
    genesisEpub: string,
    currentPub: string,
    currentPriv: string,
    currentEpub: string,
    currentEpriv: string,
    retired: readonly { epub: string; epriv: string }[],
    laneId: string,
    contentEpoch: number,
    rotationSeq: number,
    rotations: readonly unknown[],
    context: ResolutionContext,
  ): AccountKeyring {
    const id = parsePrincipalId(principal);
    if (!id.ok) throw new Error(id.reason);
    const keyring = hold(
      id.value,
      genesisEpub,
      currentPub,
      currentPriv,
      currentEpub,
      currentEpriv,
      retired,
      laneId,
      contentEpoch,
      rotationSeq,
    );
    keyring.confirm(rotations, context);
    return keyring;
  }

  currentPriv(): string {
    return this.#priv;
  }

  currentEpriv(): string {
    return this.#epriv;
  }

  retired(): readonly RetiredEpriv[] {
    return this.#retired.map((row) => ({ epub: row.epub, epriv: row.epriv }));
  }

  laneId(): string {
    return this.#laneId;
  }

  /** Public fields only. Secrets stay off this projection. */
  toJSON(): {
    principal: PrincipalId;
    genesisEpub: PrincipalId;
    pub: PrincipalId;
    epub: PrincipalId;
    contentEpoch: number;
    rotationSeq: number;
  } {
    return {
      principal: this.principal,
      genesisEpub: this.genesisEpub,
      pub: this.pub,
      epub: this.epub,
      contentEpoch: this.contentEpoch,
      rotationSeq: this.rotationSeq,
    };
  }

  /** Gun user node. Secrets, retired scalars, and the lane id are absent. */
  gunDocument(): string {
    const soul = userSoul(this.principal);
    return `{"soul":${jsonString(soul)},"account":${jsonString(this.principal)},"pub":${jsonString(this.pub)},"epub":${jsonString(this.epub)}}`;
  }

  confirm(rotations: readonly unknown[], context: ResolutionContext): PrincipalId {
    if (context.genesisEpub != null && context.genesisEpub !== this.genesisEpub) {
      throw new Error("epub-mismatch");
    }
    const resolved = resolveCurrentKey(this.principal, rotations, { ...context, genesisEpub: this.genesisEpub });
    if (!resolved.ok) throw new Error(resolved.reason);
    if (resolved.value.currentKey !== this.pub) throw new Error("pub-mismatch");
    if (resolved.value.currentEpub == null) throw new Error("epub-unknown");
    if (resolved.value.currentEpub !== this.epub) throw new Error("epub-mismatch");
    if (resolved.value.rotations.length !== this.rotationSeq) throw new Error("rotation-rejected");
    return resolved.value.currentEpub;
  }

  /**
   * Seal a DEK to the witnessed epub at this content epoch.
   * `gunUserEpub` is ignored. A null witness throws epub-unknown.
   */
  sealContent(
    dekHex: string,
    objectId: string,
    revisionId: string,
    rotations: readonly unknown[],
    context: ResolutionContext,
    gunUserEpub: string | null,
    ephemeralScalar: Uint8Array,
    nonce: Uint8Array,
  ): { epoch: number; targetId: string; wrappedKey: string } {
    const witnessed = this.confirm(rotations, context);
    const epub = epubForNewSeal(witnessed, gunUserEpub);
    if (epub !== this.epub) throw new Error("epub-mismatch");
    const wrappedKey = sealDek(epub, dekHex, this.contentEpoch, objectId, revisionId, ephemeralScalar, nonce);
    return { epoch: this.contentEpoch, targetId: epub, wrappedKey };
  }

  /** Open with the current epriv, or a retired one when the target epub matches. */
  openContent(wrappedHex: string, epoch: number, objectId: string, revisionId: string, targetEpub: string): string {
    if (targetEpub === this.epub) return openDek(this.#epriv, this.epub, wrappedHex, epoch, objectId, revisionId);
    for (const retired of this.#retired) {
      if (targetEpub === retired.epub) return openDek(retired.epriv, retired.epub, wrappedHex, epoch, objectId, revisionId);
    }
    throw new Error("wrap-rejected");
  }
}

/** The witnessed epub, or an error. `gunUserEpub` is never the result. */
export function epubForNewSeal(currentEpub: PrincipalId | null, gunUserEpub: string | null): PrincipalId {
  if (currentEpub == null) throw new Error("epub-unknown");
  void gunUserEpub;
  return currentEpub;
}

export function mintRotation(): RotationMint {
  const signing = randomScalar();
  const encryption = randomScalar();
  const lane = randomBytes(32);
  const mint = {
    signingPub: seaPoint(signing),
    signingPriv: b64(signing),
    epub: seaPoint(encryption),
    epriv: b64(encryption),
    laneId: bytesToHex(lane),
  };
  signing.fill(0);
  encryption.fill(0);
  lane.fill(0);
  return mint;
}

/** Mint the next v3 rotation, re-enroll every trusted device except `lost`, and advance the content epoch. */
export function rotateKeyring(
  keyring: AccountKeyring,
  trusted: readonly string[],
  lost: string,
  mint: () => RotationMint,
): KeyringRotation {
  if (trusted.length === 0 || !trusted.includes(lost)) throw new Error("lost-device");
  const seen = new Set<string>();
  for (const localId of trusted) {
    if (seen.has(localId)) throw new Error("duplicate-device");
    seen.add(localId);
    requireDevice(localId);
  }
  const minted = mint();
  const nextPub = signingPoint(minted.signingPub, minted.signingPriv);
  const nextEpub = encryptionPoint(minted.epub, minted.epriv);
  if (!/^[0-9a-f]{64}$/u.test(minted.laneId)) throw new Error("bad-lane");
  if (nextEpub === nextPub || holdsPoint(keyring, nextEpub) || holdsPoint(keyring, nextPub)) {
    throw new Error("epub-reuse");
  }
  if (minted.laneId === keyring.laneId()) throw new Error("bad-lane");
  const retired = [...keyring.retired(), { epub: keyring.epub, epriv: keyring.currentEpriv() }];
  const seq = keyring.rotationSeq + 1;
  const epoch = keyring.contentEpoch + 1;
  if (!Number.isSafeInteger(seq) || !Number.isSafeInteger(epoch)) throw new Error("rotation-rejected");
  const rotated = new AccountKeyring(
    keyring.principal,
    keyring.genesisEpub,
    nextPub,
    minted.signingPriv,
    nextEpub,
    minted.epriv,
    retired,
    minted.laneId,
    epoch,
    seq,
  );
  const devices: KeyringDevice[] = [];
  for (const localId of trusted) {
    if (localId === lost) continue;
    devices.push({
      localId,
      keyring: rotated,
      grantsSee: false,
      gunDocument: () => rotated.gunDocument(),
    });
  }
  const draft: RotationDraft = {
    v: 1,
    kind: "rotate",
    principal: rotated.principal,
    seq,
    prevKey: keyring.pub,
    nextKey: nextPub,
    nextEpub,
    version: 3,
  };
  return { keyring: rotated, devices, draft, lostLocalId: lost };
}

export function draftDocument(draft: RotationDraft): string {
  return `{"v":1,"kind":"rotate","principal":${jsonString(draft.principal)},"seq":${draft.seq},"prevKey":${jsonString(draft.prevKey)},"nextKey":${jsonString(draft.nextKey)},"nextEpub":${jsonString(draft.nextEpub)}}`;
}

function hold(
  principal: PrincipalId,
  genesisEpubText: string,
  currentPubText: string,
  currentPriv: string,
  currentEpubText: string,
  currentEpriv: string,
  retired: readonly { epub: string; epriv: string }[],
  laneId: string,
  contentEpoch: number,
  rotationSeq: number,
): AccountKeyring {
  if (!/^[0-9a-f]{64}$/u.test(laneId)) throw new Error("bad-lane");
  const genesisEpub = encryptionPoint(genesisEpubText, null);
  if (genesisEpub === principal) throw new Error("epub-mismatch");
  const currentPub = signingPoint(currentPubText, currentPriv);
  const currentEpub = encryptionPoint(currentEpubText, currentEpriv);
  if (currentEpub === currentPub || currentEpub === principal) throw new Error("epub-mismatch");
  if (currentPub !== principal && currentEpub === genesisEpub) throw new Error("epub-mismatch");
  const retiredKeys: RetiredSecret[] = [];
  const seen = new Set<string>([currentEpub]);
  for (const row of retired) {
    const point = encryptionPoint(row.epub, row.epriv);
    // The genesis epub is retired once the signing key moves. It is not a second current epub.
    if (seen.has(point) || point === currentPub || point === principal) throw new Error("epub-reuse");
    seen.add(point);
    retiredKeys.push({ epub: point, epriv: row.epriv });
  }
  if (currentPub !== principal && !retiredKeys.some((row) => row.epub === genesisEpub)) {
    throw new Error("epub-mismatch");
  }
  return new AccountKeyring(
    principal,
    genesisEpub,
    currentPub,
    currentPriv,
    currentEpub,
    currentEpriv,
    retiredKeys,
    laneId,
    contentEpoch,
    rotationSeq,
  );
}

function holdsPoint(keyring: AccountKeyring, point: PrincipalId): boolean {
  return (
    point === keyring.principal ||
    point === keyring.genesisEpub ||
    point === keyring.pub ||
    point === keyring.epub ||
    keyring.retired().some((row) => row.epub === point)
  );
}

function requireDevice(localId: string): void {
  if (localId.length === 0) throw new Error("empty-device");
  if (parsePrincipalId(localId).ok || parseEip55(localId).ok) throw new Error("device-id");
}

function signingPoint(seaPub: string, seaPriv: string): PrincipalId {
  const parsed = parsePrincipalId(seaPub);
  if (!parsed.ok || parsed.value !== seaPub || seaPoint(unb64(seaPriv)) !== seaPub) throw new Error("pub-mismatch");
  const scalar = unb64(seaPriv);
  scalar.fill(0);
  return parsed.value;
}

function encryptionPoint(epub: string, epriv: string | null): PrincipalId {
  const parsed = parsePrincipalId(epub);
  if (!parsed.ok || parsed.value !== epub) throw new Error("epub-mismatch");
  if (epriv == null) return parsed.value;
  const scalar = unb64(epriv);
  const derived = seaPoint(scalar);
  scalar.fill(0);
  if (derived !== epub) throw new Error("epub-mismatch");
  return parsed.value;
}

function sealDek(
  epub: string,
  dekHex: string,
  epoch: number,
  objectId: string,
  revisionId: string,
  ephemeral: Uint8Array,
  nonce: Uint8Array,
): string {
  const parsed = parseObjectId(objectId);
  if (!parsed.ok) throw new Error(parsed.reason);
  if (!/^[0-9a-f]{64}$/u.test(revisionId)) throw new Error("bad-revision");
  const dek = hexToBytes(dekHex);
  if (dek.length !== 32 || ephemeral.length !== 32 || nonce.length !== 12) throw new Error("bad-key");
  const plain = lengthPrefixed([
    DOMAIN_WRAPPED_KEY,
    "item-dek",
    canonicalDecimal(epoch),
    "reader-epub",
    epub,
    parsed.value,
    "",
    revisionId,
    bytesToHex(dek),
  ]);
  dek.fill(0);
  const point = p256.getPublicKey(ephemeral, false);
  const ct = aesEncrypt(contentKdf(sharedX(ephemeral, uncompressedFromSea(epub))), nonce, plain);
  const blob = new Uint8Array(1 + point.length + nonce.length + ct.length);
  blob[0] = 1;
  blob.set(point, 1);
  blob.set(nonce, 1 + point.length);
  blob.set(ct, 1 + point.length + nonce.length);
  return bytesToHex(blob);
}

function openDek(
  epriv: string,
  epub: string,
  wrappedHex: string,
  epoch: number,
  objectId: string,
  revisionId: string,
): string {
  const scalar = unb64(epriv);
  if (seaPoint(scalar) !== epub) {
    scalar.fill(0);
    throw new Error("wrap-rejected");
  }
  const blob = hexToBytes(wrappedHex);
  if (blob[0] !== 1 || blob.length < 1 + 65 + 12 + 16) throw new Error("wrap-rejected");
  const ephemeral = blob.slice(1, 66);
  const nonce = blob.slice(66, 78);
  const plain = aesDecrypt(contentKdf(sharedX(scalar, ephemeral)), nonce, blob.slice(78));
  scalar.fill(0);
  const fields = decodeLengthPrefixed(plain);
  plain.fill(0);
  if (
    fields.length !== 9 ||
    fields[0] !== DOMAIN_WRAPPED_KEY ||
    fields[1] !== "item-dek" ||
    fields[2] !== canonicalDecimal(epoch) ||
    fields[3] !== "reader-epub" ||
    fields[4] !== epub ||
    fields[5] !== objectId ||
    fields[7] !== revisionId
  ) {
    throw new Error("wrap-rejected");
  }
  return fields[8] ?? "";
}

function contentKdf(x: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(lengthPrefixed([DOMAIN_SEA_SECRET, bytesToHex(x)])).digest());
}

function aesEncrypt(key: Uint8Array, nonce: Uint8Array, plain: Uint8Array): Uint8Array {
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(new Uint8Array());
  return new Uint8Array(Buffer.concat([cipher.update(plain), cipher.final(), cipher.getAuthTag()]));
}

function aesDecrypt(key: Uint8Array, nonce: Uint8Array, body: Uint8Array): Uint8Array {
  const tag = body.slice(body.length - 16);
  const data = body.slice(0, body.length - 16);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAAD(new Uint8Array());
  decipher.setAuthTag(tag);
  return new Uint8Array(Buffer.concat([decipher.update(data), decipher.final()]));
}

function randomScalar(): Uint8Array {
  for (;;) {
    const bytes = randomBytes(32);
    try {
      p256.getPublicKey(bytes, false);
      return bytes;
    } catch {
      bytes.fill(0);
    }
  }
}

function b64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function jsonString(value: string): string {
  return JSON.stringify(value);
}
