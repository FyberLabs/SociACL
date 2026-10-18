/**
 * Account keyring. Holds the current signing key, the current encryption
 * key, the retired encryption keys, and the disclosed base lane id.
 * The contact-lane secret is a separate 32-byte value. Per-contact lanes
 * are derived from that secret in contact-lane.ts. The disclosed base lane
 * is not that secret. The account id stays the genesis signing pub. Import
 * checks that pair against resolveCurrentKey. A null currentEpub is not a
 * match and is not Gun's user.epub. New rotations are v3 and mint a fresh epub.
 *
 * Passphrase recovery lives in recovery.ts.
 */
import { randomBytes } from "node:crypto";
import { p256 } from "@noble/curves/nist.js";
import {
  parseEip55,
  parsePrincipalId,
  checkRotationDraft,
  resolveCurrentKey,
  userSoul,
  type PrincipalId,
  type ResolutionContext,
} from "../ids/src/index.js";
import type { GenesisAccount } from "./account-key.ts";
import { bytesToHex, seaPoint, unb64 } from "./account-key-seal.ts";
import { openReaderWrap, sealReaderWrap } from "./content-wrap.ts";

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
  readonly contactLaneSecret?: string;
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

/** Module seal. The constructor is not an import path; it rejects any other caller. */
const keyringSeal: unique symbol = Symbol("account-keyring");

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
  readonly #priorLanes: readonly string[];
  readonly #contactLaneSecret: string;
  readonly #priorContactSecrets: readonly string[];

  /**
   * Not a public entry. {@link fromGenesis}, {@link import}, and
   * {@link rotateKeyring} pass the module seal after the hold or rotation
   * checks. Any other caller is rejected.
   */
  constructor(
    principal: PrincipalId,
    genesisEpub: PrincipalId,
    currentPub: PrincipalId,
    currentPriv: string,
    currentEpub: PrincipalId,
    currentEpriv: string,
    retired: readonly RetiredSecret[],
    laneId: string,
    priorLanes: readonly string[],
    contactLaneSecret: string,
    priorContactSecrets: readonly string[],
    contentEpoch: number,
    rotationSeq: number,
    seal: typeof keyringSeal,
  ) {
    if (seal !== keyringSeal) throw new Error("bad-construction");
    if (retired.length > 1024) throw new Error("too-many-keys");
    if (!Number.isSafeInteger(contentEpoch) || contentEpoch < 0 || !Number.isSafeInteger(rotationSeq) || rotationSeq < 0) {
      throw new Error("content-epoch");
    }
    requireLaneSet(laneId, priorLanes);
    if (priorLanes.length !== rotationSeq) throw new Error("bad-lane");
    requireContactSet(contactLaneSecret, priorContactSecrets, laneId, priorLanes);
    if (priorContactSecrets.length !== rotationSeq) throw new Error("bad-lane");
    this.principal = principal;
    this.genesisEpub = genesisEpub;
    this.pub = currentPub;
    this.#priv = currentPriv;
    this.epub = currentEpub;
    this.#epriv = currentEpriv;
    this.#retired = retired;
    this.#laneId = laneId;
    this.#priorLanes = priorLanes;
    this.#contactLaneSecret = contactLaneSecret;
    this.#priorContactSecrets = priorContactSecrets;
    this.contentEpoch = contentEpoch;
    this.rotationSeq = rotationSeq;
  }

  /** Local constructor for a new account. Import is the witnessed check. */
  static fromGenesis(account: GenesisAccount, contactLaneSecret = randomDisjoint([account.laneId])): AccountKeyring {
    return hold(
      account.principal,
      account.epub,
      account.pub,
      account.priv,
      account.epub,
      account.epriv,
      [],
      account.laneId,
      [],
      contactLaneSecret,
      [],
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
    priorLanes: readonly string[] = [],
    contactLaneSecret?: string,
    priorContactSecrets?: readonly string[],
  ): AccountKeyring {
    const id = parsePrincipalId(principal);
    if (!id.ok) throw new Error(id.reason);
    const history = contactLaneSecret === undefined
      ? mintContactHistory(rotationSeq, laneId, priorLanes)
      : { secret: contactLaneSecret, prior: priorContactSecrets ?? [] };
    const keyring = hold(
      id.value,
      genesisEpub,
      currentPub,
      currentPriv,
      currentEpub,
      currentEpriv,
      retired,
      laneId,
      priorLanes,
      history.secret,
      history.prior,
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

  /** Lane ids this keyring has already issued. A later mint cannot reuse one. */
  priorLanes(): readonly string[] {
    return [...this.#priorLanes];
  }

  /** HKDF input for contact lanes. Never write this to Gun. It is not {@link laneId}. */
  contactLaneSecret(): string {
    return this.#contactLaneSecret;
  }

  /** Contact-lane secrets already issued. Length equals `rotationSeq`. */
  priorContactSecrets(): readonly string[] {
    return [...this.#priorContactSecrets];
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

  /** Gun user node. Secrets, retired scalars, the contact-lane secret, and the base lane id are absent. */
  gunDocument(): string {
    const soul = userSoul(this.principal);
    return `{"soul":${jsonString(soul)},"account":${jsonString(this.principal)},"pub":${jsonString(this.pub)},"epub":${jsonString(this.epub)}}`;
  }

  confirm(rotations: readonly unknown[], context: ResolutionContext): PrincipalId {
    const resolved = resolveCurrentKey(this.principal, rotations, context);
    if (!resolved.ok) throw new Error(resolved.reason);
    if (resolved.value.currentKey !== this.pub) throw new Error("pub-mismatch");
    if (resolved.value.currentEpub == null) throw new Error("epub-unknown");
    if (resolved.value.currentEpub !== this.epub) throw new Error("epub-mismatch");
    if (resolved.value.bindingEpub != null && resolved.value.bindingEpub !== this.genesisEpub) {
      throw new Error("epub-mismatch");
    }
    if (resolved.value.rotations.length !== this.rotationSeq) throw new Error("rotation-rejected");
    if (this.contentEpoch < resolved.value.rotations.length) throw new Error("content-epoch");
    for (const row of resolved.value.rotations) {
      if (row.nextEpub && row.nextEpub !== this.epub && !this.#retired.some((retired) => retired.epub === row.nextEpub)) {
        throw new Error("epub-mismatch");
      }
    }
    if (this.#retired.length > 1024) throw new Error("too-many-keys");
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
  ): { epoch: number; targetId: string; wrappedKey: string } {
    const witnessed = this.confirm(rotations, context);
    const epub = epubForNewSeal(witnessed, gunUserEpub);
    if (epub !== this.epub) throw new Error("epub-mismatch");
    const wrappedKey = sealReaderWrap(epub, dekHex, this.contentEpoch, objectId, revisionId, randomScalar(), randomBytes(12));
    return { epoch: this.contentEpoch, targetId: epub, wrappedKey };
  }

  /** Open with the current epriv, or a retired one when the target epub matches. */
  openContent(wrappedHex: string, epoch: number, objectId: string, revisionId: string, targetEpub: string): string {
    if (targetEpub === this.epub) return openReaderWrap(this.#epriv, this.epub, wrappedHex, epoch, objectId, revisionId);
    for (const retired of this.#retired) {
      if (targetEpub === retired.epub) return openReaderWrap(retired.epriv, retired.epub, wrappedHex, epoch, objectId, revisionId);
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
  const contact = randomBytes(32);
  if (bytesToHex(contact) === bytesToHex(lane)) contact[0] = (contact[0] ?? 0) ^ 0x01;
  const mint = {
    signingPub: seaPoint(signing),
    signingPriv: b64(signing),
    epub: seaPoint(encryption),
    epriv: b64(encryption),
    laneId: bytesToHex(lane),
    contactLaneSecret: bytesToHex(contact),
  };
  signing.fill(0);
  encryption.fill(0);
  lane.fill(0);
  contact.fill(0);
  return mint;
}

/** Mint the next v3 rotation. Name every trusted device except `lost`.
 * `rotateAndReseal` seals the recovery copy. `deliverKeyring` sends it to a device.
 * `confirm` runs before the current epub is retired. The draft is checked with
 * `checkRotationDraft` before it is returned. A lane id is never reused. */
export function rotateKeyring(
  keyring: AccountKeyring,
  trusted: readonly string[],
  lost: string,
  rotations: readonly unknown[],
  context: ResolutionContext,
  mint: () => RotationMint = mintRotation,
): KeyringRotation {
  if (trusted.length === 0 || !trusted.includes(lost)) throw new Error("lost-device");
  const seen = new Set<string>();
  for (const localId of trusted) {
    if (seen.has(localId)) throw new Error("duplicate-device");
    seen.add(localId);
    requireDevice(localId);
  }
  const minted = mint();
  const contactLaneSecret = minted.contactLaneSecret ?? randomDisjoint([
    minted.laneId,
    keyring.laneId(),
    ...keyring.priorLanes(),
    keyring.contactLaneSecret(),
    ...keyring.priorContactSecrets(),
  ]);
  const nextPub = signingPoint(minted.signingPub, minted.signingPriv);
  const nextEpub = encryptionPoint(minted.epub, minted.epriv);
  if (nextEpub === nextPub || holdsPoint(keyring, nextEpub) || holdsPoint(keyring, nextPub)) {
    throw new Error("epub-reuse");
  }
  if (
    reusesLane(keyring, minted.laneId) ||
    reusesContactSecret(keyring, contactLaneSecret) ||
    reusesContactSecret(keyring, minted.laneId) ||
    disclosedLane(contactLaneSecret, minted.laneId, keyring)
  ) {
    throw new Error("bad-lane");
  }
  keyring.confirm(rotations, context);
  const resolved = resolveCurrentKey(keyring.principal, rotations, context);
  if (!resolved.ok) throw new Error(resolved.reason);
  const historical = new Set<string>([keyring.principal, keyring.pub]);
  for (const row of resolved.value.rotations) {
    historical.add(row.prevKey);
    historical.add(row.nextKey);
  }
  if (historical.has(nextPub) || nextPub === resolved.value.bindingEpub || nextEpub === resolved.value.bindingEpub) {
    throw new Error("epub-reuse");
  }
  if (keyring.retired().length >= 1024) throw new Error("too-many-keys");
  const retired = [...keyring.retired(), { epub: keyring.epub, epriv: keyring.currentEpriv() }];
  const seq = keyring.rotationSeq + 1;
  const epoch = keyring.contentEpoch + 1;
  if (!Number.isSafeInteger(seq)) throw new Error("rotation-rejected");
  if (!Number.isSafeInteger(epoch)) throw new Error("content-epoch");
  const rotated = new AccountKeyring(
    keyring.principal,
    keyring.genesisEpub,
    nextPub,
    minted.signingPriv,
    nextEpub,
    minted.epriv,
    retired,
    minted.laneId,
    [...keyring.priorLanes(), keyring.laneId()],
    contactLaneSecret,
    [...keyring.priorContactSecrets(), keyring.contactLaneSecret()],
    epoch,
    seq,
    keyringSeal,
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
  const published = checkRotationDraft(
    {
      v: 1,
      kind: "rotate",
      principal: draft.principal,
      seq: draft.seq,
      prevKey: draft.prevKey,
      nextKey: draft.nextKey,
      nextEpub: draft.nextEpub,
      retainedLinks: [],
    },
    [],
    keyring.principal,
    rotations,
    context,
  );
  if (!published.ok) throw new Error(published.reason);
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
  priorLanes: readonly string[],
  contactLaneSecret: string,
  priorContactSecrets: readonly string[],
  contentEpoch: number,
  rotationSeq: number,
): AccountKeyring {
  if (retired.length > 1024) throw new Error("too-many-keys");
  if (!Number.isSafeInteger(contentEpoch) || contentEpoch < 0 || !Number.isSafeInteger(rotationSeq) || rotationSeq < 0) {
    throw new Error("content-epoch");
  }
  requireLaneSet(laneId, priorLanes);
  requireContactSet(contactLaneSecret, priorContactSecrets, laneId, priorLanes);
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
    [...priorLanes],
    contactLaneSecret,
    [...priorContactSecrets],
    contentEpoch,
    rotationSeq,
    keyringSeal,
  );
}

function requireLaneSet(laneId: string, priorLanes: readonly string[]): void {
  if (!/^[0-9a-f]{64}$/u.test(laneId)) throw new Error("bad-lane");
  const seen = new Set<string>([laneId]);
  for (const prior of priorLanes) {
    if (!/^[0-9a-f]{64}$/u.test(prior) || seen.has(prior)) throw new Error("bad-lane");
    seen.add(prior);
  }
}

function reusesLane(keyring: AccountKeyring, laneId: string): boolean {
  return !/^[0-9a-f]{64}$/u.test(laneId) || laneId === keyring.laneId() || keyring.priorLanes().includes(laneId);
}

function reusesContactSecret(keyring: AccountKeyring, secret: string): boolean {
  return !/^[0-9a-f]{64}$/u.test(secret) || secret === keyring.contactLaneSecret() || keyring.priorContactSecrets().includes(secret);
}

function disclosedLane(secret: string, laneId: string, keyring: AccountKeyring): boolean {
  return secret === laneId || secret === keyring.laneId() || keyring.priorLanes().includes(secret);
}

function requireContactSet(
  secret: string,
  prior: readonly string[],
  laneId: string,
  priorLanes: readonly string[],
): void {
  if (!/^[0-9a-f]{64}$/u.test(secret) || secret === laneId || priorLanes.includes(secret)) throw new Error("bad-lane");
  const seen = new Set<string>([secret]);
  for (const held of prior) {
    if (!/^[0-9a-f]{64}$/u.test(held) || seen.has(held) || held === laneId || priorLanes.includes(held)) {
      throw new Error("bad-lane");
    }
    seen.add(held);
  }
}

function randomDisjoint(banned: readonly string[]): string {
  for (;;) {
    const lane = bytesToHex(randomBytes(32));
    if (!banned.includes(lane)) return lane;
  }
}

function mintContactHistory(
  rotationSeq: number,
  laneId: string,
  priorLanes: readonly string[],
): { secret: string; prior: string[] } {
  const banned = [laneId, ...priorLanes];
  const secret = randomDisjoint(banned);
  const prior: string[] = [];
  const seen = [...banned, secret];
  for (let i = 0; i < rotationSeq; i += 1) {
    const next = randomDisjoint(seen);
    seen.push(next);
    prior.push(next);
  }
  return { secret, prior };
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
