/**
 * Per-contact inbox lanes.
 *
 * The account lane secret is the keyring `laneId` (32 bytes). A contact
 * lane id is HKDF-SHA256 of that secret. The recipient seals the id to
 * the sender's resolved currentEpub. Storage indexes the lane id hex and
 * nothing else. A lane is delivery only. It does not grant.
 *
 * This module does not wire Panopticon or Gun, and it does not open a
 * first-contact channel. Those are SociACL#71 and SociACL#70.
 */
import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes } from "node:crypto";
import { p256 } from "@noble/curves/nist.js";
import { parsePrincipalId, resolveCurrentKey, type PrincipalId, type ResolutionContext } from "../ids/src/index.js";
import type { AccountKeyring } from "./account-keyring.ts";
import {
  bytesToHex,
  decodeLengthPrefixed,
  hexToBytes,
  seaPoint,
  sharedX,
  unb64,
  uncompressedFromSea,
} from "./account-key-seal.ts";
import { epubForNewSeal } from "./account-keyring.ts";
import { canonicalDecimal, lengthPrefixed, sha256Hex } from "./canonical.ts";

export const CONTACT_LANE_DOMAIN = "sociacl-contact-lane-v1";
export const CONTACT_LANE_VERSION = "1";
export const CONTACT_LANE_GRANT_DOMAIN = "sociacl-contact-lane-grant-v1";
export const CONTACT_LANE_GRANT_SIG_DOMAIN = "sociacl-contact-lane-grant-sig-v1";

const LANE_ID = /^[0-9a-f]{64}$/u;
const GRANT_BLOB_MAX = 4096;

export type ContactLaneGrant = {
  readonly recipient: PrincipalId;
  readonly sender: PrincipalId;
  readonly senderEpub: PrincipalId;
  readonly rotationSeq: number;
  readonly ciphertextHex: string;
  readonly signature: string;
};

export type OpenedContactLane = {
  readonly laneId: string;
  readonly lookupKey: string;
  readonly recipient: PrincipalId;
  readonly sender: PrincipalId;
  readonly rotationSeq: number;
};

export type ContactTarget = {
  readonly principal: string;
  readonly rotations: readonly unknown[];
  readonly context: ResolutionContext;
};

/** A contact lane is not a grant. Hopcap is unchanged. */
export function contactLaneMintsGrant(): false {
  return false;
}

/**
 * HKDF info. Length-prefixed UTF-8, little-endian uint32 lengths, in this
 * order: domain, version, recipient PrincipalId, sender PrincipalId.
 * The ids are not sorted. Direction is the order of the arguments.
 */
export function contactLaneInfo(recipient: string, sender: string): Uint8Array {
  const owner = requirePrincipal(recipient);
  const from = requirePrincipal(sender);
  return lengthPrefixed([CONTACT_LANE_DOMAIN, CONTACT_LANE_VERSION, owner, from]);
}

/**
 * HKDF-SHA256. IKM is the 32-byte lane secret. Salt is 32 zero bytes.
 * Info is {@link contactLaneInfo}. Output is 32 bytes, lowercase hex.
 */
export function deriveContactLane(laneSecretHex: string, recipient: string, sender: string): string {
  const ikm = laneSecretBytes(laneSecretHex);
  let info: Uint8Array | undefined;
  let okm: Uint8Array | undefined;
  try {
    info = contactLaneInfo(recipient, sender);
    okm = hkdfSha256(ikm, info);
    return bytesToHex(okm);
  } finally {
    ikm.fill(0);
    info?.fill(0);
    okm?.fill(0);
  }
}

/**
 * Contact lane at `seq`. `priorLanes[seq]` is the secret that was current
 * at that sequence, and `priorLanes.length` is `rotationSeq`. The current
 * secret is `laneId`. A derived id that equals the current or a prior
 * base lane is `bad-lane`.
 */
export function resolveContactLane(keyring: AccountKeyring, sender: string, seq: number): string {
  if (!Number.isSafeInteger(seq) || seq < 0) throw new Error("bad-lane");
  const prior = keyring.priorLanes();
  if (prior.length !== keyring.rotationSeq || seq > keyring.rotationSeq) throw new Error("bad-lane");
  const secret = seq === keyring.rotationSeq ? keyring.laneId() : prior[seq];
  if (secret === undefined) throw new Error("bad-lane");
  const lane = deriveContactLane(secret, keyring.principal, sender);
  if (contactLaneReusesBase(lane, keyring.laneId(), prior)) throw new Error("bad-lane");
  return lane;
}

/** Same rule as a keyring mint: the current base lane and every prior base lane are taken. */
export function contactLaneReusesBase(laneId: string, current: string, prior: readonly string[]): boolean {
  return !LANE_ID.test(laneId) || laneId === current || prior.includes(laneId);
}

/**
 * Opaque storage key. It is the lane id hex. It is not a PrincipalId and
 * not a `~pub` path. Callers index by this string alone.
 */
export function laneLookupKey(laneId: string): string {
  if (!LANE_ID.test(laneId)) throw new Error("bad-lane");
  return laneId;
}

export function contactLaneGrantPlaintext(laneId: string, recipient: string, rotationSeq: number): Uint8Array {
  if (!LANE_ID.test(laneId)) throw new Error("bad-lane");
  const owner = requirePrincipal(recipient);
  return lengthPrefixed([
    CONTACT_LANE_GRANT_DOMAIN,
    laneId,
    owner,
    canonicalDecimal(rotationSeq),
  ]);
}

export function contactLaneGrantAad(
  recipient: string,
  sender: string,
  senderEpub: string,
  ephemeralPub: string,
  rotationSeq: number,
): Uint8Array {
  return lengthPrefixed([
    CONTACT_LANE_GRANT_DOMAIN,
    requirePrincipal(recipient),
    requirePrincipal(sender),
    requirePrincipal(senderEpub),
    requirePrincipal(ephemeralPub),
    canonicalDecimal(rotationSeq),
  ]);
}

export function contactLaneGrantSignatureMessage(
  blob: Uint8Array,
  recipient: string,
  sender: string,
  senderEpub: string,
  rotationSeq: number,
): Uint8Array {
  return lengthPrefixed([
    CONTACT_LANE_GRANT_SIG_DOMAIN,
    sha256Hex(blob),
    requirePrincipal(recipient),
    requirePrincipal(sender),
    requirePrincipal(senderEpub),
    canonicalDecimal(rotationSeq),
  ]);
}

/**
 * Seal the current contact lane to the sender's resolved `currentEpub`.
 * A null `currentEpub` is `epub-unknown`. There is no Gun user-encryption fallback.
 */
export function sealContactLaneGrant(
  keyring: AccountKeyring,
  senderPrincipal: string,
  senderRotations: readonly unknown[],
  senderContext: ResolutionContext,
  recipientRotations: readonly unknown[],
  recipientContext: ResolutionContext,
): ContactLaneGrant {
  const sender = requirePrincipal(senderPrincipal);
  const resolved = resolveCurrentKey(sender, senderRotations, senderContext);
  if (!resolved.ok) throw new Error(resolved.reason);
  const senderEpub = epubForNewSeal(resolved.value.currentEpub, null);
  const ephemeral = randomScalar();
  const nonce = randomBytes(12);
  try {
    return sealContactLaneGrantWith(
      keyring,
      sender,
      senderEpub,
      ephemeral,
      nonce,
      recipientRotations,
      recipientContext,
    );
  } finally {
    ephemeral.fill(0);
    nonce.fill(0);
  }
}

/**
 * Caller-chosen ephemeral and nonce. `senderEpub` is that sender's resolved
 * `currentEpub`. This function does not read Gun and does not take a second
 * epub to fall back to. The shared vectors call this.
 */
export function sealContactLaneGrantWith(
  keyring: AccountKeyring,
  senderPrincipal: string,
  senderEpub: string,
  ephemeral: Uint8Array,
  nonce: Uint8Array,
  recipientRotations: readonly unknown[],
  recipientContext: ResolutionContext,
): ContactLaneGrant {
  if (ephemeral.length !== 32 || nonce.length !== 12) throw new Error("bad-key");
  const sender = requirePrincipal(senderPrincipal);
  const epub = requirePrincipal(senderEpub);
  keyring.confirm(recipientRotations, recipientContext);
  const laneId = resolveContactLane(keyring, sender, keyring.rotationSeq);
  const plain = contactLaneGrantPlaintext(laneId, keyring.principal, keyring.rotationSeq);
  let shared: Uint8Array | undefined;
  let key: Uint8Array | undefined;
  let signing: Uint8Array | undefined;
  try {
    signing = unb64(keyring.currentPriv());
    const peer = uncompressedFromSea(epub);
    p256.Point.fromBytes(peer);
    const point = p256.getPublicKey(ephemeral, false);
    const ephemeralPub = seaPoint(ephemeral);
    shared = sharedX(ephemeral, peer);
    key = grantKdf(shared, keyring.principal, sender, epub, ephemeralPub, keyring.rotationSeq);
    shared.fill(0);
    const aad = contactLaneGrantAad(keyring.principal, sender, epub, ephemeralPub, keyring.rotationSeq);
    const ciphertext = aesEncrypt(key, nonce, aad, plain);
    const blob = new Uint8Array(1 + point.length + nonce.length + ciphertext.length);
    blob[0] = 1;
    blob.set(point, 1);
    blob.set(nonce, 1 + point.length);
    blob.set(ciphertext, 1 + point.length + nonce.length);
    if (blob.length > GRANT_BLOB_MAX) throw new Error("lane-grant-rejected");
    const ciphertextHex = bytesToHex(blob);
    if (ciphertextHex.includes(keyring.laneId())) throw new Error("lane-grant-rejected");
    const message = contactLaneGrantSignatureMessage(blob, keyring.principal, sender, epub, keyring.rotationSeq);
    const signature = bytesToHex(p256.sign(message, signing, { lowS: true, prehash: true }));
    return {
      recipient: keyring.principal,
      sender,
      senderEpub: epub,
      rotationSeq: keyring.rotationSeq,
      ciphertextHex,
      signature,
    };
  } finally {
    plain.fill(0);
    shared?.fill(0);
    key?.fill(0);
    signing?.fill(0);
  }
}

/**
 * After the lane secret rotates, seal a fresh grant for each contact.
 * A contact whose `currentEpub` is null fails the whole call with
 * `epub-unknown` before any grant is returned.
 */
export function regrantContactLanes(
  keyring: AccountKeyring,
  contacts: readonly ContactTarget[],
  recipientRotations: readonly unknown[],
  recipientContext: ResolutionContext,
): ContactLaneGrant[] {
  const ready = contacts.map((contact) => {
    const sender = requirePrincipal(contact.principal);
    const resolved = resolveCurrentKey(sender, contact.rotations, contact.context);
    if (!resolved.ok) throw new Error(resolved.reason);
    return { sender, epub: epubForNewSeal(resolved.value.currentEpub, null) };
  });
  return ready.map((contact) => {
    const ephemeral = randomScalar();
    const nonce = randomBytes(12);
    try {
      return sealContactLaneGrantWith(
        keyring,
        contact.sender,
        contact.epub,
        ephemeral,
        nonce,
        recipientRotations,
        recipientContext,
      );
    } finally {
      ephemeral.fill(0);
      nonce.fill(0);
    }
  });
}

/**
 * Open a grant. A stale grant, a forged grant, a tampered blob, the wrong
 * sender, and the wrong recipient are all `lane-grant-rejected`. This
 * function has no error-code argument.
 */
export function openContactLaneGrant(
  senderPrincipal: string,
  senderEpriv: string,
  grant: ContactLaneGrant,
  expectedRecipient: string,
  recipientRotations: readonly unknown[],
  recipientContext: ResolutionContext,
): OpenedContactLane {
  try {
    return openContactLaneGrantInner(
      senderPrincipal,
      senderEpriv,
      grant,
      expectedRecipient,
      recipientRotations,
      recipientContext,
    );
  } catch {
    throw new Error("lane-grant-rejected");
  }
}

function openContactLaneGrantInner(
  senderPrincipal: string,
  senderEpriv: string,
  grant: ContactLaneGrant,
  expectedRecipient: string,
  recipientRotations: readonly unknown[],
  recipientContext: ResolutionContext,
): OpenedContactLane {
  const sender = requirePrincipal(senderPrincipal);
  const expected = requirePrincipal(expectedRecipient);
  if (grant.sender !== sender || grant.recipient !== expected) throw new Error("lane-grant-rejected");
  if (!Number.isSafeInteger(grant.rotationSeq) || grant.rotationSeq < 0) throw new Error("lane-grant-rejected");
  if (grant.ciphertextHex.length > GRANT_BLOB_MAX * 2 || grant.signature.length !== 128) {
    throw new Error("lane-grant-rejected");
  }
  const scalar = unb64(senderEpriv);
  let shared: Uint8Array | undefined;
  let key: Uint8Array | undefined;
  let plain: Uint8Array | undefined;
  try {
    if (seaPoint(scalar) !== grant.senderEpub) throw new Error("lane-grant-rejected");
    const blob = hexToBytes(grant.ciphertextHex);
    if (blob.length > GRANT_BLOB_MAX || blob[0] !== 1 || blob.length < 1 + 65 + 12 + 16) {
      throw new Error("lane-grant-rejected");
    }
    const ephemeral = blob.subarray(1, 66);
    const nonce = blob.subarray(66, 78);
    const ephemeralPub = seaPoint(ephemeral);
    shared = sharedX(scalar, ephemeral);
    key = grantKdf(shared, expected, sender, grant.senderEpub, ephemeralPub, grant.rotationSeq);
    shared.fill(0);
    const aad = contactLaneGrantAad(expected, sender, grant.senderEpub, ephemeralPub, grant.rotationSeq);
    plain = aesDecrypt(key, nonce, aad, blob.subarray(78));
    const fields = decodeLengthPrefixed(plain);
    if (
      fields.length !== 4 ||
      fields[0] !== CONTACT_LANE_GRANT_DOMAIN ||
      !LANE_ID.test(fields[1] ?? "") ||
      fields[2] !== expected ||
      fields[3] !== canonicalDecimal(grant.rotationSeq)
    ) {
      throw new Error("lane-grant-rejected");
    }
    const laneId = fields[1];
    if (laneId === undefined) throw new Error("lane-grant-rejected");
    const resolved = resolveCurrentKey(expected, recipientRotations, recipientContext);
    if (!resolved.ok) throw new Error("lane-grant-rejected");
    if (resolved.value.rotations.length !== grant.rotationSeq) throw new Error("lane-grant-rejected");
    const message = contactLaneGrantSignatureMessage(
      blob,
      expected,
      sender,
      grant.senderEpub,
      grant.rotationSeq,
    );
    const keyAtSeq = signingKeyAt(expected, recipientRotations, recipientContext, grant.rotationSeq);
    if (keyAtSeq !== resolved.value.currentKey) throw new Error("lane-grant-rejected");
    const ok = p256.verify(hexToBytes(grant.signature), message, uncompressedFromSea(keyAtSeq), {
      lowS: true,
      prehash: true,
    });
    if (!ok) throw new Error("lane-grant-rejected");
    return {
      laneId,
      lookupKey: laneLookupKey(laneId),
      recipient: expected,
      sender,
      rotationSeq: grant.rotationSeq,
    };
  } finally {
    scalar.fill(0);
    shared?.fill(0);
    key?.fill(0);
    plain?.fill(0);
  }
}

function signingKeyAt(
  principal: PrincipalId,
  rotations: readonly unknown[],
  context: ResolutionContext,
  seq: number,
): PrincipalId {
  const through = rotations.filter((row) => {
    if (typeof row !== "object" || row === null) return false;
    const record = row as { kind?: unknown; seq?: unknown };
    return record.kind === "rotate" && typeof record.seq === "number" && Number.isSafeInteger(record.seq) && record.seq <= seq;
  });
  const resolved = resolveCurrentKey(principal, through, context);
  if (!resolved.ok || resolved.value.rotations.length !== seq) throw new Error("lane-grant-rejected");
  return resolved.value.currentKey;
}

function requirePrincipal(value: string): PrincipalId {
  const parsed = parsePrincipalId(value);
  if (!parsed.ok || parsed.value !== value) throw new Error(parsed.ok ? "non-canonical" : parsed.reason);
  return parsed.value;
}

function laneSecretBytes(hex: string): Uint8Array {
  if (!LANE_ID.test(hex)) throw new Error("bad-lane");
  return hexToBytes(hex);
}

/** RFC 5869 HKDF-SHA256, L = 32. Salt is HashLen zero bytes. One expand block. */
function hkdfSha256(ikm: Uint8Array, info: Uint8Array): Uint8Array {
  const salt = new Uint8Array(32);
  const prk = hmacSha256(salt, ikm);
  salt.fill(0);
  const block = new Uint8Array(info.length + 1);
  block.set(info, 0);
  block[info.length] = 1;
  const okm = hmacSha256(prk, block);
  prk.fill(0);
  block.fill(0);
  return okm;
}

function hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
  const mac = createHmac("sha256", key);
  mac.update(data);
  const out = new Uint8Array(mac.digest());
  return out;
}

function grantKdf(
  x: Uint8Array,
  recipient: string,
  sender: string,
  senderEpub: string,
  ephemeralPub: string,
  rotationSeq: number,
): Uint8Array {
  const material = lengthPrefixed([
    CONTACT_LANE_GRANT_DOMAIN,
    bytesToHex(x),
    recipient,
    sender,
    senderEpub,
    ephemeralPub,
    canonicalDecimal(rotationSeq),
  ]);
  const key = new Uint8Array(createHash("sha256").update(material).digest());
  material.fill(0);
  return key;
}

function aesEncrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, plain: Uint8Array): Uint8Array {
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(aad);
  return new Uint8Array(Buffer.concat([cipher.update(plain), cipher.final(), cipher.getAuthTag()]));
}

function aesDecrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, body: Uint8Array): Uint8Array {
  if (body.length < 16) throw new Error("lane-grant-rejected");
  const tag = body.subarray(body.length - 16);
  const data = body.subarray(0, body.length - 16);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAAD(aad);
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
