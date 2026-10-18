/**
 * Per-contact inbox lane derivation and the confidential grant.
 *
 * The HKDF input is the keyring contact-lane secret, 32 random bytes.
 * It is not the disclosed base `laneId`. The recipient signs the lane id
 * and then encrypts that signature. The outer envelope is the ciphertext.
 * Recipient and sender ids that the opener already knows are associated
 * data. They are not a public signature. A lane is delivery only.
 *
 * There is no Gun user-encryption fallback. This file does not wire
 * Panopticon or Gun and does not open a first-contact channel.
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
import { canonicalDecimal, lengthPrefixed } from "./canonical.ts";

export const CONTACT_LANE_DOMAIN = "sociacl-contact-lane-v1";
export const CONTACT_LANE_VERSION = "1";
export const CONTACT_LANE_GRANT_DOMAIN = "sociacl-contact-lane-grant-v1";
export const CONTACT_LANE_GRANT_SIG_DOMAIN = "sociacl-contact-lane-grant-sig-v1";

const LANE_ID = /^[0-9a-f]{64}$/u;
const SIG_HEX = /^[0-9a-f]{128}$/u;
const GRANT_BLOB_MAX = 4096;

/** Outer envelope. The lane id and the recipient signature are inside. */
export type ContactLaneGrant = {
  readonly ciphertextHex: string;
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
 * HKDF-SHA256. IKM is the 32-byte contact-lane secret. Salt is 32 zero
 * bytes. Info is {@link contactLaneInfo}. Output is 32 bytes, lowercase hex.
 * HKDF of the disclosed base lane id is a different value.
 */
export function deriveContactLane(contactSecretHex: string, recipient: string, sender: string): string {
  const ikm = laneSecretBytes(contactSecretHex);
  const info = contactLaneInfo(recipient, sender);
  const okm = hkdfSha256(ikm, info);
  const lane = bytesToHex(okm);
  ikm.fill(0);
  okm.fill(0);
  return lane;
}

/**
 * Contact lane at `seq`. `priorContactSecrets[seq]` is the secret that was
 * current at that sequence, and `priorContactSecrets.length` is
 * `rotationSeq`. The current secret is `contactLaneSecret`. A sequence
 * above `rotationSeq` is `bad-lane`. A derived id that equals a disclosed
 * base lane or a contact-lane secret is `bad-lane`.
 */
export function resolveContactLane(keyring: AccountKeyring, sender: string, seq: number): string {
  if (!Number.isSafeInteger(seq) || seq < 0) throw new Error("bad-lane");
  const prior = keyring.priorContactSecrets();
  if (prior.length !== keyring.rotationSeq || seq > keyring.rotationSeq) throw new Error("bad-lane");
  const secret = seq === keyring.rotationSeq ? keyring.contactLaneSecret() : prior[seq];
  if (secret === undefined) throw new Error("bad-lane");
  const lane = deriveContactLane(secret, keyring.principal, sender);
  if (contactLaneCollides(lane, keyring)) throw new Error("bad-lane");
  return lane;
}

/**
 * Opaque storage key. It is the lane id hex. It is not a PrincipalId and
 * not a `~pub` path. Callers index by this string alone.
 */
export function laneLookupKey(laneId: string): string {
  if (!LANE_ID.test(laneId)) throw new Error("bad-lane");
  return laneId;
}

export function contactLaneGrantPlaintext(
  laneId: string,
  recipient: string,
  rotationSeq: number,
  signature: string,
): Uint8Array {
  if (!LANE_ID.test(laneId)) throw new Error("bad-lane");
  if (!SIG_HEX.test(signature)) throw new Error("bad-key");
  const owner = requirePrincipal(recipient);
  return lengthPrefixed([
    CONTACT_LANE_GRANT_DOMAIN,
    laneId,
    owner,
    canonicalDecimal(rotationSeq),
    signature,
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

/** Signed before encryption. The message does not cover the ciphertext. */
export function contactLaneGrantSignatureMessage(
  laneId: string,
  recipient: string,
  sender: string,
  senderEpub: string,
  rotationSeq: number,
): Uint8Array {
  if (!LANE_ID.test(laneId)) throw new Error("bad-lane");
  return lengthPrefixed([
    CONTACT_LANE_GRANT_SIG_DOMAIN,
    laneId,
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
 * Caller-chosen ephemeral and nonce. Test support and the vector generator
 * call this. The production module does not re-export it.
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
  const message = contactLaneGrantSignatureMessage(laneId, keyring.principal, sender, epub, keyring.rotationSeq);
  let shared: Uint8Array | undefined;
  let key: Uint8Array | undefined;
  let signing: Uint8Array | undefined;
  let plain: Uint8Array | undefined;
  try {
    signing = unb64(keyring.currentPriv());
    const signature = bytesToHex(p256.sign(message, signing, { lowS: true, prehash: true }));
    plain = contactLaneGrantPlaintext(laneId, keyring.principal, keyring.rotationSeq, signature);
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
    return { ciphertextHex: bytesToHex(blob) };
  } finally {
    plain?.fill(0);
    shared?.fill(0);
    key?.fill(0);
    signing?.fill(0);
  }
}

/**
 * After the contact-lane secret rotates, seal a fresh grant for each contact.
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
 * Open a grant. The caller supplies the sender, the sender's `epriv`, and
 * the recipient chain. The sequence is that chain's length, so a stale
 * grant fails authenticated decryption. A forged grant, a tampered blob,
 * the wrong sender, and the wrong recipient are all `lane-grant-rejected`.
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
  if (grant.ciphertextHex.length > GRANT_BLOB_MAX * 2) throw new Error("lane-grant-rejected");
  const scalar = unb64(senderEpriv);
  let shared: Uint8Array | undefined;
  let key: Uint8Array | undefined;
  let plain: Uint8Array | undefined;
  try {
    const senderEpub = seaPoint(scalar);
    const resolved = resolveCurrentKey(expected, recipientRotations, recipientContext);
    if (!resolved.ok) throw new Error("lane-grant-rejected");
    const seq = resolved.value.rotations.length;
    const blob = hexToBytes(grant.ciphertextHex);
    if (blob.length > GRANT_BLOB_MAX || blob[0] !== 1 || blob.length < 1 + 65 + 12 + 16) {
      throw new Error("lane-grant-rejected");
    }
    const ephemeral = blob.subarray(1, 66);
    const nonce = blob.subarray(66, 78);
    const ephemeralPub = seaPoint(ephemeral);
    shared = sharedX(scalar, ephemeral);
    key = grantKdf(shared, expected, sender, senderEpub, ephemeralPub, seq);
    shared.fill(0);
    const aad = contactLaneGrantAad(expected, sender, senderEpub, ephemeralPub, seq);
    plain = aesDecrypt(key, nonce, aad, blob.subarray(78));
    const fields = decodeLengthPrefixed(plain);
    if (
      fields.length !== 5 ||
      fields[0] !== CONTACT_LANE_GRANT_DOMAIN ||
      !LANE_ID.test(fields[1] ?? "") ||
      fields[2] !== expected ||
      fields[3] !== canonicalDecimal(seq) ||
      !SIG_HEX.test(fields[4] ?? "")
    ) {
      throw new Error("lane-grant-rejected");
    }
    const laneId = fields[1];
    const signature = fields[4];
    if (laneId === undefined || signature === undefined) throw new Error("lane-grant-rejected");
    const message = contactLaneGrantSignatureMessage(laneId, expected, sender, senderEpub, seq);
    const ok = p256.verify(hexToBytes(signature), message, uncompressedFromSea(resolved.value.currentKey), {
      lowS: true,
      prehash: true,
    });
    if (!ok) throw new Error("lane-grant-rejected");
    return {
      laneId,
      lookupKey: laneLookupKey(laneId),
      recipient: expected,
      sender,
      rotationSeq: seq,
    };
  } finally {
    scalar.fill(0);
    shared?.fill(0);
    key?.fill(0);
    plain?.fill(0);
  }
}

function contactLaneCollides(laneId: string, keyring: AccountKeyring): boolean {
  return (
    !LANE_ID.test(laneId) ||
    laneId === keyring.laneId() ||
    keyring.priorLanes().includes(laneId) ||
    laneId === keyring.contactLaneSecret() ||
    keyring.priorContactSecrets().includes(laneId)
  );
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
  return new Uint8Array(mac.digest());
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
