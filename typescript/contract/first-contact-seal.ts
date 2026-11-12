/** Confidential first-contact reference envelope. Opening never grants a lane. */
import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto';
import { p256 } from '@noble/curves/nist.js';
import { parsePrincipalId, type ResolutionContext, type Result } from '../ids/src/index.js';
import { fail } from '../ids/src/util.js';
import { decodeLengthPrefixed, seaPoint, sharedX, unb64, uncompressedFromSea } from './account-key-seal.ts';
import { lengthPrefixed } from './canonical.ts';
import { FIRST_CONTACT_DOMAIN, firstContactRequestBytes, parseFirstContactRequest,
  verifyFirstContactRequest, type FirstContactDescriptor, type FirstContactRequest,
  type VerifiedFirstContact } from './first-contact.ts';

export const FIRST_CONTACT_SEAL_DOMAIN = 'sociacl-first-contact-seal-v1';
export const FIRST_CONTACT_ENVELOPE_MAX_BYTES = 8192;
/** Authenticated, immutable recipient configuration; never take this from a request. */
export type FirstContactSealDescriptor = FirstContactDescriptor & Readonly<{ encryptionEpub: string }>;

function aadFor(d: FirstContactSealDescriptor, ephemeral: Uint8Array): Uint8Array {
  const key = parsePrincipalId(d.encryptionEpub);
  if (!key.ok || key.value !== d.encryptionEpub ||
      d.channelId.length !== 64 || !/^[0-9a-f]{64}$/.test(d.channelId) ||
      !Number.isSafeInteger(d.revision) || d.revision < 1) throw Error('bad-record');
  return lengthPrefixed([FIRST_CONTACT_SEAL_DOMAIN, '1', d.channelId, String(d.revision),
    d.encryptionEpub, seaPoint(ephemeral)]);
}
function keyFor(shared: Uint8Array, aad: Uint8Array): Uint8Array {
  return new Uint8Array(hkdfSync('sha256', shared, new Uint8Array(32), aad, 32));
}
function plaintext(r: FirstContactRequest): Uint8Array {
  return new Uint8Array(Buffer.concat([firstContactRequestBytes(r), lengthPrefixed([r.sig])]));
}

/** Random ephemeral P-256 key and 96-bit GCM nonce on every invocation.
 * Signature verification is the recipient's responsibility; sealing is not admission.
 */
export function sealFirstContactRequest(input: unknown, descriptor: FirstContactSealDescriptor): Uint8Array {
  const parsed = parseFirstContactRequest(input);
  if (!parsed.ok) throw Error('bad-record');
  const r = parsed.value;
  if (r.channelId !== descriptor.channelId || r.descriptorRevision !== descriptor.revision) throw Error('bad-record');
  const ephemeral = p256.utils.randomSecretKey();
  const nonce = randomBytes(12);
  let shared: Uint8Array | undefined, key: Uint8Array | undefined, plain: Uint8Array | undefined;
  try {
    const point = p256.getPublicKey(ephemeral, false);
    const aad = aadFor(descriptor, point);
    shared = sharedX(ephemeral, uncompressedFromSea(descriptor.encryptionEpub));
    key = keyFor(shared, aad);
    plain = plaintext(r);
    const cipher = createCipheriv('aes-256-gcm', key, nonce);
    cipher.setAAD(aad);
    const blob = new Uint8Array(Buffer.concat([Uint8Array.of(1), point, nonce,
      cipher.update(plain), cipher.final(), cipher.getAuthTag()]));
    if (blob.length > FIRST_CONTACT_ENVELOPE_MAX_BYTES) throw Error('bad-record');
    return blob;
  } finally {
    ephemeral.fill(0); nonce.fill(0); shared?.fill(0); key?.fill(0); plain?.fill(0);
  }
}

/** Decrypt then authenticate against independently supplied sender history.
 * The caller must still atomically reserve replayKey through replayUntil before
 * display or acceptance. All malformed envelopes fail closed with bad-record.
 */
export function openFirstContactRequest(envelope: Uint8Array, recipientEpriv: string,
  descriptor: FirstContactSealDescriptor, rotations: readonly unknown[],
  context: ResolutionContext): Result<VerifiedFirstContact> {
  let scalar: Uint8Array | undefined, shared: Uint8Array | undefined,
    key: Uint8Array | undefined, plain: Uint8Array | undefined;
  try {
    if (!(envelope instanceof Uint8Array) || envelope.length < 94 ||
        envelope.length > FIRST_CONTACT_ENVELOPE_MAX_BYTES) return fail('bad-record');
    const blob = new Uint8Array(envelope);
    if (blob[0] !== 1 || blob[1] !== 4) return fail('bad-record');
    scalar = unb64(recipientEpriv);
    if (scalar.length !== 32 || seaPoint(scalar) !== descriptor.encryptionEpub) return fail('bad-record');
    const point = blob.subarray(1, 66), nonce = blob.subarray(66, 78);
    const aad = aadFor(descriptor, point);
    shared = sharedX(scalar, point); key = keyFor(shared, aad);
    const decipher = createDecipheriv('aes-256-gcm', key, nonce);
    decipher.setAAD(aad); decipher.setAuthTag(blob.subarray(blob.length - 16));
    plain = new Uint8Array(Buffer.concat([decipher.update(blob.subarray(78, -16)), decipher.final()]));
    const f = decodeLengthPrefixed(plain);
    if (f.length !== 11 || f[0] !== FIRST_CONTACT_DOMAIN || f[1] !== '1') return fail('bad-record');
    const parsed = parseFirstContactRequest({ v: 1, channelId: f[2], descriptorRevision: Number(f[3]),
      sender: f[4], replyEpub: f[5], nonce: f[6], issuedAt: Number(f[7]), expiresAt: Number(f[8]),
      message: f[9], sig: f[10] });
    if (!parsed.ok) return parsed;
    // Reject noncanonical decimals, replacement-decoded UTF-8 and trailing fields.
    const canonical = plaintext(parsed.value);
    try { if (!Buffer.from(canonical).equals(plain)) return fail('bad-record'); }
    finally { canonical.fill(0); }
    return verifyFirstContactRequest(parsed.value, rotations, context, descriptor);
  } catch { return fail('bad-record'); }
  finally { scalar?.fill(0); shared?.fill(0); key?.fill(0); plain?.fill(0); }
}
