/** Browser opening of the existing confidential contact-lane grant wire format.
 * A lane permits delivery only; it does not grant access to contact objects.
 */
import { p256 } from '@noble/curves/nist.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { parsePrincipalId, resolveCurrentKey, type ResolutionContext } from '../ids/src/index.js';
import { b64, unb64, hex, unhex, lp, data, integer } from '../ids/src/util.js';
import type { ContactLaneGrant, OpenedContactLane } from '../ids/src/contact-lane.js';

const DOMAIN = 'sociacl-contact-lane-grant-v1';
const SIGNATURE_DOMAIN = 'sociacl-contact-lane-grant-sig-v1';
const LANE = /^[0-9a-f]{64}$/u;
export type ContactLaneRecipientState = () => { rotations: readonly unknown[]; context: ResolutionContext };

function principal(value: string) {
  const parsed = parsePrincipalId(value);
  if (!parsed.ok || parsed.value !== value) throw Error('bad-principal');
  return parsed.value;
}
export function laneLookupKey(laneId: string): string {
  if (typeof laneId !== 'string' || !LANE.test(laneId)) throw Error('bad-lane');
  return laneId;
}
export function deriveContactLane(contactSecretHex: string, recipient: string, sender: string): string {
  laneLookupKey(contactSecretHex);
  const info = lp(['sociacl-contact-lane-v1', '1', principal(recipient), principal(sender)]);
  const secret = unhex(contactSecretHex);
  let output: Uint8Array | undefined;
  try {
    output = hkdf(sha256, secret, new Uint8Array(32), info, 32);
    return hex(output);
  } finally { secret.fill(0); output?.fill(0); }
}
function sea(point: Uint8Array): string {
  p256.Point.fromBytes(point);
  if (point.length !== 65 || point[0] !== 4) throw Error('bad-point');
  return b64(point.subarray(1, 33)) + '.' + b64(point.subarray(33));
}
function point(value: string): Uint8Array {
  const parts = principal(value).split('.');
  const bytes = new Uint8Array(65);
  bytes[0] = 4;
  bytes.set(unb64(parts[0]!), 1);
  bytes.set(unb64(parts[1]!), 33);
  return bytes;
}
function buffer(bytes: Uint8Array): ArrayBuffer { return new Uint8Array(bytes).buffer; }
function fields(bytes: Uint8Array): string[] {
  const values: string[] = [];
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
  let at = 0;
  while (at < bytes.length) {
    if (values.length === 5 || at + 4 > bytes.length) throw Error('bad-fields');
    const length = view.getUint32(at, true); at += 4;
    if (length > bytes.length - at) throw Error('bad-fields');
    values.push(decoder.decode(bytes.subarray(at, at + length))); at += length;
  }
  return values;
}

/** Read authoritative recipient history both before and after WebCrypto awaits.
 * The callback must return current witnessed state, not a captured stale snapshot.
 * Invalid input, stale authority, and decryption failures have one public error.
 */
export async function openContactLaneGrant(
  senderPrincipal: string, senderEpriv: string, grant: ContactLaneGrant,
  expectedRecipient: string, currentState: ContactLaneRecipientState,
): Promise<OpenedContactLane> {
  let scalar: Uint8Array | undefined;
  let shared: Uint8Array | undefined;
  let material: Uint8Array | undefined;
  let key: Uint8Array | undefined;
  let plain: Uint8Array | undefined;
  try {
    const sender = principal(senderPrincipal);
    const recipient = principal(expectedRecipient);
    const record = data(grant);
    if (!record.ok) throw Error('bad-grant');
    const ciphertext = record.value.ciphertextHex;
    if (typeof ciphertext !== 'string' || ciphertext.length < 188 || ciphertext.length > 8192 ||
        !/^(?:[0-9a-f]{2})+$/u.test(ciphertext)) throw Error('bad-grant');
    const blob = unhex(ciphertext);
    if (blob[0] !== 1) throw Error('bad-grant');
    scalar = unb64(senderEpriv);
    if (scalar.length !== 32) throw Error('bad-key');
    const senderEpub = sea(p256.getPublicKey(scalar, false));
    const ephemeral = blob.subarray(1, 66);
    const ephemeralPub = sea(ephemeral);
    const initial = currentState();
    const startedAt = initial.context.now;
    if (!integer(startedAt)) throw Error('bad-time');
    const resolved = resolveCurrentKey(recipient, initial.rotations, initial.context);
    if (!resolved.ok) throw Error('bad-authority');
    const seq = resolved.value.rotations.length;
    const signingKey = resolved.value.currentKey;
    const initialHistory = initial.context.history(recipient, startedAt, startedAt);
    if (!initialHistory.ok || initialHistory.value.currentKey !== signingKey) throw Error('missing-history');
    shared = p256.getSharedSecret(scalar, ephemeral, false);
    material = lp([DOMAIN, hex(shared.subarray(1, 33)), recipient, sender, senderEpub, ephemeralPub, String(seq)]);
    key = sha256(material);
    material.fill(0); shared.fill(0);
    const aad = lp([DOMAIN, recipient, sender, senderEpub, ephemeralPub, String(seq)]);
    const cryptoKey = await crypto.subtle.importKey('raw', buffer(key), 'AES-GCM', false, ['decrypt']);
    plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buffer(blob.subarray(66, 78)),
      additionalData: buffer(aad), tagLength: 128 }, cryptoKey, buffer(blob.subarray(78))));
    const decoded = fields(plain);
    const [domain, laneId, owner, sequence, signature] = decoded;
    if (decoded.length !== 5 || domain !== DOMAIN || !laneId || !LANE.test(laneId) || owner !== recipient ||
        sequence !== String(seq) || !signature || !/^[0-9a-f]{128}$/u.test(signature)) throw Error('bad-fields');
    const message = lp([SIGNATURE_DOMAIN, laneId, recipient, sender, senderEpub, String(seq)]);
    if (!p256.verify(unhex(signature), message, point(signingKey), { lowS: true, prehash: true })) throw Error('bad-signature');
    const latest = currentState();
    if (!integer(latest.context.now) || latest.context.now < startedAt) throw Error('bad-time');
    const fresh = resolveCurrentKey(recipient, latest.rotations, latest.context);
    if (!fresh.ok || fresh.value.currentKey !== signingKey || fresh.value.rotations.length !== seq) throw Error('stale-authority');
    const freshHistory = latest.context.history(recipient, latest.context.now, latest.context.now);
    if (!freshHistory.ok || freshHistory.value.currentKey !== signingKey) throw Error('missing-history');
    return { laneId, lookupKey: laneLookupKey(laneId), recipient, sender, rotationSeq: seq };
  } catch { throw Error('lane-grant-rejected'); }
  finally { scalar?.fill(0); shared?.fill(0); material?.fill(0); key?.fill(0); plain?.fill(0); }
}
