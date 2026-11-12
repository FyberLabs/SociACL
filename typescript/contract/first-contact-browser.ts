/** Browser WebCrypto envelope, wire-compatible with the Node and Rust implementations. */
import { p256 } from '@noble/curves/nist.js';
import { parsePrincipalId, type ResolutionContext, type Result } from '../ids/src/index.js';
import { fail, integer, b64, unb64, lp as lengthPrefixed } from '../ids/src/util.js';
function concat(...parts:Uint8Array[]):Uint8Array {
  const bytes=new Uint8Array(parts.reduce((n,p)=>n+p.length,0));let at=0;
  for(const part of parts){bytes.set(part,at);at+=part.length;}return bytes;
}
function buffer(bytes:Uint8Array):ArrayBuffer {const copy=new Uint8Array(bytes.length);copy.set(bytes);return copy.buffer;}
function seaPoint(key:Uint8Array):string {
  const point=key.length===65?key:p256.getPublicKey(key,false);
  return `${b64(point.subarray(1,33))}.${b64(point.subarray(33))}`;
}
function uncompressedFromSea(key:string):Uint8Array {
  if(!parsePrincipalId(key).ok)throw Error('bad-record');
  return concat(Uint8Array.of(4),unb64(key.slice(0,43)),unb64(key.slice(44)));
}
const sharedX=(scalar:Uint8Array,point:Uint8Array)=>p256.getSharedSecret(scalar,point,false).slice(1,33);
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
function decodePlaintext(bytes: Uint8Array): string[] {
  const fields: string[] = [];
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
  let offset = 0;
  while (offset < bytes.length) {
    if (fields.length >= 11 || bytes.length - offset < 4) throw Error('bad-record');
    const length = view.getUint32(offset, true); offset += 4;
    if (length > bytes.length - offset) throw Error('bad-record');
    fields.push(decoder.decode(bytes.subarray(offset, offset + length))); offset += length;
  }
  return fields;
}
async function keyFor(shared:Uint8Array,aad:Uint8Array):Promise<CryptoKey> {
  const material=await crypto.subtle.importKey('raw',buffer(shared),'HKDF',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt:buffer(new Uint8Array(32)),info:buffer(aad)},
    material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}
function plaintext(r: FirstContactRequest): Uint8Array {
  return concat(firstContactRequestBytes(r), lengthPrefixed([r.sig]));
}

/** Random ephemeral P-256 key and 96-bit GCM nonce on every invocation.
 * Signature verification is the recipient's responsibility; sealing is not admission.
 */
export async function sealFirstContactRequestBrowser(input: unknown, supplied: FirstContactSealDescriptor): Promise<Uint8Array> {
  const descriptor=Object.freeze({...supplied});
  const parsed = parseFirstContactRequest(input);
  if (!parsed.ok) throw Error('bad-record');
  const r = parsed.value;
  if (r.channelId !== descriptor.channelId || r.descriptorRevision !== descriptor.revision) throw Error('bad-record');
  const ephemeral = p256.utils.randomSecretKey();
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  let shared: Uint8Array | undefined, plain: Uint8Array | undefined;
  try {
    const point = p256.getPublicKey(ephemeral, false);
    const aad = aadFor(descriptor, point);
    shared = sharedX(ephemeral, uncompressedFromSea(descriptor.encryptionEpub));
    const key = await keyFor(shared, aad);
    plain = plaintext(r);
    const encrypted=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv:buffer(nonce),additionalData:buffer(aad),tagLength:128},key,buffer(plain)));
    const blob=concat(Uint8Array.of(1),point,nonce,encrypted);
    if (blob.length > FIRST_CONTACT_ENVELOPE_MAX_BYTES) throw Error('bad-record');
    return blob;
  } finally {
    ephemeral.fill(0); nonce.fill(0); shared?.fill(0); plain?.fill(0);
  }
}

/** Decrypt then authenticate against independently supplied sender history.
 * The caller must still atomically reserve replayKey through replayUntil before
 * display or acceptance. All malformed envelopes fail closed with bad-record.
 */
export async function openFirstContactRequestBrowser(envelope: Uint8Array, recipientEpriv: string,
  supplied: FirstContactSealDescriptor, currentState:()=>{rotations:readonly unknown[];context:ResolutionContext}): Promise<Result<VerifiedFirstContact>> {
  const descriptor=Object.freeze({...supplied});
  let scalar: Uint8Array | undefined, shared: Uint8Array | undefined,
    plain: Uint8Array | undefined;
  try {
    if (!(envelope instanceof Uint8Array) || envelope.length < 94 ||
        envelope.length > FIRST_CONTACT_ENVELOPE_MAX_BYTES) return fail('bad-record');
    const started=currentState().context.now;
    if(!integer(started))return fail('bad-record');
    const blob = new Uint8Array(envelope);
    if (blob[0] !== 1 || blob[1] !== 4) return fail('bad-record');
    scalar = unb64(recipientEpriv);
    if (scalar.length !== 32 || seaPoint(scalar) !== descriptor.encryptionEpub) return fail('bad-record');
    const point = blob.subarray(1, 66), nonce = blob.subarray(66, 78);
    const aad = aadFor(descriptor, point);
    shared = sharedX(scalar, point); const key=await keyFor(shared,aad);
    plain=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:buffer(nonce),additionalData:buffer(aad),tagLength:128},key,buffer(blob.subarray(78))));
    const f = decodePlaintext(plain);
    if (f.length !== 11 || f[0] !== FIRST_CONTACT_DOMAIN || f[1] !== '1') return fail('bad-record');
    const parsed = parseFirstContactRequest({ v: 1, channelId: f[2], descriptorRevision: Number(f[3]),
      sender: f[4], replyEpub: f[5], nonce: f[6], issuedAt: Number(f[7]), expiresAt: Number(f[8]),
      message: f[9], sig: f[10] });
    if (!parsed.ok) return parsed;
    // Reject noncanonical decimals, replacement-decoded UTF-8 and trailing fields.
    const canonical = plaintext(parsed.value);
    try { if (canonical.length!==plain.length || canonical.some((byte,i)=>byte!==plain![i])) return fail('bad-record'); }
    finally { canonical.fill(0); }
    const {rotations,context}=currentState();
    if(context.now<started)return fail('bad-record');
    return verifyFirstContactRequest(parsed.value, rotations, context, descriptor);
  } catch { return fail('bad-record'); }
  finally { scalar?.fill(0); shared?.fill(0); plain?.fill(0); }
}
