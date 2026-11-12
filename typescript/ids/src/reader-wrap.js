/** Browser counterpart of sociacl-encdisc's item-DEK reader wrap.
 * Encryption never grants access. Callers supply a current authorized named set
 * and verify Check plus fresh epoch status before using an opened key. */
import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { parsePrincipalId, parseObjectId } from './ids.js';
import { data, integer, lp, hex, unhex, unb64, b64, ok, fail } from './util.js';
/** @import {Result, ItemReaderWrap, ItemWrapContext} from './types.js' */
const ERROR = 'bad-record';
const DOMAIN = 's3rch-wrapped-key-v1';
const intrinsicByteLength = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), 'byteLength')?.get;

/** @param {unknown} input @returns {ItemWrapContext} */
function binding(input) {
  const parsed = data(input);
  if (!parsed.ok || Object.keys(parsed.value).sort().join() !== 'epoch,object,revisionId') throw Error();
  const { epoch, object, revisionId } = parsed.value;
  if (typeof epoch !== 'number' || !integer(epoch) || typeof object !== 'string' || !parseObjectId(object).ok ||
      typeof revisionId !== 'string' || !/^[a-f0-9]{64}$/.test(revisionId)) throw Error();
  return Object.freeze({ epoch, object, revisionId });
}
/** @param {unknown} value */
function point(value) {
  const parsed = parsePrincipalId(value); if (!parsed.ok) throw Error();
  return { name: parsed.value, bytes: new Uint8Array([4, ...unb64(parsed.value.slice(0, 43)), ...unb64(parsed.value.slice(44))]) };
}
/** Snapshot bounded arrays without invoking getters or caller-supplied methods.
 * @param {unknown} value @returns {unknown[]} */
function list(value) {
  if (!Array.isArray(value)) throw Error();
  const descriptors = Object.getOwnPropertyDescriptors(value), length = descriptors.length;
  if (!length || !('value' in length) || !Number.isSafeInteger(length.value) || length.value < 0 || length.value > 64 ||
      Reflect.ownKeys(descriptors).length !== length.value + 1) throw Error();
  const output = [];
  for (let index = 0; index < length.value; index++) {
    const entry = descriptors[String(index)];
    if (!entry || !('value' in entry)) throw Error();
    output.push(entry.value);
  }
  return output;
}
/** @param {ItemWrapContext} context @param {string} epub */
const prefix = (context, epub) => lp([DOMAIN, 'item-dek', String(context.epoch), 'reader-epub', epub, context.object, '', context.revisionId]);
/** @param {Uint8Array} secret @param {Uint8Array} peer */
async function aesKey(secret, peer) {
  const shared = p256.getSharedSecret(secret, peer, false);
  const material = sha256(lp(['s3rch-sea-secret-v1', hex(shared.subarray(1, 33))]));
  try { return await crypto.subtle.importKey('raw', new Uint8Array(material), 'AES-GCM', false, ['encrypt', 'decrypt']); }
  finally { shared.fill(0); material.fill(0); }
}

/** Wrap only to the already-authorized enrolled readers. No partial result is
 * returned when any reader is invalid or unnamed. Input is copied before await.
 * @param {Uint8Array} dek @param {unknown} context @param {unknown} readers @param {unknown} named
 * @returns {Promise<Result<readonly ItemReaderWrap[]>>} */
export async function wrapItemDekToReaders(dek, context, readers, named) {
  /** @type {Uint8Array | undefined} */ let key;
  try {
    if (!ArrayBuffer.isView(dek) || !(dek instanceof Uint8Array) || intrinsicByteLength?.call(dek) !== 32) throw Error();
    key = new Uint8Array(dek);
    if (key.byteLength !== 32) throw Error();
    const scope = binding(context);
    const readerList = list(readers), namedList = list(named);
    const authorized = new Set(namedList.map(value => { const p = parsePrincipalId(value); if (!p.ok) throw Error(); return p.value; }));
    if (authorized.size !== namedList.length) throw Error();
    const seen = new Set();
    const targets = readerList.map(raw => {
      const d = data(raw); if (!d.ok || Object.keys(d.value).sort().join() !== 'account,epub,identityPub,pub') throw Error();
      const { account, pub, epub, identityPub } = d.value;
      const owner = parsePrincipalId(account), signer = parsePrincipalId(pub);
      if (!owner.ok || !signer.ok || identityPub !== signer.value || !authorized.has(owner.value) || seen.has(owner.value)) throw Error();
      seen.add(owner.value); return point(epub);
    });
    /** @type {ItemReaderWrap[]} */ const output = [];
    for (const target of targets) {
      const secret = p256.utils.randomSecretKey();
      const nonce = crypto.getRandomValues(new Uint8Array(12));
      const plainPrefix = prefix(scope, target.name), tail = lp([hex(key)]);
      const plain = new Uint8Array([...plainPrefix, ...tail]);
      try {
        const aes = await aesKey(secret, target.bytes);
        const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, tagLength: 128 }, aes, plain));
        const bytes = new Uint8Array([1, ...p256.getPublicKey(secret, false), ...nonce, ...sealed]);
        output.push(Object.freeze({ ...scope, scope: 'item-dek', target: 'reader-epub', targetId: target.name, wrappedKey: hex(bytes) }));
      } finally { secret.fill(0); plain.fill(0); tail.fill(0); }
    }
    return ok(Object.freeze(output));
  } catch { return fail(ERROR); }
  finally { key?.fill(0); }
}

/** Opens only this item's expected epoch/revision. The expected context must
 * come from the caller's current authorized view, not the untrusted wrap label.
 * @param {unknown} input @param {string} epriv @param {string} epub @param {unknown} expected
 * @returns {Promise<Result<Uint8Array>>} */
export async function openItemDekReaderWrap(input, epriv, epub, expected) {
  /** @type {Uint8Array | undefined} */ let secret;
  /** @type {Uint8Array | undefined} */ let plain;
  try {
    const scope = binding(expected), target = point(epub), d = data(input);
    if (!d.ok || Object.keys(d.value).sort().join() !== 'epoch,object,revisionId,scope,target,targetId,wrappedKey') throw Error();
    const wrap = d.value;
    if (!integer(wrap.epoch) || wrap.scope !== 'item-dek' || wrap.target !== 'reader-epub' || wrap.targetId !== target.name ||
        wrap.epoch !== scope.epoch || wrap.object !== scope.object || wrap.revisionId !== scope.revisionId ||
        typeof wrap.wrappedKey !== 'string' || wrap.wrappedKey.length > 16384 || !/^(?:[a-f0-9]{2}){95,}$/.test(wrap.wrappedKey) ||
        typeof epriv !== 'string' || epriv.length !== 43) throw Error();
    secret = unb64(epriv);
    const own = p256.getPublicKey(secret, false);
    if (b64(own.subarray(1, 33)) + '.' + b64(own.subarray(33)) !== target.name) throw Error();
    const bytes = unhex(wrap.wrappedKey);
    if (bytes[0] !== 1 || bytes[1] !== 4) throw Error();
    const aes = await aesKey(secret, bytes.slice(1, 66));
    plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.slice(66, 78), tagLength: 128 }, aes, bytes.slice(78)));
    const leading = prefix(scope, target.name);
    if (plain.length !== leading.length + 68 || leading.some((value, index) => plain?.[index] !== value) ||
        new DataView(plain.buffer, plain.byteOffset + leading.length, 4).getUint32(0, true) !== 64) throw Error();
    const encoded = new TextDecoder('utf-8', { fatal: true }).decode(plain.subarray(leading.length + 4));
    if (!/^[a-f0-9]{64}$/.test(encoded)) throw Error();
    return ok(unhex(encoded));
  } catch { return fail(ERROR); }
  finally { secret?.fill(0); plain?.fill(0); }
}
