/** @import {Reason, Result} from './types.js' */
/** @template T @param {T} value @returns {Result<T>} */
export const ok = (value) => ({ ok: true, value });
/** @param {Reason} reason @returns {{ok: false, reason: Reason}} */
export const fail = (reason) => ({ ok: false, reason });
export const utf8 = new TextEncoder();
/** @param {Uint8Array} bytes */
export const hex = (bytes) => Array.from(bytes, x => x.toString(16).padStart(2, '0')).join('');
/** @param {string} s */
export const unhex = (s) => Uint8Array.from(s.match(/../g) ?? [], x => parseInt(x, 16));
/** @param {Uint8Array} bytes */
export const b64 = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
/** @param {string} s @returns {Uint8Array} */
export function unb64(s) {
  if (!/^[A-Za-z0-9_-]+$/.test(s)) throw Error('base64url');
  const bytes = Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
  if (b64(bytes) !== s) throw Error('noncanonical base64url');
  return bytes;
}
/** Shared precedence, lengths in UTF-16 code units, no coercion. @param {unknown} x @param {number} max @returns {Result<string>} */
export function text(x, max) {
  if (typeof x !== 'string') return fail('not-string');
  if (/get\s*\(|\['get'\]|\["get"\]|\\/.test(x)) return fail('gun-chain');
  if (!x.length) return fail('empty');
  if (x.length > max) return fail('too-long');
  if (/[\u0000-\u001f\u007f-\u009f]/.test(x)) return fail('control-char');
  if (/[\ufeff\u200b-\u200f\u2028\u2029\ufffd]/.test(x)) return fail('invisible-char');
  if (/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/.test(x)) return fail('unpaired-surrogate');
  if (x.startsWith(' ') || x.endsWith(' ')) return fail('whitespace');
  if (/^[\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000]|[\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000]$/.test(x)) return fail('bad-alphabet');
  return ok(x);
}
/** Snapshot data properties once. No getters, coercion or prototype reads. Proxies fail closed. @param {unknown} x @returns {Result<Record<string, unknown>>} */
export function data(x) {
  try {
    if (x === null || typeof x !== 'object' || Array.isArray(x)) return fail('bad-record');
    const ds = Object.getOwnPropertyDescriptors(x);
    /** @type {Record<string, unknown>} */
    const out = Object.create(null);
    for (const [k, d] of Object.entries(ds)) {
      if (!('value' in d)) return fail('bad-record');
      out[k] = d.value;
    }
    return ok(out);
  } catch { return fail('bad-record'); }
}
/** @param {unknown} n */
export const integer = (n) => typeof n === 'number' && Number.isSafeInteger(n) && n >= 0 && !Object.is(n, -0);
/** Little-endian UTF-8 length prefix. Callers pass strings this function already trusts.
 * @param {readonly string[]} fields */
export function lp(fields) {
  const parts = fields.map(s => utf8.encode(s));
  const bytes = new Uint8Array(parts.reduce((n, p) => n + 4 + p.length, 0));
  const view = new DataView(bytes.buffer);
  let at = 0;
  for (const part of parts) {
    view.setUint32(at, part.length, true); at += 4;
    bytes.set(part, at); at += part.length;
  }
  return bytes;
}
const loneSurrogate = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;
/** Public encoder. Only real, well-formed strings. No coercion.
 * `length` is read once. Each element is read and validated once, and the
 * first bad element returns before the rest of the array is touched.
 * @param {unknown} fields @returns {Result<Uint8Array>} */
export function lengthPrefixed(fields) {
  /** @type {string[]} */
  const copy = [];
  try {
    if (!Array.isArray(fields)) return fail('bad-record');
    const n = fields.length;
    if (typeof n !== 'number' || !Number.isSafeInteger(n) || n < 0) return fail('bad-record');
    for (let i = 0; i < n; i++) {
      const field = fields[i];
      if (typeof field !== 'string') return fail('not-string');
      if (loneSurrogate.test(field)) return fail('unpaired-surrogate');
      copy.push(field);
    }
  } catch { return fail('bad-record'); }
  return ok(lp(copy));
}
