import { p256 } from '@noble/curves/nist.js';
import { parsePrincipalId } from './ids.js';
import { uniqueJson } from './json.js';
import { ok, fail, integer, utf8, unb64 } from './util.js';

export const MAX_WITNESS_POLICY_BYTES = 262144;
export const MAX_WITNESS_ENVELOPE_BYTES = 360448;
const domain = utf8.encode('sociacl-witness-policy-v1\n');
/** @param {unknown} value @param {string[]} fields @returns {value is Record<string, unknown>} */
function exact(value, fields) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).length === fields.length && fields.every(k => Object.hasOwn(value, k));
}
/** Canonical decoding without a large argument-spread allocation. @param {unknown} value */
function decode(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) throw Error('encoding');
  const binary = atob(value.replace(/-/g, '+').replace(/_/g, '/'));
  if (btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') !== value) throw Error('encoding');
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}
/** Authenticate a Panopticon export; does NOT install trust or establish freshness.
 * Root and audience must come from independent trusted configuration; now from a
 * trusted clock. Before using returned JWKS, an adapter must atomically enforce
 * durable revision/key-history rules and trusted bootstrap freshness.
 * @param {unknown} envelope JSON text, including duplicate-member validation.
 * @param {string} root Pinned administrative P-256 public key in x.y encoding.
 * @param {string} audience Pinned deployment audience.
 * @param {number} now Trusted current Unix seconds, without skew.
 * @returns {import('./types.js').Result<import('./types.js').WitnessPolicy>}
 */
export function verifyWitnessPolicyEnvelope(envelope, root, audience, now) {
  try {
    if (typeof envelope !== 'string' || envelope.length > MAX_WITNESS_ENVELOPE_BYTES ||
        utf8.encode(envelope).length > MAX_WITNESS_ENVELOPE_BYTES ||
        typeof audience !== 'string' || !audience || !integer(now)) return fail('bad-attestation');
    const pinned = parsePrincipalId(root);
    if (!pinned.ok) return fail('bad-attestation');
    const outer = uniqueJson(envelope);
    if (!exact(outer, ['type', 'payload', 'signature']) || outer.type !== 'sociacl-witness-policy-envelope-v1') return fail('bad-attestation');
    const payload = decode(outer.payload), signature = decode(outer.signature);
    if (!payload.length || payload.length > MAX_WITNESS_POLICY_BYTES || signature.length !== 64) return fail('bad-attestation');
    const message = new Uint8Array(domain.length + payload.length);
    message.set(domain); message.set(payload, domain.length);
    const publicKey = new Uint8Array([4, ...unb64(root.slice(0, 43)), ...unb64(root.slice(44))]);
    if (!p256.verify(signature, message, publicKey, { prehash: true, lowS: true, format: 'compact' })) return fail('bad-attestation');
    const source = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(payload);
    const doc = uniqueJson(source);
    // Policy integer fields use JSON integer spelling, matching the publisher.
    const tokens = source.replace(/"(?:\\.|[^"\\])*"/g, '').match(/-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g) ?? [];
    if (tokens.some(n => !/^(0|[1-9]\d*)$/.test(n))) return fail('bad-attestation');
    if (!exact(doc, ['type', 'audience', 'revision', 'issuedAt', 'expiresAt', 'jwks']) ||
        doc.type !== 'sociacl-witness-policy-v1' || doc.audience !== audience ||
        !integer(doc.revision) || /** @type {number} */(doc.revision) === 0 ||
        !integer(doc.issuedAt) || !integer(doc.expiresAt)) return fail('bad-attestation');
    const start = /** @type {number} */(doc.issuedAt), end = /** @type {number} */(doc.expiresAt);
    if (end <= start || end - start > 86400 || now < start || now >= end ||
        !exact(doc.jwks, ['keys']) || !Array.isArray(doc.jwks.keys)) return fail('bad-attestation');
    const kids = new Set(), points = new Set();
    for (const key of doc.jwks.keys) {
      if (!exact(key, ['kid', 'kty', 'crv', 'alg', 'use', 'key_ops', 'x', 'y', 'notBefore', 'notAfter']) ||
          key.kty !== 'EC' || key.crv !== 'P-256' || key.alg !== 'ES256' || key.use !== 'sig' ||
          !Array.isArray(key.key_ops) || key.key_ops.length !== 1 || key.key_ops[0] !== 'verify' ||
          typeof key.kid !== 'string' || !key.kid || Array.from(key.kid).length > 128 ||
          typeof key.x !== 'string' || typeof key.y !== 'string' ||
          !integer(key.notBefore) || !integer(key.notAfter) ||
          /** @type {number} */(key.notBefore) >= /** @type {number} */(key.notAfter)) return fail('bad-attestation');
      const point = parsePrincipalId(`${key.x}.${key.y}`);
      if (!point.ok || point.value === root || kids.has(key.kid) || points.has(point.value)) return fail('bad-attestation');
      kids.add(key.kid); points.add(point.value);
      Object.freeze(key.key_ops); Object.freeze(key);
    }
    Object.freeze(doc.jwks.keys); Object.freeze(doc.jwks);
    return ok(/** @type {import('./types.js').WitnessPolicy} */(Object.freeze(doc)));
  } catch { return fail('bad-attestation'); }
}
