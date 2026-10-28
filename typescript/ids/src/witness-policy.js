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
    validateKeys(doc.jwks.keys, root);
    Object.freeze(doc.jwks.keys); Object.freeze(doc.jwks);
    return ok(/** @type {import('./types.js').WitnessPolicy} */(Object.freeze(doc)));
  } catch { return fail('bad-attestation'); }
}

/** @param {unknown[]} keys @param {string} root */
function validateKeys(keys, root) {
  const kids = new Set(), points = new Set();
  for (const key of keys) {
    if (!exact(key, ['kid', 'kty', 'crv', 'alg', 'use', 'key_ops', 'x', 'y', 'notBefore', 'notAfter']) ||
        key.kty !== 'EC' || key.crv !== 'P-256' || key.alg !== 'ES256' || key.use !== 'sig' ||
        !Array.isArray(key.key_ops) || key.key_ops.length !== 1 || key.key_ops[0] !== 'verify' ||
        typeof key.kid !== 'string' || !key.kid || Array.from(key.kid).length > 128 ||
        typeof key.x !== 'string' || typeof key.y !== 'string' ||
        !integer(key.notBefore) || !integer(key.notAfter) ||
        /** @type {number} */(key.notBefore) >= /** @type {number} */(key.notAfter)) throw Error('bad-attestation');
    const point = parsePrincipalId(`${key.x}.${key.y}`);
    if (!point.ok || point.value === root || kids.has(key.kid) || points.has(point.value)) throw Error('bad-attestation');
    kids.add(key.kid); points.add(point.value);
    Object.freeze(key.key_ops); Object.freeze(key);
  }
}

export const MAX_WITNESS_POLICY_HISTORY = 1024;
export const MAX_WITNESS_STATE_BYTES = 2097152;
/** @import {Jwks, WitnessPolicyState, WitnessPolicyHistoryEntry} from './types.js' */
/** @param {{kid:string}} a @param {{kid:string}} b */
function keyOrder(a, b) {
  const x = utf8.encode(a.kid), y = utf8.encode(b.kid);
  for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i] - y[i];
  return x.length - y.length;
}
/** @param {Jwks['keys'][number]} key */
const identity = key => `${key.x}.${key.y}`;
/** All remaining public metadata is fixed by validateKeys. @param {Jwks['keys'][number]} key */
const fingerprint = key => JSON.stringify([key.kid, key.x, key.y, key.notBefore, key.notAfter]);
/** @param {Jwks['keys']} a @param {Jwks['keys']} b */
function sameRegistry(a, b) {
  const wanted = new Map(a.map(key => [key.kid, fingerprint(key)]));
  return a.length === b.length && b.every(key => wanted.get(key.kid) === fingerprint(key));
}
/** Calculate a candidate snapshot inside the adapter's serialized update.
 * Previous JSON MUST come from trusted, rollback-protected storage, never the
 * publisher or caller. Null is only for independently authorized first bootstrap.
 * Re-run against the latest state/clock after CAS conflicts or lock waits, then
 * atomically persist the WHOLE result before exposing its JWKS. This is pure:
 * it neither persists nor proves freshness of a previous snapshot.
 * @param {unknown} envelope
 * @param {unknown} previousJson
 * @param {string} root
 * @param {string} audience
 * @param {number} minimumRevision Independently provisioned positive bootstrap floor.
 * @param {number} now Trusted clock at serialized transition/commit.
 * @returns {import('./types.js').Result<WitnessPolicyState>}
 */
export function advanceWitnessPolicy(envelope, previousJson, root, audience, minimumRevision, now) {
  try {
    if (!integer(minimumRevision) || minimumRevision === 0) return fail('bad-attestation');
    const verified = verifyWitnessPolicyEnvelope(envelope, root, audience, now);
    if (!verified.ok || verified.value.revision < minimumRevision) return fail('bad-attestation');
    const policy = verified.value;
    /** @type {WitnessPolicyState|null} */
    let previous = null;
    if (previousJson !== null) {
      if (typeof previousJson !== 'string' || previousJson.length > MAX_WITNESS_STATE_BYTES ||
          utf8.encode(previousJson).length > MAX_WITNESS_STATE_BYTES) return fail('bad-attestation');
      const raw = uniqueJson(previousJson);
      const numbers = previousJson.replace(/"(?:\\.|[^"\\])*"/g, '').match(/-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g) ?? [];
      if (numbers.some(n => !/^(0|[1-9]\d*)$/.test(n))) return fail('bad-attestation');
      if (!exact(raw, ['type', 'root', 'audience', 'revision', 'jwks', 'history']) ||
          raw.type !== 'sociacl-witness-policy-state-v1' || raw.root !== root || raw.audience !== audience ||
          !integer(raw.revision) || raw.revision === 0 || !exact(raw.jwks, ['keys']) ||
          !Array.isArray(raw.jwks.keys) || !Array.isArray(raw.history) || raw.history.length > MAX_WITNESS_POLICY_HISTORY) return fail('bad-attestation');
      for (const entry of raw.history) if (!exact(entry, ['jwk', 'removed']) || typeof entry.removed !== 'boolean') return fail('bad-attestation');
      validateKeys(raw.jwks.keys, root);
      validateKeys(raw.history.map(entry => entry.jwk), root);
      previous = /** @type {WitnessPolicyState} */(raw);
      if (!sameRegistry(previous.jwks.keys, previous.history.filter(e => !e.removed).map(e => e.jwk))) return fail('bad-attestation');
      if (policy.revision < previous.revision ||
          (policy.revision === previous.revision && !sameRegistry(policy.jwks.keys, previous.jwks.keys))) return fail('bad-attestation');
    }
    const history = new Map((previous?.history ?? []).map(entry => [entry.jwk.kid, entry]));
    const material = new Map([...history.values()].map(entry => [identity(entry.jwk), entry.jwk.kid]));
    const present = new Set();
    for (const key of policy.jwks.keys) {
      present.add(key.kid);
      const old = history.get(key.kid);
      if (old ? old.removed || identity(old.jwk) !== identity(key) || key.notBefore < old.jwk.notBefore || key.notAfter > old.jwk.notAfter
        : material.has(identity(key))) return fail('bad-attestation');
      history.set(key.kid, Object.freeze({jwk: key, removed: false}));
    }
    if (history.size > MAX_WITNESS_POLICY_HISTORY) return fail('bad-attestation');
    for (const [kid, entry] of history) if (!present.has(kid)) history.set(kid, Object.freeze({...entry, removed: true}));
    const result = Object.freeze({ type: /** @type {const} */('sociacl-witness-policy-state-v1'), root, audience, revision: policy.revision,
      jwks: Object.freeze({keys: Object.freeze([...policy.jwks.keys].sort(keyOrder))}),
      history: Object.freeze([...history.values()].sort((a, b) => keyOrder(a.jwk, b.jwk)).map(entry => Object.freeze(entry))) });
    if (utf8.encode(JSON.stringify(result)).length > MAX_WITNESS_STATE_BYTES) return fail('bad-attestation');
    return ok(result);
  } catch { return fail('bad-attestation'); }
}
