import { p256 } from '@noble/curves/nist.js';
import { parsePrincipalId } from './ids.js';
import { uniqueJson } from './json.js';
import { ok, fail, integer, utf8, unb64 } from './util.js';
import { advanceWitnessPolicy, MAX_WITNESS_STATE_BYTES } from './witness-policy.js';

export const MAX_WITNESS_CHECKPOINT_BYTES = MAX_WITNESS_STATE_BYTES + 8192;
export const MAX_WITNESS_CHECKPOINT_ENVELOPE_BYTES = 3145728;
const domain = utf8.encode('sociacl-witness-checkpoint-v1\n');
/** @param {unknown} value @param {string[]} fields @returns {value is Record<string, unknown>} */
function exact(value, fields) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).length === fields.length && fields.every(k => Object.hasOwn(value, k));
}
/** @param {unknown} value */
function decode(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) throw Error('encoding');
  const binary = atob(value.replace(/-/g, '+').replace(/_/g, '/'));
  if (btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') !== value) throw Error('encoding');
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}
/** @param {unknown} value @returns {value is string} */
function label(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 1024 && utf8.encode(value).length <= 1024;
}
/** Authenticate a complete-history management checkpoint and matching live policy.
 * Expectations must be independently provisioned (challenge from a fresh request).
 * This pure verifier does NOT consume the challenge, reconcile local continuity,
 * install state, authorize recovery/root migration, or track a monotonic lease.
 * Every call rechecks both signatures and current transport expiry.
 * @param {unknown} envelope Exact checkpoint envelope JSON text.
 * @param {unknown} policyEnvelope Exact policy envelope JSON text.
 * @param {import('./types.js').WitnessCheckpointExpectations} expected
 * @returns {import('./types.js').Result<import('./types.js').WitnessCheckpoint>}
 */
export function verifyWitnessCheckpoint(envelope, policyEnvelope, expected) {
  try {
    const { managementRoot, root, rootEpoch, audience, client, challenge, minimumRevision, now } = expected;
    if (typeof envelope !== 'string' || envelope.length > MAX_WITNESS_CHECKPOINT_ENVELOPE_BYTES ||
        utf8.encode(envelope).length > MAX_WITNESS_CHECKPOINT_ENVELOPE_BYTES ||
        !parsePrincipalId(managementRoot).ok || !parsePrincipalId(root).ok || managementRoot === root ||
        !integer(rootEpoch) || rootEpoch === 0 || !integer(now) ||
        !integer(minimumRevision) || minimumRevision === 0 || !label(audience) || !label(client) ||
        typeof challenge !== 'string' || challenge.length !== 43 || decode(challenge).length !== 32) return fail('bad-attestation');
    const outer = uniqueJson(envelope);
    if (!exact(outer, ['type', 'payload', 'signature']) || outer.type !== 'sociacl-witness-checkpoint-envelope-v1') return fail('bad-attestation');
    const payload = decode(outer.payload), signature = decode(outer.signature);
    if (payload.length > MAX_WITNESS_CHECKPOINT_BYTES || signature.length !== 64) return fail('bad-attestation');
    const message = new Uint8Array(domain.length + payload.length);
    message.set(domain); message.set(payload, domain.length);
    const publicKey = new Uint8Array([4, ...unb64(managementRoot.slice(0, 43)), ...unb64(managementRoot.slice(44))]);
    if (!p256.verify(signature, message, publicKey, { prehash: true, lowS: true, format: 'compact' })) return fail('bad-attestation');
    const source = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(payload);
    const doc = uniqueJson(source);
    const numbers = source.replace(/"(?:\\.|[^"\\])*"/g, '').match(/-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g) ?? [];
    if (numbers.some(n => !/^(0|[1-9]\d*)$/.test(n)) ||
        !exact(doc, ['type', 'audience', 'client', 'challenge', 'rootEpoch', 'issuedAt', 'expiresAt', 'state']) ||
        doc.type !== 'sociacl-witness-checkpoint-v1' || doc.audience !== audience || doc.client !== client ||
        doc.challenge !== challenge || doc.rootEpoch !== rootEpoch || !integer(doc.rootEpoch) ||
        !integer(doc.issuedAt) || !integer(doc.expiresAt)) return fail('bad-attestation');
    const start = /** @type {number} */(doc.issuedAt), end = /** @type {number} */(doc.expiresAt);
    if (end <= start || end - start > 300 || now < start || now >= end ||
        !exact(doc.state, ['type', 'root', 'audience', 'revision', 'jwks', 'history'])) return fail('bad-attestation');
    // Reuse the shared state parser and same-revision registry checks. Refuse a
    // newer policy here: the checkpoint must name the exact installed snapshot.
    const state = advanceWitnessPolicy(policyEnvelope, JSON.stringify(doc.state), root, audience, minimumRevision, now);
    if (!state.ok || state.value.revision !== doc.state.revision ||
        state.value.history.some(e => `${e.jwk.x}.${e.jwk.y}` === managementRoot)) return fail('bad-attestation');
    return ok(Object.freeze({ type: /** @type {const} */('sociacl-witness-checkpoint-v1'), audience, client, challenge,
      rootEpoch, issuedAt: start, expiresAt: end, state: state.value }));
  } catch { return fail('bad-attestation'); }
}

/** Authenticate and reconcile a checkpoint against the latest trusted local state.
 * No bootstrap/reset: previousJson must name existing validated continuity.
 * Additional authenticated history is allowed, but no local restriction may be lost.
 * Run inside the adapter's serialized transaction; this function performs no I/O.
 * @param {unknown} envelope
 * @param {unknown} policyEnvelope
 * @param {unknown} previousJson
 * @param {import('./types.js').WitnessCheckpointExpectations} expected
 * @returns {import('./types.js').Result<import('./types.js').WitnessCheckpoint>}
 */
export function advanceWitnessCheckpoint(envelope, policyEnvelope, previousJson, expected) {
  try {
    if (typeof previousJson !== 'string') return fail('bad-attestation');
    const checkpoint = verifyWitnessCheckpoint(envelope, policyEnvelope, expected);
    if (!checkpoint.ok) return checkpoint;
    const required = advanceWitnessPolicy(policyEnvelope, previousJson, expected.root,
      expected.audience, expected.minimumRevision, expected.now);
    if (!required.ok) return fail('bad-attestation');
    const offered = new Map(checkpoint.value.state.history.map(entry => [entry.jwk.kid, entry]));
    for (const old of required.value.history) {
      const next = offered.get(old.jwk.kid);
      if (!next || (old.removed && !next.removed) || next.jwk.x !== old.jwk.x || next.jwk.y !== old.jwk.y ||
          next.jwk.notBefore < old.jwk.notBefore || next.jwk.notAfter > old.jwk.notAfter) return fail('bad-attestation');
    }
    return checkpoint;
  } catch { return fail('bad-attestation'); }
}
