import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { verifyWitnessPolicyEnvelope } from '../src/index.js';
const f = JSON.parse(readFileSync(new URL('../../../vectors/ids/witness-policy.json', import.meta.url), 'utf8'));
const { root, audience, now } = f.context;
test('policy authentication refuses coercion and invalid caller clocks', () => {
  for (const input of [null, {}, [], 1, {toString() {throw Error('must not run');}}])
    assert.deepEqual(verifyWitnessPolicyEnvelope(input, root, audience, now), {ok:false,reason:'bad-attestation'});
  for (const clock of [NaN, Infinity, -1, -0, 1.5, '1700000000'])
    assert.deepEqual(verifyWitnessPolicyEnvelope(f.accept[0].input, root, audience, clock), {ok:false,reason:'bad-attestation'});
});
test('authenticated document and public registry are immutable copies', () => {
  const result = verifyWitnessPolicyEnvelope(f.accept[0].input, root, audience, now);
  assert.ok(result.ok);
  assert.throws(() => {result.value.revision = 0;}, TypeError);
  assert.throws(() => {result.value.jwks.keys[0].notAfter = 0;}, TypeError);
  assert.throws(() => {result.value.jwks.keys.push({});}, TypeError);
  assert.throws(() => {result.value.jwks.keys[0].key_ops.push('sign');}, TypeError);
});

import { advanceWitnessPolicy } from '../src/index.js';
const lifecycle = JSON.parse(readFileSync(new URL('../../../vectors/ids/witness-lifecycle.json', import.meta.url), 'utf8'));
const initialEnvelope = lifecycle.accept.find(c => c.name === 'bootstrap-at-floor').input.steps[0].envelope;
test('policy transition requires an explicit positive bootstrap floor and explicit null for first use', () => {
  for (const floor of [undefined, null, '7', NaN, Infinity, -1, -0, 1.5])
    assert.deepEqual(advanceWitnessPolicy(initialEnvelope, null, root, audience, floor, now), {ok:false,reason:'bad-attestation'});
  for (const previous of [undefined, {}, [], {toString() {throw Error('must not run');}}])
    assert.deepEqual(advanceWitnessPolicy(initialEnvelope, previous, root, audience, 7, now), {ok:false,reason:'bad-attestation'});
});
test('policy transition freezes retained removed-key history as well as current keys', () => {
  const fixture = lifecycle.accept.find(c => c.name === 'retained-tombstone-after-restart');
  const saved = fixture.input.previous;
  const result = advanceWitnessPolicy(fixture.input.steps[0].envelope, saved, root, audience, 7, now);
  assert.ok(result.ok);
  const tomb = result.value.history.find(e => e.removed);
  assert.throws(() => {tomb.removed = false;}, TypeError);
  assert.throws(() => {tomb.jwk.notAfter += 1;}, TypeError);
  assert.throws(() => {result.value.history.pop();}, TypeError);
  assert.equal(fixture.input.previous, saved);
});
