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
