import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { p256 } from '@noble/curves/nist.js';
import { verifyWitnessCheckpoint, MAX_WITNESS_CHECKPOINT_BYTES, MAX_WITNESS_CHECKPOINT_ENVELOPE_BYTES } from '../src/index.js';
const f = JSON.parse(readFileSync(new URL('../../../vectors/ids/witness-checkpoint.json', import.meta.url)));
const { checkpoint, policy } = f.accept[0].input;
const verify = (cp = checkpoint, context = f.context) => verifyWitnessCheckpoint(cp, policy, context);

test('checkpoint expectations reject missing, coercible and noninteger inputs', () => {
  for (const value of [null, undefined, {}, [], 1]) assert.equal(verifyWitnessCheckpoint(checkpoint, policy, value).ok, false);
  for (const field of ['now','rootEpoch','minimumRevision']) {
    for (const value of [undefined, NaN, Infinity, -1, -0, 1.5, '1'])
      assert.equal(verify(checkpoint, {...f.context, [field]:value}).ok, false, field);
  }
  for (const value of [null, {}, [], 1, {toString() {throw Error('do not coerce');}}])
    assert.equal(verify(value).ok, false);
});

test('checkpoint output deeply freezes authenticated history', () => {
  const result = verify();
  assert.ok(result.ok);
  assert.throws(() => {result.value.rootEpoch++;}, TypeError);
  assert.throws(() => {result.value.state.history[0].removed = false;}, TypeError);
  assert.throws(() => {result.value.state.history[0].jwk.notAfter++;}, TypeError);
  assert.throws(() => {result.value.state.history[0].jwk.key_ops.push('sign');}, TypeError);
});

test('pure verification does not consume a challenge or extend the signed expiry', () => {
  assert.deepEqual(verify(), verify()); // adapter MUST own one-use request state
  const result = verify();
  assert.ok(result.ok);
  assert.equal(verify(checkpoint, {...f.context, now:result.value.expiresAt}).ok, false);
});

test('checkpoint payload byte bound is inclusive, measured before parsing whitespace', () => {
  const base = JSON.parse(checkpoint);
  const raw = Buffer.from(base.payload, 'base64url');
  const signer = Buffer.from('12'.padStart(64, '0'), 'hex'); // public fixture scalar 18
  const padded = size => {
    const bytes = Buffer.concat([raw, Buffer.alloc(size - raw.length, 32)]);
    const signature = p256.sign(Buffer.concat([Buffer.from('sociacl-witness-checkpoint-v1\n'), bytes]), signer, {lowS:true});
    return JSON.stringify({...base, payload:bytes.toString('base64url'), signature:Buffer.from(signature).toString('base64url')});
  };
  assert.ok(verify(padded(MAX_WITNESS_CHECKPOINT_BYTES)).ok);
  assert.equal(verify(padded(MAX_WITNESS_CHECKPOINT_BYTES + 1)).ok, false);
});

test('checkpoint envelope byte bound includes transport whitespace', () => {
  const padded = checkpoint + ' '.repeat(MAX_WITNESS_CHECKPOINT_ENVELOPE_BYTES - Buffer.byteLength(checkpoint));
  assert.ok(verify(padded).ok);
  assert.equal(verify(padded + ' ').ok, false);
});
