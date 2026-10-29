import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { verifyWitnessCheckpoint } from '../src/index.js';
const f=JSON.parse(readFileSync(new URL('../../../vectors/interop/panopticon-checkpoint.json',import.meta.url)));
test('actual Panopticon checkpoint signature preserves full history and request binding',()=>{
  const {checkpoint,policy}=f.response;
  const verify=expected=>verifyWitnessCheckpoint(checkpoint,policy,expected);
  const result=verify(f.expected);assert.ok(result.ok);assert.deepEqual(result.value,f.canonical);
  assert.ok(result.value.state.history.some(entry=>entry.removed));
  for(const expected of [{...f.expected,client:'another-client'},{...f.expected,rootEpoch:2},
    {...f.expected,challenge:'A'.repeat(43)},{...f.expected,now:f.canonical.expiresAt}]) assert.equal(verify(expected).ok,false);
  const tampered=JSON.parse(checkpoint);tampered.payload=tampered.payload.slice(0,-1)+(tampered.payload.endsWith('A')?'B':'A');
  assert.equal(verifyWitnessCheckpoint(JSON.stringify(tampered),policy,f.expected).ok,false);
});
