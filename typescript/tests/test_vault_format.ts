import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { vaultVersionSigningBytes,vaultAuditSigningBytes } from '../contract/vault-format.ts';
import { decodeLengthPrefixed } from '../contract/account-key-seal.ts';
const fixture=JSON.parse(readFileSync(new URL('../../vectors/vault/v1.json',import.meta.url),'utf8'));
test('vault version and audit transcripts match shared field vectors',()=>{
  assert.deepEqual(decodeLengthPrefixed(vaultVersionSigningBytes(fixture.version)),fixture.versionFields);
  assert.deepEqual(decodeLengthPrefixed(vaultAuditSigningBytes(fixture.audit)),fixture.auditFields);
  for(const patch of [{sensitive:false},{epoch:4},{ciphertextDigest:'ab'.repeat(32)},{parents:[]}]) {
    assert.notDeepEqual(vaultVersionSigningBytes({...fixture.version,...patch}),vaultVersionSigningBytes(fixture.version));
  }
});
test('vault versions reject ambiguous parents, identities, decimals and ids',()=>{
  const v=fixture.version;
  for(const patch of [{parents:[v.versionId]},{parents:[v.parents[0],v.parents[0]]},{parents:[...v.parents].reverse()},
    {parents:Array.from({length:17},(_,i)=>i.toString(16).padStart(64,'0'))},{owner:'https://login.example/user'},
    {epoch:-0},{issuedAt:Number.MAX_SAFE_INTEGER+1},{itemId:'AB'.repeat(32)},{versionId:v.versionId+'\n'},{sensitive:1}]) {
    assert.throws(()=>vaultVersionSigningBytes({...v,...patch}));
  }
  for(const patch of [{operation:'execute-unchecked'},{outcome:'yes'},{previousDigest:fixture.audit.previousDigest+'\n'},{issuedAt:-0}]) {
    assert.throws(()=>vaultAuditSigningBytes({...fixture.audit,...patch}));
  }
});
