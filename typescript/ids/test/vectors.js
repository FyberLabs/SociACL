import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import * as ids from '../src/index.js';
import { hex } from '../src/util.js';
const root = new URL('../../../vectors/ids/', import.meta.url);
const files = readdirSync(root).filter(f => f.endsWith('.json')).sort();
const parsers = { principal:ids.parsePrincipalId, wallet:ids.parseEip55, tenant:ids.parseTenantId,
  oidc:ids.parseOidcCredential, object:ids.parseObjectId, network:ids.parseNetworkId,
  'source-key':ids.parseSourceKey, soul:ids.parseSoul };
const keys = { principal:ids.formatPrincipalKey, wallet:ids.formatWalletKey, oidc:ids.formatOidcKey,
  object:ids.objectKey, network:ids.formatNetworkKey, 'source-key':ids.formatSourcePathKey };
const names = [];
function run(f, c) {
  if (f.family === 'signing-bytes') {
    const b = ids.signingBytes(c.input);
    return b.ok ? {ok:true,value:hex(b.value)} : b;
  }
  if (f.family === 'records') {
    const ctx = {...f.context,...c}; let r;
    const links = new Map(ctx.links);
    switch(c.operation) {
      case 'wallet-link': r=ids.verifyWalletLink(c.input,ctx.now,ctx.currentKey); break;
      case 'oidc-link': r=ids.verifyOidcLink(c.input,ctx.jwks,new Set(ctx.pinnedIss),ctx.now,ctx.currentKey); break;
      case 'rotate': r=ids.verifyRotate(c.input,ctx.currentKey,links,ctx.jwks,ctx.now); break;
      case 'revoke': r=ids.verifyRevoke(c.input,ctx.currentKey,ctx.now); break;
      case 'resolve': r=ids.resolveCurrentKey(ctx.genesis,c.input,{jwks:ctx.jwks,links,revocations:ctx.revocations,now:ctx.now}); break;
      case 'wallet-resolve': r=ids.resolveWalletLink(ctx.address,c.input,ctx.revocations??[],ctx.now); break;
      default: throw Error('unknown operation: '+c.operation);
    }
    return r.ok ? {ok:true,value:typeof r.value==='string'?r.value:r.value.principal} : r;
  }
  if(c.operation === 'claim') return ids.deriveClaimId(c.input);
  if(c.operation === 'external') return ids.deriveExternalId(c.input.source,c.input.providerItemId);
  if(c.operation === 'mint') return ids.mintObjectId(c.input.kind,()=>new Uint8Array(c.input.bytes));
  return (c.parser === 'wallet-input' ? ids.parseWalletInput : parsers[f.family])(c.input);
}
test('every shared vector and exact rejection reason', () => {
  assert.equal(files.length,10);
  for(const file of files) {
    const f = JSON.parse(readFileSync(new URL(file,root),'utf8'));
    assert.equal(f.v,1);
    for(const disposition of ['accept','reject']) for(const c of f[disposition]) {
      const name = `${f.family}/${disposition}/${c.name}`;
      assert.ok(!names.includes(name),'duplicate vector '+name);
      const actual=run(f,c);
      assert.deepEqual(actual,disposition==='accept'?{ok:true,value:c.canonical}:{ok:false,reason:c.reason},name);
      if(c.pathKey) assert.equal(keys[f.family](actual.value),c.pathKey,name+' pathKey');
      if(c.linkId) assert.deepEqual(ids.linkId(c.input),{ok:true,value:c.linkId},name+' linkId');
      names.push(name);
    }
  }
  if(process.env.IDS_VECTOR_REPORT) writeFileSync(process.env.IDS_VECTOR_REPORT,names.sort().join('\n')+'\n');
});
