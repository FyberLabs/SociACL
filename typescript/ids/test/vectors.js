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
  if (f.family === 'edges') {
    const parsers={ 'principal-key':ids.parsePrincipalKey, 'path-key':ids.parsePathKey, json:ids.parseJsonInput, sec1:x=>ids.principalFromSec1(Uint8Array.from(Buffer.from(x,'hex'))) };
    return parsers[c.operation](c.input);
  }
  if (f.family === 'signing-bytes') {
    const b = ids.signingBytes(c.input);
    return b.ok ? {ok:true,value:hex(b.value)} : b;
  }
  if (f.family === 'records') {
    const ctx = {...f.context,...c}; let r;
    const links = new Map(ctx.links);
    const history = ctx.missingHistory ? undefined : (p,at,until) => new Map(ctx.historyErrors??[]).has(p) ? {ok:false,reason:new Map(ctx.historyErrors).get(p)} : ctx.authenticatedAccounts.includes(p) ? {ok:true,value:ids.historyState(p,new Map(ctx.histories??[]).get(p)??[],at,until)} : {ok:false,reason:'missing-history'};
    const rc={...ctx,links,history,pinnedIss:new Set(ctx.pinnedIss)};
    const keyState=ctx.directState??{key:ctx.currentKey,currentKey:ctx.currentKey,retainedLinks:null};
    switch(c.operation) {
      case 'wallet-link': r=ids.verifyWalletLink(c.input,ctx.jwks,ctx.policy,ctx.now,keyState); break;
      case 'oidc-link': r=ids.verifyOidcLink(c.input,ctx.jwks,new Set(ctx.pinnedIss),ctx.now,keyState); break;
      case 'rotate': r=ids.verifyRotate(c.input,ctx.currentKey,rc); break;
      case 'revoke-now': r=ids.verifyRevokeNow(c.input,ctx.currentKey,ctx.now); break;
      case 'revoke': r=ids.verifyRevoke(c.input,ctx.currentKey,ctx.jwks,ctx.now); break;
      case 'resolve': r=ids.resolveCurrentKey(ctx.genesis,c.input,rc); break;
      case 'resolve-and-wallet-now':
      case 'resolve-and-wallet': {
        const account=ids.resolveCurrentKey(ctx.genesis,c.input,rc);
        if (!account.ok) {r=account;break;}
        const resolved={...rc,history:(p,at,until)=>p===ctx.genesis?{ok:true,value:ids.historyState(p,account.value.rotations,at,until)}:history(p,at,until)};
        r=(c.operation==='resolve-and-wallet-now'?ids.resolveWalletLinkNow:ids.resolveWalletLink)(ctx.address,[...links.values()],ctx.revocations??[],resolved);break;
      }
      case 'wallet-resolve-now': r=ids.resolveWalletLinkNow(ctx.address,c.input,ctx.revocations??[],rc); break;
      case 'wallet-resolve': r=ids.resolveWalletLink(ctx.address,c.input,ctx.revocations??[],rc); break;
      default: throw Error('unknown operation: '+c.operation);
    }
    if(c.diagnosticReasons) assert.deepEqual(r.diagnostics.map(d=>d.reason),c.diagnosticReasons,c.name+' diagnostics');
    return r.ok ? {ok:true,value:r.value.currentKey??r.value.principal} : {ok:false,reason:r.reason};
  }
  if(c.operation === 'claim') return ids.deriveClaimId(c.input);
  if(c.operation === 'external') return ids.deriveExternalId(c.input.source,c.input.providerItemId);
  if(c.operation === 'mint') return ids.mintObjectId(c.input.kind,()=>new Uint8Array(c.input.bytes));
  return (c.parser === 'wallet-input' ? ids.parseWalletInput : parsers[f.family])(c.input);
}
test('every shared vector and exact rejection reason', () => {
  assert.equal(files.length,11);
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
