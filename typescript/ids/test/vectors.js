import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import * as ids from '../src/index.js';
import { hex, unb64, unhex } from '../src/util.js';
const root = new URL('../../../vectors/ids/', import.meta.url);
const files = readdirSync(root).filter(f => f.endsWith('.json')).sort();
const parsers = { principal:ids.parsePrincipalId, wallet:ids.parseEip55, tenant:ids.parseTenantId,
  oidc:ids.parseOidcCredential, object:ids.parseObjectId, network:ids.parseNetworkId,
  'source-key':ids.parseSourceKey, soul:ids.parseSoul };
const keys = { principal:ids.formatPrincipalKey, wallet:ids.formatWalletKey, oidc:ids.formatOidcKey,
  object:ids.objectKey, network:ids.formatNetworkKey, 'source-key':ids.formatSourcePathKey };
const names = [];
function run(f, c) {
  if (f.family === 'witness-checkpoint') return c.operation === 'advance'
    ? ids.advanceWitnessCheckpoint(c.input.checkpoint, c.input.policy, c.input.previous, {...f.context, ...c})
    : ids.verifyWitnessCheckpoint(c.input.checkpoint, c.input.policy, {...f.context, ...c});
  if (f.family === 'witness-lifecycle') {
    const ctx = {...f.context, ...c};
    let previous = c.input.previous;
    let result;
    for (const step of c.input.steps) {
      result = ids.advanceWitnessPolicy(step.envelope, previous, ctx.root, ctx.audience, ctx.minimumRevision, step.now ?? ctx.now);
      if (!result.ok) return result;
      previous = JSON.stringify(result.value);
    }
    return result;
  }
  if (f.family === 'witness-policy') {
    const ctx = {...f.context, ...c};
    return ids.verifyWitnessPolicyEnvelope(c.input, ctx.root, ctx.audience, ctx.now);
  }
  if (f.family === 'edges') {
    const parsers={ 'principal-key':ids.parsePrincipalKey, 'path-key':ids.parsePathKey, json:ids.parseJsonInput, sec1:x=>ids.principalFromSec1(Uint8Array.from(Buffer.from(x,'hex'))) };
    return parsers[c.operation](c.input);
  }
  if (f.family === 'signing-bytes') {
    if (c.operation === 'length-prefixed') {
      const encoded = ids.lengthPrefixed(c.input);
      return encoded.ok ? {ok:true,value:hex(encoded.value)} : encoded;
    }
    const b = ids.signingBytes(c.input);
    return b.ok ? {ok:true,value:hex(b.value)} : b;
  }
  if (f.family === 'signed-at') {
    const ctx = {...f.context,...c};
    const links = new Map(ctx.links ?? []);
    const history = (p,at,until) => new Map(ctx.historyErrors??[]).has(p) ? {ok:false,reason:new Map(ctx.historyErrors).get(p)} : (ctx.authenticatedAccounts??[]).includes(p) ? {ok:true,value:ids.historyState(p,new Map(ctx.histories??[]).get(p)??[],at,until)} : {ok:false,reason:'missing-history'};
    const policy = ctx.policy ? {...ctx.policy} : ctx.policy;
    if (policy && policy.clockSkewSeconds === 'NaN') policy.clockSkewSeconds = NaN;
    else if (policy && policy.clockSkewSeconds === 'Infinity') policy.clockSkewSeconds = Infinity;
    const rc={jwks:ctx.jwks,links,revocations:ctx.revocations??[],now:ctx.now,policy,pinnedIss:new Set(ctx.pinnedIss??[]),history,genesisEpubBindings:ctx.genesisEpubBindings??[]};
    const rotations = c.rotations ?? ctx.rotations ?? [];
    let r;
    switch (c.operation) {
      case 'verify-signed-at': r = ids.verifySignedAt(c.input.principal, rotations, rc, unhex(c.input.bytes), c.input.sig, c.input.issuedAt); break;
      case 'verify-acl-attest': r = ids.verifyAclAttestation(c.input.jws, ctx.jwks, c.input.issuedAt, unhex(c.input.bytes)); break;
      case 'verify-key-signature': r = ids.verifyKeySignature(c.input.key, c.input.sig, unhex(c.input.bytes)); break;
      case 'sign-with-keyring': {
        const scalar = unb64(c.input.seaPriv);
        try { r = ids.signWithKeyring(scalar, unhex(c.input.bytes), c.input.expectedKey); }
        finally { scalar.fill(0); }
        break;
      }
      default: throw Error('unknown operation: '+c.operation);
    }
    if (c.diagnosticReasons) assert.deepEqual((r.diagnostics??[]).map(d=>d.reason), c.diagnosticReasons, c.name+' diagnostics');
    return r.ok ? {ok:true,value:r.value} : {ok:false,reason:r.reason};
  }
  if (f.family === 'records') {
    const ctx = {...f.context,...c}; let r;
    const links = new Map(ctx.links);
    const history = ctx.missingHistory ? undefined : (p,at,until) => new Map(ctx.historyErrors??[]).has(p) ? {ok:false,reason:new Map(ctx.historyErrors).get(p)} : ctx.authenticatedAccounts.includes(p) ? {ok:true,value:ids.historyState(p,new Map(ctx.histories??[]).get(p)??[],at,until)} : {ok:false,reason:'missing-history'};
    const rc={...ctx,links,history,pinnedIss:new Set(ctx.pinnedIss)};
    const keyState=ctx.directState??{key:ctx.currentKey,currentKey:ctx.currentKey,retainedLinks:null};
    switch(c.operation) {
      case 'prepare-retained-links-now': return ids.prepareRetainedLinksNow(c.input, rc);
      case 'oidc-resolve-now': r=ids.resolveOidcLinkNow(ctx.cred, c.input, ctx.revocations??[], rc); break;
      case 'verifying-link-map': {
        const built=ids.verifyingLinkMap(c.input, rc);
        return built.ok ? {ok:true, value:[...built.value.keys()].sort()} : built;
      }
      case 'wallet-link': r=ids.verifyWalletLink(c.input,ctx.jwks,ctx.policy,ctx.now,keyState); break;
      case 'oidc-link': r=ids.verifyOidcLink(c.input,ctx.jwks,new Set(ctx.pinnedIss),ctx.now,keyState); break;
      case 'publish-check': r=ids.checkRotationPublish(c.input.candidate,c.input.siblings,ctx.genesis,c.input.prior,rc); break;
      case 'draft-check': r=ids.checkRotationDraft(c.input.candidate,c.input.siblings,ctx.genesis,c.input.prior,rc); break;
      case 'rotation-request': r=ids.verifyRotationRequest(c.input,ctx.currentKey,rc); break;
      case 'genesis-epub-request': r=ids.verifyGenesisEpubRequest(c.input,ctx.genesis,ctx.now,ctx.policy); break;
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
    if (r.ok && (c.operation === 'publish-check' || c.operation === 'draft-check') && Object.hasOwn(c, 'retainedLinks')) assert.deepEqual(r.value.retainedLinks, c.retainedLinks, c.name+' retainedLinks');
    if (r.ok && c.operation === 'resolve') assert.equal(r.value.currentEpub ?? null, c.currentEpub ?? null, c.name+' currentEpub');
    if (r.ok && c.operation === 'rotate' && Object.hasOwn(c, 'nextEpub')) assert.equal(r.value.nextEpub, c.nextEpub, c.name+' nextEpub');
    return r.ok ? {ok:true,value:r.value.currentKey??r.value.principal} : {ok:false,reason:r.reason};
  }
  if (c.operation === 'build-membership' || c.operation === 'build-objset') {
    const owner = ids.parsePrincipalId(c.input[0]);
    if (!owner.ok) return owner;
    if (c.operation === 'build-objset') {
      if (c.input[2] !== 'same-group' && c.input[2] !== 'named-circle') return {ok:false, reason:'bad-template'};
      const object = ids.parseObjectId(c.input[1]);
      const set = ids.parseObjectId(c.input[3]);
      if (!object.ok) return object;
      if (!set.ok) return set;
      return {ok:true, value: ids.objectSetSoul(owner.value, object.value, c.input[2], set.value)};
    }
    if (c.input[1] !== 'same-group' && c.input[1] !== 'named-circle') return {ok:false, reason:'bad-template'};
    const set = ids.parseObjectId(c.input[2]);
    const member = ids.parsePrincipalId(c.input[3]);
    if (!set.ok) return set;
    if (!member.ok) return member;
    return {ok:true, value: ids.membershipSoul(owner.value, c.input[1], set.value, member.value)};
  }
  if(c.operation === 'claim') return ids.deriveClaimId(c.input);
  if(c.operation === 'external') return ids.deriveExternalId(c.input.source,c.input.providerItemId);
  if(c.operation === 'mint') return ids.mintObjectId(c.input.kind,c.input.creator,()=>new Uint8Array(c.input.bytes));
  if(c.operation === 'object-principal') return ids.objectPrincipal(c.input);
  return (c.parser === 'wallet-input' ? ids.parseWalletInput : parsers[f.family])(c.input);
}
test('verifySignedAt does not take a kind or an attestation', () => {
  assert.equal(ids.verifySignedAt.length, 6);
});
test('lengthPrefixed reads each field once', () => {
  const good = ids.lengthPrefixed(['ok']);
  assert.equal(good.ok, true);
  const stateful = (second) => {
    let n = 0;
    const fields = new Array(1);
    Object.defineProperty(fields, '0', { enumerable: true, get() { return n++ === 0 ? 'ok' : second; } });
    return fields;
  };
  assert.deepEqual(ids.lengthPrefixed(stateful('\uD800')), good);
  assert.deepEqual(ids.lengthPrefixed(stateful({ toString() { return 'evil'; } })), good);
  const surrogateFirst = new Array(1);
  let reads = 0;
  Object.defineProperty(surrogateFirst, '0', { enumerable: true, get() { return reads++ === 0 ? '\uD800' : 'ok'; } });
  assert.deepEqual(ids.lengthPrefixed(surrogateFirst), { ok: false, reason: 'unpaired-surrogate' });
  const throwing = new Array(1);
  Object.defineProperty(throwing, '0', { enumerable: true, get() { throw new Error('getter'); } });
  assert.deepEqual(ids.lengthPrefixed(throwing), { ok: false, reason: 'bad-record' });
  const iterating = ['ok'];
  iterating[Symbol.iterator] = () => { throw new Error('iterator'); };
  assert.deepEqual(ids.lengthPrefixed(iterating), good);
  const throwingLength = new Proxy(['ok'], {
    get(target, prop, receiver) {
      if (prop === 'length') throw new Error('length');
      return Reflect.get(target, prop, receiver);
    },
  });
  assert.deepEqual(ids.lengthPrefixed(throwingLength), { ok: false, reason: 'bad-record' });
  const sparse = [];
  sparse.length = 1e8;
  const started = Date.now();
  assert.deepEqual(ids.lengthPrefixed(sparse), { ok: false, reason: 'not-string' });
  assert.ok(Date.now() - started < 1000, 'sparse length must fail on the first hole');
  let proxyReads = 0;
  const proxy = new Proxy(['ok'], {
    get(target, prop, receiver) {
      if (prop === '0') return proxyReads++ === 0 ? 'ok' : '\uD800';
      return Reflect.get(target, prop, receiver);
    },
  });
  assert.deepEqual(ids.lengthPrefixed(proxy), good);
  const throwingProxy = new Proxy(['ok'], {
    get(target, prop, receiver) {
      if (prop === '0') throw new Error('proxy');
      return Reflect.get(target, prop, receiver);
    },
  });
  assert.deepEqual(ids.lengthPrefixed(throwingProxy), { ok: false, reason: 'bad-record' });
});
test('every shared vector and exact rejection reason', () => {
  assert.equal(files.length,15);
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
