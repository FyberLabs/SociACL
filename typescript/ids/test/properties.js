import { test } from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { p256 } from '@noble/curves/nist.js';
import * as ids from '../src/index.js';
import { hex,b64 } from '../src/util.js';
import { pct } from '../src/ids.js';
import * as schemas from '../src/zod.js';
const val = r => {assert.equal(r.ok,true,JSON.stringify(r));return r.value;};
const count = 10_000;
const bytes = n => fc.uint8Array({minLength:n,maxLength:n});
test('10k roundtrips, idempotence, injectivity and segment safety across all families',()=>{
  fc.assert(fc.property(bytes(32),bytes(20),bytes(16),fc.integer({min:1,max:1000000}),(seed,wallet,object,n)=>{
    // Scalar reduced into 1..2^255, safely below the curve order.
    seed[0]&=0x7f; seed[31]|=1;
    const point=p256.getPublicKey(seed,false);
    const p=val(ids.parsePrincipalId(b64(point.slice(1,33))+'.'+b64(point.slice(33))));
    const w=val(ids.parseWalletInput('0x'+hex(wallet)));
    const t=val(ids.parseTenantId(hex(object.slice(0,4))+'-'+hex(object.slice(4,6))+'-'+hex(object.slice(6,8))+'-'+hex(object.slice(8,10))+'-'+hex(object.slice(10))));
    const o=val(ids.mintObjectId('room',p,()=>object));
    const set=val(ids.mintObjectId('set',p,()=>object));
    assert.equal(val(ids.objectPrincipal(o)),p);
    const n1=val(ids.parseNetworkId(`s3rch:https://node${n}.s3r.ch:443;key=${hex(seed)}`));
    const s=val(ids.parseSourceKey(`sr1:${pct(n1)}/${pct(p)}/${o}/chat`));
    const c=val(ids.parseOidcCredential({iss:'https://id.s3r.ch',tenant:t,sub:'subject'+n}));
    for(const [parser,v] of [[ids.parsePrincipalId,p],[ids.parseEip55,w],[ids.parseTenantId,t],[ids.parseObjectId,o],[ids.parseNetworkId,n1],[ids.parseSourceKey,s],[ids.parseOidcCredential,c]]) assert.deepEqual(val(parser(v)),v);
    const all=[ids.formatPrincipalKey(p),ids.formatWalletKey(w),ids.formatOidcKey(c),ids.formatNetworkKey(n1),ids.formatSourcePathKey(s),ids.objectKey(o)];
    assert.equal(new Set(all).size,all.length);
    const secondSeed=seed.slice();secondSeed[31]^=2;
    const point2=p256.getPublicKey(secondSeed,false);
    const p2=val(ids.parsePrincipalId(b64(point2.slice(1,33))+'.'+b64(point2.slice(33))));
    const wallet2=wallet.slice();wallet2[0]^=1;
    const w2=val(ids.parseWalletInput('0x'+hex(wallet2)));
    const n2=val(ids.parseNetworkId(n1.replace('https://node','https://other')));
    const s2=val(ids.parseSourceKey(s.replace('/chat','/forum')));
    const c2=val(ids.parseOidcCredential({...c,sub:c.sub+'x'}));
    const flipped=object.slice(); flipped[0]^=0xff;
    const o2=val(ids.mintObjectId('chat',p,()=>flipped));
    const others=[ids.formatPrincipalKey(p2),ids.formatWalletKey(w2),ids.formatOidcKey(c2),ids.formatNetworkKey(n2),ids.formatSourcePathKey(s2),ids.objectKey(o2)];
    all.forEach((key,i)=>assert.notEqual(key,others[i]));
    const claim=val(ids.deriveClaimId('ens:'+hex(seed)));
    const ext=val(ids.deriveExternalId(s,'provider/'+n));
    assert.equal(val(ids.parseObjectId(claim)),claim);assert.equal(val(ids.parseObjectId(ext)),ext);
    assert.notEqual(claim,val(ids.deriveClaimId('ens:'+hex(secondSeed))));
    assert.notEqual(ext,val(ids.deriveExternalId(s2,'provider/'+n)));

    all.forEach(k=>assert.match(k,/^[A-Za-z0-9_:-]{1,180}$/));
    const changed=o2;
    assert.notEqual(ids.objectKey(o),ids.objectKey(changed));
    assert.notEqual(ids.formatOidcKey(c),ids.formatOidcKey({...c,sub:c.sub+'x'}));
    for(const [s,count] of [[ids.objectSoul('items',o),3],[ids.aclSoul(p),3],[ids.grantSoul(p,o,p),5],[ids.postSoul(p,o,p),6],[ids.membershipSoul(p,'same-group',set,p),7],[ids.objectSetSoul(p,o,'same-group',set),7]]) {
      assert.equal(s.split('/').length,count); s.split('/').forEach(k=>assert.match(k,/^[A-Za-z0-9_:-]+$/)); val(ids.parseSoul(s));
    }
    const user=val(ids.parseSoul(ids.userSoul(p))); assert.deepEqual(user,{template:'user',ids:[p]});
    assert.notEqual(ids.grantSoul(p,o,p),ids.grantSoul(p,changed,p));
  }),{numRuns:count});
});
test('100k arbitrary values cannot throw in any edge parser or record verifier',()=>{
  const parsers=[ids.parsePrincipalId,ids.parseEip55,ids.parseWalletInput,ids.parseTenantId,ids.parseOidcCredential,ids.parseObjectId,ids.parseNetworkId,ids.parseSourceKey,ids.parseSoul,
    x=>ids.verifyWalletLink(x,1700000000),x=>ids.verifyOidcLink(x,{keys:[]},new Set(),1700000000)];
  const arbitrary=fc.oneof(fc.jsonValue(),fc.array(fc.integer({min:0,max:65535}),{maxLength:100}).map(a=>String.fromCharCode(...a)));
  fc.assert(fc.property(arbitrary,x=>{for(const parse of parsers){const r=parse(x);assert.equal(typeof r.ok,'boolean');}}),{numRuns:100_000});
});
test('one million CSPRNG mints parse and have no duplicates',()=>{
  const seen=new Set();
  const creator=val(ids.parsePrincipalId('axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY.T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU'));
  for(let i=0;i<1_000_000;i++){const id=val(ids.mintObjectId('room',creator));assert.equal(val(ids.parseObjectId(id)),id);assert.equal(val(ids.objectPrincipal(id)),creator);seen.add(id);}
  assert.equal(seen.size,1_000_000);
});
test('hostile objects never invoke getters or coercion; RNG failure is closed',()=>{
  let reads=0; const hostile={get principal(){reads++;throw Error('getter');},toString(){reads++;throw Error('coercion');}};
  assert.deepEqual(ids.parsePrincipalId(hostile),{ok:false,reason:'not-string'});
  assert.deepEqual(ids.verifyWalletLink(hostile,1),{ok:false,reason:'bad-record'});
  assert.deepEqual(ids.parseOidcCredential(new Proxy({},{ownKeys(){throw Error('proxy');}})),{ok:false,reason:'bad-record'});
  assert.equal(reads,0);
  const creator=val(ids.parsePrincipalId('axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY.T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU'));
  for(const rng of [()=>new Uint8Array(15),()=>{throw Error('rng');}]) assert.deepEqual(ids.mintObjectId('room',creator,rng),{ok:false,reason:'rng-failure'});
});
test('zod adapters preserve parser reasons and return branded values',()=>{
  const r=schemas.objectId.safeParse('room.alpha');assert.equal(r.success,false);assert.equal(r.error.issues[0].message,'bad-alphabet');
  const creator=val(ids.parsePrincipalId('axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY.T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU'));
  const id=val(ids.mintObjectId('room',creator));assert.equal(schemas.objectId.parse(id),id);
});
