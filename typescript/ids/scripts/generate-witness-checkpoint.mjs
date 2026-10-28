// Public deterministic test scalars only. Never provision these keys or challenges.
import { writeFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import { p256 } from '@noble/curves/nist.js';
import { verifyWitnessCheckpoint } from '../src/index.js';
const secret = n => Buffer.from(BigInt(n).toString(16).padStart(64, '0'), 'hex');
const b64 = b => Buffer.from(b).toString('base64url');
const principal = n => {const p=p256.getPublicKey(secret(n),false);return b64(p.slice(1,33))+'.'+b64(p.slice(33));};
const key = (n,kid='key-'+n) => {const p=principal(n).split('.');return {kid,kty:'EC',crv:'P-256',alg:'ES256',use:'sig',key_ops:['verify'],x:p[0],y:p[1],notBefore:1699999000,notAfter:1700001000};};
const context={managementRoot:principal(18),root:principal(17),rootEpoch:1,audience:'panopticon-test',client:'enrollment-1',challenge:b64(Buffer.alloc(32,42)),minimumRevision:8,now:1700000000};
const a=key(19), b=key(20);
const state={type:'sociacl-witness-policy-state-v1',root:context.root,audience:context.audience,revision:8,jwks:{keys:[b]},history:[{jwk:a,removed:true},{jwk:b,removed:false}]};
const doc={type:'sociacl-witness-checkpoint-v1',audience:context.audience,client:context.client,challenge:context.challenge,rootEpoch:1,issuedAt:context.now-1,expiresAt:context.now+60,state};
function sign(source, signer=18, kind='checkpoint', domain=kind) {
 const payload=Buffer.isBuffer(source)?source:Buffer.from(typeof source==='string'?source:JSON.stringify(source));
 const sig=p256.sign(Buffer.concat([Buffer.from(`sociacl-witness-${domain}-v1\n`),payload]),secret(signer),{lowS:true});
 return JSON.stringify({type:`sociacl-witness-${kind}-envelope-v1`,payload:b64(payload),signature:b64(sig)});
}
const policy=(s=state,patch={})=>sign({type:'sociacl-witness-policy-v1',audience:s.audience,revision:s.revision,issuedAt:context.now-1,expiresAt:context.now+120,jwks:s.jwks,...patch},17,'policy');
const base={checkpoint:sign(doc),policy:policy()};
const accept=[],reject=[];
function yes(name,d=doc,input={},ctx={}) {accept.push({name,input:{checkpoint:sign(d),policy:policy(d.state),...input},canonical:d,...ctx});}
function no(name,input={},ctx={}) {reject.push({name,input:{...base,...input},reason:'bad-attestation',...ctx});}
function change(name,fn,ctx={}) {const d=structuredClone(doc);fn(d);no(name,{checkpoint:sign(d)},ctx);}
yes('complete-history-tombstones');
yes('exact-signed-whitespace',doc,{checkpoint:sign(' \n'+JSON.stringify(doc)+'\t ')});
yes('inclusive-issuance', {...doc,issuedAt:context.now});
yes('maximum-300-second-lease',{...doc,issuedAt:context.now,expiresAt:context.now+300});
yes('one-second-lease',{...doc,issuedAt:context.now,expiresAt:context.now+1});
yes('utf8-client',{...doc,client:'设备-é'}, {}, {client:'设备-é'});
yes('maximum-safe-root-epoch',{...doc,rootEpoch:9007199254740991},{},{rootEpoch:9007199254740991});
yes('empty-active-registry-retains-removal',{...doc,state:{...state,jwks:{keys:[]},history:[{jwk:a,removed:true},{jwk:b,removed:true}]}});
for (const [name,ctx] of Object.entries({
 'wrong-management-key':{managementRoot:principal(21)}, 'wrong-policy-root':{root:principal(21)},
 'wrong-audience':{audience:'other'},'wrong-client':{client:'other'},'replayed-other-challenge':{challenge:b64(Buffer.alloc(32,43))},
 'retired-root-epoch':{rootEpoch:2},'checkpoint-below-floor':{minimumRevision:9},'zero-floor':{minimumRevision:0},
 'unsafe-floor':{minimumRevision:9007199254740992},'zero-root-epoch':{rootEpoch:0},'unsafe-root-epoch':{rootEpoch:9007199254740992},
 'same-management-and-policy-root':{managementRoot:context.root},'bad-management-key':{managementRoot:'bad'},'bad-policy-key':{root:'bad'},
 'empty-audience':{audience:''},'empty-client':{client:''},'client-byte-limit':{client:'é'.repeat(513)},
 'short-challenge':{challenge:b64(Buffer.alloc(31))},'long-challenge':{challenge:b64(Buffer.alloc(33))},'padded-challenge':{challenge:context.challenge+'='},
 'expired-checkpoint':{now:doc.expiresAt},'future-checkpoint':{now:doc.issuedAt-1},'unsafe-clock':{now:9007199254740992}
})) no(name,{},ctx);
for(const [name,fn] of Object.entries({
 'unknown-type':d=>d.type='other','extra-field':d=>d.extra=1,'missing-client':d=>delete d.client,
 'unbound-challenge':d=>d.challenge=b64(Buffer.alloc(32,43)), 'fractional-root-epoch':d=>d.rootEpoch=1.5,
 'overlong-lease':d=>{d.issuedAt=context.now;d.expiresAt=context.now+301;},'empty-lease':d=>d.expiresAt=d.issuedAt,
 'negative-issue-time':d=>d.issuedAt=-1,'fractional-expiry':d=>d.expiresAt+=0.5,'unsafe-expiry':d=>d.expiresAt=9007199254740992,
 'state-other-root':d=>d.state.root=principal(21),'state-other-audience':d=>d.state.audience='other',
 'state-older-than-policy':d=>d.state.revision=7,'state-newer-than-policy':d=>d.state.revision=9,
 'state-missing-history':d=>delete d.state.history,'state-dropped-active-history':d=>d.state.history=[],
 'state-conflicting-registry':d=>{d.state.jwks.keys=[a];d.state.history=[{jwk:a,removed:false}];},
 'state-resurrected-key':d=>d.state.history[1].removed=true,
 'state-window-conflict':d=>d.state.history[1].jwk.notAfter--,
 'state-unknown-field':d=>d.state.reset=true,
 'state-history-duplicate':d=>d.state.history.push(structuredClone(d.state.history[0])),
 'state-private-history-key':d=>d.state.history[0].jwk.d='secret'
})) change(name,fn);
for (const [name,patch] of Object.entries({'policy-ahead':{revision:9},'policy-behind':{revision:7},'expired-policy':{expiresAt:context.now},'policy-other-audience':{audience:'other'}})) no(name,{policy:policy(state,patch)});
const withManagement={...state,history:[{jwk:key(18),removed:true},...state.history]};
no('management-key-is-retired-witness',{checkpoint:sign({...doc,state:withManagement})});
const activeManagement={...state,jwks:{keys:[key(18)]},history:[{jwk:key(18),removed:false}]};
no('management-key-is-active-witness',{checkpoint:sign({...doc,state:activeManagement}),policy:policy(activeManagement)});
no('policy-signed-by-management-key',{policy:sign({type:'sociacl-witness-policy-v1',audience:context.audience,revision:8,issuedAt:doc.issuedAt,expiresAt:doc.expiresAt,jwks:state.jwks},18,'policy')});
no('policy-envelope-used-as-checkpoint',{checkpoint:base.policy});
no('checkpoint-wrong-signing-domain',{checkpoint:sign(doc,18,'checkpoint','policy')});
no('invalid-utf8',{checkpoint:sign(Buffer.from([0xff]))});
no('utf8-bom',{checkpoint:sign('\ufeff'+JSON.stringify(doc))});
for (const [name,source] of [
 ['duplicate-root-epoch',JSON.stringify(doc).replace('"rootEpoch":1','"rootEpoch":2,"rootEpoch":1')],
 ['escaped-duplicate-client',JSON.stringify(doc).replace('"client":"enrollment-1"','"client":"enrollment-1","cl\\u0069ent":"enrollment-1"')],
 ['nested-duplicate-state-revision',JSON.stringify(doc).replace('"revision":8','"revision":7,"revision":8')],
 ['integral-float',JSON.stringify(doc).replace('"rootEpoch":1','"rootEpoch":1.0')],
 ['exponent-revision',JSON.stringify(doc).replace('"revision":8','"revision":8e0')],
 ['negative-zero-time',JSON.stringify(doc).replace('"issuedAt":1699999999','"issuedAt":-0')],
 ['unpaired-surrogate',JSON.stringify(doc).replace('enrollment-1','\\ud800')]
]) no(name,{checkpoint:sign(source)});
const alter=(name,fn)=>{const o=JSON.parse(base.checkpoint);fn(o);no(name,{checkpoint:JSON.stringify(o)});};
alter('unsigned-history-tampering',o=>{const d=JSON.parse(Buffer.from(o.payload,'base64url'));d.state.history.shift();o.payload=b64(JSON.stringify(d));});
alter('padded-payload',o=>o.payload+='=');alter('padded-signature',o=>o.signature+='=');
alter('unknown-outer-field',o=>o.root=context.managementRoot);
alter('wrong-envelope-type',o=>o.type='other');alter('short-signature',o=>o.signature=b64(Buffer.alloc(63)));
alter('high-s-signature',o=>{const sig=Buffer.from(o.signature,'base64url');const order=BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');const s=BigInt('0x'+sig.subarray(32).toString('hex'));sig.set(Buffer.from((order-s).toString(16).padStart(64,'0'),'hex'),32);o.signature=b64(sig);});
no('duplicate-envelope-member',{checkpoint:base.checkpoint.replace('"type":','"payload":"AA","type":')});
for(const c of [...accept,...reject]) {
 const result=verifyWitnessCheckpoint(c.input.checkpoint,c.input.policy,{...context,...c});
 if(c.reason) assert.deepEqual(result,{ok:false,reason:c.reason},c.name);
 else {assert.ok(result.ok,c.name);assert.deepEqual(result.value,c.canonical,c.name);}
}
writeFileSync(new URL('../../../vectors/ids/witness-checkpoint.json',import.meta.url),JSON.stringify({v:1,family:'witness-checkpoint',context,accept,reject},null,2)+'\n');
console.log(`${accept.length} accepted, ${reject.length} rejected checkpoint cases`);
