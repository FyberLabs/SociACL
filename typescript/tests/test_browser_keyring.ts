import assert from 'node:assert/strict';
import {p256} from '@noble/curves/nist.js';
import {b64,unb64} from '../ids/src/util.js';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';
import {prepareKeyringRotation,exportPendingKeyring,activatePendingKeyring,closePendingKeyring,admitKeyring,exportCurrentPair,importKeyring,exportKeyring,validateKeyring,closeKeyring,openKeyringContent} from '../contract/keyring-browser.ts';
import {AccountKeyring} from '../contract/account-keyring.ts';
import {decodeKeyring,encodeKeyring} from '../contract/keyring-codec.ts';
import {signingBytes,historyState, type ResolutionContext, type PrincipalId} from '../ids/src/index.js';
import {sealReaderWrap} from '../contract/content-wrap.ts';
const vectors=JSON.parse(readFileSync(new URL('../../vectors/encrypted-discovery/browser-keyring.json',import.meta.url),'utf8'));
const records=JSON.parse(readFileSync(new URL('../../vectors/ids/records.json',import.meta.url),'utf8'));
const wraps=JSON.parse(readFileSync(new URL('../../vectors/encrypted-discovery/account-keyring.json',import.meta.url),'utf8')).witnessed;
const bytes=(hex:string)=>new Uint8Array(Buffer.from(hex,'hex'));
function state(v:any) {
 const rotations=v.rotationNames.map((name:string)=>records.accept.find((r:any)=>r.name===name).input);
 const context:ResolutionContext={jwks:records.context.jwks,links:new Map(records.context.links),revocations:[],now:records.context.now,
  policy:records.context.policy,pinnedIss:new Set(records.context.pinnedIss),genesisEpubBindings:v.genesisBindings,
  history:(principal:PrincipalId,at:number,until:number)=>records.context.authenticatedAccounts.includes(principal)
   ?{ok:true,value:historyState(principal,[],at,until)}:{ok:false,reason:'missing-history'}};
 return {rotations,context};
}
function expected(v:any) {const {principal,pub,epub,rotationSeq}=v.fields;return {principal,pub,epub,rotationSeq};}
function nodeImport(encoded:Uint8Array,v:any) {
 const f=decodeKeyring(encoded),s=state(v);
 return AccountKeyring.import(f.principal,f.genesisEpub,f.pub,f.priv,f.epub,f.epriv,f.retired,f.laneId,f.contentEpoch,f.rotationSeq,s.rotations,s.context,f.priorLanes,f.contactLaneSecret,f.priorContactSecrets);
}
for(const v of vectors.accept)test(`shared ${v.name} codec/import agrees with canonical Node path`,()=>{
 const encoded=bytes(v.encodedHex),handle=importKeyring(encoded,expected(v),()=>state(v));
 assert.deepEqual(exportKeyring(handle,()=>state(v)),encoded);
 assert.deepEqual(encodeKeyring(nodeImport(encoded,v)),encoded);
 assert.deepEqual(decodeKeyring(encoded),v.fields);
 assert(Object.isFrozen(handle));assert.equal(JSON.stringify(handle).includes(v.fields.priv),false);
 assert.equal(JSON.stringify(handle).includes(v.fields.contactLaneSecret),false);
 validateKeyring(encoded,expected(v),()=>state(v));
 assert.throws(()=>exportKeyring({...handle},()=>state(v)),/keyring-rejected/);
 closeKeyring(handle);assert.throws(()=>exportKeyring(handle,()=>state(v)),/keyring-rejected/);
});
for(const v of vectors.reject)test(`shared rejection ${v.name}`,()=>{
 const accepted=vectors.accept[1];
 assert.throws(()=>importKeyring(bytes(v.encodedHex),expected(accepted),()=>state(accepted)),new RegExp(v.expected));
 assert.throws(()=>nodeImport(bytes(v.encodedHex),accepted));
});
test('historical DEK remains decryptable after browser export/import',async()=>{
 const v=vectors.accept[1],encoded=bytes(v.encodedHex),handle=importKeyring(encoded,expected(v),()=>state(v));
 const ephemeral=new Uint8Array(32);ephemeral[31]=9;
 const wrappedKey=sealReaderWrap(v.fields.genesisEpub,wraps.dekHex,0,wraps.objectId,wraps.revisionId,ephemeral,new Uint8Array(12));
 const expectedScope={epoch:0,object:wraps.objectId,revisionId:wraps.revisionId};
 const wrap={...expectedScope,scope:'item-dek',target:'reader-epub',targetId:v.fields.genesisEpub,wrappedKey};
 assert.deepEqual(await openKeyringContent(handle,wrap,expectedScope),bytes(wraps.dekHex));
 await assert.rejects(openKeyringContent(handle,wrap,{...expectedScope,epoch:1}),/keyring-rejected/);
 const pending=openKeyringContent(handle,wrap,expectedScope);closeKeyring(handle);
 await assert.rejects(pending,/keyring-rejected/);
});
test('strict decoding, bounds, identity mismatch and missing authority fail closed',()=>{
 const v=vectors.accept[1],encoded=bytes(v.encodedHex);
 for(const bad of [encoded.slice(0,-1),new Uint8Array([...encoded,0]),new Uint8Array(524289)])assert.throws(()=>importKeyring(bad,expected(v),()=>state(v)),/keyring-rejected/);
 const utf8=encoded.slice();utf8[4]=255;assert.throws(()=>importKeyring(utf8,expected(v),()=>state(v)),/keyring-rejected/);
 assert.throws(()=>importKeyring(encoded,{...expected(v),pub:v.fields.genesisEpub},()=>state(v)),/keyring-rejected/);
 assert.throws(()=>importKeyring(encoded,expected(v),()=>({...state(v),rotations:[]})),/keyring-rejected/);
 assert.throws(()=>importKeyring(encoded,expected(v),()=>{throw Error('private diagnostic');}),/^Error: keyring-rejected$/);
 const handle=importKeyring(encoded,expected(v),()=>state(v));
 assert.throws(()=>exportKeyring(handle,()=>({...state(v),rotations:[]})),/keyring-rejected/);
 closeKeyring(handle);
});
test('owner revocation and stale authenticated history refuse import and export',()=>{
 const v=vectors.accept[1],encoded=bytes(v.encodedHex),handle=importKeyring(encoded,expected(v),()=>state(v));
 const revoked=records.reject.find((r:any)=>r.name==='revoked-recovery').revocations;
 const badStates=[
  ()=>{const s=state(v);return {...s,context:{...s.context,revocations:revoked}};},
  ()=>{const s=state(v);return {...s,context:{...s.context,now:0}};},
 ];
 for(const badState of badStates){
  assert.throws(()=>importKeyring(encoded,expected(v),badState),/keyring-rejected/);
  assert.throws(()=>exportKeyring(handle,badState),/keyring-rejected/);
 }
 closeKeyring(handle);
});

test('old genesis keyring is rejected against authenticated rotated owner state',()=>{
 const old=vectors.accept[0],current=vectors.accept[1];
 assert.throws(()=>importKeyring(bytes(old.encodedHex),expected(old),()=>state(current)),/keyring-rejected/);
});

for(const v of vectors.accept)test(`complete fields and current pair preserve ${v.name}`,()=>{
 const material=structuredClone(v.fields),handle=admitKeyring(material,expected(v),()=>state(v));
 material.priv='changed';material.retired.length=0;material.priorLanes.length=0;
 assert.deepEqual(exportKeyring(handle,()=>state(v)),bytes(v.encodedHex));
 const pair=exportCurrentPair(handle,()=>state(v));
 assert.deepEqual(pair,{pub:v.fields.pub,priv:v.fields.priv,epub:v.fields.epub,epriv:v.fields.epriv});
 pair.priv='changed';assert.equal(exportCurrentPair(handle,()=>state(v)).priv,v.fields.priv);
 assert.throws(()=>exportCurrentPair({...handle},()=>state(v)),/^Error: keyring-rejected$/);
 assert.throws(()=>exportCurrentPair(handle,()=>{closeKeyring(handle);return state(v);}),/^Error: keyring-rejected$/);
 assert.throws(()=>exportCurrentPair(handle,()=>state(v)),/^Error: keyring-rejected$/);
});
test('field admission refuses incomplete, oversized, accessor and stale material',()=>{
 const v=vectors.accept[1];let invoked=false;
 const bad=[{...v.fields,retired:[]},{...v.fields,priorContactSecrets:[]},
  {...v.fields,priorLanes:Array(1025).fill('ab'.repeat(32))},{...v.fields,priv:'a'.repeat(524289)},
  {...v.fields,privateExtra:'secret'},Object.defineProperty({...v.fields},'priv',{get(){invoked=true;return v.fields.priv;}}),
  {...v.fields,priorLanes:Object.defineProperty([v.fields.priorLanes[0]],'0',{get(){invoked=true;return v.fields.priorLanes[0];}})}];
 for(const material of bad)assert.throws(()=>admitKeyring(material,expected(v),()=>state(v)),/^Error: keyring-rejected$/);
 assert.equal(invoked,false);
 assert.throws(()=>admitKeyring(v.fields,expected(v),()=>({...state(v),rotations:[]})),/^Error: keyring-rejected$/);
 const handle=admitKeyring(v.fields,expected(v),()=>state(v));
 assert.throws(()=>exportCurrentPair(handle,()=>({...state(v),rotations:[]})),/^Error: keyring-rejected$/);
 closeKeyring(handle);
});


test('pending rotation preserves old keys without admitting or publishing new authority',()=>{
 const v=vectors.accept[1],handle=importKeyring(bytes(v.encodedHex),expected(v),()=>state(v));
 const pending=prepareKeyringRotation(handle,['lost-device','trusted-device'],'lost-device',()=>state(v));
 assert(Object.isFrozen(pending));assert(Object.isFrozen(pending.draft));
 assert.equal(pending.principal,handle.principal);assert.equal(pending.rotationSeq,handle.rotationSeq+1);
 assert.equal(pending.draft.prevKey,handle.pub);assert.equal(pending.draft.nextKey,pending.pub);
 assert.notEqual(pending.pub,handle.pub);assert.notEqual(pending.epub,handle.epub);
 const encoded=exportPendingKeyring(pending,()=>state(v)),fields=decodeKeyring(encoded);
 assert.equal(fields.retired.at(-1)?.epub,handle.epub);
 assert.deepEqual(fields.priorLanes,[...v.fields.priorLanes,v.fields.laneId]);
 assert.deepEqual(fields.priorContactSecrets,[...v.fields.priorContactSecrets,v.fields.contactLaneSecret]);
 assert.equal(JSON.stringify(pending).includes(fields.priv),false);
 assert.throws(()=>exportKeyring(pending,()=>state(v)),/keyring-rejected/);
 assert.throws(()=>activatePendingKeyring(pending,()=>state(v)),/keyring-rejected/);
 assert.deepEqual(exportKeyring(handle,()=>state(v)),bytes(v.encodedHex));
 assert.throws(()=>exportPendingKeyring({...pending},()=>state(v)),/keyring-rejected/);
 closePendingKeyring(pending);
 assert.throws(()=>exportPendingKeyring(pending,()=>state(v)),/keyring-rejected/);
 assert.throws(()=>activatePendingKeyring(pending,()=>state(v)),/keyring-rejected/);
 encoded.fill(0);closeKeyring(handle);
});
test('pending preparation and export refuse closed origin, missing history and bad devices',()=>{
 const v=vectors.accept[1],handle=importKeyring(bytes(v.encodedHex),expected(v),()=>state(v));
 for(const [trusted,lost] of [[[],'lost'],[['lost','lost'],'lost'],[['trusted'],'lost']] as const)
  assert.throws(()=>prepareKeyringRotation(handle,trusted,lost,()=>state(v)),/keyring-rejected/);
 assert.throws(()=>prepareKeyringRotation({...handle},['lost'],'lost',()=>state(v)),/keyring-rejected/);
 assert.throws(()=>prepareKeyringRotation(handle,['lost'],'lost',()=>({...state(v),rotations:[]})),/keyring-rejected/);
 const pending=prepareKeyringRotation(handle,['lost'],'lost',()=>state(v));
 assert.throws(()=>exportPendingKeyring(pending,()=>({...state(v),rotations:[]})),/keyring-rejected/);
 assert.throws(()=>exportPendingKeyring(pending,()=>{closePendingKeyring(pending);return state(v);}),/keyring-rejected/);
 const second=prepareKeyringRotation(handle,['lost'],'lost',()=>state(v));
 assert.throws(()=>exportPendingKeyring(second,()=>{closeKeyring(handle);return state(v);}),/keyring-rejected/);
 assert.throws(()=>activatePendingKeyring(second,()=>state(v)),/keyring-rejected/);
 assert.throws(()=>prepareKeyringRotation(handle,['lost'],'lost',()=>state(v)),/keyring-rejected/);
 closePendingKeyring(second);
});


test('activation requires the exact published new keys and consumes the pending handle once',()=>{
 const v=vectors.accept[0],handle=importKeyring(bytes(v.encodedHex),expected(v),()=>state(v));
 const pending=prepareKeyringRotation(handle,['lost','kept'],'lost',()=>state(v));
 const encoded=exportPendingKeyring(pending,()=>state(v)),f=decodeKeyring(encoded);
 const link=records.context.links.find((pair:any)=>pair[1].kind==='oidc')[0];
 const issuedAt=records.context.now;
 const unsigned={v:1,kind:'rotate',principal:f.principal,seq:f.rotationSeq,prevKey:handle.pub,
  nextKey:f.pub,nextEpub:f.epub,issuedAt,retainedLinks:[link],authorizer:{kind:'oidc-fresh-login',link}};
 const transcript=signingBytes(unsigned as any);assert(transcript.ok);
 const nextSig=b64(p256.sign(transcript.value,unb64(f.priv),{lowS:false}));
 const claims={typ:'sociacl-rotate-attest-v3',principal:f.principal,nextKey:f.pub,nextEpub:f.epub,
  seq:f.rotationSeq,iat:issuedAt,exp:issuedAt+600,auth:'oidc-fresh-login',linkId:link,retainedLinks:[link]};
 const header=b64(new TextEncoder().encode(JSON.stringify({alg:'ES256',kid:'fixture-1',typ:'JWT'})));
 const body=`${header}.${b64(new TextEncoder().encode(JSON.stringify(claims)))}`;
 const witness=new Uint8Array(32);witness[31]=5;
 const attest=`${body}.${b64(p256.sign(new TextEncoder().encode(body),witness,{lowS:false}))}`;
 const published=()=>({...state(v),rotations:[{...unsigned,nextSig,attest}]});
 const activated=activatePendingKeyring(pending,published);
 assert.deepEqual(exportKeyring(activated,published),encoded);
 assert.throws(()=>activatePendingKeyring(pending,published),/keyring-rejected/);
 assert.throws(()=>exportPendingKeyring(pending,()=>state(v)),/keyring-rejected/);
 closeKeyring(handle);assert.deepEqual(exportKeyring(activated,published),encoded);
 closeKeyring(activated);encoded.fill(0);witness.fill(0);
});
