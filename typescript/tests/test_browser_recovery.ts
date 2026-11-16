// Native crypto contracts run in CI only.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';
import {openRecoveryKeyring} from '../contract/recovery-browser.ts';
import {openRecoveryCopy} from '../contract/recovery-seal.ts';
import {exportKeyring,closeKeyring} from '../contract/keyring-browser.ts';
import {encodeKeyring} from '../contract/keyring-codec.ts';
import {historyState} from '../ids/src/index.js';
const read=(name:string)=>JSON.parse(readFileSync(new URL('../../vectors/'+name,import.meta.url),'utf8'));
const vector=read('encrypted-discovery/recovery-copy.json'),legacy=read('encrypted-discovery/recovery-legacy-strength.json');
const ring=read('encrypted-discovery/account-keyring.json'),records=read('ids/records.json');
const expected={principal:ring.genesis.principal,pub:ring.genesis.signingPub,epub:ring.genesis.epub,rotationSeq:0};
const state=()=>({rotations:[],context:{...records.context,links:new Map(records.context.links),revocations:[],pinnedIss:new Set(records.context.pinnedIss),
 genesisEpubBindings:[ring.genesisBinding],history:(p:any,at:number,until:number)=>records.context.authenticatedAccounts.includes(p)?{ok:true as const,value:historyState(p,[],at,until)}:{ok:false as const,reason:'missing-history' as const}}});
const envelope=(v=vector)=>({principal:expected.principal,signingPub:expected.pub,epub:expected.epub,rotationSeq:0,bytes:new Uint8Array(Buffer.from(v.envelopeHex,'hex'))});
for(const [name,v] of [['current',vector],['legacy weak',legacy]] as const)test(`${name} recovery opens identically in browser and Node`,async()=>{
 const pass=new TextEncoder().encode(v.passphraseUtf8),e=envelope(v),s=state();
 const handle=await openRecoveryKeyring(pass,e,expected,state);
 const node=await openRecoveryCopy(pass,e,expected.principal,0,s.rotations,s.context);
 assert.deepEqual(exportKeyring(handle,state),encodeKeyring(node));closeKeyring(handle);
 assert.deepEqual(pass,new TextEncoder().encode(v.passphraseUtf8));
});
test('snapshots caller bytes and refuses tamper, stale owner, malformed params and changed history',async()=>{
 const pass=new TextEncoder().encode(vector.passphraseUtf8),e=envelope(),pending=openRecoveryKeyring(pass,e,expected,state);
 pass.fill(0);e.bytes.fill(0);e.principal='changed';
 const handle=await pending;closeKeyring(handle);
 const good=new TextEncoder().encode(vector.passphraseUtf8);
 const tampered=envelope();tampered.bytes[tampered.bytes.length-1]^=1;
 for(const row of [tampered,{...envelope(),rotationSeq:1},{...envelope(),bytes:new Uint8Array(524414)}, {...envelope(),bytes:new Uint8Array(33)}]){
  await assert.rejects(openRecoveryKeyring(good,row,expected,state),/^Error: recovery-rejected$/);
 }
 await assert.rejects(openRecoveryKeyring(new TextEncoder().encode('wrong'),envelope(),expected,state),/recovery-rejected/);
 await assert.rejects(openRecoveryKeyring(good,envelope(),expected,()=>{throw Error('private history failure');}),/^Error: recovery-rejected$/);
 const c=new AbortController(),stopped=openRecoveryKeyring(good,envelope(),expected,state,c.signal);c.abort();await assert.rejects(stopped,/recovery-rejected/);
 await assert.rejects(openRecoveryKeyring(good,envelope(),expected,state,c.signal),/recovery-rejected/);
});

test('new browser copy snapshots strong passphrase and agrees with Node opening',async()=>{
 const {sealRecoveryKeyring}=await import('../contract/recovery-browser.ts');
 const handle=await openRecoveryKeyring(new TextEncoder().encode(legacy.passphraseUtf8),envelope(legacy),expected,state);
 try{
  const pass=new TextEncoder().encode(vector.passphraseUtf8),pending=sealRecoveryKeyring(handle,pass,state);pass.fill(0);
  const copy=await pending,s=state();
  const node=await openRecoveryCopy(new TextEncoder().encode(vector.passphraseUtf8),copy,expected.principal,0,s.rotations,s.context);
  assert.deepEqual(encodeKeyring(node),exportKeyring(handle,state));
  assert.notDeepEqual(copy.bytes,envelope(vector).bytes);
  await assert.rejects(sealRecoveryKeyring(handle,new TextEncoder().encode('password'),state),/recovery-weak-passphrase/);
  const closed=sealRecoveryKeyring(handle,new TextEncoder().encode(vector.passphraseUtf8),state);closeKeyring(handle);
  await assert.rejects(closed,/recovery-rejected/);
 }finally{closeKeyring(handle);}
});
test('new-copy cancellation and owner changes refuse ciphertext delivery',async()=>{
 const {sealRecoveryKeyring}=await import('../contract/recovery-browser.ts');
 const handle=await openRecoveryKeyring(new TextEncoder().encode(legacy.passphraseUtf8),envelope(legacy),expected,state);
 try{
  const abort=new AbortController(),pending=sealRecoveryKeyring(handle,new TextEncoder().encode(vector.passphraseUtf8),state,abort.signal);abort.abort();await assert.rejects(pending,/recovery-rejected/);
  let count=0;await assert.rejects(sealRecoveryKeyring(handle,new TextEncoder().encode(vector.passphraseUtf8),()=>{if(++count>1)throw Error();return state();}),/recovery-rejected/);
 }finally{closeKeyring(handle);}
});
