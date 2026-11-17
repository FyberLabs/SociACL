// Native crypto contracts run in CI only.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';
import {openRecoveryKeyring,sealPendingRecoveryKeyring} from '../contract/recovery-browser.ts';
import {openRecoveryCopy} from '../contract/recovery-seal.ts';
import {exportKeyring,closeKeyring,prepareKeyringRotation,exportPendingKeyring,closePendingKeyring} from '../contract/keyring-browser.ts';
import {encodeKeyring} from '../contract/keyring-codec.ts';
import {parseHeader,deriveKey,recoveryAad} from '../contract/recovery-wire.ts';
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
  await assert.rejects(sealRecoveryKeyring(handle,new TextEncoder().encode('q7vN2mR9pL4xT8wK3c'),state,undefined,'q7vN2mR9pL4xT8wK3c'),/recovery-weak-passphrase/);
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

test('new-copy input guards reject empty passphrases, forged handles and prior cancellation',async()=>{
 const {sealRecoveryKeyring}=await import('../contract/recovery-browser.ts');
 const handle=await openRecoveryKeyring(new TextEncoder().encode(legacy.passphraseUtf8),envelope(legacy),expected,state);
 try{
  for(const value of [new Uint8Array(),new TextEncoder().encode(' \t\n'),'not-bytes' as any]){
   await assert.rejects(sealRecoveryKeyring(handle,value,state),/recovery-rejected/);
  }
  await assert.rejects(sealRecoveryKeyring({...handle},new TextEncoder().encode(vector.passphraseUtf8),state),/recovery-rejected/);
  const abort=new AbortController();abort.abort();
  await assert.rejects(sealRecoveryKeyring(handle,new TextEncoder().encode(vector.passphraseUtf8),state,abort.signal),/recovery-rejected/);
 }finally{closeKeyring(handle);}
});

test('WebCrypto input copies are wiped after successful and failed encryption',async()=>{
 const {sealRecoveryKeyring}=await import('../contract/recovery-browser.ts');
 const handle=await openRecoveryKeyring(new TextEncoder().encode(legacy.passphraseUtf8),envelope(legacy),expected,state);
 const subtle=crypto.subtle,originalImport=subtle.importKey,originalEncrypt=subtle.encrypt;
 const captured:Uint8Array[]=[];
 try{
  subtle.importKey=(async function(...args:any[]){
   if(args[0]==='raw'&&args[2]?.name==='AES-GCM')captured.push(args[1]);
   return (originalImport as any).apply(subtle,args);
  }) as any;
  for(const fail of [false,true]){
   captured.length=0;
   subtle.encrypt=(async function(...args:any[]){
    captured.push(args[2]);
    if(fail)throw Error('encryption refused');
    return (originalEncrypt as any).apply(subtle,args);
   }) as any;
   const pending=sealRecoveryKeyring(handle,new TextEncoder().encode(vector.passphraseUtf8),state);
   if(fail)await assert.rejects(pending,/recovery-rejected/);else await pending;
   assert.equal(captured.length,2);
   for(const bytes of captured)assert.ok(bytes.every(byte=>byte===0));
  }
 }finally{subtle.importKey=originalImport;subtle.encrypt=originalEncrypt;closeKeyring(handle);}
});


test('current-copy signatures agree with native store CAS and reject replay',async()=>{
 const {signRecoveryCurrentPut}=await import('../contract/recovery-browser.ts');
 const {MemoryRecoveryStore}=await import('../contract/recovery-seal.ts');
 const {HeadFloor}=await import('../contract/store-write.ts');
 const handle=await openRecoveryKeyring(new TextEncoder().encode(legacy.passphraseUtf8),envelope(legacy),expected,state);
 const account={currentKey:expected.pub,currentEpub:expected.epub,rotations:[]};
 const store=new MemoryRecoveryStore(()=>account as any,new HeadFloor());
 const head={sequence:0,currentKey:expected.pub,currentEpub:expected.epub};
 try{
  const view={generation:0,head,row:null},e=envelope(legacy);
  const op=signRecoveryCurrentPut(handle,e,view,()=>{view.generation=99;e.bytes.fill(0);return state();});
  const row={...op.row,bytes:new Uint8Array(Buffer.from(op.row.bytesHex,'hex'))};
  store.put(row as any,op.signature);
  assert.equal(store.writeGeneration(expected.principal),1);
  assert.throws(()=>store.put(row as any,op.signature),/store-rejected/);
  const next=signRecoveryCurrentPut(handle,envelope(),{generation:1,head,row:envelope(legacy)},state);
  store.put({...next.row,bytes:new Uint8Array(Buffer.from(next.row.bytesHex,'hex'))} as any,next.signature);
  assert.equal(store.writeGeneration(expected.principal),2);
 }finally{closeKeyring(handle);}
});
test('current-copy signer refuses invalid views, stale heads, malformed envelopes and closed handles',async()=>{
 const {signRecoveryCurrentPut}=await import('../contract/recovery-browser.ts');
 const handle=await openRecoveryKeyring(new TextEncoder().encode(legacy.passphraseUtf8),envelope(legacy),expected,state);
 const head={sequence:0,currentKey:expected.pub,currentEpub:expected.epub},view={generation:0,head,row:null};
 try{
  for(const v of [{...view,extra:1},{...view,head:{}},{...view,head:{...head,sequence:1}},
   {...view,generation:-1},{...view,generation:Number.MAX_SAFE_INTEGER},{...view,row:{}},
   {...view,row:{...envelope(),principal:'foreign'}}])assert.throws(()=>signRecoveryCurrentPut(handle,envelope(),v as any,state),/recovery-rejected/);
  for(const e of [{...envelope(),extra:1},{...envelope(),rotationSeq:1},{...envelope(),bytes:new Uint8Array(524414)},
   {...envelope(),bytes:new Uint8Array(33)},{...envelope(),signingPub:'invalid'},
   {...envelope(),epub:expected.pub}])assert.throws(()=>signRecoveryCurrentPut(handle,e,view,state),/recovery-rejected/);
  assert.throws(()=>signRecoveryCurrentPut(handle,envelope(),view,()=>{throw Error();}),/recovery-rejected/);
  let calls=0;assert.throws(()=>signRecoveryCurrentPut(handle,envelope(),view,()=>{if(++calls>1)throw Error();return state();}),/recovery-rejected/);
  closeKeyring(handle);assert.throws(()=>signRecoveryCurrentPut(handle,envelope(),view,state),/recovery-rejected/);
 }finally{closeKeyring(handle);}
});


test('pending recovery sealing preserves future metadata and refuses cancelled or closed handles',async()=>{
 const handle=await openRecoveryKeyring(new TextEncoder().encode(legacy.passphraseUtf8),envelope(legacy),expected,state);
 const pending=prepareKeyringRotation(handle,['lost','kept'],'lost',state);
 const phrase=new TextEncoder().encode(vector.passphraseUtf8);
 try{
  const sealing=sealPendingRecoveryKeyring(pending,phrase,state);phrase.fill(0);
  const copy=await sealing;
  assert.equal(copy.rotationSeq,1);assert.equal(copy.signingPub,pending.pub);assert.equal(copy.epub,pending.epub);
  assert.equal(copy.principal,handle.principal);
  // Ciphertext cannot be opened against the still-current old history.
  await assert.rejects(openRecoveryKeyring(new TextEncoder().encode(vector.passphraseUtf8),copy,
   {principal:pending.principal,pub:pending.pub,epub:pending.epub,rotationSeq:pending.rotationSeq},state),/recovery-rejected/);
  const plain=exportPendingKeyring(pending,state),header=parseHeader(copy.bytes);
  const phraseCopy=new TextEncoder().encode(vector.passphraseUtf8);
  const key=await deriveKey(phraseCopy,header.salt,header.memoryKiB,header.iterations,header.parallelism,header.hashLength);
  const aad=recoveryAad(copy.principal,header.rotationSeq,copy.signingPub,copy.epub,header.memoryKiB,
   header.iterations,header.parallelism,header.hashLength,header.version,header.salt);
  let decrypted:Uint8Array|undefined;
  try{
   const cryptoKey=await crypto.subtle.importKey('raw',new Uint8Array(key),{name:'AES-GCM'},false,['decrypt']);
   decrypted=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:new Uint8Array(header.nonce),
    additionalData:new Uint8Array(aad),tagLength:128},cryptoKey,new Uint8Array(header.ciphertext)));
   assert.deepEqual(decrypted,plain);
  }finally{decrypted?.fill(0);plain.fill(0);key.fill(0);phraseCopy.fill(0);}
  await assert.rejects(sealPendingRecoveryKeyring(pending,new TextEncoder().encode('password'),state),/recovery-weak-passphrase/);
  const abort=new AbortController();const cancelled=sealPendingRecoveryKeyring(pending,new TextEncoder().encode(vector.passphraseUtf8),state,abort.signal);
  abort.abort();await assert.rejects(cancelled,/recovery-rejected/);
  const closing=sealPendingRecoveryKeyring(pending,new TextEncoder().encode(vector.passphraseUtf8),state);
  closePendingKeyring(pending);await assert.rejects(closing,/recovery-rejected/);
  await assert.rejects(sealPendingRecoveryKeyring({...pending},new TextEncoder().encode(vector.passphraseUtf8),state),/recovery-rejected/);
 }finally{phrase.fill(0);closePendingKeyring(pending);closeKeyring(handle);}
});


test('pending-copy signatures bind exact future material and native generation CAS',async()=>{
 const {signRecoveryPendingPut}=await import('../contract/recovery-browser.ts');
 const {MemoryRecoveryStore}=await import('../contract/recovery-seal.ts');
 const {HeadFloor}=await import('../contract/store-write.ts');
 const handle=await openRecoveryKeyring(new TextEncoder().encode(legacy.passphraseUtf8),envelope(legacy),expected,state);
 const pending=prepareKeyringRotation(handle,['lost'],'lost',state);
 const e=await sealPendingRecoveryKeyring(pending,new TextEncoder().encode(vector.passphraseUtf8),state);
 const account={currentKey:expected.pub,currentEpub:expected.epub,rotations:[]};
 const store=new MemoryRecoveryStore(()=>account as any,new HeadFloor());
 const head={sequence:0,currentKey:expected.pub,currentEpub:expected.epub},view={generation:0,head,row:null};
 try{
  const op=signRecoveryPendingPut(handle,pending,e,view,state);
  const row={...op.row,bytes:new Uint8Array(Buffer.from(op.row.bytesHex,'hex'))};
  store.put(row as any,op.signature);
  assert.equal(store.pending(expected.principal)?.signingPub,pending.pub);
  assert.equal(store.current(expected.principal),undefined);
  assert.equal(store.writeGeneration(expected.principal),1);
  assert.throws(()=>store.put(row as any,op.signature),/store-rejected/);
  for(const bad of [{...e,signingPub:handle.pub},{...e,epub:handle.epub},{...e,rotationSeq:0}])
   assert.throws(()=>signRecoveryPendingPut(handle,pending,bad,view,state),/recovery-rejected/);
  assert.throws(()=>signRecoveryPendingPut(handle,{...pending},e,view,state),/recovery-rejected/);
  assert.throws(()=>signRecoveryPendingPut(handle,pending,e,{...view,row:envelope()},state),/recovery-rejected/);
  const replacement=signRecoveryPendingPut(handle,pending,e,{generation:1,head,row:e},state);
  store.put({...replacement.row,bytes:new Uint8Array(Buffer.from(replacement.row.bytesHex,'hex'))} as any,replacement.signature);
  assert.equal(store.writeGeneration(expected.principal),2);
  let calls=0;
  assert.throws(()=>signRecoveryPendingPut(handle,pending,e,{generation:2,head,row:e},()=>{
   if(++calls===2)closePendingKeyring(pending);return state();
  }),/recovery-rejected/);
 }finally{closePendingKeyring(pending);closeKeyring(handle);}
});
