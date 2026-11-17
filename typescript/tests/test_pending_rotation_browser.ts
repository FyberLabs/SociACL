// Native wallet/signing contracts execute in CI only; keys are public fixtures.
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {readFileSync} from 'node:fs';
import {secp256k1} from '@noble/curves/secp256k1.js';
import {sha256} from '@noble/hashes/sha2.js';
import {keccak_256} from '@noble/hashes/sha3.js';
import {b64,hex,utf8} from '../ids/src/util.js';
import {signingBytes,historyState,checkRotationPublish,type ResolutionContext} from '../ids/src/index.js';
import {admitKeyring,prepareKeyringRotation,closeKeyring,closePendingKeyring} from '../contract/keyring-browser.ts';
import {signPendingWalletRotation} from '../contract/pending-rotation-browser.ts';
const records=JSON.parse(readFileSync(new URL('../../vectors/ids/records.json',import.meta.url),'utf8'));
const vectors=JSON.parse(readFileSync(new URL('../../vectors/encrypted-discovery/browser-keyring.json',import.meta.url),'utf8'));
function fixture(){
 const material=structuredClone(vectors.accept[1].fields),signing=new Uint8Array(32),encryption=new Uint8Array(32);signing[31]=1;encryption[31]=9;
 Object.assign(material,{pub:material.principal,priv:b64(signing),epub:material.genesisEpub,epriv:b64(encryption),
  rotationSeq:0,contentEpoch:0,retired:[],priorLanes:[],priorContactSecrets:[]});
 const context:ResolutionContext={...records.context,links:new Map(records.context.links),pinnedIss:new Set(records.context.pinnedIss),revocations:[],
  genesisEpubBindings:records.accept.find((row:any)=>row.name==='binding-valid-no-rotation').genesisEpubBindings,
  history:(p,at,until)=>({ok:true,value:historyState(p,[],at,until)})};
 const state=()=>({rotations:[],context});
 const handle=admitKeyring(material,{principal:material.principal,pub:material.pub,epub:material.epub,rotationSeq:0},state);
 const pending=prepareKeyringRotation(handle,['lost','kept'],'lost',state);
 const [link,wallet]=records.context.links.find((pair:any)=>pair[1].kind==='wallet');
 const {version:_,...draft}=pending.draft;
 const unsigned={...draft,issuedAt:context.now,retainedLinks:[link],authorizer:{kind:'wallet',link,siwe:{message:'',signature:''}}};
 const bytes=signingBytes(unsigned as any);assert(bytes.ok);
 const message=`s3r.ch wants you to sign in with your Ethereum account:\n${wallet.address}\n\nSociACL link: ${hex(sha256(bytes.value))}\n\nURI: https://s3r.ch/identity/link\nVersion: 1\nChain ID: 1\nNonce: rotation1234\nIssued At: ${new Date(context.now*1000).toISOString().replace('.000Z','Z')}`;
 const raw=utf8.encode(message),digest=keccak_256(new Uint8Array([...utf8.encode('\x19Ethereum Signed Message:\n'+raw.length),...raw]));
 const scalar=new Uint8Array(32);scalar[31]=4;
 const sig=secp256k1.sign(digest,scalar,{prehash:false,format:'recovered'});
 unsigned.authorizer.siwe={message,signature:'0x'+hex(new Uint8Array([...sig.slice(1),sig[0]!+27]))};
 return {pending,handle,state,unsigned,close(){closePendingKeyring(pending);closeKeyring(handle);scalar.fill(0);signing.fill(0);encryption.fill(0);}};
}
test('next-key signature binds exactly the prepared transition and valid present wallet proof',()=>{
 const f=fixture();try{
  const result=signPendingWalletRotation(f.pending,f.unsigned,f.state);
  assert.equal(Object.hasOwn(result,'attest'),false);assert.equal(typeof result.nextSig,'string');
  assert.ok(checkRotationPublish(result,[],f.pending.principal as any,[],f.state().context).ok);
  assert(Object.isFrozen(result));
  const original=structuredClone(f.unsigned);let calls=0;
  const snapshot=signPendingWalletRotation(f.pending,f.unsigned,()=>{if(++calls===1){f.unsigned.authorizer.siwe.message='changed';f.unsigned.retainedLinks.length=0;}return f.state();});
  assert.deepEqual(snapshot.authorizer,original.authorizer);assert.deepEqual(snapshot.retainedLinks,original.retainedLinks);
 }finally{f.close();}
});
test('malformed, foreign, stale, closed or unproved transitions refuse without publication',()=>{
 const f=fixture();try{
  for(const input of [null,{}, {...f.unsigned,nextSig:'unexpected'},{...f.unsigned,nextKey:f.handle.pub},
   {...f.unsigned,retainedLinks:[]},{...f.unsigned,retainedLinks:Array(1025).fill('a')},
   {...f.unsigned,retainedLinks:new Array(1)},{...f.unsigned,retainedLinks:[1]},
   {...f.unsigned,retainedLinks:Object.defineProperty(['x'],'0',{get(){throw Error('getter');}})},
   {...f.unsigned,authorizer:{kind:'oidc-fresh-login',link:f.unsigned.authorizer.link}},
   {...f.unsigned,authorizer:{...f.unsigned.authorizer,siwe:{message:1,signature:'x'}}},
   {...f.unsigned,authorizer:{...f.unsigned.authorizer,siwe:{message:'wrong',signature:'0x'+'00'.repeat(65)}}}])
   assert.throws(()=>signPendingWalletRotation(f.pending,input,f.state),/recovery-rejected/);
  assert.throws(()=>signPendingWalletRotation({...f.pending},f.unsigned,f.state),/recovery-rejected/);
  assert.throws(()=>signPendingWalletRotation(f.pending,f.unsigned,()=>{throw Error('stale');}),/recovery-rejected/);
  assert.throws(()=>signPendingWalletRotation(f.pending,{...f.unsigned,issuedAt:-1},f.state),/recovery-rejected/);
  assert.throws(()=>signPendingWalletRotation(f.pending,f.unsigned,()=>{closePendingKeyring(f.pending);return f.state();}),/recovery-rejected/);
 }finally{f.close();}
});
