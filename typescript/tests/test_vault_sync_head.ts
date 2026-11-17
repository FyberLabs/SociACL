import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { parsePrincipalId,signWithKeyring,historyState,type ResolutionContext } from '../ids/src/index.js';
import { seaPoint } from '../contract/account-key-seal.ts';
import { vaultSyncHeadSigningBytes,vaultSyncHeadFloor,verifyVaultSyncHead,openVaultSyncHeadStore,type VaultSyncHead } from '../contract/vault-sync-head.ts';
const {IDBFactory}=createRequire(new URL('../ids/package.json',import.meta.url))('fake-indexeddb');
const key=new Uint8Array(32);key[31]=1;
const principal=parsePrincipalId(seaPoint(key));if(!principal.ok)throw Error(principal.reason);
const owner=principal.value,vaultId='12'.repeat(32);
const context:ResolutionContext={now:20,jwks:{keys:[]},links:new Map(),pinnedIss:new Set(),
  policy:{allowedDomains:[],allowedUris:[],allowedChainIds:[],clockSkewSeconds:0},
  history:(p,at,until)=>({ok:true,value:historyState(p,[],at,until)})};
const current=()=>({rotations:[],context});
function signed(change:Partial<VaultSyncHead>={}):VaultSyncHead {
  const r:VaultSyncHead={v:1,owner,vaultId,revision:1,previousDigest:'00'.repeat(32),keybagDigest:'23'.repeat(32),
    indexDigest:'34'.repeat(32),minimumProfile:1,issuedAt:10,sig:'A'.repeat(86),...change};
  const s=signWithKeyring(key,vaultSyncHeadSigningBytes(r),owner);if(!s.ok)throw Error(s.reason);
  return {...r,sig:s.value};
}
const successor=(r:VaultSyncHead,change:Partial<VaultSyncHead>={})=>signed({revision:r.revision+1,
  previousDigest:vaultSyncHeadFloor(r).digest,issuedAt:r.issuedAt+1,...change});

test('vault sync signatures bind owner, namespace, ciphertext and profile without granting reads',()=>{
  const r=signed();assert.deepEqual(verifyVaultSyncHead(r,owner,vaultId,[],context),r);
  assert.equal('allowed' in verifyVaultSyncHead(r,owner,vaultId,[],context),false);
  for(const changed of [{indexDigest:'45'.repeat(32)},{keybagDigest:'45'.repeat(32)},{minimumProfile:2},{sig:'A'.repeat(86)}]){
    assert.throws(()=>verifyVaultSyncHead({...r,...changed},owner,vaultId,[],context));
  }
  assert.throws(()=>verifyVaultSyncHead(r,owner,'56'.repeat(32),[],context));
  assert.throws(()=>verifyVaultSyncHead(r,owner,vaultId,[],{...context,now:9}));
  assert.throws(()=>verifyVaultSyncHead(r,owner,vaultId,[],{...context,history:()=>({ok:false,reason:'missing-history'})}));
  assert.throws(()=>vaultSyncHeadSigningBytes({...r,unknown:true}));
  assert.throws(()=>vaultSyncHeadSigningBytes({...r,revision:Number.MAX_SAFE_INTEGER+1}));
  let invoked=false;const accessor={...r};Object.defineProperty(accessor,'indexDigest',{get(){invoked=true;return r.indexDigest;}});
  assert.throws(()=>vaultSyncHeadSigningBytes(accessor));assert.equal(invoked,false);
});

test('vault head retained across reopen refuses forks, skips, downgrade and lost state',async()=>{
  const initial=signed(),indexedDB=new IDBFactory();
  const opts={name:'vault-reopen',owner,vaultId,anchor:vaultSyncHeadFloor(initial),now:()=>20,indexedDB};
  let store=await openVaultSyncHeadStore({...opts,create:true});
  const next=successor(initial,{minimumProfile:2});
  assert.deepEqual(await store.verifyCurrent(initial,current),initial);
  await assert.rejects(store.advance(initial,{...next,sig:'A'.repeat(86)},current));
  assert.deepEqual(await store.read(),vaultSyncHeadFloor(initial));
  await store.advance(initial,next,current);store.close();store=await openVaultSyncHeadStore(opts);
  assert.deepEqual(await store.verifyCurrent(next,current),next);
  assert.deepEqual(await store.advance(initial,next,current),next); // Exact interrupted retry.
  await assert.rejects(store.verifyCurrent(initial,current));
  await assert.rejects(store.advance(initial,successor(initial,{indexDigest:'45'.repeat(32)}),current));
  await assert.rejects(store.advance(next,successor(next,{minimumProfile:1}),current));
  await assert.rejects(store.advance(next,successor(next,{revision:4}),current));
  await assert.rejects(store.advance(next,successor(next,{previousDigest:'67'.repeat(32)}),current));
  store.close();
  await assert.rejects(openVaultSyncHeadStore({...opts,indexedDB:new IDBFactory()}));
});

test('competing signed heads have one committed winner, and history is checked during commit',async()=>{
  const initial=signed(),indexedDB=new IDBFactory();
  const opts={name:'vault-race',owner,vaultId,anchor:vaultSyncHeadFloor(initial),now:()=>20,indexedDB};
  const a=await openVaultSyncHeadStore({...opts,create:true}),b=await openVaultSyncHeadStore(opts);
  const candidates=[successor(initial),successor(initial,{indexDigest:'45'.repeat(32)})];
  const results=await Promise.allSettled([a.advance(initial,candidates[0]!,current),b.advance(initial,candidates[1]!,current)]);
  assert.equal(results.filter(r=>r.status==='fulfilled').length,1);
  const winner=candidates[results[0]!.status==='fulfilled'?0:1]!;
  assert.deepEqual(await a.read(),vaultSyncHeadFloor(winner));
  await assert.rejects(a.advance(winner,successor(winner),()=>({rotations:[],context:{...context,history:()=>({ok:false,reason:'missing-history'})}})));
  assert.deepEqual(await a.read(),vaultSyncHeadFloor(winner));
  await assert.rejects(a.verifyCurrent(winner,()=>({rotations:[],context:{...context,now:19}})));
  a.close();b.close();
});
