/** Explicit wallet-authorized next-key signing for an opaque prepared rotation. */
import {data,unb64} from '../ids/src/util.js';
import {signingBytes,signWithKeyring,checkRotationPublish,type PrincipalId} from '../ids/src/index.js';
import {exportPendingKeyring} from './keyring-browser.ts';
import {decodeKeyring} from './keyring-codec.ts';
import type {PendingKeyringRotation,KeyringState} from '../ids/src/keyring.js';
const rejected=():never=>{throw Error('recovery-rejected');};
export function signPendingWalletRotation(pending:PendingKeyringRotation,input:unknown,
 currentState:KeyringState):Readonly<Record<string,unknown>> {
 let plain:Uint8Array|undefined,scalar:Uint8Array|undefined;
 try{
  const parsed=data(input);
  if(!parsed.ok||Object.keys(parsed.value).sort().join()!=='authorizer,issuedAt,kind,nextEpub,nextKey,prevKey,principal,retainedLinks,seq,v')return rejected();
  const r=parsed.value,a=data(r.authorizer);
  if(!a.ok||Object.keys(a.value).sort().join()!=='kind,link,siwe'||a.value.kind!=='wallet')return rejected();
  const proof=data(a.value.siwe);
  if(!proof.ok||Object.keys(proof.value).sort().join()!=='message,signature'||
   typeof proof.value.message!=='string'||typeof proof.value.signature!=='string')return rejected();
  if(!Array.isArray(r.retainedLinks)||r.retainedLinks.length>1024)return rejected();
  const retainedLinks:string[]=[];
  for(let i=0;i<r.retainedLinks.length;i++){
   const descriptor=Object.getOwnPropertyDescriptor(r.retainedLinks,String(i));
   if(!descriptor||!('value' in descriptor)||typeof descriptor.value!=='string')return rejected();
   retainedLinks.push(descriptor.value);
  }
  const candidate={...r,retainedLinks,authorizer:{...a.value,siwe:{...proof.value}}};
  const draft=pending.draft;
  if(r.v!==1||r.kind!=='rotate'||r.principal!==draft.principal||r.seq!==draft.seq||r.prevKey!==draft.prevKey||
   r.nextKey!==draft.nextKey||r.nextEpub!==draft.nextEpub)return rejected();
  const transcript=signingBytes(candidate as any);if(!transcript.ok)return rejected();
  plain=exportPendingKeyring(pending,currentState);
  const fields=decodeKeyring(plain);scalar=unb64(fields.priv);
  const signature=signWithKeyring(scalar,transcript.value,fields.pub as PrincipalId);if(!signature.ok)return rejected();
  const state=currentState();
  const checked=checkRotationPublish({...candidate,nextSig:signature.value},[],fields.principal as PrincipalId,state.rotations,state.context);
  if(!checked.ok)return rejected();
  const final=exportPendingKeyring(pending,currentState);final.fill(0);
  const {attest:_,...request}=checked.value;
  return Object.freeze(request);
 }catch{return rejected();}
 finally{plain?.fill(0);scalar?.fill(0);}
}
