/** Recover pending inbox plaintext after restart without replaying network admission. */
import { sha256 } from '@noble/hashes/sha2.js';
import { hex, integer } from '../ids/src/util.js';
import type { FirstContactStore, Row } from '../ids/src/first-contact-store.js';
import type { ResolutionContext } from '../ids/src/index.js';
import { openFirstContactRequestBrowser } from './first-contact-browser.ts';
import { verifyFirstContactRequest, type VerifiedFirstContact } from './first-contact.ts';

function snapshot(rows:Row[]):Row[] {
  if(!Array.isArray(rows)||rows.length>256)throw Error('Invalid pending request batch');
  return rows.map(row=>{
    if(!(row.envelope instanceof Uint8Array)||row.envelope.length<94||row.envelope.length>8192)throw Error('Invalid pending envelope');
    return {...row,envelope:new Uint8Array(row.envelope)};
  });
}
/** The store and identity providers are trusted local adapters. Fresh sender
 * history remains mandatory: a previously admitted request can have expired or
 * lost its signing authority. No reserve, acceptance or acknowledgement occurs.
 * The final committed snapshot excludes decisions made while crypto was pending;
 * later user decisions still perform their own atomic journal checks. */
export async function restorePendingFirstContacts(store:FirstContactStore,epriv:string,
  senderState:()=>{rotations:readonly unknown[];context:ResolutionContext}):Promise<readonly VerifiedFirstContact[]> {
  const descriptor=Object.freeze({...await store.descriptor()});
  const rows=snapshot(await store.pending(descriptor));
  let time=-1,failed=false;
  const current=()=>{
    const state=senderState();
    if(failed||!integer(state.context.now)||state.context.now<time){failed=true;throw Error('First-contact clock rollback');}
    time=state.context.now;return state;
  };
  const opened=new Map<string,{value:VerifiedFirstContact;digest:string}>();
  for(const row of rows){
    const result=await openFirstContactRequestBrowser(row.envelope,epriv,descriptor,current);
    if(!result.ok)continue;
    const v=result.value;
    if(row.status!=='pending'||row.revision!==descriptor.revision||row.replayKey!==v.replayKey||
      row.requestId!==v.requestId||row.replayUntil!==v.replayUntil||row.expiresAt!==v.request.expiresAt)continue;
    opened.set(v.replayKey,{value:v,digest:hex(sha256(row.envelope))});
  }
  // This second transaction checks status and descriptor atomically after decrypt.
  const pending=snapshot(await store.pending(descriptor)),fresh=current();
  const result:VerifiedFirstContact[]=[];
  for(const row of pending){
    const candidate=opened.get(row.replayKey);if(!candidate)continue;
    const v=candidate.value;
    if(row.status==='pending'&&row.revision===descriptor.revision&&row.requestId===v.requestId&&
      row.replayUntil===v.replayUntil&&row.expiresAt===v.request.expiresAt&&
      candidate.digest===hex(sha256(row.envelope))&&
      verifyFirstContactRequest(v.request,fresh.rotations,fresh.context,descriptor).ok)result.push(v);
  }
  return Object.freeze(result);
}
