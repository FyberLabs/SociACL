/** Public ciphertext polling into the recipient-owned replay journal. */
import { sha256 } from '@noble/hashes/sha2.js';
import { data, hex, integer } from '../ids/src/util.js';
import type { ResolutionContext } from '../ids/src/index.js';
import type { FirstContactStore } from '../ids/src/first-contact-store.js';
import { openFirstContactRequest } from './first-contact-seal.ts';
import type { VerifiedFirstContact } from './first-contact.ts';

/** Bind this adapter to the configured Spanopticon origin, never a returned URL. */
export type FirstContactSource = (channelId:string,signal:AbortSignal)=>Promise<unknown>;
/** Transport returns decoded {id,ciphertext:Uint8Array} rows. No account or lane
 * grant is sent to storage. Invalid signatures are ignored; storage failures abort.
 * Plaintext is returned only after durable reservation and fresh re-verification.
 */
export async function pollFirstContact(store:FirstContactStore,source:FirstContactSource,epriv:string,
  senderState:()=>{rotations:readonly unknown[];context:ResolutionContext},timeoutMs=10000):Promise<readonly VerifiedFirstContact[]> {
  if(!integer(timeoutMs)||timeoutMs<1||timeoutMs>10000)throw Error('Invalid polling deadline');
  const descriptor=Object.freeze({...await store.descriptor()});
  const controller=new AbortController();let timer:ReturnType<typeof setTimeout>|undefined;
  try {
    const timeout=new Promise<never>((_,reject)=>{timer=setTimeout(()=>{controller.abort();reject(Error('First-contact timeout'));},timeoutMs);});
    const input=await Promise.race([Promise.resolve().then(()=>source(descriptor.channelId,controller.signal)),timeout]);
    if(!Array.isArray(input)||input.length>128)throw Error('Invalid public request batch');
    const rows:{id:string;ciphertext:Uint8Array}[]=[];let total=0;
    // Snapshot the entire bounded batch before any asynchronous journal operation.
    for(let i=0;i<input.length;i++) {
      const own=Object.getOwnPropertyDescriptor(input,String(i));
      if(!own||!('value' in own))throw Error('Invalid public request row');
      const parsed=data(own.value);if(!parsed.ok)throw Error('Invalid public request row');
      const row=parsed.value;
      if(Object.keys(row).sort().join()!=='ciphertext,id'||typeof row.id!=='string'||row.id.length!==64||
        !(row.ciphertext instanceof Uint8Array)||row.ciphertext.length<94||row.ciphertext.length>8192)throw Error('Invalid public request row');
      const ciphertext=new Uint8Array(row.ciphertext);total+=ciphertext.length;
      if(total>1048576||hex(sha256(ciphertext))!==row.id)throw Error('Invalid public request digest');
      rows.push({id:row.id,ciphertext});
    }
    const accepted:{ciphertext:Uint8Array;checkedAt:number}[]=[];
    for(const row of rows) {
      const state=senderState(),started=state.context.now;
      const opened=openFirstContactRequest(row.ciphertext,epriv,descriptor,state.rotations,state.context);
      if(!opened.ok)continue;
      const v=opened.value;
      if(!await store.reserve(descriptor,{replayKey:v.replayKey,requestId:v.requestId,replayUntil:v.replayUntil,
        expiresAt:v.request.expiresAt,envelope:row.ciphertext}))continue;
      const fresh=senderState();
      if(fresh.context.now<started)throw Error('First-contact clock rollback');
      const checked=openFirstContactRequest(row.ciphertext,epriv,descriptor,fresh.rotations,fresh.context);
      if(!checked.ok)continue; // Keep replay protection even if authorization expired during commit.
      accepted.push({ciphertext:row.ciphertext,checkedAt:fresh.context.now});
    }
    const current=await store.descriptor();
    for(const key of ['channelId','revision','encryptionEpub','expiresAt','maxLifetimeSeconds','maxMessageBytes'] as const) {
      if(current[key]!==descriptor[key])throw Error('First-contact descriptor changed');
    }
    const result:VerifiedFirstContact[]=[];
    for(const row of accepted) {
      const fresh=senderState();
      if(fresh.context.now<row.checkedAt)throw Error('First-contact clock rollback');
      const checked=openFirstContactRequest(row.ciphertext,epriv,descriptor,fresh.rotations,fresh.context);
      if(checked.ok)result.push(checked.value);
    }
    return Object.freeze(result);
  }finally{if(timer!==undefined)clearTimeout(timer);controller.abort();}
}
