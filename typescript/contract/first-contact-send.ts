/** Authenticated browser sender composition; transport acknowledgement is not acceptance. */
import { sha256 } from '@noble/hashes/sha2.js';
import { hex, integer } from '../ids/src/util.js';
import type { PrincipalId, ResolutionContext } from '../ids/src/index.js';
import type { FirstContactFloor } from '../ids/src/first-contact-floor.js';
import { verifyFirstContactRequest } from './first-contact.ts';
import { verifyFirstContactDescriptor } from './first-contact-descriptor.ts';
import { firstContactDescriptorFloor } from './first-contact-discovery.ts';
import { sealFirstContactRequestBrowser } from './first-contact-browser.ts';

export type FirstContactState = () => {rotations:readonly unknown[];context:ResolutionContext};
/** Must be bound to configured Spanopticon, never a descriptor-supplied URL. */
export type FirstContactAppend = (channel:string,ciphertext:Uint8Array,signal:AbortSignal)=>Promise<unknown>;
/** Prepare once and retain this object across ambiguous responses. Every submit
 * retries identical ciphertext, with fresh identity, expiry and floor checks.
 * The caller still needs independently authenticated descriptor discovery and
 * disable freshness. A retained floor alone cannot supply either guarantee. */
export async function prepareFirstContactSubmission(input:unknown,advertisement:unknown,
  owner:PrincipalId,floor:FirstContactFloor,recipientState:FirstContactState,senderState:FirstContactState) {
  if(floor.owner!==owner)throw Error('Wrong descriptor floor owner');
  const initial=recipientState();
  const parsed=verifyFirstContactDescriptor(advertisement,owner,1,initial.rotations,initial.context);
  if(!parsed.ok)throw Error(parsed.reason);
  const descriptor=parsed.value, expected=firstContactDescriptorFloor(descriptor);
  const sender=senderState();
  const verified=verifyFirstContactRequest(input,sender.rotations,sender.context,descriptor.descriptor);
  if(!verified.ok)throw Error(verified.reason);
  const request=verified.value.request;
  let recipientTime=initial.context.now,senderTime=sender.context.now,clockFailed=false;
  function authenticate(now:number) {
    const recipient=recipientState(),sender=senderState();
    if(clockFailed||!integer(recipient.context.now)||!integer(sender.context.now)||
      recipient.context.now<recipientTime||sender.context.now<senderTime){clockFailed=true;throw Error('First-contact clock rollback');}
    recipientTime=recipient.context.now;senderTime=sender.context.now;
    const d=verifyFirstContactDescriptor(descriptor,owner,expected.revision,recipient.rotations,
      {...recipient.context,now:Math.max(now,recipientTime)});
    const r=verifyFirstContactRequest(request,sender.rotations,{...sender.context,now:Math.max(now,senderTime)},descriptor.descriptor);
    if(!d.ok||!r.ok)throw Error('First-contact authorization changed');
  }
  await floor.observe(expected,authenticate);
  const ciphertext=await sealFirstContactRequestBrowser(request,descriptor.descriptor);
  const ciphertextId=hex(sha256(ciphertext));
  await floor.observe(expected,authenticate);
  return Object.freeze({ciphertextId,
    async submit(append:FirstContactAppend,timeoutMs=10000):Promise<string> {
      if(!integer(timeoutMs)||timeoutMs<1||timeoutMs>10000)throw Error('Invalid submission deadline');
      await floor.observe(expected,authenticate);
      const controller=new AbortController();let timer:ReturnType<typeof setTimeout>|undefined;
      try {
        const timeout=new Promise<never>((_,reject)=>{timer=setTimeout(()=>{controller.abort();reject(Error('First-contact submission ambiguous'));},timeoutMs);});
        const result=await Promise.race([Promise.resolve().then(()=>append(descriptor.descriptor.channelId,new Uint8Array(ciphertext),controller.signal)),timeout]);
        if(result!==ciphertextId)throw Error('First-contact acknowledgement mismatch');
        await floor.observe(expected,authenticate);
        return ciphertextId;
      }finally{if(timer!==undefined)clearTimeout(timer);controller.abort();}
    },
  });
}
