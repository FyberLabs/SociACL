// Executed from an isolated packed-package directory by CI, never shared TEST.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {importKeyring,exportKeyring,validateKeyring,closeKeyring,openKeyringContent} from 'sociacl-ids/keyring';
import {historyState,wrapItemDekToReaders} from 'sociacl-ids';
import {Sender,Receiver,reconcile} from 'sea-device-link';
const vectors=JSON.parse(readFileSync(process.env.KEYRING_VECTOR,'utf8'));
const records=JSON.parse(readFileSync(process.env.KEYRING_RECORDS,'utf8'));
const v=vectors.accept[1],raw=new Uint8Array(Buffer.from(v.encodedHex,'hex'));
const {principal,pub,epub,rotationSeq}=v.fields,identity={principal,pub,epub,rotationSeq};
let unavailable=false;
const state=()=>{
 if(unavailable)throw Error('owner unavailable');
 return {rotations:v.rotationNames.map(name=>records.accept.find(r=>r.name===name).input),context:{
  jwks:records.context.jwks,links:new Map(records.context.links),revocations:[],now:records.context.now,
  policy:records.context.policy,pinnedIss:new Set(records.context.pinnedIss),genesisEpubBindings:v.genesisBindings,
  history:(p,at,until)=>records.context.authenticatedAccounts.includes(p)?{ok:true,value:historyState(p,[],at,until)}:{ok:false,reason:'missing-history'}};
};
const authority={
 async validateKeyring(bytes,expected){validateKeyring(bytes,expected,state);},
 // Synthetic owner checkpoint for the SDK contract; NOT a production ACL adapter.
 async current(binding){assert.deepEqual(binding.identity,identity);state();return {revision:'synthetic-current',validUntil:binding.expiresAt};},
};
const source=importKeyring(raw,identity,state),encoded=exportKeyring(source,state);
const scope={sourceOrigin:'https://source.example',destinationOrigin:'https://destination.example',application:'keyring-contract',tenant:'synthetic',audience:'ci'};
const receiver=await Receiver.create(scope),sender=await Sender.create({request:receiver.request,expectedScope:scope,identity,keyring:encoded,authority});
encoded.fill(0);closeKeyring(source);
await receiver.bind(sender.offer);
assert.equal(sender.comparison,receiver.comparison);sender.confirm(receiver.comparison);receiver.confirm(sender.comparison);
let packet,done,stored,imported,commits=0;
const transport={async send(_,p){packet=structuredClone(p);},async receive(){return structuredClone(packet);},async complete(_,c){done=structuredClone(c);},async completed(){return done;}};
const storage={
 async lookup(binding){if(!stored)return null;assert.deepEqual(binding,stored.binding);return structuredClone(stored.completion);},
 async commit(input){
  await input.beforeCommit();assert.equal(input.signal.aborted,false);
  imported=importKeyring(input.keyring,input.binding.identity,state);
  stored=structuredClone({binding:input.binding,completion:input.completion});commits++;
 },
};
await sender.send(transport);
await assert.rejects(receiver.receive({...transport,async complete(){throw Error('lost acknowledgement');}},authority,storage),e=>e.code==='transport');
assert.equal(commits,1);assert.equal(await reconcile(sender.binding,storage,transport),true);await sender.finish(transport);
assert.deepEqual(exportKeyring(imported,state),raw);
// Canonical browser wrapping can still decrypt to the retired key after transfer.
const wraps=JSON.parse(readFileSync(process.env.KEYRING_WRAP,'utf8')).witnessed;
const context={epoch:0,object:wraps.objectId,revisionId:wraps.revisionId};
const dek=new Uint8Array(32).fill(7);
const sealed=await wrapItemDekToReaders(dek,context,[{account:principal,pub,identityPub:pub,epub:v.fields.genesisEpub}],[principal]);
assert(sealed.ok);assert.deepEqual(await openKeyringContent(imported,sealed.value[0],context),dek);
unavailable=true;assert.throws(()=>exportKeyring(imported,state),/keyring-rejected/);closeKeyring(imported);
console.log('Packed SociACL keyring + merged SDK: full-keyring preservation, historical DEK, owner refusal and uncertain completion contracts passed');
