// Scoped package-import contract check. Execution belongs only to CI.
if(process.env.GITHUB_ACTIONS!=='true')throw Error('Packed contract checks require CI');
import {execFileSync} from 'node:child_process';
import {mkdtempSync,writeFileSync,rmSync,readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
const root=fileURLToPath(new URL('../',import.meta.url)),temp=mkdtempSync(join(tmpdir(),'sociacl-browser-exports-'));
try{
  const packed=JSON.parse(execFileSync('npm',['pack','--ignore-scripts','--json','--pack-destination',temp],{cwd:root,encoding:'utf8'}));
  writeFileSync(join(temp,'package.json'),JSON.stringify({private:true,type:'module'}));
  execFileSync('npm',['install','--ignore-scripts','--no-audit','--no-fund','--cache',join(temp,'cache'),join(temp,packed[0].filename)],{cwd:temp,stdio:'inherit'});
  const keys=JSON.parse(readFileSync(new URL('test/test-keys.json',new URL('../',import.meta.url))));
  const source=`import {signMembershipAssent,signObjectSet,signGroupCancel,membershipSoul,objectSetSoul} from 'sociacl-ids/group-signing';
for(const fn of [signMembershipAssent,signObjectSet,signGroupCancel,membershipSoul,objectSetSoul])if(typeof fn!=='function')throw Error('Missing group signer');
const keys=${JSON.stringify(keys)},scalar=new Uint8Array(32);scalar[31]=1;
const set=keys.obj.replace('room_','set_');
const row=signObjectSet({owner:keys.p,object:keys.obj,predicate:'same-group',set,stated:1,hamState:1,issuedAt:1,cancels:[]},scalar,keys.p);
if(!row.sig||!Object.isFrozen(row)||row.owner!==keys.p)throw Error('Packed group producer failed');
let refused=false;try{signObjectSet({...row,sig:'injected'},scalar,keys.p);}catch{refused=true;}
if(!refused)throw Error('Packed signer accepted supplied signature');scalar.fill(0);
import {wrapGroupKeyToMembers,openGroupKeyReaderWrap} from 'sociacl-ids/group-reader-wrap';
for(const fn of [wrapGroupKeyToMembers,openGroupKeyReaderWrap])if(typeof fn!=='function')throw Error('Missing group reader API');
import {wrapItemDekToGroupEpoch,openGroupEpochWrap} from 'sociacl-ids/group-wrap';
for(const fn of [wrapItemDekToGroupEpoch,openGroupEpochWrap])if(typeof fn!=='function')throw Error('Missing group wrap API');
import {signPrivateMediaGrant,signPrivateMediaEpoch,signPrivateMediaFinalization,signPrivateMediaStatus,signPrivateMediaDeletion,signPrivateMediaGroupConfig} from 'sociacl-ids/private-media';
for(const fn of [signPrivateMediaGrant,signPrivateMediaEpoch,signPrivateMediaFinalization,signPrivateMediaStatus,signPrivateMediaDeletion,signPrivateMediaGroupConfig])if(typeof fn!=='function')throw Error('Missing media producer');
import {sealFirstContactRequest,openFirstContactRequest,pollFirstContact,restorePendingFirstContacts,prepareFirstContactSubmission} from 'sociacl-ids/first-contact';
import {openIndependentWitnessPolicyStore,advanceIndependentWitnessPolicy,collectIndependentWitnesses} from 'sociacl-ids/independent-witness';
for(const fn of [sealFirstContactRequest,openFirstContactRequest,pollFirstContact,restorePendingFirstContacts,prepareFirstContactSubmission,openIndependentWitnessPolicyStore,advanceIndependentWitnessPolicy,collectIndependentWitnesses])if(typeof fn!=='function')throw Error('Missing packed API');`;
  writeFileSync(join(temp,'check.ts'),source);
  execFileSync(process.execPath,[join(root,'node_modules/typescript/bin/tsc'),'--strict','--noEmit','--target','ES2022','--module','NodeNext','--moduleResolution','NodeNext','check.ts'],{cwd:temp,stdio:'inherit'});
  execFileSync(process.execPath,['check.ts'],{cwd:temp,stdio:'inherit'});
}finally{rmSync(temp,{recursive:true,force:true});}
