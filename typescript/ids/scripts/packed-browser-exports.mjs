// Scoped package-import contract check. Execution belongs only to CI.
if(process.env.GITHUB_ACTIONS!=='true')throw Error('Packed contract checks require CI');
import {execFileSync} from 'node:child_process';
import {mkdtempSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
const root=fileURLToPath(new URL('../',import.meta.url)),temp=mkdtempSync(join(tmpdir(),'sociacl-browser-exports-'));
try{
  const packed=JSON.parse(execFileSync('npm',['pack','--ignore-scripts','--json','--pack-destination',temp],{cwd:root,encoding:'utf8'}));
  writeFileSync(join(temp,'package.json'),JSON.stringify({private:true,type:'module'}));
  execFileSync('npm',['install','--ignore-scripts','--no-audit','--no-fund','--cache',join(temp,'cache'),join(temp,packed[0].filename)],{cwd:temp,stdio:'inherit'});
  const source=`import {signPrivateMediaGrant,signPrivateMediaEpoch,signPrivateMediaFinalization,signPrivateMediaStatus,signPrivateMediaDeletion} from 'sociacl-ids/private-media';
for(const fn of [signPrivateMediaGrant,signPrivateMediaEpoch,signPrivateMediaFinalization,signPrivateMediaStatus,signPrivateMediaDeletion])if(typeof fn!=='function')throw Error('Missing media producer');
import {sealFirstContactRequest,openFirstContactRequest,pollFirstContact,restorePendingFirstContacts,prepareFirstContactSubmission} from 'sociacl-ids/first-contact';
import {openIndependentWitnessPolicyStore,advanceIndependentWitnessPolicy,collectIndependentWitnesses} from 'sociacl-ids/independent-witness';
for(const fn of [sealFirstContactRequest,openFirstContactRequest,pollFirstContact,restorePendingFirstContacts,prepareFirstContactSubmission,openIndependentWitnessPolicyStore,advanceIndependentWitnessPolicy,collectIndependentWitnesses])if(typeof fn!=='function')throw Error('Missing packed API');`;
  writeFileSync(join(temp,'check.ts'),source);
  execFileSync(process.execPath,[join(root,'node_modules/typescript/bin/tsc'),'--strict','--noEmit','--target','ES2022','--module','NodeNext','--moduleResolution','NodeNext','check.ts'],{cwd:temp,stdio:'inherit'});
  execFileSync(process.execPath,['check.ts'],{cwd:temp,stdio:'inherit'});
}finally{rmSync(temp,{recursive:true,force:true});}
