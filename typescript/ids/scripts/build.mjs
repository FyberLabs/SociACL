import { copyFileSync, mkdirSync, readdirSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
const root = new URL('../', import.meta.url);
const dist = new URL('dist/', root);
rmSync(dist, { recursive: true, force: true });
execFileSync(process.execPath, [fileURLToPath(new URL('node_modules/typescript/bin/tsc', root)),
  '--strict', '--allowJs', '--checkJs', '--declaration', '--emitDeclarationOnly', '--noEmit', 'false',
  '--target', 'ES2022', '--module', 'NodeNext', '--moduleResolution', 'NodeNext',
  '--outDir', 'dist', ...readdirSync(new URL('src/',root)).filter(f=>f.endsWith('.js')).map(f=>'src/'+f)],
  { cwd: fileURLToPath(root), stdio: 'inherit' });
mkdirSync(dist, { recursive: true });
for (const name of readdirSync(new URL('src/',root)).filter(f=>f.endsWith('.js') || f.endsWith('.d.ts'))) {
  copyFileSync(new URL('src/'+name,root),new URL(name,dist));
}

// Browser consumer entrypoints bundle the reference contracts, never Node crypto.
const {build}=await import('esbuild');
const consumerEntries={
  'first-contact': "export {restorePendingFirstContacts} from '../../contract/first-contact-restore.ts'; export {prepareFirstContactSubmission} from '../../contract/first-contact-send.ts'; export {firstContactDescriptorFloor,observeFirstContactDescriptor} from '../../contract/first-contact-discovery.ts'; export {verifyFirstContactDescriptor,firstContactDescriptorBytes} from '../../contract/first-contact-descriptor.ts'; export {sealFirstContactRequestBrowser as sealFirstContactRequest,openFirstContactRequestBrowser as openFirstContactRequest} from '../../contract/first-contact-browser.ts'; export {pollFirstContact} from '../../contract/first-contact-poll.ts'; export {firstContactRequestBytes,parseFirstContactRequest,verifyFirstContactRequest} from '../../contract/first-contact.ts';",
  'independent-witness': "export {independentWitnessPolicyBytes,witnessRequestBytes,witnessReceiptBytes,verifyIndependentWitnesses} from '../../contract/independent-witness.ts'; export {independentWitnessTransitionDigest,advanceIndependentWitnessPolicy} from '../../contract/independent-witness-transition.ts'; export {collectIndependentWitnesses} from '../../contract/independent-witness-client.ts'; export {openIndependentWitnessPolicyStore} from '../../contract/independent-witness-store.ts';",
};
for(const [name,contents] of Object.entries(consumerEntries)){
  const result=await build({stdin:{contents,resolveDir:fileURLToPath(new URL('src/',root)),loader:'ts'},
    bundle:true,platform:'browser',format:'esm',target:'es2022',packages:'external',metafile:true,
    outfile:fileURLToPath(new URL(name+'.js',dist))});
  for(const input of Object.values(result.metafile.inputs))for(const ref of input.imports){
    if(ref.path.startsWith('node:'))throw Error('Node import in browser consumer');
  }
}
