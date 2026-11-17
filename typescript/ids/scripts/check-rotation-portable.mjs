// CI portability guard: browser preparation must not import Node-only modules.
import {build} from 'esbuild';
import {fileURLToPath} from 'node:url';
for(const entry of ['keyring-rotation.ts','rotation-mint.ts']){
const result=await build({entryPoints:[fileURLToPath(new URL(`../../contract/${entry}`,import.meta.url))],
  bundle:true,platform:'browser',format:'esm',write:false});
if(result.outputFiles.length!==1||result.outputFiles[0].contents.length===0)throw Error('rotation bundle missing');
console.log('Shared keyring rotation bundles for browsers.');

}
