// Real-browser state transitions and restart belong only to the central schedule.
if(process.env.GITHUB_ACTIONS!=='true'||process.env.GITHUB_EVENT_NAME!=='schedule'||
  process.env.NIGHTLY_SUITE!=='sociacl-browser'||process.env.GITHUB_REPOSITORY!=='FyberLabs/SociACL')throw Error('Requires central nightly CI');
const {default:assert}=await import('node:assert/strict');
const {mkdtemp,rm}=await import('node:fs/promises');
const {tmpdir}=await import('node:os');const {join}=await import('node:path');
const {fileURLToPath}=await import('node:url');const {createServer}=await import('node:http');
const {build}=await import('esbuild');const {chromium}=await import('playwright');
const {p256}=await import('@noble/curves/nist.js');
const key=n=>{const bytes=new Uint8Array(32);bytes[31]=n;return bytes;};
const pub=n=>{const p=p256.getPublicKey(key(n),false);return Buffer.from(p.subarray(1,33)).toString('base64url')+'.'+Buffer.from(p.subarray(33)).toString('base64url');};
const time=1700000020,principal=pub(1);
const policy={id:'12'.repeat(32),epoch:1,threshold:3,maxFaulty:1,operators:[2,3,4,5].map(n=>({id:`operator-${n}`,keys:[{key:pub(n),notBefore:1699990000,notAfter:1700010000}]}))};
const {outputFiles}=await build({stdin:{contents:"export {openIndependentWitnessPolicyStore} from '../../contract/independent-witness-store.ts'; export {independentWitnessTransitionDigest} from '../../contract/independent-witness-transition.ts'; export {witnessRequestBytes,witnessReceiptBytes} from '../../contract/independent-witness.ts'; export {signWithKeyring,historyState} from './index.js';",resolveDir:fileURLToPath(new URL('../src/',import.meta.url)),loader:'js'},nodePaths:[fileURLToPath(new URL('../node_modules/',import.meta.url))],bundle:true,platform:'browser',format:'esm',write:false});
const server=createServer((req,res)=>{res.setHeader('Content-Type',req.url==='/witness.js'?'text/javascript':'text/html');res.end(req.url==='/witness.js'?outputFiles[0].text:'<!doctype html><title>Witness membership</title>');});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const url=`http://127.0.0.1:${server.address().port}`,profile=await mkdtemp(join(tmpdir(),'sociacl-witness-browser-'));let browser;
async function page(create=false){
  const p=await browser.newPage();await p.goto(url);
  await p.evaluate(async({policy,principal,time,create})=>{
    const api=await import('/witness.js');
    const scalar=n=>{const b=new Uint8Array(32);b[31]=n;return b;};
    const sign=(n,bytes,pub)=>{const s=api.signWithKeyring(scalar(n),bytes,pub);if(!s.ok)throw Error(s.reason);return s.value;};
    const ctx={now:time,jwks:{keys:[]},links:new Map(),revocations:[],pinnedIss:new Set(),policy:{allowedDomains:[],allowedUris:[],allowedChainIds:[],clockSkewSeconds:0},history:(p,at,until)=>({ok:true,value:api.historyState(p,[],at,until)})};
    const request=(epoch,digest)=>{const r={v:1,principal,operation:'rotate',recordDigest:digest,policyId:policy.id,epoch,issuedAt:time-20,expiresAt:time+200};return {...r,sig:sign(1,api.witnessRequestBytes(r),principal)};};
    const receipt=(r,n)=>{const operator=`operator-${n}`,observedAt=time-10;return {operator,observedAt,sig:sign(n,api.witnessReceiptBytes(r,operator,observedAt),policy.operators[n-2].keys[0].key)};};
    window.store=await api.openIndependentWitnessPolicyStore({name:'membership',principal,anchor:policy,create,now:()=>time});
    window.advance=next=>{const digest=api.independentWitnessTransitionDigest(policy,next),old=request(1,digest),fresh=request(2,digest);
      return window.store.advance(policy,next,old,[2,3,4].map(n=>receipt(old,n)),fresh,[2,3,4].map(n=>receipt(fresh,n)),()=>({rotations:[],context:ctx}));};
    window.collect=async candidate=>{let called=0;const r=request(candidate.epoch,'34'.repeat(32));
      const transport=new Map([2,3,4,5].map(n=>[`operator-${n}`,async input=>{called++;return receipt(input,n);}]));
      try{const value=await window.store.collect(r,r.recordDigest,candidate,()=>({rotations:[],context:ctx}),transport);return {ok:true,called,epoch:value.observation.epoch};}
      catch{return {ok:false,called};}
    };
  },{policy,principal,time,create});return p;
}
try{
  browser=await chromium.launchPersistentContext(profile,{headless:true});
  const a=await page(true),b=await page();
  const next={...policy,epoch:2},alternate={...next,operators:policy.operators.map(op=>({...op,keys:op.keys.map(k=>({...k,notAfter:k.notAfter+1}))}))};
  const attempts=await Promise.all([a,b].map((p,i)=>p.evaluate(async candidate=>{try{await window.advance(candidate);return true;}catch{return false;}},i?alternate:next)));
  assert.equal(attempts.filter(Boolean).length,1);const winner=attempts[0]?next:alternate;
  assert.equal((await a.evaluate(candidate=>window.collect(candidate),winner)).ok,true);
  await browser.close();browser=undefined;
  browser=await chromium.launchPersistentContext(profile,{headless:true});
  const reopened=await page();
  assert.deepEqual(await reopened.evaluate(candidate=>window.store.read(candidate),winner),winner);
  assert.deepEqual(await reopened.evaluate(candidate=>window.collect(candidate),policy),{ok:false,called:0});
  assert.deepEqual(await reopened.evaluate(candidate=>window.collect(candidate),winner),{ok:true,called:4,epoch:2});
  assert.equal(await reopened.evaluate(async candidate=>{try{await window.store.read(candidate);return true;}catch{return false;}},attempts[0]?alternate:next),false);
  console.log('Witness Chromium: competing membership, restart, stale-policy refusal and collection passed');
}finally{await browser?.close();await new Promise(resolve=>server.close(resolve));await rm(profile,{recursive:true,force:true});}
