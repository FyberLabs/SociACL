// Real HTTPS + authenticated POST + IndexedDB. Temporary TLS and public fixture
// signing keys are test-only; production never disables TLS verification.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, basename } from 'node:path';
import { createServer } from 'node:https';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { chromium } from 'playwright';
import { p256 } from '@noble/curves/nist.js';
const f = JSON.parse(await readFile(new URL('../../../vectors/ids/witness-checkpoint.json', import.meta.url)));
const lifecycle = JSON.parse(await readFile(new URL('../../../vectors/ids/witness-lifecycle.json', import.meta.url)));
const initial = lifecycle.accept.find(c=>c.name==='bootstrap-at-floor').input.steps[0].envelope;
function sign(doc,scalar,kind) {
  const payload=Buffer.from(JSON.stringify(doc)),signature=p256.sign(Buffer.concat([Buffer.from(`sociacl-witness-${kind}-v1\n`),payload]),
    Buffer.from(scalar.toString(16).padStart(64,'0'),'hex'),{lowS:true});
  return JSON.stringify({type:`sociacl-witness-${kind}-envelope-v1`,payload:payload.toString('base64url'),signature:Buffer.from(signature).toString('base64url')});
}
function response(request,state=f.accept[0].canonical.state) {
  const doc={...f.accept[0].canonical,state,challenge:request.challenge};
  return [sign(doc,18,'checkpoint'),sign({type:'sociacl-witness-policy-v1',audience:doc.audience,revision:state.revision,
    issuedAt:doc.issuedAt,expiresAt:doc.expiresAt,jwks:state.jwks},17,'policy')];
}

const {outputFiles}=await build({entryPoints:['checkpoint-client.js','indexeddb.js'].map(n=>fileURLToPath(new URL('../src/'+n,import.meta.url))),
  bundle:true,platform:'browser',format:'esm',outdir:'unused',write:false});
const scripts=new Map(outputFiles.map(f=>['/'+basename(f.path),f.text]));
const temp=await mkdtemp(join(tmpdir(),'sociacl-checkpoint-https-'));
let context,server,mode='normal',oldResponse,redirectHits=0;
try {
  execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-days','1','-keyout',join(temp,'key.pem'),
    '-out',join(temp,'cert.pem'),'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1'],{stdio:'ignore'});
  server=createServer({key:await readFile(join(temp,'key.pem')),cert:await readFile(join(temp,'cert.pem'))},async(req,res)=>{
    if(scripts.has(req.url)){res.setHeader('Content-Type','text/javascript');res.end(scripts.get(req.url));return;}
    if(req.url==='/redirect-target'){redirectHits++;res.end();return;}
    if(req.url==='/checkpoint'){
      assert.equal(req.method,'POST');assert.equal(req.headers.authorization,'Bearer test-enrollment-token');
      assert.equal(req.headers.cookie,undefined);assert.equal(req.headers.referer,undefined);
      assert.equal(req.headers['content-type'],'application/json');
      let body='';for await(const chunk of req)body+=chunk;
      const request=JSON.parse(body);assert.equal(request.operation,'refresh');assert.equal(request.client,f.context.client);
      const [checkpoint,policy]=response(request),bundle=JSON.stringify({type:'sociacl-witness-checkpoint-response-v1',checkpoint,policy});
      res.setHeader('Content-Type','application/json');res.setHeader('Cache-Control','no-store');
      if(mode==='redirect'){res.writeHead(307,{Location:'/redirect-target'});res.end();return;}
      if(mode==='stall'){res.writeHead(200);res.flushHeaders();return;}
      if(mode==='unauthorized'){res.writeHead(401);res.end('{}');return;}
      if(mode==='replay'){res.end(oldResponse);return;}
      oldResponse=bundle;res.end(bundle);return;
    }
    res.setHeader('Content-Type','text/html');res.end('<!doctype html><title>Checkpoint client acceptance</title>');
  });
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  const origin=`https://127.0.0.1:${server.address().port}`,profile=join(temp,'profile');
  async function start(initialize=false){
    context=await chromium.launchPersistentContext(profile,{headless:true,ignoreHTTPSErrors:true});
    const page=await context.newPage();await page.goto(origin);
    await page.evaluate(async({config,initial,initialize,url})=>{
      document.cookie='must-not-send=secret; Secure';
      const options={...config,minimumRevision:7,name:'checkpoint-https',now:()=>config.now,url,timeoutMs:1000,
        getAccessToken:async()=>'test-enrollment-token'};
      if(initialize){const {openWitnessPolicyStore}=await import('/indexeddb.js');const old=await openWitnessPolicyStore(options);await old.bootstrap(initial);old.close();}
      const {openWitnessCheckpointClient}=await import('/checkpoint-client.js');window.client=await openWitnessCheckpointClient(options);
    },{config:f.context,initial,initialize,url:origin+'/checkpoint'});return page;
  }
  let page=await start(true);
  const state=await page.evaluate(()=>window.client.refresh());assert.equal(state.revision,8);
  assert.deepEqual(await page.evaluate(()=>window.client.readFresh()),state);
  for(const failure of ['replay','unauthorized','redirect','stall']){
    mode=failure;
    assert.equal(await page.evaluate(async()=>{try{await window.client.refresh();return true;}catch{return false;}}),false);
    assert.equal(await page.evaluate(async()=>{try{await window.client.readFresh();return true;}catch{return false;}}),false);
    assert.deepEqual(await page.evaluate(()=>window.client.readInstalled()),state);
  }
  assert.equal(redirectHits,0);
  await context.close();context=undefined;page=await start();
  assert.deepEqual(await page.evaluate(()=>window.client.readInstalled()),state);
  assert.equal(await page.evaluate(async()=>{try{await window.client.readFresh();return true;}catch{return false;}}),false);
  mode='normal';assert.deepEqual(await page.evaluate(()=>window.client.refresh()),state);
  console.log('Chromium HTTPS checkpoint client: authenticated challenge POST, durable install, replay/outage/redirect/timeout refusal, cookie omission and restart renewal passed');
}finally{
  await context?.close();if(server){server.closeAllConnections();await new Promise(r=>server.close(r));}
  await rm(temp,{recursive:true,force:true});
}
