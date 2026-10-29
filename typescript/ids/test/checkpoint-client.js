import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { IDBFactory, IDBObjectStore } from 'fake-indexeddb';
import { p256 } from '@noble/curves/nist.js';
import { openWitnessPolicyStore } from '../src/indexeddb.js';
import { openWitnessCheckpointClient, MAX_CHECKPOINT_RESPONSE_BYTES } from '../src/checkpoint-client.js';
const f=JSON.parse(readFileSync(new URL('../../../vectors/ids/witness-checkpoint.json',import.meta.url)));
const lifecycle=JSON.parse(readFileSync(new URL('../../../vectors/ids/witness-lifecycle.json',import.meta.url)));
const initial=lifecycle.accept.find(c=>c.name==='bootstrap-at-floor').input.steps[0].envelope;
function sign(doc,scalar,kind){
  const payload=Buffer.from(JSON.stringify(doc));
  const signature=p256.sign(Buffer.concat([Buffer.from(`sociacl-witness-${kind}-v1\n`),payload]),
    Buffer.from(scalar.toString(16).padStart(64,'0'),'hex'),{lowS:true});
  return JSON.stringify({type:`sociacl-witness-${kind}-envelope-v1`,payload:payload.toString('base64url'),signature:Buffer.from(signature).toString('base64url')});
}
function bundle(init, changes={}) {
  const doc={...f.accept[0].canonical,challenge:JSON.parse(init.body).challenge,...changes};
  return JSON.stringify({type:'sociacl-witness-checkpoint-response-v1',checkpoint:sign(doc,18,'checkpoint'),
    policy:sign({type:'sociacl-witness-policy-v1',audience:doc.audience,revision:doc.state.revision,
      issuedAt:doc.issuedAt,expiresAt:doc.expiresAt,jwks:doc.state.jwks},17,'policy')});
}
const response=(body,init={})=>new Response(body,{headers:{'Content-Type':'application/json'},...init});
async function setup(extra={},empty=false){
  const time={wall:f.context.now,mono:1000};
  const options={...f.context,name:'checkpoint-client',minimumRevision:7,indexedDB:new IDBFactory(),
    now:()=>time.wall,monotonic:()=>time.mono,url:'https://management.example/checkpoint',
    getAccessToken:async()=>'test-enrollment-token',fetch:async(_,init)=>response(bundle(init)),...extra};
  if(!empty){const old=await openWitnessPolicyStore(options);await old.bootstrap(initial);old.close();}
  return {time,options,client:await openWitnessCheckpointClient(options)};
}
for(const url of ['http://example.test','/relative','https://user:password@example.test','https://example.test/?token=secret','https://example.test/#part'])
  test('reject unsafe endpoint '+url,async()=>{await assert.rejects(setup({url}));});
for(const timeoutMs of [0,-1,60001,1.5,Infinity])
  test('reject invalid timeout '+timeoutMs,async()=>{await assert.rejects(setup({timeoutMs}));});
test('management credential provider is mandatory',async()=>{await assert.rejects(setup({getAccessToken:undefined}));});
test('authenticated POST is bound to fresh request; only committed trust survives restart',async()=>{
  const requests=[];
  const {client,options}=await setup({fetch:async(url,init)=>{
    assert.equal(url,'https://management.example/checkpoint');
    assert.equal(init.method,'POST');assert.equal(init.credentials,'omit');assert.equal(init.redirect,'error');
    assert.equal(init.cache,'no-store');assert.equal(init.referrerPolicy,'no-referrer');
    assert.equal(init.headers.Authorization,'Bearer test-enrollment-token');
    const request=JSON.parse(init.body);requests.push(request);
    assert.deepEqual(Object.keys(request).sort(),['audience','challenge','client','operation','rootEpoch','type']);
    assert.equal(request.operation,'refresh');assert.equal(request.type,'sociacl-witness-checkpoint-request-v1');
    assert.equal(request.client,f.context.client);assert.equal(request.rootEpoch,f.context.rootEpoch);
    return response(bundle(init));
  }});
  try {
    assert.equal(requests.length,0);await assert.rejects(client.readFresh());
    assert.equal((await client.readInstalled()).revision,7);assert.equal(requests.length,0);
    const state=await client.refresh();assert.deepEqual(state,f.accept[0].canonical.state);
    assert.deepEqual(await client.readFresh(),state);await client.refresh();
    assert.notEqual(requests[0].challenge,requests[1].challenge);
    client.close();const reopened=await openWitnessCheckpointClient(options);
    try{assert.deepEqual(await reopened.readInstalled(),state);await assert.rejects(reopened.readFresh());}
    finally{reopened.close();}
  }finally{client.close();}
});
test('missing state cannot request credentials, download or implicitly bootstrap',async()=>{
  let calls=0;const {client}=await setup({getAccessToken:async()=>{calls++;return 'token';}},true);
  try{await assert.rejects(client.refresh());assert.equal(calls,0);assert.equal(client.bootstrap,undefined);}
  finally{client.close();}
});
for(const token of ['', 'has space','a\r\nInjected:value','x'.repeat(8193),null])
  test('invalid credential cannot reach transport '+String(token).slice(0,12),async()=>{
    let calls=0;const {client}=await setup({getAccessToken:async()=>token,fetch:async()=>{calls++;throw Error();}});
    try{await assert.rejects(client.refresh());assert.equal(calls,0);}finally{client.close();}
  });
for(const kind of ['unauthorized','redirect','mime','declared-size','stream-size','utf8','duplicate','extra','wrong-challenge','wrong-policy','expired','network'])
  test(kind+' refuses renewal and invalidates previous freshness',async()=>{
    let fail=false;const {client}=await setup({fetch:async(_,init)=>{
      if(!fail)return response(bundle(init));
      if(kind==='unauthorized')return response('{}',{status:401});
      if(kind==='redirect')return response('{}',{status:302,headers:{Location:'https://other.test'}});
      if(kind==='mime')return response(bundle(init),{headers:{'Content-Type':'text/plain'}});
      if(kind==='declared-size')return response('{}',{headers:{'Content-Type':'application/json','Content-Length':String(MAX_CHECKPOINT_RESPONSE_BYTES+1)}});
      if(kind==='stream-size')return response(' '.repeat(MAX_CHECKPOINT_RESPONSE_BYTES+1));
      if(kind==='utf8')return response(new Uint8Array([0xff]));
      if(kind==='duplicate')return response(bundle(init).replace('{','{"type":"sociacl-witness-checkpoint-response-v1",'));
      if(kind==='extra')return response(bundle(init).replace('{','{"extra":true,'));
      if(kind==='wrong-challenge')return response(bundle(init,{challenge:f.context.challenge}));
      if(kind==='wrong-policy'){const b=JSON.parse(bundle(init));b.policy=initial;return response(JSON.stringify(b));}
      if(kind==='expired')return response(bundle(init,{issuedAt:f.context.now-60,expiresAt:f.context.now}));
      throw Error('provider-secret-must-not-leak');
    }});
    try{const state=await client.refresh();fail=true;await assert.rejects(client.refresh(),e=>e.message==='Checkpoint refresh failed');
      await assert.rejects(client.readFresh());assert.deepEqual(await client.readInstalled(),state);
    }finally{client.close();}
  });
test('old response cannot satisfy a fresh retry',async()=>{
  let previous;const {client}=await setup({fetch:async(_,init)=>{previous??=bundle(init);return response(previous);}});
  try{await client.refresh();await assert.rejects(client.refresh());await assert.rejects(client.readFresh());}
  finally{client.close();}
});
for(const stage of ['credentials','fetch','body'])test('timeout bounds uncooperative '+stage,async()=>{
  let cancelled=false;
  const extra={timeoutMs:25};
  if(stage==='credentials')extra.getAccessToken=()=>new Promise(()=>{});
  if(stage==='fetch')extra.fetch=()=>new Promise(()=>{});
  if(stage==='body')extra.fetch=async()=>response(new ReadableStream({pull:()=>new Promise(()=>{}),cancel:()=>{cancelled=true;}}));
  const {client}=await setup(extra);
  try{await assert.rejects(client.refresh());await assert.rejects(client.readFresh());assert.equal((await client.readInstalled()).revision,7);
    if(stage==='body')assert.equal(cancelled,true);
  }finally{client.close();}
});
for(const action of ['abort','cancel','close'])test(action+' cancels an in-flight response without late installation',async()=>{
  let deliver, init, started;const ready=new Promise(r=>started=r);
  const {client}=await setup({fetch:(_,request)=>{init=request;started();return new Promise(r=>deliver=r);}});
  const controller=new AbortController(), pending=client.refresh({signal:controller.signal});
  await ready;
  if(action==='abort')controller.abort();else client[action]();
  await assert.rejects(pending);
  const late=response(bundle(init));deliver(late);await new Promise(r=>setTimeout(r,0));
  assert.ok(late.bodyUsed);
  if(action!=='close'){assert.equal((await client.readInstalled()).revision,7);await assert.rejects(client.readFresh());}
  client.close();
});
test('superseded failure cannot invalidate the newer successful lease',async()=>{
  let deliver,oldInit,started,calls=0;const ready=new Promise(r=>started=r);
  const {client}=await setup({fetch:(_,init)=>{if(++calls===1){oldInit=init;started();return new Promise(r=>deliver=r);}return Promise.resolve(response(bundle(init)));}});
  try{const first=client.refresh();const rejected=assert.rejects(first);await ready;
    const state=await client.refresh();await rejected;deliver(response(bundle(oldInit)));await new Promise(r=>setTimeout(r,0));
    assert.deepEqual(await client.readFresh(),state);
  }finally{client.close();}
});
test('abort after commit preserves historical evidence but grants no fresh lease',async()=>{
  const {client}=await setup();const original=IDBObjectStore.prototype.put;const controller=new AbortController();
  IDBObjectStore.prototype.put=function(...args){const result=original.apply(this,args);this.transaction.addEventListener('complete',()=>controller.abort());return result;};
  try{await assert.rejects(client.refresh({signal:controller.signal}));await assert.rejects(client.readFresh());
    assert.equal((await client.readInstalled()).revision,8);
  }finally{IDBObjectStore.prototype.put=original;client.close();}
});
test('exact response cap is accepted across streamed chunks',async()=>{
  const {client}=await setup({fetch:async(_,init)=>{
    const body=bundle(init), bytes=new TextEncoder().encode(body+' '.repeat(MAX_CHECKPOINT_RESPONSE_BYTES-Buffer.byteLength(body)));
    return response(new ReadableStream({start(c){for(let i=0;i<bytes.length;i+=65537)c.enqueue(bytes.slice(i,i+65537));c.close();}}));
  }});
  try{assert.equal((await client.refresh()).revision,8);}finally{client.close();}
});
test('an overdue timer cannot accept a response after an event-loop stall',async()=>{
  const {client}=await setup({timeoutMs:50,fetch:async(_,init)=>{
    const result=response(bundle(init)),end=performance.now()+80;
    while(performance.now()<end){} // Simulate synchronous transport blocking timers.
    return result;
  }});
  try{await assert.rejects(client.refresh());assert.equal((await client.readInstalled()).revision,7);await assert.rejects(client.readFresh());}
  finally{client.close();}
});
test('already aborted refresh blocks old freshness without contacting credentials',async()=>{
  let calls=0;const {client}=await setup({getAccessToken:async()=>{calls++;return 'token';}});
  try{await client.refresh();const controller=new AbortController();controller.abort();
    await assert.rejects(client.refresh({signal:controller.signal}));assert.equal(calls,1);await assert.rejects(client.readFresh());
  }finally{client.close();}
});
test('credential failures are sanitized and block previously fresh trust',async()=>{
  let fail=false;const {client}=await setup({getAccessToken:async()=>{if(fail)throw Error('private-credential');return 'token';}});
  try{await client.refresh();fail=true;await assert.rejects(client.refresh(),e=>e.message==='Checkpoint refresh failed');await assert.rejects(client.readFresh());}
  finally{client.close();}
});
