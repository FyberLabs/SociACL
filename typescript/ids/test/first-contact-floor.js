import test from 'node:test';
import assert from 'node:assert/strict';
import { IDBFactory, IDBObjectStore } from 'fake-indexeddb';
import { openFirstContactFloor } from '../src/first-contact-floor.js';
const owner='axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY.T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU';
const anchor={revision:1,digest:'ab'.repeat(32)},next={revision:2,digest:'cd'.repeat(32)};
const options=()=>({name:'floors',owner,anchor,now:()=>100,create:true,indexedDB:new IDBFactory()});
const verify=()=>{};
test('descriptor floors survive restart and refuse rollback or same-revision equivocation',async()=>{
  const o=options();let a=await openFirstContactFloor(o);await a.observe(next,verify);a.close();
  a=await openFirstContactFloor({...o,create:false});assert.deepEqual(await a.read(),next);
  await assert.rejects(a.observe(anchor,verify));await assert.rejects(a.observe({...next,digest:anchor.digest},verify));
  assert.deepEqual(await a.observe(next,verify),next);a.close();
  await assert.rejects(openFirstContactFloor({...o,now:()=>99}));
  await assert.rejects(openFirstContactFloor({...o,anchor:{...next,digest:anchor.digest}}));
});
test('competing connections preserve one descriptor per revision',async()=>{
  const o=options(),a=await openFirstContactFloor(o),b=await openFirstContactFloor({...o,create:false});
  const results=await Promise.allSettled([a.observe(next,verify),b.observe({...next,digest:'ef'.repeat(32)},verify)]);
  assert.equal(results.filter(r=>r.status==='fulfilled').length,1);a.close();b.close();
});
test('missing state, failed verification, aborts and expiry across commit yield no accepted result',async()=>{
  const o=options();await assert.rejects(openFirstContactFloor({...o,create:false}));
  const a=await openFirstContactFloor(o);
  await assert.rejects(a.observe(next,async()=>{}));
  await assert.rejects(a.observe(next,()=>{throw Error('invalid signature');}));assert.deepEqual(await a.read(),anchor);
  const put=IDBObjectStore.prototype.put;
  IDBObjectStore.prototype.put=function(){throw Error('quota');};
  try{await assert.rejects(a.observe(next,verify));}finally{IDBObjectStore.prototype.put=put;}
  assert.deepEqual(await a.read(),anchor);
  let calls=0;await assert.rejects(a.observe(next,()=>{if(++calls===2)throw Error('expired during commit');}));
  assert.deepEqual(await a.read(),next); // Retain observed protection, expose no stale descriptor.
  a.close();
});
