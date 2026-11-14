// Native/browser contracts execute only in CI.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,writeFileSync} from 'node:fs';
import {wrapItemDekToGroupEpoch,openGroupEpochWrap} from '../src/group-wrap.js';
const fixture=JSON.parse(readFileSync(new URL('../../../vectors/encrypted-discovery/sea-fixture.json',import.meta.url)));
const vector=JSON.parse(readFileSync(new URL('../../../vectors/encrypted-discovery/wrap.json',import.meta.url)));
const context={epoch:3,object:vector.object,group:vector.object.replace('item_','set_'),revisionId:fixture.revisionId};
const group=new Uint8Array(32).fill(0x33),dek=new Uint8Array(32).fill(0x11);
const seal=(key=dek,groupKey=group,scope=context)=>wrapItemDekToGroupEpoch(key,groupKey,scope);
const open=(wrap,key=group,scope=context)=>openGroupEpochWrap(wrap,key,scope);
test('fresh browser group wraps retain caller keys and open exact scope',async()=>{
 const first=await seal(),second=await seal();assert.equal(first.ok,true);assert.equal(second.ok,true);
 assert.notEqual(first.value.wrappedKey,second.value.wrappedKey);assert.ok(Object.isFrozen(first.value));
 assert.deepEqual((await open(first.value)).value,dek);
 assert.deepEqual(group,new Uint8Array(32).fill(0x33));assert.deepEqual(dek,new Uint8Array(32).fill(0x11));
 if(process.env.GROUP_WRAP_TS_VECTOR)writeFileSync(process.env.GROUP_WRAP_TS_VECTOR,JSON.stringify(first.value));
});
test('browser opens the actual Rust group wrap', {skip:!process.env.GROUP_WRAP_RUST_VECTOR},async()=>{
 const wrap=JSON.parse(readFileSync(process.env.GROUP_WRAP_RUST_VECTOR));assert.deepEqual((await open(wrap)).value,dek);
});
test('group wrap labels, key and independent scope must all match',async()=>{
 const wrap=(await seal()).value;
 for(const patch of [{scope:'group-key'},{target:'reader-epub'},{targetId:'other'},{group:'other'},{object:'other'},
  {epoch:4},{revisionId:'a'.repeat(64)},{extra:1},{wrappedKey:'00'},{wrappedKey:'00'.repeat(8193)},
  {wrappedKey:'01'+wrap.wrappedKey.slice(2)},{wrappedKey:wrap.wrappedKey.slice(0,-2)+(parseInt(wrap.wrappedKey.slice(-2),16)^1).toString(16).padStart(2,'0')}])assert.equal((await open({...wrap,...patch})).ok,false);
 const other=context.object.slice(0,-1)+'2';
 assert.equal((await open({...wrap,object:other},group,{...context,object:other})).ok,false);
 assert.equal((await open(wrap,new Uint8Array(32).fill(0x44))).ok,false);
 assert.equal((await open(wrap,group,{...context,epoch:4})).ok,false);
 for(const bad of [null,{}, {...context,extra:1},{...context,epoch:-0},{...context,epoch:NaN},
  {...context,group:'bad'},{...context,group:context.object},{...context,object:'bad'},{...context,revisionId:'bad'}]){
  assert.equal((await seal(dek,group,bad)).ok,false);assert.equal((await open(wrap,group,bad)).ok,false);
 }
 for(const key of [null,new Uint8Array(31),new Uint16Array(16)]){
  assert.equal((await seal(key)).ok,false);assert.equal((await seal(dek,key)).ok,false);assert.equal((await open(wrap,key)).ok,false);
 }
 assert.equal((await open(null)).ok,false);
});
test('group wrap inputs are detached before the first asynchronous operation',async()=>{
 const key=dek.slice(),groupKey=group.slice(),scope={...context};
 const pending=seal(key,groupKey,scope);key.fill(0);groupKey.fill(0);scope.epoch=4;
 const wrap=(await pending).value;assert.deepEqual((await open(wrap)).value,dek);
 let called=false;
 const getter=Object.defineProperty({...context},'group',{get(){called=true;return context.group;}});
 assert.equal((await seal(dek,group,getter)).ok,false);assert.equal(called,false);
 const hidden={...context,[Symbol('extra')]:1};assert.equal((await seal(dek,group,hidden)).ok,false);
});

test('the exact AES import buffer is cleared after success and rejection',async()=>{
 const original=crypto.subtle.importKey;
 try {
  for(const reject of [false,true]) {
   let raw;
   crypto.subtle.importKey=async function(...args){raw=args[1];if(reject)throw Error('refused');return original.apply(this,args);};
   assert.equal((await seal()).ok,!reject);assert.ok(raw instanceof Uint8Array);assert.ok(raw.every(value=>value===0));
  }
 }finally{crypto.subtle.importKey=original;}
});
