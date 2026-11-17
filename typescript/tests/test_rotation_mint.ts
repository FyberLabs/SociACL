import test from 'node:test';
import assert from 'node:assert/strict';
import {mintRotationMaterial} from '../contract/rotation-mint.ts';
import {p256} from '@noble/curves/nist.js';
import {b64,unb64} from '../ids/src/util.js';

test('portable mint returns matching independent pairs and wipes supplied buffers',()=>{
  const held:Uint8Array[]=[];
  const minted=mintRotationMaterial(bytes=>{held.push(bytes);bytes[31]=held.length;});
  for(const [pub,priv] of [[minted.signingPub,minted.signingPriv],[minted.epub,minted.epriv]]){
    const raw=p256.getPublicKey(unb64(priv),false);
    assert.equal(pub,`${b64(raw.subarray(1,33))}.${b64(raw.subarray(33))}`);
  }
  assert.notEqual(minted.signingPub,minted.epub);
  assert.notEqual(minted.laneId,minted.contactLaneSecret);
  assert.equal(minted.laneId,'00'.repeat(31)+'03');
  assert.equal(minted.contactLaneSecret,'00'.repeat(31)+'04');
  assert.ok(held.every(bytes=>bytes.every(byte=>byte===0)));
});
test('invalid scalar retries and equal lane material remains disjoint',()=>{
  const held:Uint8Array[]=[];
  const minted=mintRotationMaterial(bytes=>{held.push(bytes);if(held.length>1)bytes[31]=1;});
  assert.equal(held.length,5);
  assert.notEqual(minted.laneId,minted.contactLaneSecret);
  assert.ok(held.every(bytes=>bytes.every(byte=>byte===0)));
});
test('entropy exceptions wipe all buffers including partially filled current draw',()=>{
  for(let stop=1;stop<=4;stop++){
    const held:Uint8Array[]=[];
    assert.throws(()=>mintRotationMaterial(bytes=>{held.push(bytes);bytes.fill(7);if(held.length===stop)throw Error('entropy failed');}),/entropy failed/);
    assert.ok(held.every(bytes=>bytes.every(byte=>byte===0)));
  }
});
test('persistently invalid entropy refuses after bounded attempts',()=>{
  let count=0;
  assert.throws(()=>mintRotationMaterial(()=>{count++;}),/rotation-entropy/);
  assert.equal(count,128);
});
test('default browser entropy source produces valid material',()=>{
  const minted=mintRotationMaterial();
  assert.ok(p256.utils.isValidSecretKey(unb64(minted.signingPriv)));
  assert.ok(p256.utils.isValidSecretKey(unb64(minted.epriv)));
  assert.notEqual(minted.signingPub,minted.epub);
  assert.notEqual(minted.laneId,minted.contactLaneSecret);
});
