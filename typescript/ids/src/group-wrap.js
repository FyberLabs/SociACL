/** Browser consumer of SociACL's group-epoch item-DEK wrap. A wrap is not a
 * grant: expected scope must come from current Check and settled epoch state. */
import {sha256} from '@noble/hashes/sha2.js';
import {parseObjectId} from './ids.js';
import {data,integer,lp,hex,unhex,ok,fail} from './util.js';
/** @import {GroupItemContext,GroupItemWrap} from './group-wrap-types.js' */
const byteLength=Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype),'byteLength')?.get;
/** @param {unknown} input @returns {GroupItemContext} */
function context(input) {
  const d=data(input);
  if(!d.ok||Reflect.ownKeys(/** @type {object} */(input)).length!==4||Object.keys(d.value).sort().join()!=='epoch,group,object,revisionId')throw Error();
  const {epoch,group,object,revisionId}=d.value;
  if(typeof epoch!=='number'||!integer(epoch)||typeof group!=='string'||!group.startsWith('set_')||!parseObjectId(group).ok||
      typeof object!=='string'||!parseObjectId(object).ok||typeof revisionId!=='string'||!/^[a-f0-9]{64}$/.test(revisionId))throw Error();
  return Object.freeze({epoch,group,object,revisionId});
}
/** @param {Uint8Array} input */
function keyCopy(input) {
  if(!ArrayBuffer.isView(input)||!(input instanceof Uint8Array)||byteLength?.call(input)!==32)throw Error();
  const key=new Uint8Array(input);if(key.byteLength!==32)throw Error();return key;
}
/** @param {GroupItemContext} held */
const prefix=held=>lp(['s3rch-wrapped-key-v1','item-dek',String(held.epoch),'group-epoch',held.group,held.object,held.group,held.revisionId]);
/** @param {Uint8Array} groupKey */
async function aesKey(groupKey) {
  const encoded=lp(['s3rch-group-epoch-wrap-v1',hex(groupKey)]),material=sha256(encoded);
  try{return await crypto.subtle.importKey('raw',new Uint8Array(material),'AES-GCM',false,['encrypt','decrypt']);}
  finally{encoded.fill(0);material.fill(0);}
}
/** Wrap an item key once to a current group epoch. All inputs are copied before
 * awaiting crypto. A fresh nonce is always generated; callers cannot supply it.
 * @param {Uint8Array} dek @param {Uint8Array} groupKey @param {unknown} expected
 * @returns {Promise<import('./types.js').Result<GroupItemWrap>>} */
export async function wrapItemDekToGroupEpoch(dek,groupKey,expected) {
  /** @type {Uint8Array|undefined} */let key;
  /** @type {Uint8Array|undefined} */let group;
  /** @type {Uint8Array|undefined} */let plain;
  /** @type {Uint8Array|undefined} */let tail;
  try {
    key=keyCopy(dek);group=keyCopy(groupKey);const held=context(expected);
    const nonce=crypto.getRandomValues(new Uint8Array(12));tail=lp([hex(key)]);plain=new Uint8Array([...prefix(held),...tail]);
    const aes=await aesKey(group);
    const sealed=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv:nonce,tagLength:128},aes,plain));
    return ok(Object.freeze({...held,scope:'item-dek',target:'group-epoch',targetId:held.group,wrappedKey:hex(new Uint8Array([2,...nonce,...sealed]))}));
  }catch{return fail('bad-record');}
  finally{key?.fill(0);group?.fill(0);plain?.fill(0);tail?.fill(0);}
}
/** Open only the independent current object, group, epoch and winning revision.
 * The authenticated payload must match every outer label.
 * @param {unknown} input @param {Uint8Array} groupKey @param {unknown} expected
 * @returns {Promise<import('./types.js').Result<Uint8Array>>} */
export async function openGroupEpochWrap(input,groupKey,expected) {
  /** @type {Uint8Array|undefined} */let group;
  /** @type {Uint8Array|undefined} */let plain;
  try {
    group=keyCopy(groupKey);const held=context(expected),d=data(input);
    if(!d.ok||Reflect.ownKeys(/** @type {object} */(input)).length!==8||
        Object.keys(d.value).sort().join()!=='epoch,group,object,revisionId,scope,target,targetId,wrappedKey')throw Error();
    const w=d.value;
    if(w.scope!=='item-dek'||w.target!=='group-epoch'||w.targetId!==held.group||w.group!==held.group||w.object!==held.object||
        w.epoch!==held.epoch||w.revisionId!==held.revisionId||typeof w.wrappedKey!=='string'||w.wrappedKey.length>16384||!/^(?:[a-f0-9]{2}){29,}$/.test(w.wrappedKey))throw Error();
    const bytes=unhex(w.wrappedKey);if(bytes[0]!==2)throw Error();
    const aes=await aesKey(group);
    plain=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes.slice(1,13),tagLength:128},aes,bytes.slice(13)));
    const leading=prefix(held);
    if(plain.length!==leading.length+68||leading.some((value,index)=>plain?.[index]!==value)||
        new DataView(plain.buffer,plain.byteOffset+leading.length,4).getUint32(0,true)!==64)throw Error();
    const encoded=new TextDecoder('utf-8',{fatal:true}).decode(plain.subarray(leading.length+4));
    if(!/^[a-f0-9]{64}$/.test(encoded))throw Error();return ok(unhex(encoded));
  }catch{return fail('bad-record');}
  finally{group?.fill(0);plain?.fill(0);}
}
