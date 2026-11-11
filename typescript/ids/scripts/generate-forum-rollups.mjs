// Deterministic public fixture scalars, never account credentials.
import { readFileSync, writeFileSync } from 'node:fs';
import { p256 } from '@noble/curves/nist.js';
import { mintObjectId, objectRecordBytes, seeGrantBytes, signWithKeyring } from '../src/index.js';
import { b64 } from './vector-util.mjs';
const value = r => { if (!r.ok) throw Error(r.reason); return r.value; };
const key = n => { const k = new Uint8Array(32); k[31] = n; return k; };
const pub = n => { const p = p256.getPublicKey(key(n), false); return b64(p.slice(1,33))+'.'+b64(p.slice(33)); };
const mint = (kind, n) => value(mintObjectId(kind, pub(1), () => new Uint8Array(16).fill(n)));
const base = JSON.parse(readFileSync(new URL('../../../vectors/mesh/v2/see.json', import.meta.url)));
const at = base.accept.find(c => c.name === 'delegate-cancel-denies')?.steps[0].record.issuedAt ?? 1700000000;
const signed = (fields, bytes) => ({ ...fields, sig: value(signWithKeyring(key(1), bytes({ ...fields, sig: '' }), pub(1))) });
const levels = ['squad','fleet','command'].map((level, i) => {
  const forum = mint('forum', 0x70+i), object = mint('item', 0x80+i);
  const grant = {owner: pub(1), object, accessor: pub(2), stated: 1, from: 0, until: 100, hamState: 1, issuedAt: at};
  return {level, forum, object, record: signed({object,owner:pub(1),issuedAt:at},objectRecordBytes),
    grant: signed(grant, seeGrantBytes), cancel: signed({...grant,stated:0,hamState:2},seeGrantBytes)};
});
const doc = {v:1,contract:'forum-rollup-v1',context:base.context,accessor:pub(2),now:10,levels,
  cases:[
    {name:'hint-alone-fails-closed',admit:[],expected:[false,false,false]},
    {name:'squad-access-does-not-grant-fleet',admit:['squad:grant'],expected:[true,false,false]},
    {name:'fleet-grant-does-not-grant-command',admit:['fleet:grant'],expected:[true,true,false]},
    {name:'command-has-independent-destination-grant',admit:['command:grant'],expected:[true,true,true]},
    {name:'fleet-cancel-visible-on-next-check',admit:['fleet:cancel'],expected:[true,false,true]},
    {name:'replayed-fleet-grant-stays-cancelled',admit:['fleet:grant'],expected:[true,false,true]},
    {name:'resolve-escalated-projection-does-not-elect',admit:[],resolve:true,expected:[true,false,true]},
  ]};
writeFileSync(new URL('../../../vectors/mesh/forum-rollups.json', import.meta.url),JSON.stringify(doc,null,2)+'\n');
