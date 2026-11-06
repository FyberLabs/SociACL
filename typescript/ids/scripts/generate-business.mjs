// Business consume vectors use the existing signed post fixture; public test scalars only.
import { readFileSync, writeFileSync } from 'node:fs';
import { p256 } from '@noble/curves/nist.js';
import { mintObjectId, parsePrincipalId, objectRecordBytes, signWithKeyring } from '../src/index.js';
import { b64 } from './vector-util.mjs';
const value = r => { if (!r.ok) throw Error(r.reason); return r.value; };
const principal = n => {
  const secret = new Uint8Array(32); secret[31] = n;
  const pub = p256.getPublicKey(secret, false);
  return value(parsePrincipalId(b64(pub.slice(1, 33)) + '.' + b64(pub.slice(33))));
};
const post = JSON.parse(readFileSync(new URL('../../../vectors/mesh/v2/post.json', import.meta.url)));
const cancelPost = post.accept.find(c => c.name === 'delegate-post-cancel-denies').steps;
const cancelSee = post.accept.find(c => c.name === 'cancel-see-denies-post').steps;
const record = cancelPost[0].record;
const grants = { see: cancelPost[1].row, post: cancelPost[3].row,
  cancelPost: cancelPost[5].row, cancelSee: cancelSee[4].row };
const mint = (kind, owner, byte) => value(mintObjectId(kind, owner, () => new Uint8Array(16).fill(byte)));
const forum = mint('forum', principal(2), 0x61);
const window = mint('item', principal(2), 0x62);
const mount = mint('item', principal(2), 0x63);
const roles = ['treasurer', 'secretary', 'practice-manager', 'president-pm'];
const modes = ['distinct-principals', 'role-labels'].map(mode => {
  const rows = roles.map((role, i) => ({ role, principal: principal(mode === 'role-labels' ? 2 : i + 2) }));
  const stages = [
    ['hint-only', [], false, false],
    ['read-mount', ['see'], true, false],
    ['read-write-mount', ['post'], true, true],
    ['downgrade-to-read', ['cancelPost'], true, false],
    ['cancel-all-access', ['cancelSee'], false, false],
    ['replay-old-grants', ['see', 'post'], false, false],
  ].map(([name, admit, read, write]) => ({ name, admit, expected: rows.map(row => ({
    principal: row.principal, read: row.principal === grants.see.accessor && read,
    write: row.principal === grants.see.accessor && write,
  })) }));
  return { mode, rows, stages };
});
const sourceRecords = [forum, window, mount].map(object => {
  const row = { object, owner: principal(2), issuedAt: record.issuedAt, sig: '' };
  const scalar = new Uint8Array(32); scalar[31] = 2;
  row.sig = value(signWithKeyring(scalar, objectRecordBytes(row), row.owner));
  return row;
});
const doc = { v: 1, family: 'business', forum, window, mount, target: record.object,
  foreignItem: mint('item', principal(1), 0x64),
  souls: { mount: `s3rch/forums/${forum}/mounts/${mount}`,
    windows: roles.map(role => ({ role, soul: `s3rch/forums/${forum}/windows/${role}/${window}` })) },
  record, sourceRecords, grants, modes, now: 10 };
writeFileSync(new URL('../../../vectors/mesh/business.json', import.meta.url), JSON.stringify(doc, null, 2) + '\n');
