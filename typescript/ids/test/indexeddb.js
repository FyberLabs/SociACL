import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { IDBFactory, IDBObjectStore, IDBDatabase } from 'fake-indexeddb';
import { openWitnessPolicyStore } from '../src/indexeddb.js';

const vectors = JSON.parse(readFileSync(new URL('../../../vectors/ids/witness-lifecycle.json', import.meta.url)));
const base = vectors.accept.find(x => x.name === 'bootstrap-at-floor');
const initial = base.input.steps[0].envelope;
const narrow = vectors.accept.find(x => x.name === 'narrow-both-bounds').input.steps[1].envelope;
const removed = vectors.accept.find(x => x.name === 'empty-update-removes-all-trust').input.steps[1].envelope;
function setup(overrides = {}) {
  const options = { ...vectors.context, name: 'policy', indexedDB: new IDBFactory(), now: () => vectors.context.now, ...overrides };
  return { options, open: () => openWitnessPolicyStore(options) };
}
async function raw(options, edit) {
  const db = await new Promise((resolve, reject) => {
    const r = options.indexedDB.open(options.name, 1);
    r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error);
  });
  try {
    await new Promise((resolve, reject) => {
      const tx = db.transaction('witness-policy', 'readwrite');
      const store = tx.objectStore('witness-policy');
      const r = store.get('installed');
      r.onsuccess = () => edit(store, r.result);
      tx.oncomplete = resolve; tx.onabort = () => reject(tx.error);
    });
  } finally { db.close(); }
}

// Reuse the TS/Rust lifecycle corpus through actual database transactions;
// cases needing fabricated previous snapshots remain in the shared pure runner.
for (const kind of ['accept', 'reject']) {
  for (const vector of vectors[kind].filter(v => v.input.previous === null)) {
    test(`IndexedDB shared ${kind}: ${vector.name}`, async () => {
      let time = vectors.context.now;
      const { open } = setup({ minimumRevision: vector.minimumRevision ?? vectors.context.minimumRevision, now: () => time });
      let store;
      const run = async () => {
        store = await open();
        let result;
        for (const [i, step] of vector.input.steps.entries()) {
          time = step.now;
          result = await store[i ? 'refresh' : 'bootstrap'](step.envelope);
        }
        return result;
      };
      try {
        if (kind === 'accept') assert.deepEqual(await run(), vector.canonical);
        else await assert.rejects(run());
      } finally { store?.close(); }
    });
  }
}

test('restart preserves revision and history; transport expiry does not erase installed windows', async () => {
  const { open, options } = setup();
  let store = await open();
  await assert.rejects(store.read());
  await assert.rejects(store.refresh(initial));
  await store.bootstrap(initial);
  const expected = await store.refresh(removed);
  store.close();
  options.now = () => vectors.context.now + 100000;
  store = await open();
  assert.deepEqual(await store.read(), expected);
  await assert.rejects(store.bootstrap(initial));
  await assert.rejects(store.refresh(initial));
  assert.deepEqual(await store.read(), expected);
  store.close();
});

test('independent connections serialize competing revisions and retain the winner', async () => {
  const { open } = setup();
  const a = await open(), b = await open();
  await a.bootstrap(initial);
  const results = await Promise.allSettled([a.refresh(narrow), b.refresh(removed)]);
  assert.equal(results[0].status, 'fulfilled');
  assert.equal(results[1].status, 'rejected');
  assert.deepEqual(await b.read(), results[0].value);
  a.close(); b.close();
});

test('concurrent bootstrap admits exactly one writer', async () => {
  const { open } = setup();
  const a = await open(), b = await open();
  const result = await Promise.allSettled([a.bootstrap(initial), b.bootstrap(initial)]);
  assert.equal(result.filter(x => x.status === 'fulfilled').length, 1);
  assert.equal(result.filter(x => x.status === 'rejected').length, 1);
  a.close(); b.close();
});

test('expiry after write request aborts before commit and retains old row', async () => {
  let time = vectors.context.now;
  const { open } = setup({ now: () => time });
  const store = await open();
  const before = await store.bootstrap(initial);
  const original = IDBObjectStore.prototype.put;
  IDBObjectStore.prototype.put = function (...args) {
    const request = original.apply(this, args);
    request.addEventListener('success', () => { time += 100000; });
    return request;
  };
  try { await assert.rejects(store.refresh(narrow)); }
  finally { IDBObjectStore.prototype.put = original; }
  assert.deepEqual(await store.read(), before);
  store.close();
});

test('abort after successful put never exposes candidate and preserves full old row', async () => {
  const { open } = setup();
  const store = await open();
  const before = await store.bootstrap(initial);
  const original = IDBObjectStore.prototype.put;
  IDBObjectStore.prototype.put = function (...args) {
    const request = original.apply(this, args);
    request.addEventListener('success', () => this.transaction.abort());
    return request;
  };
  try { await assert.rejects(store.refresh(narrow)); }
  finally { IDBObjectStore.prototype.put = original; }
  assert.deepEqual(await store.read(), before);
  store.close();
});

test('quota/write exception does not update state', async () => {
  const { open } = setup();
  const store = await open();
  const before = await store.bootstrap(initial);
  const original = IDBObjectStore.prototype.put;
  IDBObjectStore.prototype.put = () => { throw new DOMException('full', 'QuotaExceededError'); };
  try { await assert.rejects(store.refresh(narrow), /full/); }
  finally { IDBObjectStore.prototype.put = original; }
  assert.deepEqual(await store.read(), before);
  store.close();
});

test('lost response after commit reconciles by read without bootstrap or extra revision', async () => {
  let calls = 0;
  const { open, options } = setup();
  let store = await open();
  await store.bootstrap(initial); store.close();
  options.now = () => ++calls === 3 ? vectors.context.now + 100000 : vectors.context.now;
  store = await open();
  await assert.rejects(store.refresh(narrow));
  const installed = await store.read();
  assert.equal(installed.revision, 8);
  assert.deepEqual(await store.refresh(narrow), installed);
  store.close();
});

for (const corruption of ['missing', 'bad-state', 'bad-signature', 'bad-time', 'extra']) {
  test(`stored ${corruption} fails closed`, async () => {
    const { open, options } = setup();
    const store = await open(); await store.bootstrap(initial);
    await raw(options, (db, row) => {
      if (corruption === 'missing') { db.delete('installed'); return; }
      if (corruption === 'bad-state') row.state = '{}';
      if (corruption === 'bad-signature') row.envelope = '{}';
      if (corruption === 'bad-time') row.acceptedAt += 100000;
      if (corruption === 'extra') row.extra = true;
      db.put(row, 'installed');
    });
    await assert.rejects(store.read());
    await assert.rejects(store.refresh(narrow));
    store.close();
  });
}

test('changed root or audience cannot silently reset saved trust', async () => {
  const { open, options } = setup();
  const store = await open(); await store.bootstrap(initial); store.close();
  for (const change of [{ root: 'other' }, { audience: 'other' }]) {
    const other = await openWitnessPolicyStore({ ...options, ...change });
    await assert.rejects(other.read()); await assert.rejects(other.refresh(narrow));
    await assert.rejects(other.bootstrap(initial)); other.close();
  }
});

test('unsupported strict durability fails rather than falling back', async () => {
  const { open } = setup(); const store = await open();
  const original = IDBDatabase.prototype.transaction;
  IDBDatabase.prototype.transaction = function (names, mode) { return original.call(this, names, mode); };
  try { await assert.rejects(store.bootstrap(initial), /durability/); }
  finally { IDBDatabase.prototype.transaction = original; }
  await assert.rejects(store.read()); store.close();
});


test('raised floor blocks reads but permits authenticated upgrade with retained history', async () => {
  const { open, options } = setup();
  const old = await open(); await old.bootstrap(initial); old.close();
  const store = await openWitnessPolicyStore({ ...options, minimumRevision: 8 });
  await assert.rejects(store.read());
  const state = await store.refresh(narrow);
  assert.equal(state.revision, 8);
  assert.deepEqual(await store.read(), state);
  store.close();
});

test('mismatched saved envelope cannot silently advance a corrupted snapshot', async () => {
  const { open, options } = setup();
  const store = await open(); await store.bootstrap(initial);
  await raw(options, (db, row) => { row.envelope = narrow; db.put(row, 'installed'); });
  await assert.rejects(store.read()); await assert.rejects(store.refresh(narrow));
  store.close();
});

test('clock is sampled after an earlier transaction releases its lock', async () => {
  let time = vectors.context.now;
  const { open, options } = setup({ now: () => time });
  const store = await open(); const before = await store.bootstrap(initial);
  let queued;
  await raw(options, () => {
    queued = assert.rejects(store.refresh(narrow));
    time += 100000;
  });
  await queued;
  assert.deepEqual(await store.read(), before);
  store.close();
});
