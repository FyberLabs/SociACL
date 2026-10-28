import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { IDBFactory, IDBObjectStore } from 'fake-indexeddb';
import { openWitnessPolicyClient } from '../src/witness-client.js';
import { MAX_WITNESS_ENVELOPE_BYTES } from '../src/witness-policy.js';

const vectors = JSON.parse(readFileSync(new URL('../../../vectors/ids/witness-lifecycle.json', import.meta.url)));
const initial = vectors.accept.find(v => v.name === 'bootstrap-at-floor').input.steps[0].envelope;
const narrow = vectors.accept.find(v => v.name === 'narrow-both-bounds').input.steps[1].envelope;
const removed = vectors.accept.find(v => v.name === 'empty-update-removes-all-trust').input.steps[1].envelope;
const encode = value => new TextEncoder().encode(value);
const response = (body = initial, init = {}) => new Response(body, { headers: { 'Content-Type': 'application/json' }, ...init });
function config(extra = {}) {
  return { ...vectors.context, name: 'http-policy', indexedDB: new IDBFactory(),
    url: 'https://policy.example/api/v1/acl/sociacl/witness-policy',
    now: () => vectors.context.now, fetch: async () => response(), ...extra };
}

for (const url of ['http://policy.example', '/relative', 'file:///policy', 'https://user:secret@policy.example',
  'https://policy.example/?root=untrusted', 'https://policy.example/#fragment']) {
  test(`reject unsafe endpoint ${url}`, async () => {
    await assert.rejects(openWitnessPolicyClient(config({ url })));
  });
}
for (const timeoutMs of [0, -1, 60001, 1.5, Infinity]) {
  test(`reject invalid timeout ${timeoutMs}`, async () => {
    await assert.rejects(openWitnessPolicyClient(config({ timeoutMs })));
  });
}

test('open/read do not download; missing refresh never bootstraps; commits survive reopen', async () => {
  let calls = 0, envelope = initial;
  const options = config({ fetch: async (url, init) => {
    calls++;
    assert.equal(url, options.url);
    assert.equal(init.method, 'GET'); assert.equal(init.redirect, 'error');
    assert.equal(init.credentials, 'omit'); assert.equal(init.cache, 'no-store');
    assert.equal(init.referrerPolicy, 'no-referrer');
    assert.deepEqual(init.headers, { Accept: 'application/json' });
    return response(envelope);
  } });
  let client = await openWitnessPolicyClient(options);
  assert.equal(calls, 0); await assert.rejects(client.read()); assert.equal(calls, 0);
  await assert.rejects(client.refresh()); await assert.rejects(client.read());
  await client.bootstrap(); await assert.rejects(client.bootstrap());
  envelope = narrow;
  const saved = await client.refresh();
  assert.equal(saved.revision, 8); assert.ok(Object.isFrozen(saved));
  client.close(); client = await openWitnessPolicyClient(options);
  const beforeRead = calls;
  assert.deepEqual(await client.read(), saved); assert.equal(calls, beforeRead);
  envelope = initial; await assert.rejects(client.refresh());
  assert.deepEqual(await client.read(), saved); client.close();
});

const badResponses = {
  unavailable: () => response('{}', { status: 503 }),
  notFound: () => response('{}', { status: 404 }),
  partial: () => response(initial, { status: 206 }),
  unchanged: () => response(null, { status: 304 }),
  redirect: () => response(null, { status: 302, headers: { Location: 'https://other.example' } }),
  redirectedTransport: () => { const r = response(); Object.defineProperty(r, 'redirected', { value: true }); return r; },
  html: () => response(initial, { headers: { 'Content-Type': 'text/html' } }),
  missingType: () => new Response(encode(initial)),
  empty: () => response(''),
  malformed: () => response('{}'),
  badUtf8: () => response(new Uint8Array([0xc0, 0xaf])),
  truncatedUtf8: () => response(new Uint8Array([0xe2, 0x82])),
  bom: () => response(new Uint8Array([0xef, 0xbb, 0xbf, ...encode(initial)])),
  duplicateFields: () => response(initial.replace('{', '{"type":"wrong",')),
  badSignature: () => { const value = JSON.parse(initial); value.signature = 'a'.repeat(86); return response(JSON.stringify(value)); },
  excessiveLength: () => response(initial, { headers: { 'Content-Type': 'application/json', 'Content-Length': String(MAX_WITNESS_ENVELOPE_BYTES + 1) } }),
  invalidLength: () => response(initial, { headers: { 'Content-Type': 'application/json', 'Content-Length': '-1' } }),
  excessiveStream: () => response(new Uint8Array(MAX_WITNESS_ENVELOPE_BYTES + 1)),
  falseLength: () => response(new Uint8Array(MAX_WITNESS_ENVELOPE_BYTES + 1), { headers: { 'Content-Type': 'application/json', 'Content-Length': '1' } }),
  network: () => { throw Error('network unavailable'); },
};
for (const [name, bad] of Object.entries(badResponses)) {
  test(`${name} rejects without fallback or changing saved policy`, async () => {
    let current = () => response();
    const client = await openWitnessPolicyClient(config({ fetch: async () => current() }));
    const before = await client.bootstrap(); current = bad;
    await assert.rejects(client.refresh());
    assert.deepEqual(await client.read(), before); client.close();
  });
}

test('stream limit counts decoded bytes across chunks and cancels the body', async () => {
  let cancelled = false;
  const client = await openWitnessPolicyClient(config({ fetch: async () => response(new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array(MAX_WITNESS_ENVELOPE_BYTES));
      controller.enqueue(new Uint8Array(1));
    }, cancel() { cancelled = true; },
  })) }));
  await assert.rejects(client.bootstrap(), /Oversized/);
  assert.equal(cancelled, true); await assert.rejects(client.read()); client.close();
});

test('chunked download preserves exact valid bytes and accepts exactly the byte cap', async () => {
  const text = initial + ' '.repeat(MAX_WITNESS_ENVELOPE_BYTES - encode(initial).length - 2) + '\r\n';
  const bytes = encode(text);
  assert.equal(bytes.length, MAX_WITNESS_ENVELOPE_BYTES);
  const client = await openWitnessPolicyClient(config({ fetch: async () => response(new ReadableStream({
    start(controller) {
      for (let i = 0; i < bytes.length; i += 997) controller.enqueue(bytes.slice(i, i + 997));
      controller.close();
    },
  })) }));
  assert.equal((await client.bootstrap()).revision, 7); client.close();
});

test('timeout bounds headers even if injected fetch ignores abort', async () => {
  const client = await openWitnessPolicyClient(config({ timeoutMs: 20, fetch: () => new Promise(() => {}) }));
  await assert.rejects(client.bootstrap(), /cancelled/);
  await assert.rejects(client.read()); client.close();
});

test('timeout bounds stalled body and does not await a broken cancel handler', async () => {
  let cancelled = false;
  const client = await openWitnessPolicyClient(config({ timeoutMs: 20, fetch: async () => response(new ReadableStream({
    cancel() { cancelled = true; return new Promise(() => {}); },
  })) }));
  await assert.rejects(client.bootstrap(), /cancelled/);
  assert.equal(cancelled, true); await assert.rejects(client.read()); client.close();
});

test('late response after timeout is cancelled and never installed', async () => {
  let release, cancelled = false;
  const client = await openWitnessPolicyClient(config({ timeoutMs: 20, fetch: () => new Promise(resolve => { release = resolve; }) }));
  await assert.rejects(client.bootstrap(), /cancelled/);
  release(response(new ReadableStream({ cancel() { cancelled = true; } })));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(cancelled, true); await assert.rejects(client.read()); client.close();
});

test('caller abort and close cancel pending downloads; pre-aborted calls never fetch', async () => {
  let calls = 0;
  const client = await openWitnessPolicyClient(config({ fetch: () => { calls++; return new Promise(() => {}); } }));
  const signal = AbortSignal.abort(); await assert.rejects(client.bootstrap({ signal })); assert.equal(calls, 0);
  const controller = new AbortController();
  const pending = client.bootstrap({ signal: controller.signal }); controller.abort(); await assert.rejects(pending);
  const second = client.bootstrap(); client.close(); await assert.rejects(second);
  await assert.rejects(client.refresh(), /closed/); assert.equal(calls, 2);
});

test('expiry during download rejects before durable installation', async () => {
  let now = vectors.context.now;
  const client = await openWitnessPolicyClient(config({ now: () => now, fetch: async () => {
    now += 100000; return response();
  } }));
  await assert.rejects(client.bootstrap()); await assert.rejects(client.read()); client.close();
});

test('concurrent downloads still validate against the latest committed history', async () => {
  let envelope = initial, release;
  const client = await openWitnessPolicyClient(config({ fetch: async () => {
    if (envelope === 'delayed') return new Promise(resolve => { release = () => resolve(response(removed)); });
    return response(envelope);
  } }));
  await client.bootstrap(); envelope = 'delayed';
  const slow = client.refresh(); envelope = narrow;
  const winner = await client.refresh(); release();
  await assert.rejects(slow); assert.deepEqual(await client.read(), winner); client.close();
});

test('successful download cannot expose policy when database commit aborts', async () => {
  let envelope = initial;
  const client = await openWitnessPolicyClient(config({ fetch: async () => response(envelope) }));
  const before = await client.bootstrap(); envelope = narrow;
  const original = IDBObjectStore.prototype.put;
  IDBObjectStore.prototype.put = function (...args) {
    const request = original.apply(this, args);
    request.addEventListener('success', () => this.transaction.abort());
    return request;
  };
  try { await assert.rejects(client.refresh()); }
  finally { IDBObjectStore.prototype.put = original; }
  assert.deepEqual(await client.read(), before); client.close();
});


test('elapsed deadline rejects even when event-loop blocking delays the timer callback', async () => {
  const client = await openWitnessPolicyClient(config({ timeoutMs: 5, fetch: async () => {
    const end = performance.now() + 25;
    while (performance.now() < end) { /* Simulate a delayed timeout callback. */ }
    return response();
  } }));
  await assert.rejects(client.bootstrap()); await assert.rejects(client.read()); client.close();
});
