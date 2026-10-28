// Explicit real-browser acceptance run; requires `npx playwright install chromium`.
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { chromium } from 'playwright';

const vectors = JSON.parse(await readFile(new URL('../../../vectors/ids/witness-lifecycle.json', import.meta.url)));
const initial = vectors.accept.find(v => v.name === 'bootstrap-at-floor').input.steps[0].envelope;
const narrow = vectors.accept.find(v => v.name === 'narrow-both-bounds').input.steps[1].envelope;
const removed = vectors.accept.find(v => v.name === 'empty-update-removes-all-trust').input.steps[1].envelope;
const { outputFiles } = await build({ entryPoints: [fileURLToPath(new URL('../src/indexeddb.js', import.meta.url))],
  bundle: true, platform: 'browser', format: 'esm', write: false });
const server = createServer((req, res) => {
  res.setHeader('Content-Type', req.url === '/store.js' ? 'text/javascript' : 'text/html');
  res.end(req.url === '/store.js' ? outputFiles[0].text : '<!doctype html><title>Policy store test</title>');
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const url = `http://127.0.0.1:${server.address().port}`;
const profile = await mkdtemp(join(tmpdir(), 'sociacl-policy-browser-'));
let context;
async function page() {
  const page = await context.newPage();
  await page.goto(url);
  await page.evaluate(async config => {
    const { openWitnessPolicyStore } = await import('/store.js');
    window.store = await openWitnessPolicyStore({ ...config, name: 'acceptance', now: () => config.now });
  }, vectors.context);
  return page;
}
try {
  context = await chromium.launchPersistentContext(profile, { headless: true });
  const a = await page(), b = await page();
  await a.evaluate(envelope => window.store.bootstrap(envelope), initial);
  // Queue two transactions synchronously on separate connections in the same
  // browser page, ensuring the first acquires the lock before its competitor.
  const outcome = await a.evaluate(async ({ narrow, removed, config }) => {
    const { openWitnessPolicyStore } = await import('/store.js');
    const other = await openWitnessPolicyStore({ ...config, name: 'acceptance', now: () => config.now });
    try {
      return (await Promise.allSettled([window.store.refresh(narrow), other.refresh(removed)]))
        .map(result => result.status);
    } finally { other.close(); }
  }, { narrow, removed, config: vectors.context });
  assert.deepEqual(outcome, ['fulfilled', 'rejected']);
  const winner = await b.evaluate(() => window.store.read());
  assert.equal(winner.revision, 8);
  await context.close(); context = undefined;
  // Reopen the on-disk profile in a new browser process, not just a new handle.
  context = await chromium.launchPersistentContext(profile, { headless: true });
  const restarted = await page();
  assert.deepEqual(await restarted.evaluate(() => window.store.read()), winner);
  assert.equal(await restarted.evaluate(async envelope => {
    try { await window.store.refresh(envelope); return 'accepted'; } catch { return 'rejected'; }
  }, initial), 'rejected');
  assert.deepEqual(await restarted.evaluate(() => window.store.read()), winner);
  console.log('Chromium policy store: concurrent conflict, cross-page read, process restart and rollback rejection passed');
} finally {
  await context?.close();
  await new Promise(resolve => server.close(resolve));
  await rm(profile, { recursive: true, force: true });
}
