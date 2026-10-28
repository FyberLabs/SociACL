// Real HTTPS fetch + IndexedDB acceptance. The temporary self-signed certificate
// is test-only; production fetch keeps normal browser TLS verification.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:https';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { chromium } from 'playwright';

const vectors = JSON.parse(await readFile(new URL('../../../vectors/ids/witness-lifecycle.json', import.meta.url)));
const initial = vectors.accept.find(v => v.name === 'bootstrap-at-floor').input.steps[0].envelope;
const narrow = vectors.accept.find(v => v.name === 'narrow-both-bounds').input.steps[1].envelope;
const { outputFiles } = await build({ entryPoints: [fileURLToPath(new URL('../src/witness-client.js', import.meta.url))],
  bundle: true, platform: 'browser', format: 'esm', write: false });
const temp = await mkdtemp(join(tmpdir(), 'sociacl-policy-https-'));
let context, server;
let current = initial, status = 200, mode = 'normal', redirectHits = 0;
try {
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-keyout', join(temp, 'key.pem'), '-out', join(temp, 'cert.pem'), '-subj', '/CN=localhost',
    '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'], { stdio: 'ignore' });
  server = createServer({ key: await readFile(join(temp, 'key.pem')), cert: await readFile(join(temp, 'cert.pem')) }, (req, res) => {
    if (req.url === '/client.js') {
      res.setHeader('Content-Type', 'text/javascript'); res.end(outputFiles[0].text); return;
    }
    if (req.url === '/redirect-target') { redirectHits++; res.end(current); return; }
    if (req.url === '/api/v1/acl/sociacl/witness-policy') {
      assert.equal(req.headers.cookie, undefined);
      assert.equal(req.headers.authorization, undefined);
      assert.equal(req.headers.referer, undefined);
      assert.equal(req.headers.accept, 'application/json');
      res.setHeader('Content-Type', 'application/json'); res.setHeader('Cache-Control', 'no-store');
      if (mode === 'redirect') { res.writeHead(302, { Location: '/redirect-target' }); res.end(); return; }
      if (mode === 'stall') { res.writeHead(200); res.flushHeaders(); return; }
      res.statusCode = status; res.end(current); return;
    }
    res.setHeader('Content-Type', 'text/html'); res.end('<!doctype html><title>HTTPS policy acceptance</title>');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `https://127.0.0.1:${server.address().port}`;
  const profile = join(temp, 'profile');
  async function start() {
    context = await chromium.launchPersistentContext(profile, { headless: true, ignoreHTTPSErrors: true });
    const page = await context.newPage(); await page.goto(origin);
    await page.evaluate(async ({ config, url }) => {
      document.cookie = 'must-not-send=secret; Secure';
      const { openWitnessPolicyClient } = await import('/client.js');
      window.client = await openWitnessPolicyClient({ ...config, name: 'https-acceptance', url,
        timeoutMs: 1000, now: () => config.now });
    }, { config: vectors.context, url: origin + '/api/v1/acl/sociacl/witness-policy' });
    return page;
  }
  let page = await start();
  assert.equal((await page.evaluate(() => window.client.bootstrap())).revision, 7);
  current = narrow;
  const installed = await page.evaluate(() => window.client.refresh()); assert.equal(installed.revision, 8);
  for (const failure of ['unavailable', 'redirect', 'stall', 'rollback']) {
    mode = failure; status = failure === 'unavailable' ? 503 : 200;
    current = failure === 'rollback' ? initial : narrow;
    assert.equal(await page.evaluate(async () => {
      try { await window.client.refresh(); return 'accepted'; } catch { return 'rejected'; }
    }), 'rejected');
    assert.deepEqual(await page.evaluate(() => window.client.read()), installed);
  }
  assert.equal(redirectHits, 0);
  await context.close(); context = undefined;
  page = await start();
  assert.deepEqual(await page.evaluate(() => window.client.read()), installed);
  assert.equal(await page.evaluate(async () => {
    try { await window.client.refresh(); return 'accepted'; } catch { return 'rejected'; }
  }), 'rejected');
  console.log('Chromium HTTPS policy client: durable install, cookie/referrer omission, redirect refusal, timeout, failure preservation and process restart passed');
} finally {
  await context?.close();
  if (server) {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
  await rm(temp, { recursive: true, force: true });
}
