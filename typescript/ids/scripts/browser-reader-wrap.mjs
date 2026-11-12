// CI-only browser conformance; loopback fixture server, no deployed services.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { chromium } from 'playwright';
const fixture = JSON.parse(await readFile(new URL('../../../vectors/encrypted-discovery/sea-fixture.json', import.meta.url)));
const vector = JSON.parse(await readFile(new URL('../../../vectors/encrypted-discovery/wrap.json', import.meta.url)));
const { outputFiles } = await build({ entryPoints: [fileURLToPath(new URL('../src/reader-wrap.js', import.meta.url))],
  bundle: true, platform: 'browser', format: 'esm', write: false });
const server = createServer((req, res) => {
  if (req.url === '/wrap.js') { res.setHeader('Content-Type', 'text/javascript'); res.end(outputFiles[0].text); }
  else { res.setHeader('Content-Type', 'text/html'); res.end('<!doctype html><title>Reader wrap conformance</title>'); }
});
let browser;
try {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  await page.goto(`http://127.0.0.1:${server.address().port}`);
  const result = await page.evaluate(async ({ fixture, vector }) => {
    const { wrapItemDekToReaders, openItemDekReaderWrap } = await import('/wrap.js');
    const scope = { epoch: vector.epoch, object: vector.object, revisionId: fixture.revisionId };
    const reader = { account: fixture.signing.pub, pub: fixture.signing.pub, identityPub: fixture.signing.pub, epub: fixture.encryption.epub };
    const row = { ...scope, scope: 'item-dek', target: 'reader-epub', targetId: reader.epub, wrappedKey: vector.wrappedKey };
    const opened = await openItemDekReaderWrap(row, fixture.encryption.epriv, reader.epub, scope);
    if (!opened.ok) return { vector: false };
    const sealed = await wrapItemDekToReaders(opened.value, scope, [reader], [reader.account]);
    if (!sealed.ok) return { vector: true, seal: false };
    const restored = await openItemDekReaderWrap(sealed.value[0], fixture.encryption.epriv, reader.epub, scope);
    const stale = await openItemDekReaderWrap(sealed.value[0], fixture.encryption.epriv, reader.epub, { ...scope, epoch: scope.epoch + 1 });
    return { vector: Array.from(opened.value, byte => byte.toString(16).padStart(2, '0')).join('') === vector.dekHex,
      roundtrip: restored.ok && restored.value.every((byte, i) => byte === opened.value[i]), stale: stale.ok,
      fresh: sealed.value[0].wrappedKey !== vector.wrappedKey };
  }, { fixture, vector });
  assert.deepEqual(result, { vector: true, roundtrip: true, stale: false, fresh: true });
  console.log('Chromium reader wraps: Rust vector, fresh seal/open, and stale epoch refusal passed');
} finally {
  await browser?.close(); server.closeAllConnections(); await new Promise(resolve => server.close(resolve));
}
