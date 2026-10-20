import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const UNBOUND = /(?<![A-Za-z0-9_])[a-z][a-z0-9]{1,15}_[0-9a-f]{32}(?![0-9a-f_])/;
const SKIP = new Set(['node_modules', 'target', '.git', 'vectors', 'tests', 'test']);

function sourceFile(name) {
  if (name.startsWith('test_') || name.endsWith('_tests.rs')) return false;
  return name.endsWith('.js') || name.endsWith('.ts') || name.endsWith('.mjs') || name.endsWith('.rs');
}

function walk(dir, hits) {
  let seen = 0;
  for (const name of readdirSync(dir)) {
    if (SKIP.has(name)) continue;
    const path = join(dir, name);
    if (statSync(path).isDirectory()) {
      const nested = walk(path, hits);
      seen += nested;
    } else if (sourceFile(name)) {
      seen += 1;
      const text = readFileSync(path, 'utf8');
      if (UNBOUND.test(text)) hits.push(path);
    }
  }
  return seen;
}

test('non-test sources do not build an unbound kind_32hex id', () => {
  assert.match(`chat_${'1'.repeat(32)}`, UNBOUND);
  assert.doesNotMatch(`chat_p_${'ab'.repeat(64)}_${'1'.repeat(32)}`, UNBOUND);
  assert.doesNotMatch(`claim_${'ab'.repeat(32)}`, UNBOUND);
  assert.doesNotMatch(`ext_${'cd'.repeat(32)}`, UNBOUND);
  const root = fileURLToPath(new URL('../../../', import.meta.url));
  const hits = [];
  const seen = walk(root, hits);
  assert.ok(seen > 0);
  assert.deepEqual(hits, []);
});
