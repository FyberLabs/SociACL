import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

for (const mode of ['available', 'unavailable']) {
  test(`recovery lazily loads strength dictionaries (${mode})`, { timeout: 60_000 }, () => {
    const run = spawnSync(process.execPath, [
      '--experimental-strip-types',
      fileURLToPath(new URL('./support/passphrase-lazy.mjs', import.meta.url)),
      mode,
    ], { encoding: 'utf8', timeout: 55_000 });
    assert.equal(run.status, 0, `${run.stdout}\n${run.stderr}`);
  });
}
