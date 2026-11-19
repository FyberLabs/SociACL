// Run only through the central scheduled TEST lane.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

if (process.env.GITHUB_ACTIONS !== 'true' || process.env.GITHUB_EVENT_NAME !== 'schedule' ||
    process.env.NIGHTLY_SUITE !== 'sociacl-browser' || process.env.GITHUB_REPOSITORY !== 'FyberLabs/SociACL') {
  throw new Error('Native vault qualification requires the scheduled Infra lane');
}

const fixtureText = process.env.NIGHTLY_NATIVE_VAULT_FIXTURE_JSON ?? '';
delete process.env.NIGHTLY_NATIVE_VAULT_FIXTURE_JSON;
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const hex = /^[a-f0-9]{64}$/;
const key = /^[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}$/;
const origin = 'https://test.s3r.ch';
function requireCondition(condition, message) {
  if (!condition) throw new Error(message);
}
let fixture;
try {
  requireCondition(fixtureText.length > 0 && fixtureText.length < 48000, '');
  fixture = JSON.parse(fixtureText);
  requireCondition(fixture.origin === origin && fixture.dedicated === true &&
    typeof fixture.owner === 'string' && key.test(fixture.owner) &&
    typeof fixture.sessionKey === 'string' && key.test(fixture.sessionKey) &&
    typeof fixture.vaultId === 'string' && hex.test(fixture.vaultId) &&
    /^[!-~][ -~]{0,8190}$/.test(fixture.cookie) && !/[\r\n]/.test(fixture.cookie) &&
    /^[A-Za-z0-9_-]{43}$/.test(fixture.scalar) &&
    Array.isArray(fixture.heads) && fixture.heads.length === 2, '');
} catch {
  throw new Error('Missing or invalid dedicated native vault TEST fixture');
}

function ciphertext(value) {
  requireCondition(typeof value === 'string' && value.length <= 16000, 'Invalid fixture ciphertext');
  const bytes = Buffer.from(value, 'base64');
  requireCondition(bytes.subarray(0, 8).toString('ascii') === 'SAVFILE1' &&
    bytes.length >= 295 && bytes.toString('base64') === value, 'Invalid fixture ciphertext');
  return bytes;
}

const heads = fixture.heads.map(ciphertext);
requireCondition(!heads[0].equals(heads[1]), 'Distinct prepared heads are required');
const input = [origin, fixture.owner, fixture.vaultId, fixture.sessionKey, fixture.cookie, fixture.scalar].join('\n');
const deniedInput = [origin, fixture.owner, fixture.vaultId, fixture.sessionKey, 'nightly_invalid=1', fixture.scalar].join('\n');
const cli = join(process.env.CARGO_TARGET_DIR || 'target', 'debug', 'sociacl-vault');
const built = spawnSync('cargo', ['build', '--locked', '-p', 'sociacl-encdisc', '--bin', 'sociacl-vault'], {
  stdio: 'ignore', timeout: 600000,
});
requireCondition(built.status === 0, 'Native vault CLI build failed');

function call(args, { credential = input, denied = false } = {}) {
  const command = spawnSync(cli, args, { input: credential, encoding: 'utf8', timeout: 390000, maxBuffer: 65536 });
  requireCondition(!command.error && command.signal === null, 'Native CLI execution failed');
  if (denied) {
    requireCondition(command.status === 1, 'A request expected to fail was accepted');
    return;
  }
  requireCondition(command.status === 0, 'Native CLI refused the live TEST operation');
  try { return JSON.parse(command.stdout); }
  catch { throw new Error('Invalid CLI response'); }
}

const directory = mkdtempSync(join(tmpdir(), 'sociacl-vault-live-'));
try {
  const before = call(['read']);
  requireCondition(before === null || (hex.test(before.revision) && fixture.heads.includes(before.bytes)),
    'Unexpected head in the dedicated TEST fixture');
  const candidate = before?.bytes === fixture.heads[0] ? 1 : 0;
  const file = join(directory, 'prepared.vault');
  writeFileSync(file, heads[candidate], { mode: 0o600, flag: 'wx' });

  // Reuse the two opaque fixtures, keeping object count and mutable head count bounded.
  const object = call(['put-object', file]);
  requireCondition(object.digest === digest(heads[candidate]), 'Unexpected published object digest');
  requireCondition(call(['get-object', object.digest]).bytes === fixture.heads[candidate], 'Object readback mismatch');
  const expected = before?.revision ?? 'create';
  const published = call(['publish', file, expected]);
  requireCondition(hex.test(published.revision), 'Invalid head revision');
  const after = call(['read']);
  requireCondition(after?.bytes === fixture.heads[candidate] && after.revision === published.revision, 'Head readback mismatch');
  requireCondition(call(['publish', file, expected]).revision === published.revision, 'Exact head retry failed');

  const conflict = join(directory, 'conflict.vault');
  writeFileSync(conflict, heads[1 - candidate], { mode: 0o600, flag: 'wx' });
  const stale = before?.revision !== published.revision ? expected : (published.revision === '0'.repeat(64) ? '1' : '0').repeat(64);
  call(['publish', conflict, stale], { denied: true });
  call(['read'], { credential: deniedInput, denied: true });
  const retained = call(['read']);
  requireCondition(retained?.bytes === after.bytes && retained.revision === after.revision, 'Refusal changed the live TEST head');
} finally {
  rmSync(directory, { recursive: true, force: true });
}
