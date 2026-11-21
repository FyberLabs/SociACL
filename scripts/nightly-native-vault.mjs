// Run only through the central Infra TEST lane.
import { spawnSync } from 'node:child_process';
import { createECDH, createHash, webcrypto } from 'node:crypto';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { requireInfraNightly } from './nightly-context.mjs';

requireInfraNightly();

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
    typeof fixture.scalar === 'string' && /^[A-Za-z0-9_-]{43}$/.test(fixture.scalar) &&
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
const deniedInput = [origin, fixture.owner, fixture.vaultId, fixture.sessionKey, 'nightly_invalid=1', fixture.scalar].join('\n');
const cli = join(process.env.CARGO_TARGET_DIR || 'target', 'debug', 'sociacl-vault');
const built = spawnSync('cargo', ['build', '--locked', '-p', 'sociacl-encdisc', '--bin', 'sociacl-vault'], {
  stdio: 'ignore', timeout: 600000,
});
requireCondition(built.status === 0, 'Native vault CLI build failed');

async function identityPost(action, body, cookie) {
  const response = await fetch(origin + '/api/identity/sea/' + action, {
    method: 'POST', redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(15000),
    headers: { Origin: origin, 'Content-Type': 'application/json', ...(cookie ? { Cookie: cookie } : {}) },
    body: JSON.stringify(body),
  });
  requireCondition(response.status === 200 &&
    response.headers.get('content-type')?.split(';')[0] === 'application/json' && response.body,
  'SEA session endpoint refused the fixture request');
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      requireCondition(size <= 8192, 'SEA session response exceeded its limit');
      chunks.push(value);
    }
    return { body: JSON.parse(Buffer.concat(chunks).toString('utf8')), cookies: response.headers.getSetCookie() };
  } finally {
    await reader.cancel().catch(() => {});
  }
}

function cookieValue(response, name) {
  const cookies = response.cookies.map(value => value.split(';', 1)[0]).filter(value => value.startsWith(name + '='));
  const value = cookies[0]?.slice(name.length + 1);
  requireCondition(cookies.length === 1 && /^[A-Za-z0-9_.-]{1,4096}$/.test(value ?? ''), 'Invalid SEA session cookie');
  return value;
}

async function issueSession() {
  try {
    const scalar = Buffer.from(fixture.scalar, 'base64url');
    const curve = createECDH('prime256v1');
    let point;
    try {
      curve.setPrivateKey(scalar);
      point = curve.getPublicKey();
    } finally {
      scalar.fill(0);
    }
    const [x, y] = fixture.sessionKey.split('.');
    requireCondition(point.subarray(1, 33).toString('base64url') === x &&
      point.subarray(33, 65).toString('base64url') === y, 'Fixture signer does not match its public key');
    const signingKey = await webcrypto.subtle.importKey('jwk', {
      kty: 'EC', crv: 'P-256', x, y, d: fixture.scalar,
    }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);

    const challengeName = '__Host-s3rch-squad-challenge';
    const challengeReply = await identityPost('challenge', { key: fixture.sessionKey });
    const challenge = cookieValue(challengeReply, challengeName);
    requireCondition(challenge === challengeReply.body.challenge, 'SEA challenge binding mismatch');
    const segments = challenge.split('.');
    requireCondition(segments.length === 3, 'Invalid challenge framing');
    const [header, claims] = segments.slice(0, 2).map(value => JSON.parse(Buffer.from(value, 'base64url').toString('utf8')));
    const now = Math.floor(Date.now() / 1000);
    requireCondition(header.alg === 'HS256' && /^s3rch-identity-challenge-v1(?::[0-9a-f]{64})?$/.test(header.typ) &&
      Object.keys(header).sort().join() === 'alg,typ' &&
      Object.keys(claims).sort().join() === 'aud,exp,iat,iss,jti,sub' &&
      claims.iss === origin && claims.aud === origin && claims.sub === fixture.sessionKey && hex.test(claims.jti) &&
      Number.isSafeInteger(claims.iat) && Number.isSafeInteger(claims.exp) &&
      claims.iat <= now && claims.exp > now && claims.exp - claims.iat === 60, 'SEA challenge intent mismatch');

    // Gun SEA signs the SHA-256 digest of the challenge with P-256/SHA-256.
    const hash = createHash('sha256').update(challenge).digest();
    const sig = await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, signingKey, hash);
    const signature = 'SEA' + JSON.stringify({ m: challenge, s: Buffer.from(sig).toString('base64') });
    const exchanged = await identityPost('exchange', { challenge, signature }, challengeName + '=' + challenge);
    requireCondition(exchanged.body.ok === true, 'SEA session exchange was refused');
    const sessionName = '__Host-s3rch-squad-session';
    return sessionName + '=' + cookieValue(exchanged, sessionName);
  } catch {
    throw new Error('Could not issue a fresh session for the dedicated TEST signer');
  }
}
const session = await issueSession();
const input = [origin, fixture.owner, fixture.vaultId, fixture.sessionKey, session, fixture.scalar].join('\n');

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

let directory;
try {
  directory = mkdtempSync(join(tmpdir(), 'sociacl-vault-live-'));
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
  try {
    if (directory) rmSync(directory, { recursive: true, force: true });
  } finally {
    await identityPost('logout', {}, session).catch(() => {});
  }
}
