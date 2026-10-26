import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { registerHooks } from 'node:module';

const unavailable = process.argv[2] === 'unavailable';
const loaded = new Set();
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier.startsWith('@zxcvbn-ts/')) {
      loaded.add(specifier);
      if (unavailable) throw new Error('estimator-unavailable');
    }
    return nextResolve(specifier, context);
  },
});
const recovery = await import('../../contract/recovery.ts');
const { AccountKeyring } = await import('../../contract/account-keyring.ts');
const { importGenesis } = await import('../../contract/account-key.ts');
const { HeadFloor } = await import('../../contract/store-write.ts');
const { historyState, resolveCurrentKey } = await import('../../ids/src/index.js');
const fixture = (path) => JSON.parse(readFileSync(new URL(path, import.meta.url), 'utf8'));
const v = fixture('../../../vectors/encrypted-discovery/recovery-copy.json');
const ring = fixture('../../../vectors/encrypted-discovery/account-keyring.json');
const records = fixture('../../../vectors/ids/records.json');
const g = ring.genesis;
const context = {
  ...records.context,
  links: new Map(records.context.links),
  revocations: [],
  pinnedIss: new Set(records.context.pinnedIss),
  history: (principal, at, until) => ({ ok: true, value: historyState(principal, [], at, until) }),
  genesisEpubBindings: [ring.genesisBinding],
};
const bytes = new TextEncoder().encode(v.passphraseUtf8);
assert.equal(loaded.size, 0, 'import must not load the estimator');
await assert.rejects(recovery.checkRecoveryPassphrase(new TextEncoder().encode('short'), g.principal),
  { message: 'recovery-weak-passphrase' });
assert.equal(loaded.size, 0, 'cheap rejection must not load dictionaries');
const envelope = {
  principal: g.principal, rotationSeq: 0, signingPub: g.signingPub, epub: g.epub,
  bytes: new Uint8Array(Buffer.from(v.envelopeHex, 'hex')),
};
const opened = await recovery.openRecoveryCopy(bytes, envelope, g.principal, 0, [], context);
assert.equal(opened.currentPriv(), g.signingPriv);
assert.equal(loaded.size, 0, 'opening an existing backup must not load dictionaries');
const keyring = AccountKeyring.fromGenesis(
  importGenesis(g.laneId, g.signingPub, g.signingPriv, g.epub, g.epriv), g.contactLaneSecret,
);
const store = new recovery.MemoryRecoveryStore((principal) => {
  const result = resolveCurrentKey(principal, [], context);
  assert.ok(result.ok);
  return result.value;
}, new HeadFloor());
if (unavailable) {
  await assert.rejects(recovery.sealRecoveryCopy(keyring, bytes, store), { message: 'estimator-unavailable' });
  assert.equal(store.writeGeneration(g.principal), 0);
  assert.equal(store.get(g.principal, 0), undefined);
} else {
  await Promise.all([
    recovery.checkRecoveryPassphrase(bytes, g.principal),
    recovery.checkRecoveryPassphrase(bytes, g.principal),
  ]);
  assert.ok(loaded.has('@zxcvbn-ts/language-common'));
  assert.ok(loaded.has('@zxcvbn-ts/language-en'));
  // Mutation after the async call must not change the passphrase checked or sealed.
  const mutable = bytes.slice();
  const sealing = recovery.sealRecoveryCopy(keyring, mutable, store);
  mutable.fill(0);
  const sealed = await sealing;
  const restored = await recovery.openRecoveryCopy(bytes, sealed, g.principal, 0, [], context);
  assert.equal(restored.currentPriv(), g.signingPriv);
}
