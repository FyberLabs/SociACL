import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  accountGrantSoul,
  accountIdFromLabel,
  contentWrapHex,
  deliveryMintsGrant,
  enroll,
  gunDocument,
  importGenesis,
  MemoryKeyWrapStore,
  openAccountBackup,
  parseWrapObject,
  principalKey,
  sameAccount,
  sealAccountBackup,
  type LinkedCredential,
} from "../contract/account-key.ts";
import {
  historyState,
  parsePrincipalId,
  resolveCurrentKey,
  verifyOidcLink,
  verifyWalletLink,
  type PrincipalId,
} from "../ids/src/index.js";

const vector = JSON.parse(readFileSync(new URL("../../vectors/encrypted-discovery/account-key.json", import.meta.url), "utf8")) as {
  signingPub: string;
  signingPriv: string;
  signingScalarHex: string;
  epub: string;
  epriv: string;
  laneId: string;
  principal: string;
  principalKey: string;
  wallet: string;
  gunDocument: string;
  nonIdentities: { name: string; input: string; reason: string }[];
  deliveries: string[];
  backupWrap: {
    transportScalarHex: string;
    ephemeralScalarHex: string;
    nonceHex: string;
    wrapId: string;
    ciphertextHex: string;
  };
  contentWrap: {
    dekHex: string;
    ephemeralScalarHex: string;
    nonceHex: string;
    epoch: number;
    objectId: string;
    revisionId: string;
    wrappedKey: string;
  };
};

const records = JSON.parse(readFileSync(new URL("../../vectors/ids/records.json", import.meta.url), "utf8")) as {
  accept: { name: string; input: Record<string, unknown> }[];
  context: {
    jwks: { keys: readonly unknown[] };
    pinnedIss: string[];
    now: number;
    genesis: string;
    currentKey: string;
    links: [string, unknown][];
    policy: { allowedDomains: string[]; allowedUris: string[]; allowedChainIds: string[] };
    authenticatedAccounts: string[];
  };
};

function account() {
  return importGenesis(vector.laneId, vector.signingPub, vector.signingPriv, vector.epub, vector.epriv);
}

test("enrollment inherits one keypair and secrets stay off gun", () => {
  const genesis = account();
  assert.equal(genesis.principal, vector.principal);
  assert.equal(genesis.pub, genesis.principal);
  assert.equal(principalKey(genesis), vector.principalKey);
  assert.notEqual(genesis.epub, genesis.principal);
  const phone = enroll(genesis, "phone");
  const laptop = enroll(genesis, "laptop");
  assert.equal(phone.account.principal, laptop.account.principal);
  assert.equal(phone.account.epub, laptop.account.epub);
  assert.equal(phone.account.priv, laptop.account.priv);
  assert.equal(phone.account.epriv, laptop.account.epriv);
  assert.equal(phone.account.laneId, laptop.account.laneId);
  assert.equal(phone.grantsSee, false);
  assert.equal(laptop.grantsSee, false);
  assert.throws(() => enroll(genesis, ""));
  assert.throws(() => enroll(genesis, genesis.principal));
  assert.throws(() => enroll(genesis, vector.wallet));
  const gun = gunDocument(phone.account);
  assert.equal(gun, vector.gunDocument);
  assert.equal(gun.includes(genesis.priv), false);
  assert.equal(gun.includes(genesis.epriv), false);
  assert.equal(gun.includes(vector.signingScalarHex), false);
  assert.equal(gun.includes(vector.signingScalarHex.toLowerCase()), false);
  assert.equal(gun.includes("\"priv\""), false);
  assert.equal(gun.includes("\"epriv\""), false);
  assert.equal(gun.includes("phone"), false);
  assert.equal(gun.includes(genesis.laneId), false);
});

test("labels are not accounts and credentials are not identities", () => {
  const genesis = account();
  for (const row of vector.nonIdentities) {
    const parsed = accountIdFromLabel(row.input);
    assert.equal(parsed.ok, false, row.name);
    if (!parsed.ok) assert.equal(parsed.reason, row.reason, row.name);
  }
  const wallet = records.accept.find((row) => row.name === "wallet");
  const oidc = records.accept.find((row) => row.name === "oidc");
  assert.ok(wallet && oidc);
  const genesisId = parsePrincipalId(records.context.genesis);
  assert.equal(genesisId.ok, true);
  if (!genesisId.ok) return;
  const keyState = { key: genesisId.value, currentKey: genesisId.value, retainedLinks: null };
  const verified = verifyWalletLink(wallet.input, records.context.jwks, records.context.policy, records.context.now, keyState);
  assert.equal(verified.ok, true);
  if (!verified.ok) return;
  const linked: LinkedCredential = { kind: "wallet", principal: verified.value.principal, label: verified.value.address };
  assert.equal(sameAccount(linked, genesisId.value), true);
  assert.equal(sameAccount(linked, genesis.principal), false);
  assert.notEqual(linked.principal, verified.value.address);
  assert.equal(accountIdFromLabel(verified.value.address).ok, false);
  const verifiedOidc = verifyOidcLink(
    oidc.input,
    records.context.jwks,
    new Set(records.context.pinnedIss),
    records.context.now,
    keyState,
  );
  assert.equal(verifiedOidc.ok, true);
  if (!verifiedOidc.ok) return;
  const oidcLink: LinkedCredential = {
    kind: "oidc",
    principal: verifiedOidc.value.principal,
    label: verifiedOidc.value.cred.sub,
  };
  assert.equal(sameAccount(oidcLink, genesisId.value), true);
  assert.notEqual(oidcLink.principal, verifiedOidc.value.cred.sub);
  assert.equal(accountIdFromLabel(verifiedOidc.value.cred.sub).ok, false);
  assert.equal(accountIdFromLabel(verifiedOidc.value.cred.iss).ok, false);
});

test("rotation uses the package current key and does not change epub", () => {
  const genesis = account();
  const rotate = records.accept.find((row) => row.name === "wallet-rotate");
  assert.ok(rotate);
  const genesisId = parsePrincipalId(records.context.genesis);
  assert.equal(genesisId.ok, true);
  if (!genesisId.ok || !rotate) return;
  const links = new Map(records.context.links);
  const history = (principal: PrincipalId, at: number, until: number) =>
    records.context.authenticatedAccounts.includes(principal)
      ? { ok: true as const, value: historyState(principal, [], at, until) }
      : { ok: false as const, reason: "missing-history" as const };
  const resolved = resolveCurrentKey(genesisId.value, [rotate.input], {
    ...records.context,
    links,
    history,
    pinnedIss: new Set(records.context.pinnedIss),
  });
  assert.equal(resolved.ok, true);
  if (!resolved.ok) return;
  const nextKey = rotate.input["nextKey"];
  assert.equal(typeof nextKey, "string");
  assert.equal(resolved.value.currentKey, nextKey);
  assert.notEqual(resolved.value.currentKey, records.context.genesis);
  assert.notEqual(resolved.value.currentKey, vector.wallet);
  assert.equal(genesis.principal, vector.principal);
  assert.equal(genesis.epub, vector.epub);
  assert.notEqual(genesis.epub, resolved.value.currentKey);
});

test("backup wrap is stored off gun and both devices open one epub wrap", () => {
  const genesis = account();
  const store = new MemoryKeyWrapStore();
  assert.equal(store.isAuthority, false);
  assert.equal(store.mintsGrant, false);
  const wrapId = parseWrapObject(vector.backupWrap.wrapId);
  const wrap = sealAccountBackup(
    genesis,
    vector.backupWrap.transportScalarHex,
    vector.backupWrap.ephemeralScalarHex,
    vector.backupWrap.nonceHex,
    wrapId,
    store,
  );
  assert.equal(wrap.ciphertextHex, vector.backupWrap.ciphertextHex);
  assert.equal(wrap.epub, genesis.epub);
  assert.equal(wrap.ciphertextHex.includes(genesis.priv), false);
  assert.equal(wrap.ciphertextHex.includes(genesis.epriv), false);
  const gun = gunDocument(genesis);
  assert.equal(gun.includes(wrap.ciphertextHex), false);
  assert.equal(gun.includes(genesis.priv), false);
  const stored = store.get(genesis.principal);
  assert.ok(stored);
  if (!stored) return;
  const opened = openAccountBackup(vector.backupWrap.transportScalarHex, stored);
  assert.equal(opened.principal, genesis.principal);
  assert.equal(opened.priv, genesis.priv);
  assert.equal(opened.epriv, genesis.epriv);
  assert.equal(opened.epub, genesis.epub);
  const inherited = enroll(opened, "tablet");
  assert.equal(inherited.grantsSee, false);
  assert.equal(inherited.account.epub, genesis.epub);
  const wrapped = contentWrapHex(
    genesis,
    vector.contentWrap.dekHex,
    vector.contentWrap.ephemeralScalarHex,
    vector.contentWrap.nonceHex,
    vector.contentWrap.epoch,
    vector.contentWrap.objectId,
    vector.contentWrap.revisionId,
  );
  assert.equal(wrapped, vector.contentWrap.wrappedKey);
  const phone = enroll(genesis, "phone");
  const laptop = enroll(genesis, "laptop");
  assert.equal(phone.account.epub, laptop.account.epub);
  assert.equal(contentWrapHex(
    laptop.account,
    vector.contentWrap.dekHex,
    vector.contentWrap.ephemeralScalarHex,
    vector.contentWrap.nonceHex,
    vector.contentWrap.epoch,
    vector.contentWrap.objectId,
    vector.contentWrap.revisionId,
  ), wrapped);
  const object = parseWrapObject(vector.contentWrap.objectId);
  const epubId = parsePrincipalId(genesis.epub);
  assert.equal(epubId.ok, true);
  if (!epubId.ok) return;
  const soul = accountGrantSoul(genesis.principal, object, epubId.value);
  assert.equal(soul.split("/").length, 5);
  assert.equal(soul.includes(principalKey(genesis)), true);
  assert.equal(soul.includes(genesis.principal), false);
});

test("enrollment hop hint wrap request and inbox do not grant", () => {
  for (const kind of vector.deliveries) assert.equal(deliveryMintsGrant(kind), false);
  assert.throws(() => deliveryMintsGrant("grant"));
  assert.equal(enroll(account(), "phone").grantsSee, false);
});
