import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import * as accountKey from "../contract/account-key.ts";
import {
  accountGrantSoul,
  accountIdFromLabel,
  contentWrapHex,
  currentSigningKey,
  deliveryMintsGrant,
  enroll,
  gunDocument,
  importGenesis,
  LinkedCredential,
  MemoryKeyWrapStore,
  openAccountBackup,
  parseWrapObject,
  principalKey,
  sameAccount,
  sealAccountBackup,
  type EncryptedAccountWrap,
} from "../contract/account-key.ts";
import { contentWrapHexWith, sealAccountBackupWith } from "./support/account-key-deterministic.ts";
import {
  historyState,
  parsePrincipalId,
  resolveCurrentKey,
  verifyOidcLink,
  verifyWalletLink,
  type Jwks,
  type PrincipalId,
  type ResolutionContext,
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
    transportPub: string;
    ephemeralScalarHex: string;
    nonceHex: string;
    wrapId: string;
    ciphertextHex: string;
    signature: string;
  };
  substitution: {
    signingPub: string;
    signingPriv: string;
    epub: string;
    epriv: string;
    laneId: string;
    ephemeralScalarHex: string;
    nonceHex: string;
    wrapId: string;
    ciphertextHex: string;
    signature: string;
  };
  offCurveTransportPub: string;
  afterRotation: {
    laneId: string;
    signingPub: string;
    signingPriv: string;
    epub: string;
    epriv: string;
    transportPub: string;
    transportScalarHex: string;
    ephemeralScalarHex: string;
    nonceHex: string;
    wrapId: string;
    ciphertextHex: string;
    signature: string;
    rotationName: string;
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
    jwks: Jwks;
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

function emptyContext(): ResolutionContext {
  return {
    jwks: { keys: [] },
    links: new Map(),
    revocations: [],
    now: 1_700_000_060,
    policy: { allowedDomains: [], allowedUris: [], allowedChainIds: [] },
    pinnedIss: new Set(),
    history: () => ({ ok: false, reason: "missing-history" }),
  };
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
  const linked = LinkedCredential.fromWallet(
    wallet.input,
    records.context.jwks,
    records.context.policy,
    records.context.now,
    keyState,
  );
  assert.equal(sameAccount(linked, genesisId.value), true);
  assert.throws(
    () => LinkedCredential.fromWallet(
      { v: 1, kind: "wallet", principal: genesisId.value, address: "0xabc", keySig: "x", attest: "y" },
      records.context.jwks,
      records.context.policy,
      records.context.now,
      keyState,
    ),
    (error: unknown) => error instanceof Error && error.message === "unverified-credential",
  );
  const flipped = { ...wallet.input, keySig: flipHex(String(wallet.input["keySig"])) };
  assert.throws(() => LinkedCredential.fromWallet(flipped, records.context.jwks, records.context.policy, records.context.now, keyState));
  assert.throws(() => sameAccount({ kind: "wallet", principal: genesisId.value, label: verified.value.address } as LinkedCredential, genesisId.value));
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
  const oidcLink = LinkedCredential.fromOidc(
    oidc.input,
    records.context.jwks,
    new Set(records.context.pinnedIss),
    records.context.now,
    keyState,
  );
  assert.throws(() =>
    LinkedCredential.fromOidc(
      { ...oidc.input, keySig: "x" },
      records.context.jwks,
      new Set(records.context.pinnedIss),
      records.context.now,
      keyState,
    ),
  );
  assert.equal(sameAccount(oidcLink, genesisId.value), true);
  assert.notEqual(oidcLink.principal, verifiedOidc.value.cred.sub);
  assert.equal(accountIdFromLabel(verifiedOidc.value.cred.sub).ok, false);
  assert.equal(accountIdFromLabel(verifiedOidc.value.cred.iss).ok, false);
});

test("rotation uses the package current key", () => {
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
  assert.equal(currentSigningKey(genesisId.value, [rotate.input], {
    ...records.context,
    links,
    history,
    pinnedIss: new Set(records.context.pinnedIss),
  } as ResolutionContext), nextKey);
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
  const context = emptyContext();
  const wrap = sealAccountBackup(genesis, vector.backupWrap.transportPub, wrapId, store, [], context);
  const again = sealAccountBackup(
    genesis,
    vector.backupWrap.transportPub,
    parseWrapObject("wrap_ffeeddccbbaa99887766554433221100"),
    new MemoryKeyWrapStore(),
    [],
    context,
  );
  assert.notEqual(wrap.ciphertextHex, again.ciphertextHex);
  assert.equal(wrap.ciphertextHex.includes(vector.signingScalarHex.toLowerCase()), false);
  assert.equal(wrap.ciphertextHex.includes(genesis.priv), false);
  assert.equal(wrap.ciphertextHex.includes(genesis.epriv), false);
  assert.throws(
    () => sealAccountBackup(genesis, genesis.epub, wrapId, new MemoryKeyWrapStore(), [], context),
    (error: unknown) => error instanceof Error && error.message === "transport",
  );
  assert.throws(
    () => sealAccountBackup(genesis, genesis.pub, wrapId, new MemoryKeyWrapStore(), [], context),
    (error: unknown) => error instanceof Error && error.message === "transport",
  );
  const gun = gunDocument(genesis);
  assert.equal(gun.includes(wrap.ciphertextHex), false);
  assert.equal(gun.includes(genesis.priv), false);
  const stored = store.get(genesis.principal);
  assert.ok(stored);
  if (!stored) return;
  const opened = openAccountBackup(vector.backupWrap.transportScalarHex, stored, genesis.principal, [], context);
  assert.equal(opened.principal, genesis.principal);
  assert.equal(opened.priv, genesis.priv);
  assert.equal(opened.epriv, genesis.epriv);
  assert.equal(opened.epub, genesis.epub);
  const inherited = enroll(opened, "tablet");
  assert.equal(inherited.grantsSee, false);
  assert.equal(inherited.account.epub, genesis.epub);
  const wrapped = contentWrapHexWith(
    genesis,
    vector.contentWrap.dekHex,
    vector.contentWrap.ephemeralScalarHex,
    vector.contentWrap.nonceHex,
    vector.contentWrap.epoch,
    vector.contentWrap.objectId,
    vector.contentWrap.revisionId,
  );
  assert.equal(wrapped, vector.contentWrap.wrappedKey);
  const randomWrap = contentWrapHex(
    genesis,
    vector.contentWrap.dekHex,
    vector.contentWrap.epoch,
    vector.contentWrap.objectId,
    vector.contentWrap.revisionId,
  );
  const randomAgain = contentWrapHex(
    genesis,
    vector.contentWrap.dekHex,
    vector.contentWrap.epoch,
    vector.contentWrap.objectId,
    vector.contentWrap.revisionId,
  );
  assert.notEqual(randomWrap, randomAgain);
  assert.notEqual(randomWrap, wrapped);
  const phone = enroll(genesis, "phone");
  const laptop = enroll(genesis, "laptop");
  assert.equal(phone.account.epub, laptop.account.epub);
  assert.equal(contentWrapHexWith(
    laptop.account,
    vector.contentWrap.dekHex,
    vector.contentWrap.ephemeralScalarHex,
    vector.contentWrap.nonceHex,
    vector.contentWrap.epoch,
    vector.contentWrap.objectId,
    vector.contentWrap.revisionId,
  ), wrapped);
  const object = parseWrapObject(vector.contentWrap.objectId);
  const soul = accountGrantSoul(genesis.principal, object, genesis.principal);
  assert.throws(() => contentWrapHex(genesis, vector.contentWrap.dekHex, Number.NaN, vector.contentWrap.objectId, vector.contentWrap.revisionId));
  assert.throws(() => contentWrapHex(genesis, vector.contentWrap.dekHex, vector.contentWrap.epoch, "not-an-object", vector.contentWrap.revisionId));
  assert.throws(
    () => sealAccountBackup(genesis, vector.offCurveTransportPub, wrapId, new MemoryKeyWrapStore(), [], context),
    (error: unknown) => error instanceof Error && error.message === "bad-key",
  );
  const shortSig: EncryptedAccountWrap = { ...stored, signature: "ab" };
  assert.throws(
    () => openAccountBackup(vector.backupWrap.transportScalarHex, shortSig, genesis.principal, [], context),
    (error: unknown) => error instanceof Error && error.message === "wrap-rejected",
  );
  const attacker = importGenesis(
    vector.substitution.laneId,
    vector.substitution.signingPub,
    vector.substitution.signingPriv,
    vector.substitution.epub,
    vector.substitution.epriv,
  );
  const swapped = sealAccountBackup(attacker, vector.backupWrap.transportPub, parseWrapObject("wrap_00112233445566778899aabbccddee00"), new MemoryKeyWrapStore(), [], context);
  assert.throws(() => openAccountBackup(vector.backupWrap.transportScalarHex, swapped, genesis.principal, [], context));
  assert.equal(soul.split("/").length, 5);
  assert.equal(soul.includes(principalKey(genesis)), true);
  assert.equal(soul.includes(genesis.principal), false);
});

test("enrollment hop hint wrap request and inbox do not grant", () => {
  for (const kind of vector.deliveries) assert.equal(deliveryMintsGrant(kind), false);
  assert.throws(() => deliveryMintsGrant("grant"));
  assert.equal(enroll(account(), "phone").grantsSee, false);
});

test("public transport key seal matches the shared vector", () => {
  const genesis = account();
  const store = new MemoryKeyWrapStore();
  const context = emptyContext();
  const wrap = sealAccountBackupWith(
    genesis,
    vector.backupWrap.transportPub,
    vector.backupWrap.ephemeralScalarHex,
    vector.backupWrap.nonceHex,
    parseWrapObject(vector.backupWrap.wrapId),
    [],
    context,
    store,
  );
  assert.equal(wrap.ciphertextHex, vector.backupWrap.ciphertextHex);
  assert.equal(wrap.signature, vector.backupWrap.signature);
  const opened = openAccountBackup(vector.backupWrap.transportScalarHex, wrap, genesis.principal, [], context);
  assert.equal(opened.principal, genesis.principal);
  assert.equal(opened.priv, genesis.priv);
});

test("a wrap sealed to the victim transport pub by another account does not open", () => {
  const victim = account();
  const attacker = importGenesis(
    vector.substitution.laneId,
    vector.substitution.signingPub,
    vector.substitution.signingPriv,
    vector.substitution.epub,
    vector.substitution.epriv,
  );
  const store = new MemoryKeyWrapStore();
  const context = emptyContext();
  const wrap = sealAccountBackupWith(
    attacker,
    vector.backupWrap.transportPub,
    vector.substitution.ephemeralScalarHex,
    vector.substitution.nonceHex,
    parseWrapObject(vector.substitution.wrapId),
    [],
    context,
    store,
  );
  assert.equal(wrap.ciphertextHex, vector.substitution.ciphertextHex);
  assert.equal(wrap.signature, vector.substitution.signature);
  assert.throws(() => openAccountBackup(vector.backupWrap.transportScalarHex, wrap, victim.principal, [], context));
  const relabeled: EncryptedAccountWrap = { ...wrap, principal: victim.principal, epub: victim.epub };
  assert.throws(() => openAccountBackup(vector.backupWrap.transportScalarHex, relabeled, victim.principal, [], context));
});

test("seal is refused and open is rejected after rotation", () => {
  const row = vector.afterRotation;
  const genesis = importGenesis(row.laneId, row.signingPub, row.signingPriv, row.epub, row.epriv);
  assert.equal(genesis.principal, records.context.genesis);
  assert.equal(row.rotationName, "wallet-rotate");
  const rotate = records.accept.find((item) => item.name === row.rotationName);
  assert.ok(rotate);
  if (!rotate) return;
  const context = recordsContext();
  const store = new MemoryKeyWrapStore();
  const wrap = sealAccountBackupWith(
    genesis,
    row.transportPub,
    row.ephemeralScalarHex,
    row.nonceHex,
    parseWrapObject(row.wrapId),
    [],
    context,
    store,
  );
  assert.equal(wrap.ciphertextHex, row.ciphertextHex);
  assert.equal(wrap.signature, row.signature);
  const opened = openAccountBackup(row.transportScalarHex, wrap, genesis.principal, [], context);
  assert.equal(opened.priv, genesis.priv);
  assert.throws(
    () => sealAccountBackup(genesis, row.transportPub, parseWrapObject(row.wrapId), new MemoryKeyWrapStore(), [rotate.input], context),
    (error: unknown) => error instanceof Error && error.message === "current-key",
  );
  assert.throws(
    () => openAccountBackup(row.transportScalarHex, wrap, genesis.principal, [rotate.input], context),
    (error: unknown) => error instanceof Error && error.message === "wrap-rejected",
  );
});

test("a forged LinkedCredential is rejected", () => {
  const victim = account().principal;
  const reject = (run: () => void) => {
    assert.throws(run, (error: unknown) => error instanceof Error && error.message === "unverified-credential");
  };
  reject(() => new (LinkedCredential as unknown as new (...args: unknown[]) => unknown)("wallet", victim, "x"));
  reject(() => Reflect.construct(LinkedCredential, ["wallet", victim, "x"]));
  reject(() => Reflect.construct(LinkedCredential, [Symbol("linked-credential-ctor"), "wallet", victim, "x"]));
  reject(() => sameAccount(Object.create(LinkedCredential.prototype), victim));
  reject(() => sameAccount(Object.setPrototypeOf({ principal: victim, kind: "wallet", label: "x" }, LinkedCredential.prototype), victim));
  const plain = { principal: victim, kind: "wallet", label: "x" };
  assert.throws(() => {
    Object.defineProperty(LinkedCredential, Symbol.hasInstance, { configurable: true, value: () => true });
  });
  assert.equal(plain instanceof LinkedCredential, false);
  reject(() => sameAccount(plain, victim));
});

test("LinkedCredential statics cannot be reassigned", () => {
  const victim = account().principal;
  const plain = { principal: victim, kind: "wallet" as const, label: "x" };
  const blocked: Array<() => void> = [
    () => {
      (LinkedCredential as unknown as { isVerified: (value: unknown) => boolean }).isVerified = () => true;
    },
    () => {
      (LinkedCredential as unknown as { fromWallet: () => unknown }).fromWallet = () => plain;
    },
    () => {
      (LinkedCredential as unknown as { fromOidc: () => unknown }).fromOidc = () => plain;
    },
    () => {
      (LinkedCredential as unknown as { prototype: object }).prototype = { principal: victim };
    },
    () => {
      Object.defineProperty(LinkedCredential, "isVerified", { configurable: true, value: () => true });
    },
  ];
  for (const assign of blocked) assert.throws(assign);
  assert.equal(Object.isFrozen(LinkedCredential), true);
  assert.equal(Object.isFrozen(LinkedCredential.prototype), true);
  for (const name of ["isVerified", "fromWallet", "fromOidc", "prototype"] as const) {
    const descriptor = Object.getOwnPropertyDescriptor(LinkedCredential, name);
    assert.equal(descriptor?.writable ?? false, false);
    assert.equal(descriptor?.configurable, false);
  }
  assert.equal(LinkedCredential.isVerified(plain), false);
  assert.throws(
    () => sameAccount(plain, victim),
    (error: unknown) => error instanceof Error && error.message === "unverified-credential",
  );
});

test("a verified principal cannot be replaced", () => {
  const wallet = records.accept.find((row) => row.name === "wallet");
  assert.ok(wallet);
  if (!wallet) return;
  const genesisId = parsePrincipalId(records.context.genesis);
  assert.equal(genesisId.ok, true);
  if (!genesisId.ok) return;
  const keyState = { key: genesisId.value, currentKey: genesisId.value, retainedLinks: null };
  const linked = LinkedCredential.fromWallet(wallet.input, records.context.jwks, records.context.policy, records.context.now, keyState);
  assert.throws(() => {
    (linked as { principal: PrincipalId }).principal = account().principal;
  });
  assert.equal(linked.principal, genesisId.value);
  assert.equal(sameAccount(linked, genesisId.value), true);
  assert.equal(sameAccount(linked, account().principal), false);
});

test("oversized and wrong-length transport pubs are bad-key", () => {
  const genesis = account();
  const wrapId = parseWrapObject(vector.backupWrap.wrapId);
  const context = emptyContext();
  for (const transportPub of ["", "A".repeat(10), "A".repeat(86), "A".repeat(87), "A".repeat(88), "A".repeat(100_000)]) {
    assert.throws(
      () => sealAccountBackup(genesis, transportPub, wrapId, new MemoryKeyWrapStore(), [], context),
      (error: unknown) => error instanceof Error && error.message === "bad-key",
      `length ${transportPub.length}`,
    );
  }
});

test("a malformed wrap id is rejected before signature verification", () => {
  const genesis = account();
  // A 128-hex signature passes the length check. If verification ran, this
  // dummy signature would be `wrap-rejected`. `bad-alphabet` and `too-long`
  // come only from parseWrapObject, which open calls first.
  const wrap: EncryptedAccountWrap = {
    principal: genesis.principal,
    wrapId: "not-an-object" as EncryptedAccountWrap["wrapId"],
    epub: genesis.epub,
    ciphertextHex: "00",
    signature: "ab".repeat(64),
  };
  assert.throws(
    () => openAccountBackup("00".repeat(32), wrap, genesis.principal, [], emptyContext()),
    (error: unknown) => error instanceof Error && error.message === "bad-alphabet",
  );
  const huge: EncryptedAccountWrap = { ...wrap, wrapId: "a".repeat(10_000) as EncryptedAccountWrap["wrapId"] };
  assert.throws(
    () => openAccountBackup("00".repeat(32), huge, genesis.principal, [], emptyContext()),
    (error: unknown) => error instanceof Error && error.message === "too-long",
  );
});

test("deterministic helpers are not production exports", () => {
  const names = Object.keys(accountKey);
  assert.equal(names.includes("sealAccountBackupWith"), false);
  assert.equal(names.includes("contentWrapHexWith"), false);
  assert.equal(names.includes("accountKeyTestApi"), false);
  assert.equal(names.includes("encryptAccountBackup"), false);
  assert.equal(names.includes("wrapContent"), false);
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { exports: Record<string, string> };
  const exported = JSON.stringify(pkg.exports);
  assert.equal(exported.includes("account-key"), false);
  assert.equal(exported.includes("account-key-deterministic"), false);
});

function recordsContext(): ResolutionContext {
  const links = new Map(records.context.links);
  const history = (principal: PrincipalId, at: number, until: number) =>
    records.context.authenticatedAccounts.includes(principal)
      ? { ok: true as const, value: historyState(principal, [], at, until) }
      : { ok: false as const, reason: "missing-history" as const };
  return {
    jwks: records.context.jwks,
    links,
    revocations: [],
    now: records.context.now,
    policy: records.context.policy,
    pinnedIss: new Set(records.context.pinnedIss),
    history,
  } as ResolutionContext;
}

function flipHex(signature: string): string {
  const first = signature[0] === "a" ? "b" : "a";
  return first + signature.slice(1);
}
