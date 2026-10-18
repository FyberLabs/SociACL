import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  deliveryMintsGrant,
  importGenesis,
  principalKey,
} from "../contract/account-key.ts";
import {
  AccountKeyring,
  draftDocument,
  epubForNewSeal,
  mintRotation,
  rotateKeyring,
} from "../contract/account-keyring.ts";
import { seaPoint } from "../contract/account-key-seal.ts";
import { openReaderWrap } from "../contract/content-wrap.ts";
import { sealContentWith } from "./support/account-key-deterministic.ts";
import {
  formatPrincipalKey,
  historyState,
  parsePrincipalId,
  type Jwks,
  type PrincipalId,
  type ResolutionContext,
} from "../ids/src/index.js";

const vector = JSON.parse(readFileSync(new URL("../../vectors/encrypted-discovery/account-keyring.json", import.meta.url), "utf8")) as {
  genesis: {
    laneId: string;
    signingPub: string;
    signingPriv: string;
    signingScalarHex: string;
    epub: string;
    epriv: string;
    principal: string;
  };
  mint: { signingPub: string; signingPriv: string; epub: string; epriv: string; laneId: string };
  trusted: string[];
  lost: string;
  wallet: string;
  errors: Record<string, string>;
  expected: {
    principal: string;
    pub: string;
    epub: string;
    laneId: string;
    contentEpoch: number;
    rotationSeq: number;
    prevKey: string;
    nextKey: string;
    nextEpub: string;
    version: number;
    devices: string[];
    retiredEpubs: string[];
    gunDocument: string;
    draftDocument: string;
  };
  witnessed: {
    rotationName: string;
    genesisScalar: number;
    genesisEpubScalar: number;
    currentScalar: number;
    epubScalar: number;
    laneId: string;
    contentEpoch: number;
    rotationSeq: number;
    dekHex: string;
    objectId: string;
    revisionId: string;
  };
  crossWrap: { ephemeralScalar: number; nonceByte: number; epoch: number; wrappedKey: string };
};

const accountKey = JSON.parse(readFileSync(new URL("../../vectors/encrypted-discovery/account-key.json", import.meta.url), "utf8")) as {
  contentWrap: { dekHex: string; epoch: number; objectId: string; revisionId: string; wrappedKey: string; ephemeralScalarHex: string; nonceHex: string };
};

const records = JSON.parse(readFileSync(new URL("../../vectors/ids/records.json", import.meta.url), "utf8")) as {
  accept: { name: string; input: Record<string, unknown> }[];
  context: {
    jwks: Jwks;
    pinnedIss: string[];
    now: number;
    genesis: string;
    links: [string, unknown][];
    policy: { allowedDomains: string[]; allowedUris: string[]; allowedChainIds: string[] };
    authenticatedAccounts: string[];
  };
};

function message(run: () => void): string {
  try {
    run();
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
  throw new Error("expected throw");
}

function b64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function scalarSea(last: number): { pub: string; priv: string } {
  const bytes = new Uint8Array(32);
  bytes[31] = last;
  const pub = seaPoint(bytes);
  const priv = b64(bytes);
  bytes.fill(0);
  return { pub, priv };
}

function vectorMint() {
  return {
    signingPub: vector.mint.signingPub,
    signingPriv: vector.mint.signingPriv,
    epub: vector.mint.epub,
    epriv: vector.mint.epriv,
    laneId: vector.mint.laneId,
  };
}

function genesis() {
  return importGenesis(
    vector.genesis.laneId,
    vector.genesis.signingPub,
    vector.genesis.signingPriv,
    vector.genesis.epub,
    vector.genesis.epriv,
  );
}

function secretsAbsent(text: string): void {
  const secrets = [
    vector.genesis.signingPriv,
    vector.genesis.epriv,
    vector.genesis.signingScalarHex,
    vector.genesis.signingScalarHex.toLowerCase(),
    vector.genesis.laneId,
    vector.mint.signingPriv,
    vector.mint.epriv,
    vector.mint.laneId,
  ];
  for (const secret of secrets) assert.equal(text.includes(secret), false);
  assert.equal(text.includes("\"priv\""), false);
  assert.equal(text.includes("\"epriv\""), false);
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

function recordsContext(bindings: readonly unknown[] = []): ResolutionContext {
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
    genesisEpubBindings: bindings,
  } as ResolutionContext;
}

test("rotation matches the shared vector and keeps secrets off gun", () => {
  const keyring = AccountKeyring.fromGenesis(genesis());
  const outcome = rotateKeyring(keyring, vector.trusted, vector.lost, [], emptyContext(), vectorMint);
  const expected = vector.expected;
  assert.equal(outcome.keyring.principal, expected.principal);
  assert.equal(outcome.keyring.principal, vector.genesis.principal);
  assert.equal(outcome.keyring.genesisEpub, vector.genesis.epub);
  assert.equal(outcome.keyring.pub, expected.pub);
  assert.equal(outcome.keyring.epub, expected.epub);
  assert.equal(outcome.keyring.currentPriv(), vector.mint.signingPriv);
  assert.equal(outcome.keyring.currentEpriv(), vector.mint.epriv);
  assert.equal(outcome.keyring.laneId(), expected.laneId);
  assert.equal(outcome.keyring.contentEpoch, expected.contentEpoch);
  assert.equal(outcome.keyring.rotationSeq, expected.rotationSeq);
  assert.equal(outcome.draft.version, expected.version);
  assert.equal(outcome.draft.prevKey, expected.prevKey);
  assert.equal(outcome.draft.nextKey, expected.nextKey);
  assert.equal(outcome.draft.nextEpub, expected.nextEpub);
  assert.equal(draftDocument(outcome.draft), expected.draftDocument);
  assert.equal(outcome.lostLocalId, vector.lost);
  assert.deepEqual(outcome.devices.map((device) => device.localId), expected.devices);
  for (const device of outcome.devices) {
    assert.equal(device.grantsSee, false);
    assert.equal(device.keyring.currentEpriv(), outcome.keyring.currentEpriv());
    assert.equal(device.keyring.laneId(), outcome.keyring.laneId());
    assert.equal(device.gunDocument(), outcome.keyring.gunDocument());
  }
  assert.deepEqual(outcome.keyring.retired().map((row) => row.epub), expected.retiredEpubs);
  assert.equal(outcome.keyring.retired()[0]?.epriv, vector.genesis.epriv);
  const gun = outcome.keyring.gunDocument();
  assert.equal(gun, expected.gunDocument);
  const pathKey = formatPrincipalKey(outcome.keyring.principal);
  assert.equal(pathKey.startsWith("p_"), true);
  assert.equal(gun.includes(pathKey), false);
  assert.equal(gun.includes("p_"), false);
  assert.equal(principalKey(genesis()), pathKey);
  secretsAbsent(gun);
  secretsAbsent(draftDocument(outcome.draft));
  secretsAbsent(JSON.stringify(outcome.keyring));
  for (const device of outcome.devices) secretsAbsent(device.gunDocument());
  const opened = outcome.keyring.openContent(
    accountKey.contentWrap.wrappedKey,
    accountKey.contentWrap.epoch,
    accountKey.contentWrap.objectId,
    accountKey.contentWrap.revisionId,
    vector.genesis.epub,
  );
  assert.equal(opened, accountKey.contentWrap.dekHex);
  assert.notEqual(outcome.keyring.epub, vector.genesis.epub);
  for (const kind of ["enrollment", "hop", "hint", "wrap", "request", "inbox"]) {
    assert.equal(deliveryMintsGrant(kind), false);
  }
});

test("builder refuses a held epub and a bad device", () => {
  const keyring = AccountKeyring.fromGenesis(genesis());
  const genesisEpubMint = () => ({
    signingPub: vector.mint.signingPub,
    signingPriv: vector.mint.signingPriv,
    epub: vector.genesis.epub,
    epriv: vector.genesis.epriv,
    laneId: vector.mint.laneId,
  });
  assert.equal(
    message(() => rotateKeyring(keyring, vector.trusted, vector.lost, [], emptyContext(), genesisEpubMint)),
    vector.errors.epubReuse,
  );
  assert.equal(
    message(() => rotateKeyring(keyring, vector.trusted, vector.lost, [], emptyContext(), () => ({
      signingPub: vector.mint.signingPub,
      signingPriv: vector.mint.signingPriv,
      epub: vector.mint.signingPub,
      epriv: vector.mint.signingPriv,
      laneId: vector.mint.laneId,
    }))),
    vector.errors.epubReuse,
  );
  assert.equal(
    message(() => rotateKeyring(keyring, vector.trusted, vector.lost, [], emptyContext(), () => ({
      signingPub: vector.genesis.signingPub,
      signingPriv: vector.genesis.signingPriv,
      epub: vector.mint.epub,
      epriv: vector.mint.epriv,
      laneId: vector.mint.laneId,
    }))),
    vector.errors.epubReuse,
  );
  assert.equal(
    message(() => rotateKeyring(keyring, vector.trusted, vector.lost, [], emptyContext(), () => ({
      ...vectorMint(),
      laneId: vector.genesis.laneId,
    }))),
    vector.errors.badLane,
  );
  assert.equal(message(() => rotateKeyring(keyring, [], vector.lost, [], emptyContext(), vectorMint)), vector.errors.lostDevice);
  assert.equal(message(() => rotateKeyring(keyring, ["phone"], vector.lost, [], emptyContext(), vectorMint)), vector.errors.lostDevice);
  assert.equal(message(() => rotateKeyring(keyring, ["phone", "phone"], "phone", [], emptyContext(), vectorMint)), vector.errors.duplicateDevice);
  assert.equal(message(() => rotateKeyring(keyring, ["", "phone"], "phone", [], emptyContext(), vectorMint)), vector.errors.emptyDevice);
  assert.equal(
    message(() => rotateKeyring(keyring, [vector.genesis.principal, "phone"], "phone", [], emptyContext(), vectorMint)),
    vector.errors.deviceId,
  );
  assert.equal(
    message(() => rotateKeyring(keyring, [vector.wallet, "phone"], "phone", [], emptyContext(), vectorMint)),
    vector.errors.deviceId,
  );
  const outcome = rotateKeyring(keyring, vector.trusted, vector.lost, [], emptyContext(), vectorMint);
  assert.equal(
    message(() => rotateKeyring(outcome.keyring, vector.trusted, vector.lost, [], emptyContext(), genesisEpubMint)),
    vector.errors.epubReuse,
  );
  assert.equal(
    message(() => rotateKeyring(outcome.keyring, vector.trusted, vector.lost, [], emptyContext(), vectorMint)),
    vector.errors.epubReuse,
  );
});

test("null currentEpub refuses the seal and ignores gun", () => {
  const keyring = AccountKeyring.fromGenesis(genesis());
  const context = emptyContext();
  assert.equal(
    message(() => keyring.sealContent(
      vector.witnessed.dekHex,
      vector.witnessed.objectId,
      vector.witnessed.revisionId,
      [],
      context,
      vector.genesis.epub,
    )),
    vector.errors.epubUnknown,
  );
  assert.equal(message(() => epubForNewSeal(null, vector.genesis.epub)), vector.errors.epubUnknown);
  const witnessed = parsePrincipalId(vector.mint.epub);
  if (!witnessed.ok) throw new Error(witnessed.reason);
  assert.equal(epubForNewSeal(witnessed.value, "not-the-witness"), witnessed.value);
  assert.equal(
    message(() => importGenesis(
      vector.genesis.laneId,
      vector.genesis.signingPub,
      vector.mint.signingPriv,
      vector.genesis.epub,
      vector.genesis.epriv,
    )),
    vector.errors.pubMismatch,
  );
  assert.equal(
    message(() => AccountKeyring.import(
      vector.genesis.principal,
      vector.genesis.epub,
      vector.mint.signingPub,
      vector.mint.signingPriv,
      vector.mint.epub,
      vector.mint.epriv,
      [{ epub: vector.genesis.epub, epriv: vector.genesis.epriv }],
      vector.mint.laneId,
      1,
      1,
      [],
      context,
    )),
    vector.errors.pubMismatch,
  );
});

test("witnessed import seals only the resolved epub", () => {
  const rotation = records.accept.find((item) => item.name === vector.witnessed.rotationName);
  if (!rotation) throw new Error("missing rotation");
  const genesisPair = scalarSea(vector.witnessed.genesisScalar);
  const genesisEpub = scalarSea(vector.witnessed.genesisEpubScalar);
  const current = scalarSea(vector.witnessed.currentScalar);
  const epub = scalarSea(vector.witnessed.epubScalar);
  const other = scalarSea(8);
  assert.equal(genesisPair.pub, records.context.genesis);
  assert.equal(genesisPair.pub, rotation.input.principal);
  assert.equal(current.pub, rotation.input.nextKey);
  assert.equal(epub.pub, rotation.input.nextEpub);
  const context = recordsContext();
  const retired = [{ epub: genesisEpub.pub, epriv: genesisEpub.priv }];
  const imported = AccountKeyring.import(
    genesisPair.pub,
    genesisEpub.pub,
    current.pub,
    current.priv,
    epub.pub,
    epub.priv,
    retired,
    vector.witnessed.laneId,
    vector.witnessed.contentEpoch,
    vector.witnessed.rotationSeq,
    [rotation.input],
    context,
  );
  assert.equal(imported.principal, genesisPair.pub);
  assert.equal(imported.genesisEpub, genesisEpub.pub);
  assert.equal(imported.epub, epub.pub);
  assert.equal(imported.rotationSeq, 1);
  const sealed = imported.sealContent(
    vector.witnessed.dekHex,
    vector.witnessed.objectId,
    vector.witnessed.revisionId,
    [rotation.input],
    context,
    genesisPair.pub,
  );
  assert.equal(sealed.epoch, vector.witnessed.contentEpoch);
  assert.equal(sealed.targetId, epub.pub);
  assert.notEqual(sealed.targetId, genesisPair.pub);
  assert.notEqual(sealed.targetId, genesisEpub.pub);
  const sealedGun = imported.sealContent(
    vector.witnessed.dekHex,
    vector.witnessed.objectId,
    vector.witnessed.revisionId,
    [rotation.input],
    context,
    genesisEpub.pub,
  );
  assert.equal(sealedGun.targetId, epub.pub);
  const gun = imported.gunDocument();
  secretsAbsent(gun);
  assert.equal(gun.includes(current.priv), false);
  assert.equal(gun.includes(epub.priv), false);
  assert.equal(gun.includes(genesisEpub.priv), false);
  assert.equal(gun.includes(vector.witnessed.laneId), false);
  assert.equal(
    message(() => AccountKeyring.import(
      genesisPair.pub,
      genesisEpub.pub,
      current.pub,
      current.priv,
      epub.pub,
      epub.priv,
      retired,
      vector.witnessed.laneId,
      vector.witnessed.contentEpoch,
      vector.witnessed.rotationSeq,
      [],
      context,
    )),
    vector.errors.pubMismatch,
  );
  assert.equal(
    message(() => AccountKeyring.import(
      genesisPair.pub,
      genesisEpub.pub,
      current.pub,
      current.priv,
      other.pub,
      other.priv,
      retired,
      vector.witnessed.laneId,
      vector.witnessed.contentEpoch,
      vector.witnessed.rotationSeq,
      [rotation.input],
      context,
    )),
    vector.errors.epubMismatch,
  );
  assert.equal(
    message(() => AccountKeyring.import(
      genesisPair.pub,
      genesisEpub.pub,
      current.pub,
      current.priv,
      epub.pub,
      epub.priv,
      retired,
      vector.witnessed.laneId,
      vector.witnessed.contentEpoch,
      0,
      [rotation.input],
      context,
    )),
    vector.errors.rotationRejected,
  );
  const ignored = AccountKeyring.import(
    genesisPair.pub,
    genesisEpub.pub,
    current.pub,
    current.priv,
    epub.pub,
    epub.priv,
    retired,
    vector.witnessed.laneId,
    vector.witnessed.contentEpoch,
    vector.witnessed.rotationSeq,
    [rotation.input],
    recordsContext([{ kind: "nope" }]),
  );
  assert.equal(ignored.epub, epub.pub);
  assert.equal(
    message(() => AccountKeyring.import(
      genesisPair.pub,
      genesisEpub.pub,
      current.pub,
      current.priv,
      epub.pub,
      epub.priv,
      retired,
      vector.witnessed.laneId,
      0,
      vector.witnessed.rotationSeq,
      [rotation.input],
      context,
    )),
    vector.errors.contentEpoch,
  );
});

test("a fresh mint is v3 and leaves the principal in place", () => {
  const account = genesis();
  const keyring = AccountKeyring.fromGenesis(account);
  const outcome = rotateKeyring(keyring, vector.trusted, vector.lost, [], emptyContext(), mintRotation);
  assert.equal(outcome.keyring.principal, account.principal);
  assert.equal(outcome.draft.version, 3);
  assert.equal(draftDocument(outcome.draft).includes("\"nextEpub\""), true);
  assert.equal(outcome.devices.some((device) => device.localId === vector.lost), false);
  const gun = outcome.keyring.gunDocument();
  secretsAbsent(gun);
  assert.equal(gun.includes(outcome.keyring.currentPriv()), false);
  assert.equal(gun.includes(outcome.keyring.currentEpriv()), false);
  assert.equal(gun.includes(outcome.keyring.laneId()), false);
  for (const retired of outcome.keyring.retired()) assert.equal(gun.includes(retired.epriv), false);
  assert.equal(message(() => outcome.keyring.confirm([], emptyContext())), vector.errors.pubMismatch);
});

test("genesis-only import accepts the witnessed binding", () => {
  const row = records.accept.find((item) => item.name === "binding-valid-no-rotation") as { genesisEpubBindings?: unknown[] } | undefined;
  if (!row?.genesisEpubBindings) throw new Error("missing binding vector");
  const signing = scalarSea(1);
  const enc = scalarSea(9);
  const context = recordsContext(row.genesisEpubBindings);
  const imported = AccountKeyring.import(
    signing.pub,
    enc.pub,
    signing.pub,
    signing.priv,
    enc.pub,
    enc.priv,
    [],
    vector.genesis.laneId,
    0,
    0,
    [],
    context,
  );
  assert.equal(imported.epub, enc.pub);
  const sealed = imported.sealContent(
    vector.witnessed.dekHex,
    vector.witnessed.objectId,
    vector.witnessed.revisionId,
    [],
    context,
    signing.pub,
  );
  assert.equal(sealed.targetId, enc.pub);
  assert.notEqual(sealed.targetId, signing.pub);
  assert.equal(
    imported.openContent(sealed.wrappedKey, sealed.epoch, vector.witnessed.objectId, vector.witnessed.revisionId, sealed.targetId),
    vector.witnessed.dekHex,
  );
  const other = scalarSea(8);
  assert.equal(
    message(() => AccountKeyring.import(
      signing.pub,
      enc.pub,
      signing.pub,
      signing.priv,
      other.pub,
      other.priv,
      [],
      vector.genesis.laneId,
      0,
      0,
      [],
      context,
    )),
    vector.errors.epubMismatch,
  );
});

test("builder refuses an older signing key", () => {
  const chain = records.accept.find((item) => item.name === "probe-v3-then-v3") as { input: unknown[] } | undefined;
  if (!chain) throw new Error("missing chain");
  const genesisPair = scalarSea(1);
  const prior = scalarSea(2);
  const current = scalarSea(3);
  const firstEpub = scalarSea(6);
  const secondEpub = scalarSea(7);
  const genesisEpub = scalarSea(9);
  const fresh = scalarSea(11);
  const context = recordsContext();
  const imported = AccountKeyring.import(
    genesisPair.pub,
    genesisEpub.pub,
    current.pub,
    current.priv,
    secondEpub.pub,
    secondEpub.priv,
    [
      { epub: genesisEpub.pub, epriv: genesisEpub.priv },
      { epub: firstEpub.pub, epriv: firstEpub.priv },
    ],
    vector.witnessed.laneId,
    2,
    2,
    chain.input,
    context,
  );
  assert.equal(
    message(() => rotateKeyring(imported, vector.trusted, vector.lost, chain.input, context, () => ({
      signingPub: prior.pub,
      signingPriv: prior.priv,
      epub: fresh.pub,
      epriv: fresh.priv,
      laneId: "ee".repeat(32),
    }))),
    vector.errors.epubReuse,
  );
});

test("too many retired keys are refused", () => {
  const retired = Array.from({ length: 1025 }, () => ({ epub: "x", epriv: "y" }));
  assert.equal(
    message(() => AccountKeyring.import(
      vector.genesis.principal,
      vector.genesis.epub,
      vector.genesis.signingPub,
      vector.genesis.signingPriv,
      vector.mint.epub,
      vector.mint.epriv,
      retired,
      vector.genesis.laneId,
      0,
      0,
      [],
      emptyContext(),
    )),
    vector.errors.tooManyKeys,
  );
});

test("typescript seal opens and matches the shared rust wrap", () => {
  const row = records.accept.find((item) => item.name === "rotate-v3-wallet");
  if (!row) throw new Error("missing rotation");
  const genesisPair = scalarSea(vector.witnessed.genesisScalar);
  const genesisEpub = scalarSea(vector.witnessed.genesisEpubScalar);
  const current = scalarSea(vector.witnessed.currentScalar);
  const epub = scalarSea(vector.witnessed.epubScalar);
  const context = recordsContext();
  const imported = AccountKeyring.import(
    genesisPair.pub,
    genesisEpub.pub,
    current.pub,
    current.priv,
    epub.pub,
    epub.priv,
    [{ epub: genesisEpub.pub, epriv: genesisEpub.priv }],
    vector.witnessed.laneId,
    vector.witnessed.contentEpoch,
    vector.witnessed.rotationSeq,
    [row.input],
    context,
  );
  const ephemeral = new Uint8Array(32);
  ephemeral[31] = vector.crossWrap.ephemeralScalar;
  const nonce = new Uint8Array(12).fill(vector.crossWrap.nonceByte);
  const sealed = sealContentWith(
    imported,
    vector.witnessed.dekHex,
    vector.witnessed.objectId,
    vector.witnessed.revisionId,
    [row.input],
    context,
    genesisPair.pub,
    ephemeral,
    nonce,
  );
  assert.equal(sealed.wrappedKey, vector.crossWrap.wrappedKey);
  assert.equal(sealed.targetId, epub.pub);
  assert.equal(
    imported.openContent(vector.crossWrap.wrappedKey, vector.crossWrap.epoch, vector.witnessed.objectId, vector.witnessed.revisionId, epub.pub),
    vector.witnessed.dekHex,
  );
  assert.equal(
    openReaderWrap(epub.priv, epub.pub, vector.crossWrap.wrappedKey, vector.crossWrap.epoch, vector.witnessed.objectId, vector.witnessed.revisionId),
    vector.witnessed.dekHex,
  );
  assert.equal(
    message(() => openReaderWrap(epub.priv, epub.pub, "ab".repeat(8193), vector.crossWrap.epoch, vector.witnessed.objectId, vector.witnessed.revisionId)),
    "wrap-rejected",
  );
});
