import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { randomBytes } from "node:crypto";
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
import { hexToBytes, seaPoint } from "../contract/account-key-seal.ts";
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

function recordsContext(genesisEpub?: PrincipalId): ResolutionContext {
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
    genesisEpub,
  } as ResolutionContext;
}

test("rotation matches the shared vector and keeps secrets off gun", () => {
  const keyring = AccountKeyring.fromGenesis(genesis());
  const outcome = rotateKeyring(keyring, vector.trusted, vector.lost, vectorMint);
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
    message(() => rotateKeyring(keyring, vector.trusted, vector.lost, genesisEpubMint)),
    vector.errors.epubReuse,
  );
  assert.equal(
    message(() => rotateKeyring(keyring, vector.trusted, vector.lost, () => ({
      signingPub: vector.mint.signingPub,
      signingPriv: vector.mint.signingPriv,
      epub: vector.mint.signingPub,
      epriv: vector.mint.signingPriv,
      laneId: vector.mint.laneId,
    }))),
    vector.errors.epubReuse,
  );
  assert.equal(
    message(() => rotateKeyring(keyring, vector.trusted, vector.lost, () => ({
      signingPub: vector.genesis.signingPub,
      signingPriv: vector.genesis.signingPriv,
      epub: vector.mint.epub,
      epriv: vector.mint.epriv,
      laneId: vector.mint.laneId,
    }))),
    vector.errors.epubReuse,
  );
  assert.equal(
    message(() => rotateKeyring(keyring, vector.trusted, vector.lost, () => ({
      ...vectorMint(),
      laneId: vector.genesis.laneId,
    }))),
    vector.errors.badLane,
  );
  assert.equal(message(() => rotateKeyring(keyring, [], vector.lost, vectorMint)), vector.errors.lostDevice);
  assert.equal(message(() => rotateKeyring(keyring, ["phone"], vector.lost, vectorMint)), vector.errors.lostDevice);
  assert.equal(message(() => rotateKeyring(keyring, ["phone", "phone"], "phone", vectorMint)), vector.errors.duplicateDevice);
  assert.equal(message(() => rotateKeyring(keyring, ["", "phone"], "phone", vectorMint)), vector.errors.emptyDevice);
  assert.equal(
    message(() => rotateKeyring(keyring, [vector.genesis.principal, "phone"], "phone", vectorMint)),
    vector.errors.deviceId,
  );
  assert.equal(
    message(() => rotateKeyring(keyring, [vector.wallet, "phone"], "phone", vectorMint)),
    vector.errors.deviceId,
  );
  const outcome = rotateKeyring(keyring, vector.trusted, vector.lost, vectorMint);
  assert.equal(
    message(() => rotateKeyring(outcome.keyring, vector.trusted, vector.lost, genesisEpubMint)),
    vector.errors.epubReuse,
  );
  assert.equal(
    message(() => rotateKeyring(outcome.keyring, vector.trusted, vector.lost, vectorMint)),
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
      randomBytes(32),
      randomBytes(12),
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
  const ephemeral = hexToBytes(accountKey.contentWrap.ephemeralScalarHex);
  const nonce = hexToBytes(accountKey.contentWrap.nonceHex);
  const sealed = imported.sealContent(
    vector.witnessed.dekHex,
    vector.witnessed.objectId,
    vector.witnessed.revisionId,
    [rotation.input],
    context,
    genesisPair.pub,
    ephemeral,
    nonce,
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
    ephemeral,
    nonce,
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
  const bound = parsePrincipalId(other.pub);
  if (!bound.ok) throw new Error(bound.reason);
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
      [rotation.input],
      recordsContext(bound.value),
    )),
    vector.errors.epubMismatch,
  );
});

test("a fresh mint is v3 and leaves the principal in place", () => {
  const account = genesis();
  const keyring = AccountKeyring.fromGenesis(account);
  const outcome = rotateKeyring(keyring, vector.trusted, vector.lost, mintRotation);
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
