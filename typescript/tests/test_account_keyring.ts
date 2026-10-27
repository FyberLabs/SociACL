import assert from "node:assert/strict";
import { createCipheriv, createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { p256 } from "@noble/curves/nist.js";
import {
  deliveryMintsGrant,
  importGenesis,
  principalKey,
} from "../contract/account-key.ts";
import {
  AccountKeyring,
  KEYRING_HISTORY_MAX,
  draftDocument,
  epubForNewSeal,
  mintRotation,
  rotateKeyring,
} from "../contract/account-keyring.ts";
import { bytesToHex, seaPoint, sharedX, uncompressedFromSea } from "../contract/account-key-seal.ts";
import { decodeKeyring, DOMAIN_KEYRING_PLAIN } from "../contract/keyring-codec.ts";
import { lengthPrefixed } from "../contract/canonical.ts";
import { openReaderWrap } from "../contract/content-wrap.ts";
import { deriveContactLane } from "../contract/contact-lane.ts";
import { sealContentWith } from "./support/account-key-deterministic.ts";
import {
  formatPrincipalKey,
  historyState,
  parsePrincipalId,
  signingBytes,
  type Jwks,
  type PrincipalId,
  type ResolutionContext,
} from "../ids/src/index.js";

const vector = JSON.parse(readFileSync(new URL("../../vectors/encrypted-discovery/account-keyring.json", import.meta.url), "utf8")) as {
  genesis: {
    laneId: string;
    contactLaneSecret: string;
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
  genesisBinding: unknown;
  unsafeContentEpoch: number;
  maxContentEpoch: number;
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
  importPriorLanes: { rule: string; rotationSeq: number; priorLane: string; missingError: string };
  witnessContact: { secret: string; prior: string[] };
};

function priorLanes(count: number): string[] {
  const extras = ["11", "22", "33", "44"].map((byte) => byte.repeat(32));
  return [vector.importPriorLanes.priorLane, ...extras].slice(0, count);
}

function contactPair(seq: number, banned: readonly string[]): [string, string[]] {
  const prior: string[] = [];
  const taken = new Set(banned);
  let n = 0xc1;
  const take = (): string => {
    let hex = n.toString(16).padStart(2, "0").repeat(32);
    while (taken.has(hex)) {
      n += 1;
      hex = n.toString(16).padStart(2, "0").repeat(32);
    }
    taken.add(hex);
    n += 1;
    return hex;
  };
  for (let i = 0; i < seq; i += 1) prior.push(take());
  return [take(), prior];
}

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
  return scalarSeaN(last);
}

function scalarSeaN(n: number): { pub: string; priv: string } {
  const bytes = new Uint8Array(32);
  bytes[30] = (n >> 8) & 0xff;
  bytes[31] = n & 0xff;
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

function witnessedContext(): ResolutionContext {
  return recordsContext([vector.genesisBinding]);
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
  const keyring = AccountKeyring.fromGenesis(genesis(), vector.genesis.contactLaneSecret);
  const outcome = rotateKeyring(keyring, vector.trusted, vector.lost, [], witnessedContext(), vectorMint);
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
  const keyring = AccountKeyring.fromGenesis(genesis(), vector.genesis.contactLaneSecret);
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
  const outcome = rotateKeyring(keyring, vector.trusted, vector.lost, [], witnessedContext(), vectorMint);
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
  const keyring = AccountKeyring.fromGenesis(genesis(), vector.genesis.contactLaneSecret);
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
      [],
      vector.witnessContact.secret,
      vector.witnessContact.prior,
    )),
    vector.importPriorLanes.missingError,
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
      vector.importPriorLanes.rotationSeq,
      [],
      context,
      priorLanes(vector.importPriorLanes.rotationSeq), vector.witnessContact.secret, vector.witnessContact.prior,
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
    priorLanes(vector.witnessed.rotationSeq), vector.witnessContact.secret, vector.witnessContact.prior,
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
      priorLanes(vector.witnessed.rotationSeq), vector.witnessContact.secret, vector.witnessContact.prior,
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
      priorLanes(vector.witnessed.rotationSeq), vector.witnessContact.secret, vector.witnessContact.prior,
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
      [],
      vector.genesis.contactLaneSecret,
      [],
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
    priorLanes(vector.witnessed.rotationSeq), vector.witnessContact.secret, vector.witnessContact.prior,
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
      priorLanes(vector.witnessed.rotationSeq), vector.witnessContact.secret, vector.witnessContact.prior,
    )),
    vector.errors.contentEpoch,
  );
});

test("a fresh mint is v3 and leaves the principal in place", () => {
  const account = genesis();
  const keyring = AccountKeyring.fromGenesis(account, vector.genesis.contactLaneSecret);
  const outcome = rotateKeyring(keyring, vector.trusted, vector.lost, [], witnessedContext(), mintRotation);
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
    [],
    vector.genesis.contactLaneSecret,
    [],
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
      [],
      vector.genesis.contactLaneSecret,
      [],
    )),
    vector.errors.epubMismatch,
  );
});

test("builder confirms the witnessed epub before rotating", () => {
  const keyring = AccountKeyring.fromGenesis({
    ...genesis(),
    epub: vector.mint.epub,
    epriv: vector.mint.epriv,
  }, vector.genesis.contactLaneSecret);
  const fresh = scalarSea(4);
  const signing = scalarSea(5);
  assert.equal(
    message(() => rotateKeyring(keyring, vector.trusted, vector.lost, [], witnessedContext(), () => ({
      signingPub: signing.pub,
      signingPriv: signing.priv,
      epub: fresh.pub,
      epriv: fresh.priv,
      laneId: "ee".repeat(32),
    }))),
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
    priorLanes(2),
    ...contactPair(2, [vector.witnessed.laneId, ...priorLanes(2)]),
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
      [],
      vector.genesis.contactLaneSecret,
      [],
    )),
    vector.errors.tooManyKeys,
  );
});

test("the builder refuses a retired set that is already full", () => {
  const row = records.accept.find((item) => item.name === "binding-valid-no-rotation") as { genesisEpubBindings?: unknown[] } | undefined;
  if (!row?.genesisEpubBindings) throw new Error("missing binding vector");
  const context = recordsContext(row.genesisEpubBindings);
  const signing = scalarSea(1);
  const enc = scalarSea(9);
  const retired = [];
  for (let n = 20; n < 1044; n++) {
    const row = scalarSeaN(n);
    retired.push({ epub: row.pub, epriv: row.priv });
  }
  const imported = AccountKeyring.import(
    signing.pub,
    enc.pub,
    signing.pub,
    signing.priv,
    enc.pub,
    enc.priv,
    retired,
    vector.genesis.laneId,
    0,
    0,
    [],
    context,
    [],
    vector.genesis.contactLaneSecret,
    [],
  );
  assert.equal(imported.retired().length, 1024);
  const next = scalarSeaN(2000);
  const nextEnc = scalarSeaN(2001);
  assert.equal(
    message(() => rotateKeyring(imported, vector.trusted, vector.lost, [], context, () => ({
      signingPub: next.pub,
      signingPriv: next.priv,
      epub: nextEnc.pub,
      epriv: nextEnc.priv,
      laneId: "ee".repeat(32),
    }))),
    vector.errors.tooManyKeys,
  );
});

test("an unsafe content epoch is refused", () => {
  const signing = scalarSea(1);
  const enc = scalarSea(9);
  assert.equal(
    message(() => AccountKeyring.import(
      signing.pub,
      enc.pub,
      signing.pub,
      signing.priv,
      enc.pub,
      enc.priv,
      [],
      vector.genesis.laneId,
      vector.unsafeContentEpoch,
      0,
      [],
      witnessedContext(),
      [],
      vector.genesis.contactLaneSecret,
      [],
    )),
    vector.errors.contentEpoch,
  );
});

test("the constructor is not an import path", () => {
  const signing = scalarSea(1);
  assert.throws(
    () => new (AccountKeyring as unknown as new (...args: unknown[]) => AccountKeyring)(
      signing.pub,
      signing.pub,
      signing.pub,
      signing.priv,
      signing.pub,
      signing.priv,
      [],
      vector.genesis.laneId,
      0,
      0,
    ),
    (error: unknown) => error instanceof Error && error.message === vector.errors.badConstruction,
  );
});

test("typescript seal opens and matches the shared rust wrap", () => {
  const row = records.accept.find((item) => item.name === vector.witnessed.rotationName);
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
    priorLanes(vector.witnessed.rotationSeq), vector.witnessContact.secret, vector.witnessContact.prior,
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
  const wrapped = vector.crossWrap.wrappedKey;
  const tampered = wrapped.slice(0, -1) + (wrapped.endsWith("0") ? "1" : "0");
  assert.equal(
    message(() => openReaderWrap(epub.priv, epub.pub, tampered, vector.crossWrap.epoch, vector.witnessed.objectId, vector.witnessed.revisionId)),
    "wrap-rejected",
  );
});

test("authenticated malformed plaintext is wrap-rejected", () => {
  const reader = scalarSea(6);
  const ephemeral = new Uint8Array(32);
  ephemeral[31] = 12;
  const nonce = new Uint8Array(12).fill(7);
  const key = createHash("sha256")
    .update(lengthPrefixed(["s3rch-sea-secret-v1", bytesToHex(sharedX(ephemeral, uncompressedFromSea(reader.pub)))]))
    .digest();
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(new Uint8Array());
  const ct = Buffer.concat([cipher.update(new TextEncoder().encode("not-length-prefixed")), cipher.final(), cipher.getAuthTag()]);
  const point = p256.getPublicKey(ephemeral, false);
  const blob = new Uint8Array(1 + point.length + nonce.length + ct.length);
  blob[0] = 1;
  blob.set(point, 1);
  blob.set(nonce, 1 + point.length);
  blob.set(ct, 1 + point.length + nonce.length);
  ephemeral.fill(0);
  assert.equal(
    message(() => openReaderWrap(reader.priv, reader.pub, bytesToHex(blob), 1, vector.witnessed.objectId, vector.witnessed.revisionId)),
    "wrap-rejected",
  );
});

test("a content epoch cannot increment past the safe integer cap", () => {
  const row = records.accept.find((item) => item.name === "binding-valid-no-rotation") as { genesisEpubBindings?: unknown[] } | undefined;
  if (!row?.genesisEpubBindings) throw new Error("missing binding vector");
  const context = recordsContext(row.genesisEpubBindings);
  const signing = scalarSea(1);
  const enc = scalarSea(9);
  const imported = AccountKeyring.import(
    signing.pub,
    enc.pub,
    signing.pub,
    signing.priv,
    enc.pub,
    enc.priv,
    [],
    vector.genesis.laneId,
    vector.maxContentEpoch,
    0,
    [],
    context,
    [],
    vector.genesis.contactLaneSecret,
    [],
  );
  const next = scalarSeaN(20);
  const nextEnc = scalarSeaN(21);
  assert.equal(
    message(() => rotateKeyring(imported, vector.trusted, vector.lost, [], context, () => ({
      signingPub: next.pub,
      signingPriv: next.priv,
      epub: nextEnc.pub,
      epriv: nextEnc.priv,
      laneId: "ee".repeat(32),
    }))),
    vector.errors.contentEpoch,
  );
});

function oidcOnlyContext(bindings: readonly unknown[]): ResolutionContext {
  const links = new Map(records.context.links.filter((pair) => (pair[1] as { kind?: string }).kind === "oidc"));
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

function signOidcRotation(input: {
  principal: string;
  seq: number;
  prevKey: string;
  nextKey: string;
  nextEpub: string;
  issuedAt: number;
  nextScalar: number;
  link: string;
}): Record<string, unknown> {
  const retainedLinks = [input.link];
  const unsigned = {
    v: 1,
    kind: "rotate",
    principal: input.principal,
    seq: input.seq,
    prevKey: input.prevKey,
    nextKey: input.nextKey,
    nextEpub: input.nextEpub,
    issuedAt: input.issuedAt,
    retainedLinks,
    authorizer: { kind: "oidc-fresh-login", link: input.link },
  };
  const messageBytes = signingBytes(unsigned);
  if (!messageBytes.ok) throw new Error(messageBytes.reason);
  const scalar = new Uint8Array(32);
  scalar[31] = input.nextScalar;
  const nextSig = Buffer.from(p256.sign(messageBytes.value, scalar, { lowS: false })).toString("base64url");
  scalar.fill(0);
  const claims = {
    typ: "sociacl-rotate-attest-v3",
    principal: input.principal,
    nextKey: input.nextKey,
    nextEpub: input.nextEpub,
    seq: input.seq,
    iat: input.issuedAt,
    exp: input.issuedAt + 600,
    auth: "oidc-fresh-login",
    linkId: input.link,
    retainedLinks,
  };
  const header = Buffer.from(JSON.stringify({ alg: "ES256", kid: "fixture-1", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const body = `${header}.${payload}`;
  const witness = new Uint8Array(32);
  witness[31] = 5;
  const sig = Buffer.from(p256.sign(new TextEncoder().encode(body), witness, { lowS: false })).toString("base64url");
  witness.fill(0);
  return { ...unsigned, nextSig, attest: `${body}.${sig}` };
}

test("a lane id cannot be reused across later rotations", () => {
  const row = records.accept.find((item) => item.name === "binding-valid-no-rotation") as { genesisEpubBindings?: unknown[] } | undefined;
  if (!row?.genesisEpubBindings) throw new Error("missing binding vector");
  const context = oidcOnlyContext(row.genesisEpubBindings);
  const link = [...context.links.keys()][0];
  if (!link) throw new Error("missing oidc link");
  const signing = scalarSea(1);
  const enc = scalarSea(9);
  const lanes = ["11".repeat(32), "22".repeat(32), "33".repeat(32), "44".repeat(32)];
  let current = AccountKeyring.import(
    signing.pub,
    enc.pub,
    signing.pub,
    signing.priv,
    enc.pub,
    enc.priv,
    [],
    lanes[0]!,
    0,
    0,
    [],
    context,
    [],
    vector.genesis.contactLaneSecret,
    [],
  );
  const chain: Record<string, unknown>[] = [];
  for (let step = 0; step < 3; step++) {
    const signN = 20 + step * 2;
    const epubN = 21 + step * 2;
    const next = scalarSeaN(signN);
    const nextEnc = scalarSeaN(epubN);
    const outcome = rotateKeyring(current, vector.trusted, vector.lost, chain, context, () => ({
      signingPub: next.pub,
      signingPriv: next.priv,
      epub: nextEnc.pub,
      epriv: nextEnc.priv,
      laneId: lanes[step + 1]!,
    }));
    assert.equal(outcome.keyring.laneId(), lanes[step + 1]);
    assert.deepEqual(outcome.keyring.priorLanes(), lanes.slice(0, step + 1));
    chain.push(signOidcRotation({
      principal: current.principal,
      seq: step + 1,
      prevKey: current.pub,
      nextKey: next.pub,
      nextEpub: nextEnc.pub,
      issuedAt: records.context.now - 30 + step * 10,
      nextScalar: signN,
      link,
    }));
    current = outcome.keyring;
    const published = JSON.stringify(current.toJSON()) + current.gunDocument();
    for (const lane of lanes) assert.equal(published.includes(lane), false);
  }
  const reuse = scalarSeaN(40);
  const reuseEnc = scalarSeaN(41);
  for (const lane of [lanes[0]!, lanes[1]!, lanes[2]!, lanes[3]!]) {
    assert.equal(
      message(() => rotateKeyring(current, vector.trusted, vector.lost, chain, context, () => ({
        signingPub: reuse.pub,
        signingPriv: reuse.priv,
        epub: reuseEnc.pub,
        epriv: reuseEnc.priv,
        laneId: lane,
      }))),
      vector.errors.badLane,
    );
  }
  const restored = AccountKeyring.import(
    current.principal,
    current.genesisEpub,
    current.pub,
    current.currentPriv(),
    current.epub,
    current.currentEpriv(),
    current.retired(),
    current.laneId(),
    current.contentEpoch,
    current.rotationSeq,
    chain,
    context,
    current.priorLanes(),
    current.contactLaneSecret(),
    current.priorContactSecrets(),
  );
  assert.equal(restored.laneId(), current.laneId());
  assert.equal(restored.contactLaneSecret(), current.contactLaneSecret());
  assert.deepEqual([...restored.priorLanes()], [...current.priorLanes()]);
  assert.deepEqual([...restored.priorContactSecrets()], [...current.priorContactSecrets()]);
  assert.equal(
    message(() => rotateKeyring(restored, vector.trusted, vector.lost, chain, context, () => ({
      signingPub: reuse.pub,
      signingPriv: reuse.priv,
      epub: reuseEnc.pub,
      epriv: reuseEnc.priv,
      laneId: lanes[0]!,
    }))),
    vector.errors.badLane,
  );
  assert.equal(
    message(() => AccountKeyring.import(
      current.principal,
      current.genesisEpub,
      current.pub,
      current.currentPriv(),
      current.epub,
      current.currentEpriv(),
      current.retired(),
      current.laneId(),
      current.contentEpoch,
      current.rotationSeq,
      chain,
      context,
      [current.laneId()],
      current.contactLaneSecret(),
      current.priorContactSecrets(),
    )),
    vector.errors.badLane,
  );
});

test("create then restore keeps lanes and a missing history is refused", () => {
  const created = AccountKeyring.createAccount();
  const another = AccountKeyring.createAccount();
  assert.notEqual(created.principal, another.principal);
  assert.notEqual(created.contactLaneSecret(), another.contactLaneSecret());
  assert.notEqual(created.laneId(), another.laneId());
  const account = importGenesis(created.laneId(), created.pub, created.currentPriv(), created.epub, created.currentEpriv());
  assert.equal(message(() => {
    // @ts-expect-error Existing accounts cannot mint another contact secret.
    AccountKeyring.createAccount(account);
  }), "bad-construction");
  assert.equal(created.rotationSeq, 0);
  assert.equal(message(() => AccountKeyring.fromGenesis(account)), vector.errors.keyringRejected);
  const restored = AccountKeyring.fromGenesis(account, created.contactLaneSecret());
  const sender = vector.mint.signingPub;
  assert.equal(
    deriveContactLane(restored.contactLaneSecret(), restored.principal, sender),
    deriveContactLane(created.contactLaneSecret(), created.principal, sender),
  );
  assert.equal(restored.laneId(), created.laneId());
  assert.notEqual(deriveContactLane(created.contactLaneSecret(), created.principal, sender), created.laneId());
  const context = emptyContext();
  assert.equal(
    message(() => AccountKeyring.import(
      account.principal,
      account.epub,
      account.pub,
      account.priv,
      account.epub,
      account.epriv,
      [],
      account.laneId,
      0,
      0,
      [],
      context,
    )),
    vector.errors.keyringRejected,
  );
  assert.equal(
    message(() => AccountKeyring.import(
      account.principal,
      account.epub,
      account.pub,
      account.priv,
      account.epub,
      account.epriv,
      [],
      account.laneId,
      0,
      1,
      [],
      context,
      [],
      vector.genesis.contactLaneSecret,
      [],
    )),
    vector.errors.keyringRejected,
  );
  for (const seq of [NaN, -1, 0.5, Infinity, Number.MAX_VALUE, vector.unsafeContentEpoch]) {
    assert.equal(
      message(() => AccountKeyring.import(
        account.principal,
        account.epub,
        account.pub,
        account.priv,
        account.epub,
        account.epriv,
        [],
        account.laneId,
        0,
        seq,
        [],
        context,
        [],
        vector.genesis.contactLaneSecret,
        [],
      )),
      vector.errors.keyringRejected,
    );
  }
});


test("shared large-history imports reject duplicates and disclosed contact secrets", () => {
  const history = JSON.parse(readFileSync(new URL("../../vectors/encrypted-discovery/keyring-history-import.json", import.meta.url), "utf8")) as {
    count: number; laneId: string; contactSecret: string;
    cases: { rotationSeq?: number; laneCount?: number; contactCount?: number; name: string; priorLaneLast?: string; priorContactLast?: string; contactSecret?: string; error: string }[];
  };
  for (const row of history.cases) {
    const lanes = Array.from({ length: row.laneCount ?? history.count }, (_, i) => (i + 1).toString(16).padStart(64, "0"));
    const contacts = Array.from({ length: row.contactCount ?? history.count }, (_, i) => (history.count + i + 1).toString(16).padStart(64, "0"));
    if (row.priorLaneLast !== undefined) lanes[lanes.length - 1] = row.priorLaneLast;
    if (row.priorContactLast !== undefined) contacts[contacts.length - 1] = row.priorContactLast;
    assert.equal(message(() => AccountKeyring.import(
      vector.genesis.principal, vector.genesis.epub,
      vector.mint.signingPub, vector.mint.signingPriv,
      vector.mint.epub, vector.mint.epriv,
      [{ epub: vector.genesis.epub, epriv: vector.genesis.epriv }],
      history.laneId, 1, row.rotationSeq ?? history.count, [], emptyContext(), lanes,
      row.contactSecret ?? history.contactSecret, contacts,
    )), row.error, row.name);
  }
});


test("history limit refuses rotation before invoking the mint", () => {
  // Isolate the preflight boundary: no private key state should be read here.
  const full = { rotationSeq: KEYRING_HISTORY_MAX } as AccountKeyring;
  assert.throws(() => rotateKeyring(full, ["phone"], "phone", [], emptyContext(), () => {
    assert.fail("mint must not run at the history limit");
  }), { message: "keyring-too-large" });
});


test("shared codec history bounds reject counts before reading their payload", () => {
  const fixture = JSON.parse(readFileSync(new URL("../../vectors/encrypted-discovery/keyring-history-import.json", import.meta.url), "utf8")) as {
    codecCases: { name: string; laneCount: number; contactCount: number; rotationSeq: number; truncateAfter?: string; error?: string }[];
  };
  for (const row of fixture.codecCases) {
    const fields = [DOMAIN_KEYRING_PLAIN, "principal", "genesisEpub", "pub", "priv", "epub", "epriv", "0", "lane", String(row.laneCount)];
    if (row.truncateAfter !== "lanes") {
      fields.push(...Array.from({ length: row.laneCount }, (_, i) => (i + 1).toString(16).padStart(64, "0")));
      fields.push("contact", String(row.contactCount));
      if (row.truncateAfter !== "contacts") {
        fields.push(...Array.from({ length: row.contactCount }, (_, i) => (i + 1025).toString(16).padStart(64, "0")));
        fields.push("0", String(row.rotationSeq));
      }
    }
    const bytes = lengthPrefixed(fields);
    if (row.error) assert.throws(() => decodeKeyring(bytes), { message: row.error }, row.name);
    else {
      // Structural decoding only; AccountKeyring.import authenticates keys and history.
      const decoded = decodeKeyring(bytes);
      assert.equal(decoded.priorLanes.length, KEYRING_HISTORY_MAX);
      assert.equal(decoded.priorContactSecrets.length, KEYRING_HISTORY_MAX);
      assert.equal(decoded.rotationSeq, KEYRING_HISTORY_MAX);
    }
  }
});
