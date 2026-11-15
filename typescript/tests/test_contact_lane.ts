import { pollFirstContact } from '../contract/first-contact-poll.ts';
import { signFirstContactDescriptor, verifyFirstContactDescriptor } from '../contract/first-contact-descriptor.ts';
import { createRequire } from 'node:module';
import { openFirstContactStore } from '../ids/src/first-contact-store.js';
import { receiveFirstContact, acceptFirstContactRequest } from '../contract/first-contact-inbox.ts';
import { sealFirstContactRequest } from '../contract/first-contact-seal.ts';
import { firstContactRequestBytes } from '../contract/first-contact.ts';
import { signWithKeyring, parsePrincipalId } from '../ids/src/index.js';
import assert from "node:assert/strict";
import { createHash, hkdfSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { p256 } from "@noble/curves/nist.js";
import { bytesToHex, decodeLengthPrefixed, hexToBytes, seaPoint } from "../contract/account-key-seal.ts";
import { importGenesis } from "../contract/account-key.ts";
import { AccountKeyring, rotateKeyring } from "../contract/account-keyring.ts";
import {
  deriveContactLane,
  laneLookupKey,
  openContactLaneGrant,
  regrantContactLanes,
  resolveContactLane,
  sealContactLaneGrant,
} from "../contract/contact-lane.ts";
import * as contactLane from "../contract/contact-lane.ts";
import {
  CONTACT_LANE_DOMAIN,
  CONTACT_LANE_GRANT_DOMAIN,
  CONTACT_LANE_GRANT_SIG_DOMAIN,
  CONTACT_LANE_VERSION,
  contactLaneGrantAad,
  contactLaneGrantPlaintext,
  contactLaneInfo,
  sealContactLaneGrantWith,
} from "./support/contact-lane-deterministic.ts";
import {
  historyState,
  signingBytes,
  type Jwks,
  type PrincipalId,
  type ResolutionContext,
} from "../ids/src/index.js";

const vector = JSON.parse(
  readFileSync(new URL("../../vectors/encrypted-discovery/contact-lane.json", import.meta.url), "utf8"),
) as {
  domain: string;
  version: string;
  saltHex: string;
  recipient: string;
  sender: string;
  otherSender: string;
  baseLaneId: string;
  contactLaneSecretHex: string;
  baseLaneHkdf: string;
  infoHex: string;
  infoLength: number;
  laneId: string;
  swappedInfoHex: string;
  swappedLaneId: string;
  otherLaneId: string;
  priorSecretHex: string;
  priorLaneId: string;
  wrongSecretHex: string;
  wrongSecretLaneId: string;
  infoOrder: string[];
  openError: string;
  grant: {
    domain: string;
    sigDomain: string;
    ephemeralScalarHex: string;
    nonceHex: string;
    senderEpub: string;
    rotationSeq: number;
    signatureHex: string;
    plaintextHex: string;
    aadHex: string;
    ciphertextHex: string;
  };
};

const ring = JSON.parse(
  readFileSync(new URL("../../vectors/encrypted-discovery/account-keyring.json", import.meta.url), "utf8"),
) as {
  genesis: {
    laneId: string;
    signingPub: string;
    signingPriv: string;
    epub: string;
    epriv: string;
    principal: string;
    contactLaneSecret: string;
  };
  mint: { signingPub: string; signingPriv: string; epub: string; epriv: string; laneId: string };
  trusted: string[];
  lost: string;
  genesisBinding: unknown;
  errors: { badLane: string; epubUnknown: string };
};

const records = JSON.parse(readFileSync(new URL("../../vectors/ids/records.json", import.meta.url), "utf8")) as {
  accept: { name: string; genesisEpubBindings?: unknown[] }[];
  context: {
    jwks: Jwks;
    pinnedIss: string[];
    now: number;
    links: [string, unknown][];
    policy: { allowedDomains: string[]; allowedUris: string[]; allowedChainIds: string[]; clockSkewSeconds?: number };
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

function scalarSea(n: number): { pub: string; priv: string } {
  const bytes = new Uint8Array(32);
  bytes[30] = (n >> 8) & 0xff;
  bytes[31] = n & 0xff;
  const pub = seaPoint(bytes);
  const priv = b64(bytes);
  bytes.fill(0);
  return { pub, priv };
}

function contextWith(bindings: readonly unknown[], oidcOnly = false): ResolutionContext {
  const links = new Map(
    records.context.links.filter((pair) => !oidcOnly || (pair[1] as { kind?: string }).kind === "oidc"),
  );
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

function emptyContext(): ResolutionContext {
  return {
    jwks: { keys: [] },
    links: new Map(),
    revocations: [],
    now: records.context.now,
    policy: { allowedDomains: [], allowedUris: [], allowedChainIds: [] },
    pinnedIss: new Set(),
    history: () => ({ ok: false, reason: "missing-history" }),
  };
}

function witnessed(): ResolutionContext {
  return contextWith([ring.genesisBinding]);
}

function genesisKeyring(): AccountKeyring {
  return AccountKeyring.fromGenesis(
    importGenesis(
      ring.genesis.laneId,
      ring.genesis.signingPub,
      ring.genesis.signingPriv,
      ring.genesis.epub,
      ring.genesis.epriv,
    ),
    ring.genesis.contactLaneSecret,
  );
}

function signGenesisEpub(principal: string, epub: string, issuedAt: number, signer: number): Record<string, unknown> {
  const unsigned = { v: 1, kind: "genesis-epub", principal, epub, issuedAt, keySig: "", attest: "" };
  const messageBytes = signingBytes(unsigned);
  if (!messageBytes.ok) throw new Error(messageBytes.reason);
  const scalar = new Uint8Array(32);
  scalar[31] = signer;
  const keySig = Buffer.from(p256.sign(messageBytes.value, scalar, { lowS: false })).toString("base64url");
  scalar.fill(0);
  const claims = { typ: "sociacl-genesis-epub-attest-v1", principal, epub, iat: issuedAt, exp: issuedAt + 600 };
  const header = Buffer.from(JSON.stringify({ alg: "ES256", kid: "fixture-1", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const body = `${header}.${payload}`;
  const witness = new Uint8Array(32);
  witness[31] = 5;
  const sig = Buffer.from(p256.sign(new TextEncoder().encode(body), witness, { lowS: false })).toString("base64url");
  witness.fill(0);
  return { v: 1, kind: "genesis-epub", principal, epub, issuedAt, keySig, attest: `${body}.${sig}` };
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

test("shared vectors pin the HKDF info layout and the grant bytes", () => {
  assert.equal(CONTACT_LANE_DOMAIN, vector.domain);
  assert.equal(CONTACT_LANE_VERSION, vector.version);
  assert.equal(CONTACT_LANE_GRANT_DOMAIN, vector.grant.domain);
  assert.equal(CONTACT_LANE_GRANT_SIG_DOMAIN, vector.grant.sigDomain);
  assert.deepEqual(vector.infoOrder, ["domain", "version", "recipient", "sender"]);
  const info = contactLaneInfo(vector.recipient, vector.sender);
  assert.equal(bytesToHex(info), vector.infoHex);
  assert.equal(info.length, vector.infoLength);
  assert.deepEqual(decodeLengthPrefixed(info), [
    vector.domain,
    vector.version,
    vector.recipient,
    vector.sender,
  ]);
  const swapped = contactLaneInfo(vector.sender, vector.recipient);
  assert.equal(bytesToHex(swapped), vector.swappedInfoHex);
  assert.notEqual(vector.infoHex, vector.swappedInfoHex);
  assert.equal(vector.baseLaneId, ring.genesis.laneId);
  assert.equal(vector.contactLaneSecretHex, ring.genesis.contactLaneSecret);
  assert.notEqual(vector.contactLaneSecretHex, vector.baseLaneId);
  assert.equal(deriveContactLane(vector.contactLaneSecretHex, vector.recipient, vector.sender), vector.laneId);
  assert.equal(deriveContactLane(vector.baseLaneId, vector.recipient, vector.sender), vector.baseLaneHkdf);
  assert.notEqual(vector.laneId, vector.baseLaneHkdf);
  assert.equal(deriveContactLane(vector.contactLaneSecretHex, vector.sender, vector.recipient), vector.swappedLaneId);
  assert.notEqual(vector.laneId, vector.swappedLaneId);
  assert.equal(deriveContactLane(vector.contactLaneSecretHex, vector.recipient, vector.otherSender), vector.otherLaneId);
  assert.equal(deriveContactLane(vector.priorSecretHex, vector.recipient, vector.sender), vector.priorLaneId);
  assert.equal(deriveContactLane(vector.wrongSecretHex, vector.recipient, vector.sender), vector.wrongSecretLaneId);
  assert.notEqual(vector.laneId, vector.otherLaneId);
  assert.notEqual(vector.laneId, vector.priorLaneId);
  assert.notEqual(vector.laneId, vector.wrongSecretLaneId);
  const oracle = Buffer.from(
    hkdfSync("sha256", hexToBytes(vector.contactLaneSecretHex), hexToBytes(vector.saltHex), info, 32),
  ).toString("hex");
  assert.equal(vector.laneId, oracle);
  const keyring = genesisKeyring();
  const grant = sealContactLaneGrantWith(
    keyring,
    vector.sender,
    vector.grant.senderEpub,
    hexToBytes(vector.grant.ephemeralScalarHex),
    hexToBytes(vector.grant.nonceHex),
    [],
    witnessed(),
  );
  assert.equal(
    bytesToHex(contactLaneGrantPlaintext(vector.laneId, vector.recipient, 0, vector.grant.signatureHex)),
    vector.grant.plaintextHex,
  );
  const ephemeralPub = seaPoint(hexToBytes(vector.grant.ephemeralScalarHex));
  assert.equal(
    bytesToHex(contactLaneGrantAad(vector.recipient, vector.sender, vector.grant.senderEpub, ephemeralPub, 0)),
    vector.grant.aadHex,
  );
  assert.deepEqual(Object.keys(grant), ["ciphertextHex"]);
  assert.equal(grant.ciphertextHex, vector.grant.ciphertextHex);
  assert.equal(grant.ciphertextHex.includes(vector.contactLaneSecretHex), false);
  assert.equal(grant.ciphertextHex.includes(vector.baseLaneId), false);
  assert.equal(grant.ciphertextHex.includes(ring.genesis.signingPriv), false);
  assert.equal(grant.ciphertextHex.includes(ring.genesis.epriv), false);
  assert.equal(JSON.stringify(grant).includes(vector.recipient), false);
  assert.equal(JSON.stringify(grant).includes(vector.sender), false);
  const opened = openContactLaneGrant(
    vector.sender,
    ring.mint.epriv,
    grant,
    vector.recipient,
    [],
    witnessed(),
  );
  assert.equal(opened.laneId, vector.laneId);
  assert.equal(opened.lookupKey, vector.laneId);
  assert.equal(opened.rotationSeq, 0);
  assert.equal(laneLookupKey(opened.laneId), opened.laneId);
  assert.notEqual(deriveContactLane(keyring.laneId(), keyring.principal, vector.sender), opened.laneId);
  assert.equal(deriveContactLane(keyring.contactLaneSecret(), keyring.principal, vector.sender), opened.laneId);
});

test("an outsider cannot read a principal or the base lane out of a lane id", () => {
  assert.match(vector.laneId, /^[0-9a-f]{64}$/u);
  assert.equal(vector.laneId.includes("."), false);
  assert.equal(vector.laneId.includes(vector.recipient), false);
  assert.equal(vector.laneId.includes(vector.sender), false);
  assert.notEqual(vector.laneId, vector.contactLaneSecretHex);
  assert.notEqual(vector.laneId, vector.baseLaneId);
  assert.notEqual(vector.laneId, vector.baseLaneHkdf);
  assert.notEqual(vector.otherLaneId, vector.laneId);
  assert.notEqual(vector.laneId, createHash("sha256").update(vector.recipient).digest("hex"));
  assert.notEqual(vector.laneId, createHash("sha256").update(vector.sender).digest("hex"));
  assert.notEqual(vector.laneId, createHash("sha256").update(vector.infoHex).digest("hex"));
  const barrel = readFileSync(new URL("../contract/contact-lane.ts", import.meta.url), "utf8");
  const seal = readFileSync(new URL("../contract/contact-lane-seal.ts", import.meta.url), "utf8");
  assert.equal(barrel.includes("user.epub"), false);
  assert.equal(barrel.includes("gunUserEpub"), false);
  assert.equal(seal.includes("user.epub"), false);
  assert.equal(seal.includes("gunUserEpub"), false);
});

test("a null currentEpub is refused and a bad id does not derive", () => {
  const keyring = genesisKeyring();
  assert.equal(
    message(() => sealContactLaneGrant(keyring, vector.sender, [], emptyContext(), [], witnessed())),
    ring.errors.epubUnknown,
  );
  assert.equal(message(() => deriveContactLane("ab", vector.recipient, vector.sender)), ring.errors.badLane);
  assert.equal(message(() => deriveContactLane(vector.contactLaneSecretHex, "not-a-principal", vector.sender)), "bad-length");
  assert.equal(message(() => laneLookupKey("zz")), ring.errors.badLane);
});

test("resolving a prior sequence and the reuse guard", () => {
  const row = records.accept.find((item) => item.name === "binding-valid-no-rotation");
  if (!row?.genesisEpubBindings) throw new Error("missing binding vector");
  const context = contextWith(row.genesisEpubBindings, true);
  const link = [...context.links.keys()][0];
  if (!link) throw new Error("missing oidc link");
  const signing = scalarSea(1);
  const enc = scalarSea(9);
  const base0 = "ab".repeat(32);
  const base1 = vector.priorSecretHex;
  const secret0 = "c0".repeat(32);
  const secret1 = "d1".repeat(32);
  let current = AccountKeyring.import(
    signing.pub,
    enc.pub,
    signing.pub,
    signing.priv,
    enc.pub,
    enc.priv,
    [],
    base0,
    0,
    0,
    [],
    context,
    [],
    secret0,
    [],
  );
  const sender = vector.sender;
  const atZero = resolveContactLane(current, sender, 0);
  assert.equal(atZero, deriveContactLane(secret0, current.principal, sender));
  assert.notEqual(atZero, deriveContactLane(base0, current.principal, sender));
  const chain: Record<string, unknown>[] = [];
  const next = scalarSea(20);
  const nextEnc = scalarSea(21);
  const rotated = rotateKeyring(current, ring.trusted, ring.lost, chain, context, () => ({
    signingPub: next.pub,
    signingPriv: next.priv,
    epub: nextEnc.pub,
    epriv: nextEnc.priv,
    laneId: base1,
    contactLaneSecret: secret1,
  }));
  current = rotated.keyring;
  assert.equal(current.priorLanes().length, current.rotationSeq);
  assert.equal(current.priorContactSecrets().length, current.rotationSeq);
  assert.equal(current.priorContactSecrets()[0], secret0);
  assert.equal(resolveContactLane(current, sender, 0), atZero);
  assert.equal(resolveContactLane(current, sender, 1), deriveContactLane(secret1, current.principal, sender));
  assert.notEqual(resolveContactLane(current, sender, 1), deriveContactLane(current.laneId(), current.principal, sender));
  assert.notEqual(resolveContactLane(current, sender, 1), atZero);
  assert.equal(
    message(() =>
      rotateKeyring(current, ring.trusted, ring.lost, chain, context, () => ({
        signingPub: scalarSea(30).pub,
        signingPriv: scalarSea(30).priv,
        epub: scalarSea(31).pub,
        epriv: scalarSea(31).priv,
        laneId: current.laneId(),
      })),
    ),
    ring.errors.badLane,
  );
  assert.equal(
    message(() =>
      rotateKeyring(current, ring.trusted, ring.lost, chain, context, () => ({
        signingPub: scalarSea(32).pub,
        signingPriv: scalarSea(32).priv,
        epub: scalarSea(33).pub,
        epriv: scalarSea(33).priv,
        laneId: current.priorLanes()[0]!,
      })),
    ),
    ring.errors.badLane,
  );
  assert.equal(
    message(() =>
      rotateKeyring(current, ring.trusted, ring.lost, chain, context, () => ({
        signingPub: scalarSea(34).pub,
        signingPriv: scalarSea(34).priv,
        epub: scalarSea(35).pub,
        epriv: scalarSea(35).priv,
        laneId: current.contactLaneSecret(),
        contactLaneSecret: "44".repeat(32),
      })),
    ),
    ring.errors.badLane,
  );
  assert.equal(
    message(() =>
      rotateKeyring(current, ring.trusted, ring.lost, chain, context, () => ({
        signingPub: scalarSea(36).pub,
        signingPriv: scalarSea(36).priv,
        epub: scalarSea(37).pub,
        epriv: scalarSea(37).priv,
        laneId: "55".repeat(32),
        contactLaneSecret: current.laneId(),
      })),
    ),
    ring.errors.badLane,
  );
  assert.equal(message(() => resolveContactLane(current, sender, 2)), ring.errors.badLane);
  void chain;
});

test("grant open, the wrong party, tamper, a stale grant, and a re-grant", () => {
  const row = records.accept.find((item) => item.name === "binding-valid-no-rotation");
  if (!row?.genesisEpubBindings) throw new Error("missing binding vector");
  const recipientContext = contextWith(row.genesisEpubBindings, true);
  const link = [...recipientContext.links.keys()][0];
  if (!link) throw new Error("missing oidc link");
  const signing = scalarSea(1);
  const enc = scalarSea(9);
  const senderSign = scalarSea(3);
  const senderEnc = scalarSea(4);
  const issuedAt = records.context.now - 40;
  const senderBinding = signGenesisEpub(senderSign.pub, senderEnc.pub, issuedAt, 3);
  const senderContext = contextWith([senderBinding]);
  let recipient = AccountKeyring.import(
    signing.pub,
    enc.pub,
    signing.pub,
    signing.priv,
    enc.pub,
    enc.priv,
    [],
    "ab".repeat(32),
    0,
    0,
    [],
    recipientContext,
    [],
    "c0".repeat(32),
    [],
  );
  const senderKeyring = AccountKeyring.import(
    senderSign.pub,
    senderEnc.pub,
    senderSign.pub,
    senderSign.priv,
    senderEnc.pub,
    senderEnc.priv,
    [],
    "44".repeat(32),
    0,
    0,
    [],
    senderContext,
    [],
    "d2".repeat(32),
    [],
  );
  const grant = sealContactLaneGrant(
    recipient,
    senderSign.pub,
    [],
    senderContext,
    [],
    recipientContext,
  );
  assert.deepEqual(Object.keys(grant), ["ciphertextHex"]);
  const opened = openContactLaneGrant(
    senderSign.pub,
    senderKeyring.currentEpriv(),
    grant,
    recipient.principal,
    [],
    recipientContext,
  );
  assert.equal(opened.laneId, resolveContactLane(recipient, senderSign.pub, 0));
  assert.equal(opened.lookupKey, laneLookupKey(opened.laneId));
  assert.equal(JSON.stringify(grant).includes(recipient.laneId()), false);
  assert.equal(JSON.stringify(grant).includes(recipient.contactLaneSecret()), false);
  assert.equal(JSON.stringify(grant).includes(recipient.principal), false);
  assert.notEqual(deriveContactLane(recipient.laneId(), recipient.principal, senderSign.pub), opened.laneId);
  assert.equal(JSON.stringify(grant).includes(recipient.currentPriv()), false);
  assert.equal(JSON.stringify(grant).includes(senderKeyring.currentEpriv()), false);
  const wrongSender = message(() =>
    openContactLaneGrant(senderSign.pub, scalarSea(6).priv, grant, recipient.principal, [], recipientContext),
  );
  const wrongRecipient = message(() =>
    openContactLaneGrant(senderSign.pub, senderKeyring.currentEpriv(), grant, senderSign.pub, [], senderContext),
  );
  const tampered = {
    ...grant,
    ciphertextHex: `${grant.ciphertextHex.slice(0, -1)}${grant.ciphertextHex.endsWith("0") ? "1" : "0"}`,
  };
  const tamper = message(() =>
    openContactLaneGrant(senderSign.pub, senderKeyring.currentEpriv(), tampered, recipient.principal, [], recipientContext),
  );
  assert.equal(wrongSender, vector.openError);
  assert.equal(wrongRecipient, vector.openError);
  assert.equal(tamper, vector.openError);
  const next = scalarSea(20);
  const nextEnc = scalarSea(21);
  const rotated = rotateKeyring(recipient, ring.trusted, ring.lost, [], recipientContext, () => ({
    signingPub: next.pub,
    signingPriv: next.priv,
    epub: nextEnc.pub,
    epriv: nextEnc.priv,
    laneId: vector.priorSecretHex,
  }));
  recipient = rotated.keyring;
  const chain = [
    signOidcRotation({
      principal: signing.pub,
      seq: 1,
      prevKey: signing.pub,
      nextKey: next.pub,
      nextEpub: nextEnc.pub,
      issuedAt: records.context.now - 20,
      nextScalar: 20,
      link,
    }),
  ];
  const stale = message(() =>
    openContactLaneGrant(
      senderSign.pub,
      senderKeyring.currentEpriv(),
      grant,
      recipient.principal,
      chain,
      recipientContext,
    ),
  );
  assert.equal(stale, vector.openError);
  const fresh = regrantContactLanes(
    recipient,
    [{ principal: senderSign.pub, rotations: [], context: senderContext }],
    chain,
    recipientContext,
  );
  assert.equal(fresh.length, 1);
  const reopened = openContactLaneGrant(
    senderSign.pub,
    senderKeyring.currentEpriv(),
    fresh[0]!,
    recipient.principal,
    chain,
    recipientContext,
  );
  assert.equal(reopened.laneId, resolveContactLane(recipient, senderSign.pub, 1));
  assert.equal(reopened.rotationSeq, 1);
  assert.notEqual(reopened.laneId, opened.laneId);
  assert.equal(reopened.lookupKey, reopened.laneId);
  assert.equal(laneLookupKey(reopened.laneId).includes("~"), false);
});

test("builders and the deterministic seal are not production exports", () => {
  assert.deepEqual(Object.keys(contactLane).sort(), [
    "deriveContactLane",
    "firstContactRequestBytes",
    "laneLookupKey",
    "openContactLaneGrant",
    "parseFirstContactRequest",
    "regrantContactLanes",
    "resolveContactLane",
    "sealContactLaneGrant",
    "verifyFirstContactRequest",
  ]);
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as {
    exports: Record<string, string>;
  };
  const exported = JSON.stringify(pkg.exports);
  assert.equal(exported.includes("sealContactLaneGrantWith"), false);
  assert.equal(exported.includes("contact-lane-deterministic"), false);
  assert.equal(exported.includes("contactLaneInfo"), false);
});


for (const mode of ['direct','poll','browser','browser-after-commit'] as const) test(`first contact ${mode} requires committed replay admission and explicit acceptance before a lane grant exists`, async () => {
  const { IDBFactory } = createRequire(new URL('../ids/package.json', import.meta.url))('fake-indexeddb') as { IDBFactory: new () => IDBFactory };
  const recipient = genesisKeyring(), sender = scalarSea(3), senderEnc = scalarSea(4), channel = scalarSea(15);
  const binding = signGenesisEpub(sender.pub, senderEnc.pub, records.context.now - 40, 3);
  const ctx = { ...contextWith([binding]), history: (p: PrincipalId, at:number, until:number) =>
    ({ok:true as const,value:historyState(p,[],at,until)}) };
  const store = await openFirstContactStore({ name:'first-contact-flow',owner:recipient.principal,
    now:()=>ctx.now,create:true,indexedDB:new IDBFactory() });
  try {
    const d = await store.activate({ encryptionEpub:channel.pub,expiresAt:ctx.now+600,maxLifetimeSeconds:300,maxMessageBytes:1024 });
    const principal = parsePrincipalId(sender.pub); assert.ok(principal.ok); if(!principal.ok) return;
    const reply = parsePrincipalId(senderEnc.pub); assert.ok(reply.ok); if(!reply.ok) return;
    const r = {v:1 as const,channelId:d.channelId,descriptorRevision:d.revision,sender:principal.value,
      replyEpub:reply.value,nonce:'aa'.repeat(32),issuedAt:ctx.now,expiresAt:ctx.now+300,message:'Hello'};
    const sig = signWithKeyring(Buffer.from(sender.priv,'base64url'),firstContactRequestBytes(r),principal.value);
    assert.ok(sig.ok); if(!sig.ok) return;
    const envelope = sealFirstContactRequest({...r,sig:sig.value},d);
    const rows=[{id:createHash('sha256').update(envelope).digest('hex'),ciphertext:envelope}];
    const polled=mode==='poll'?await Promise.all([1,2].map(()=>pollFirstContact(store,async()=>rows,channel.priv,()=>({rotations:[],context:ctx})))):[];
    if(mode==='poll')assert.equal(polled.flat().length,1);
    const opened = mode!=='poll'?await receiveFirstContact(store,envelope,channel.priv,[],ctx):polled.flat()[0]!;
    assert.deepEqual(await store.outbox(),[]);
    await assert.rejects(receiveFirstContact(store,envelope,channel.priv,[],ctx),/replayed/);
    await assert.rejects(acceptFirstContactRequest(store,opened.replayKey,channel.priv,recipient,[],
      {...ctx,history:()=>({ok:false,reason:'missing-history'})},[],witnessed()));
    assert.deepEqual(await store.outbox(),[]);
    const issuer = () => ({ issuer: { principal: recipient.principal, signingPriv: recipient.currentPriv(),
      contactSecretHex: recipient.contactLaneSecret(), rotationSeq: recipient.rotationSeq,
      baseLaneIds: [...recipient.priorLanes(), recipient.laneId()],
      contactSecrets: [...recipient.priorContactSecrets(), recipient.contactLaneSecret()] },
      rotations: [], context: { ...witnessed(), history: ctx.history } });
    if (mode === 'browser') {
      await assert.rejects(acceptBrowserRequest(store, opened.replayKey, '00'.repeat(32), channel.priv, () => ({rotations:[],context:ctx}), issuer));
      assert.deepEqual(await store.outbox(), []);
      let available = true;
      const changingIssuer = () => { const value = issuer(); return available ? value : { ...value,
        context: { ...value.context, history: () => ({ok:false as const,reason:'missing-history' as const}) } }; };
      const interrupted = { ...store, decide: (...args: Parameters<typeof store.decide>) => {
        available = false; return store.decide(...args);
      } };
      await assert.rejects(acceptBrowserRequest(interrupted, opened.replayKey, opened.requestId, channel.priv,
        () => ({rotations:[],context:ctx}), changingIssuer), /first-contact-stale/);
      assert.deepEqual(await store.outbox(), []);
      assert.equal((await store.pending()).length, 1);
    }
    if (mode === 'browser-after-commit') {
      let available = true;
      const changingIssuer = () => { const value = issuer(); return available ? value : { ...value,
        context: { ...value.context, history: () => ({ok:false as const,reason:'missing-history' as const}) } }; };
      const interrupted = { ...store, decide: async (...args: Parameters<typeof store.decide>) => {
        await store.decide(...args); available = false;
      } };
      await assert.rejects(acceptBrowserRequest(interrupted, opened.replayKey, opened.requestId, channel.priv,
        () => ({rotations:[],context:ctx}), changingIssuer), /first-contact-stale/);
      // A commit is not rolled back or reissued after an ambiguous response.
      // The retained ciphertext must be revalidated by the delivery adapter.
      assert.equal((await store.outbox()).length, 1);
      assert.equal((await store.pending()).length, 0);
      return;
    }
    const grant = mode === 'browser'
      ? await acceptBrowserRequest(store, opened.replayKey, opened.requestId, channel.priv, () => ({rotations:[],context:ctx}), issuer)
      : await acceptFirstContactRequest(store,opened.replayKey,channel.priv,recipient,[],ctx,[],witnessed());
    const lane = openContactLaneGrant(sender.pub,senderEnc.priv,grant,recipient.principal,[],witnessed());
    assert.equal(lane.laneId,resolveContactLane(recipient,sender.pub,recipient.rotationSeq));
    assert.equal((await store.outbox())[0]?.grant?.ciphertextHex,grant.ciphertextHex);
    await assert.rejects(acceptFirstContactRequest(store,opened.replayKey,channel.priv,recipient,[],ctx,[],witnessed()));
  } finally { store.close(); }
});


test('public first-contact descriptors bind owner, key and policy without becoming freshness proofs', () => {
  const keyring=genesisKeyring(),ctx={...witnessed(),history:(p:PrincipalId,at:number,until:number)=>
    p===keyring.principal ? {ok:true as const,value:historyState(p,[],at,until)} : {ok:false as const,reason:'missing-history' as const}};
  const d={channelId:'ab'.repeat(32),revision:2,encryptionEpub:scalarSea(15).pub,
    expiresAt:ctx.now+600,maxLifetimeSeconds:300,maxMessageBytes:1024};
  const signed=signFirstContactDescriptor(keyring,d,[],ctx);
  const verify=(input:unknown,floor=2)=>verifyFirstContactDescriptor(input,keyring.principal,floor,[],ctx);
  assert.ok(verify(signed).ok);assert.equal(verify(signed,3).ok,false);
  for(const patch of [{channelId:'cd'.repeat(32)},{revision:3},{encryptionEpub:scalarSea(16).pub},
    {expiresAt:d.expiresAt+1},{maxLifetimeSeconds:301},{maxMessageBytes:2048}]) {
    assert.equal(verify({...signed,descriptor:{...signed.descriptor,...patch}}).ok,false);
  }
  assert.equal(verify({...signed,owner:scalarSea(3).pub}).ok,false);
  assert.equal(verifyFirstContactDescriptor(signed,keyring.principal,2,[],{...ctx,now:d.expiresAt}).ok,false);
  assert.equal(verifyFirstContactDescriptor(signed,keyring.principal,2,[],
    {...ctx,history:()=>({ok:false,reason:'missing-history'})}).ok,false);
});

// Browser consumer uses the same persisted envelope as the Rust/Node corpus.
import {
  deriveContactLane as deriveBrowserLane,
  openContactLaneGrant as openBrowserGrant,
} from '../contract/contact-lane-browser.ts';

// This grant corpus uses a different genesis account from records.json.
function browserRecipientContext(): ResolutionContext {
  const context = witnessed();
  return { ...context, history: (principal, at, until) => principal === vector.recipient
    ? { ok: true, value: historyState(principal, [], at, until) }
    : context.history(principal, at, until) };
}

test('browser lane derivation preserves directional canonical vectors', () => {
  assert.equal(deriveBrowserLane(vector.contactLaneSecretHex, vector.recipient, vector.sender), vector.laneId);
  assert.equal(deriveBrowserLane(vector.contactLaneSecretHex, vector.sender, vector.recipient), vector.swappedLaneId);
  assert.equal(deriveBrowserLane(vector.wrongSecretHex, vector.recipient, vector.sender), vector.wrongSecretLaneId);
  assert.throws(() => deriveBrowserLane(vector.contactLaneSecretHex.toUpperCase(), vector.recipient, vector.sender));
});

test('browser opens canonical grant and rereads authority after WebCrypto', async () => {
  let reads = 0;
  const grant = Object.freeze({ ciphertextHex: vector.grant.ciphertextHex });
  const opened = await openBrowserGrant(vector.sender, ring.mint.epriv, grant, vector.recipient, () => {
    reads++;
    return { rotations: [], context: browserRecipientContext() };
  });
  assert.deepEqual(opened, openContactLaneGrant(vector.sender, ring.mint.epriv, grant, vector.recipient, [], witnessed()));
  assert.equal(reads, 2);
});

test('browser rejects wrong parties, keys and malformed or tampered envelopes uniformly', async () => {
  const state = () => ({ rotations: [], context: browserRecipientContext() });
  const open = (ciphertextHex: string, sender = vector.sender, epriv = ring.mint.epriv, recipient = vector.recipient) =>
    openBrowserGrant(sender, epriv, { ciphertextHex }, recipient, state);
  for (const blob of ['', '00', 'gg'.repeat(94), vector.grant.ciphertextHex.toUpperCase(),
    '02' + vector.grant.ciphertextHex.slice(2), '0102' + vector.grant.ciphertextHex.slice(4),
    vector.grant.ciphertextHex.slice(0, -2) + '00', '00'.repeat(4097)]) {
    await assert.rejects(open(blob), /^Error: lane-grant-rejected$/);
  }
  await assert.rejects(open(vector.grant.ciphertextHex, vector.otherSender), /lane-grant-rejected/);
  await assert.rejects(open(vector.grant.ciphertextHex, vector.sender, ring.genesis.epriv), /lane-grant-rejected/);
  await assert.rejects(open(vector.grant.ciphertextHex, vector.sender, ring.mint.epriv, vector.otherSender), /lane-grant-rejected/);
  let getterCalls = 0;
  await assert.rejects(openBrowserGrant(vector.sender, ring.mint.epriv, {
    get ciphertextHex() { getterCalls++; return vector.grant.ciphertextHex; },
  }, vector.recipient, state), /lane-grant-rejected/);
  assert.equal(getterCalls, 0);
});

test('browser withholds decrypted lane when authority becomes unavailable or clock rolls back', async () => {
  for (const change of ['history', 'clock'] as const) {
    let reads = 0;
    await assert.rejects(openBrowserGrant(vector.sender, ring.mint.epriv, vector.grant, vector.recipient, () => {
      const context = browserRecipientContext();
      if (++reads === 1) return { rotations: [], context };
      return { rotations: [], context: change === 'clock' ? { ...context, now: context.now - 1 } :
        { ...context, history: () => ({ ok: false as const, reason: 'missing-history' as const }) } };
    }), /lane-grant-rejected/);
    assert.equal(reads, 2);
  }
});


test('browser refuses a grant without independently authenticated recipient history', async () => {
  await assert.rejects(openBrowserGrant(vector.sender, ring.mint.epriv, vector.grant, vector.recipient,
    () => ({ rotations: [], context: witnessed() })), /lane-grant-rejected/);
});

import { acceptFirstContactRequest as acceptBrowserRequest } from '../contract/first-contact-accept-browser.ts';
import { sealContactLaneGrant as sealBrowserGrant } from '../contract/contact-lane-browser.ts';

test('browser seal interoperates with Node and refuses issuer or sender authority changes', async () => {
  const sender = scalarSea(3), enc = scalarSea(4), recipient = genesisKeyring();
  const ctx = contextWith([signGenesisEpub(sender.pub, enc.pub, records.context.now - 40, 3)]);
  const history = (p: PrincipalId, at: number, until: number) =>
    ({ ok: true as const, value: historyState(p, [], at, until) });
  const peer = () => ({ rotations: [], context: { ...ctx, history } });
  const issuer = () => ({ issuer: { principal: recipient.principal, signingPriv: recipient.currentPriv(),
    contactSecretHex: recipient.contactLaneSecret(), rotationSeq: 0,
    baseLaneIds: [recipient.laneId()], contactSecrets: [recipient.contactLaneSecret()] },
    rotations: [], context: { ...witnessed(), history } });
  const grant = await sealBrowserGrant(sender.pub, peer, issuer);
  const opened = openContactLaneGrant(sender.pub, enc.priv, grant, recipient.principal, [], witnessed());
  assert.equal(opened.laneId, resolveContactLane(recipient, sender.pub, 0));
  for (const change of ['key', 'secret', 'clock', 'history', 'epub'] as const) {
    let ownerReads = 0, peerReads = 0;
    await assert.rejects(sealBrowserGrant(sender.pub, () => {
      const value = peer();
      if (++peerReads > 1 && change === 'epub') return { ...value, context: { ...value.context, genesisEpubBindings: [] } };
      return value;
    }, () => {
      const value = issuer(); if (++ownerReads === 1) return value;
      if (change === 'key') value.issuer.signingPriv = scalarSea(20).priv;
      if (change === 'secret') value.issuer.contactSecretHex = '99'.repeat(32);
      if (change === 'clock') value.context.now--;
      if (change === 'history') return { ...value, context: { ...value.context, history: () => ({ok:false as const,reason:'missing-history' as const}) } };
      return value;
    }), /lane-grant-rejected/);
  }
  await assert.rejects(sealBrowserGrant(sender.pub, () => ({rotations:[],context:{...ctx,history,genesisEpubBindings:[]}}), issuer), /lane-grant-rejected/);
});
