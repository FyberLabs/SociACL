import assert from "node:assert/strict";
import { createHash, hkdfSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { p256 } from "@noble/curves/nist.js";
import { bytesToHex, decodeLengthPrefixed, hexToBytes, seaPoint } from "../contract/account-key-seal.ts";
import { importGenesis } from "../contract/account-key.ts";
import { AccountKeyring, rotateKeyring } from "../contract/account-keyring.ts";
import {
  CONTACT_LANE_DOMAIN,
  CONTACT_LANE_GRANT_DOMAIN,
  CONTACT_LANE_GRANT_SIG_DOMAIN,
  CONTACT_LANE_VERSION,
  contactLaneGrantAad,
  contactLaneGrantPlaintext,
  contactLaneInfo,
  contactLaneMintsGrant,
  contactLaneReusesBase,
  deriveContactLane,
  laneLookupKey,
  openContactLaneGrant,
  regrantContactLanes,
  resolveContactLane,
  sealContactLaneGrant,
  sealContactLaneGrantWith,
} from "../contract/contact-lane.ts";
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
  laneSecretHex: string;
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
    plaintextHex: string;
    aadHex: string;
    ciphertextHex: string;
    signature: string;
  };
};

const ring = JSON.parse(
  readFileSync(new URL("../../vectors/encrypted-discovery/account-keyring.json", import.meta.url), "utf8"),
) as {
  genesis: { laneId: string; signingPub: string; signingPriv: string; epub: string; epriv: string; principal: string };
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
  assert.equal(deriveContactLane(vector.laneSecretHex, vector.recipient, vector.sender), vector.laneId);
  assert.equal(deriveContactLane(vector.laneSecretHex, vector.sender, vector.recipient), vector.swappedLaneId);
  assert.notEqual(vector.laneId, vector.swappedLaneId);
  assert.equal(deriveContactLane(vector.laneSecretHex, vector.recipient, vector.otherSender), vector.otherLaneId);
  assert.equal(deriveContactLane(vector.priorSecretHex, vector.recipient, vector.sender), vector.priorLaneId);
  assert.equal(deriveContactLane(vector.wrongSecretHex, vector.recipient, vector.sender), vector.wrongSecretLaneId);
  assert.notEqual(vector.laneId, vector.otherLaneId);
  assert.notEqual(vector.laneId, vector.priorLaneId);
  assert.notEqual(vector.laneId, vector.wrongSecretLaneId);
  const oracle = Buffer.from(
    hkdfSync("sha256", hexToBytes(vector.laneSecretHex), hexToBytes(vector.saltHex), info, 32),
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
  assert.equal(bytesToHex(contactLaneGrantPlaintext(vector.laneId, vector.recipient, 0)), vector.grant.plaintextHex);
  const ephemeralPub = seaPoint(hexToBytes(vector.grant.ephemeralScalarHex));
  assert.equal(
    bytesToHex(contactLaneGrantAad(vector.recipient, vector.sender, vector.grant.senderEpub, ephemeralPub, 0)),
    vector.grant.aadHex,
  );
  assert.equal(grant.ciphertextHex, vector.grant.ciphertextHex);
  assert.equal(grant.signature, vector.grant.signature);
  assert.equal(grant.rotationSeq, 0);
  assert.equal(grant.ciphertextHex.includes(vector.laneSecretHex), false);
  assert.equal(grant.ciphertextHex.includes(ring.genesis.signingPriv), false);
  assert.equal(grant.ciphertextHex.includes(ring.genesis.epriv), false);
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
  assert.equal(contactLaneMintsGrant(), false);
});

test("an outsider cannot read a principal or the base lane out of a lane id", () => {
  assert.match(vector.laneId, /^[0-9a-f]{64}$/u);
  assert.equal(vector.laneId.includes("."), false);
  assert.equal(vector.laneId.includes(vector.recipient), false);
  assert.equal(vector.laneId.includes(vector.sender), false);
  assert.notEqual(vector.laneId, vector.laneSecretHex);
  assert.notEqual(vector.otherLaneId, vector.laneId);
  assert.notEqual(vector.laneId, createHash("sha256").update(vector.recipient).digest("hex"));
  assert.notEqual(vector.laneId, createHash("sha256").update(vector.sender).digest("hex"));
  assert.notEqual(vector.laneId, createHash("sha256").update(vector.infoHex).digest("hex"));
  const source = readFileSync(new URL("../contract/contact-lane.ts", import.meta.url), "utf8");
  assert.equal(source.includes("user.epub"), false);
  assert.equal(source.includes("gunUserEpub"), false);
});

test("a null currentEpub is refused and a bad id does not derive", () => {
  const keyring = genesisKeyring();
  assert.equal(
    message(() => sealContactLaneGrant(keyring, vector.sender, [], emptyContext(), [], witnessed())),
    ring.errors.epubUnknown,
  );
  assert.equal(message(() => deriveContactLane("ab", vector.recipient, vector.sender)), ring.errors.badLane);
  assert.equal(message(() => deriveContactLane(vector.laneSecretHex, "not-a-principal", vector.sender)), "bad-length");
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
  const lanes = [vector.laneSecretHex, vector.priorSecretHex, "33".repeat(32)];
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
  );
  const sender = vector.sender;
  const atZero = resolveContactLane(current, sender, 0);
  assert.equal(atZero, deriveContactLane(lanes[0]!, current.principal, sender));
  const chain: Record<string, unknown>[] = [];
  const next = scalarSea(20);
  const nextEnc = scalarSea(21);
  const rotated = rotateKeyring(current, ring.trusted, ring.lost, chain, context, () => ({
    signingPub: next.pub,
    signingPriv: next.priv,
    epub: nextEnc.pub,
    epriv: nextEnc.priv,
    laneId: lanes[1]!,
  }));
  current = rotated.keyring;
  assert.equal(current.priorLanes().length, current.rotationSeq);
  assert.equal(resolveContactLane(current, sender, 0), atZero);
  assert.equal(resolveContactLane(current, sender, 1), deriveContactLane(lanes[1]!, current.principal, sender));
  assert.notEqual(resolveContactLane(current, sender, 1), atZero);
  assert.equal(contactLaneReusesBase(current.laneId(), current.laneId(), current.priorLanes()), true);
  assert.equal(contactLaneReusesBase(current.priorLanes()[0]!, current.laneId(), current.priorLanes()), true);
  assert.equal(contactLaneReusesBase(atZero, current.laneId(), current.priorLanes()), false);
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
    vector.laneSecretHex,
    0,
    0,
    [],
    recipientContext,
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
  );
  const grant = sealContactLaneGrant(
    recipient,
    senderSign.pub,
    [],
    senderContext,
    [],
    recipientContext,
  );
  assert.equal(grant.sender, senderSign.pub);
  assert.equal(grant.senderEpub, senderEnc.pub);
  assert.equal(grant.rotationSeq, 0);
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
