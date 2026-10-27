import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { p256 } from "@noble/curves/nist.js";
import type { EpochManifestBody } from "../../docs/s3rch-check.js";
import { bytesToHex, unb64 } from "../contract/account-key-seal.ts";
import { epochRevisionBytes, epochRevisionId, lengthPrefixed, sha256Hex } from "../contract/canonical.ts";
import { KEYRING_HISTORY_MAX } from "../contract/keyring-limits.ts";
import {
  acceptCurrentKey,
  acceptEnvelope,
  acceptGrantManifest,
  acceptGroupInboxSender,
  acceptItemLocator,
  acceptRevisionManifest,
  acceptStatusSigner,
  accountKeyEntryHash,
  accountKeyHeadBytes,
  accountKeyHeadSignedBySea,
  accountKeyLogBytes,
  ACCOUNT_KEY_HEAD_MAX_AGE_MS,
  consumeStatementMints,
  envDigest,
  grantManifestBytes,
  groupInboxBodyHash,
  groupInboxSigBytes,
  groupInboxSoul,
  itemRevisionSoul,
  itemRootSoul,
  manifestSoul,
  revisionManifestBytes,
  statusAuthorityBytes,
  type AccountKeyAnchor,
  type AccountKeyLogEntry,
  type AccountKeyLogHead,
  type RevisionManifest,
} from "../contract/consume.ts";

type ConsumeCheck = {
  name: string;
  entries?: AccountKeyLogEntry[];
  head?: AccountKeyLogHead;
  anchor?: AccountKeyLogEntry;
  chain?: { account: string; lastSeq: number; keyPub: string };
  issuedAt?: number;
  maxAgeMs?: number;
  entryHash?: string;
  providerAnswered: boolean;
  headSignature: string;
  expectedAccount: string;
  statementKeyPub: string;
  now: number;
  skewAllowanceMs: number;
  policyMaxAgeMs: number;
  decision: string;
  keyPub?: string;
};

const document = JSON.parse(
  readFileSync(new URL("../../vectors/encrypted-discovery/consume.json", import.meta.url), "utf8"),
) as {
  cases: { name: string; encodedLen: number; sha256: string }[];
  inputs: { providerPub: string; headSignature: string; headMaxAgeMs: number };
  checks: ConsumeCheck[];
};
const signing = JSON.parse(
  readFileSync(new URL("../../vectors/encrypted-discovery/sea-fixture.json", import.meta.url), "utf8"),
).signing as { pub: string; priv: string };

function expectHash(name: string, bytes: Uint8Array, hash: string): void {
  const row = document.cases.find((item) => item.name === name);
  assert.ok(row, name);
  assert.equal(bytes.length, row.encodedLen, name);
  assert.equal(hash, row.sha256, name);
  assert.equal(hash, sha256Hex(bytes), name);
}

function manifest(env: string, statusAuthPub?: string): RevisionManifest {
  return {
    itemId: "itema",
    e: 1,
    rev: "rev1",
    parent: "none",
    keyId: "a".repeat(64),
    envDigest: env,
    ...(statusAuthPub === undefined ? {} : { statusAuthPub }),
  };
}

function genesis(): AccountKeyLogEntry {
  return { account: "provider:acct", keyPub: "sea-current", seq: 0, prev: "none" };
}

const ISSUED_AT = 1_700_000_000_000;
const MAX_AGE = 60_000;
const SKEW = 5_000;

function headFor(account: string, seq: number, entryHash: string): AccountKeyLogHead {
  return { account, seq, entryHash, issuedAt: ISSUED_AT, maxAgeMs: MAX_AGE };
}

function fresh(
  input: Omit<Parameters<typeof acceptCurrentKey>[0], "now" | "skewAllowanceMs" | "policyMaxAgeMs">,
) {
  return acceptCurrentKey({
    now: ISSUED_AT,
    skewAllowanceMs: SKEW,
    policyMaxAgeMs: MAX_AGE,
    ...input,
  });
}

function signHead(head: AccountKeyLogHead): { providerPub: string; headSignature: string } {
  const headSignature = bytesToHex(
    p256.sign(accountKeyHeadBytes(head), unb64(signing.priv), { lowS: true, prehash: true }),
  );
  return { providerPub: signing.pub, headSignature };
}

test("canonical consume vectors match the shared fixture", () => {
  const envBytes = lengthPrefixed([
    "s3rch-env-digest-v1",
    "itema",
    "1",
    "rev1",
    "aes-gcm",
    "aabb",
    "ccdd",
  ]);
  const env = envDigest("itema", 1, "rev1", "aes-gcm", "aabb", "ccdd");
  expectHash("env-digest", envBytes, env);

  const plainBytes = revisionManifestBytes(manifest(env));
  expectHash("revision-manifest", plainBytes, sha256Hex(plainBytes));
  const authedBytes = revisionManifestBytes(manifest(env, "sea-status-pub"));
  expectHash("revision-manifest-auth", authedBytes, sha256Hex(authedBytes));
  assert.notEqual(sha256Hex(plainBytes), sha256Hex(authedBytes));

  const soul = manifestSoul("itema", "rev1");
  const grant = grantManifestBytes("itema", "rev1", soul);
  expectHash("grant-manifest", grant, sha256Hex(grant));

  const bindingBytes = statusAuthorityBytes({
    account: "provider:acct",
    accountPub: "sea-account",
    statusAuthPub: "sea-status-pub",
    seq: 2,
  });
  expectHash("status-authority", bindingBytes, sha256Hex(bindingBytes));

  const bodyBytes = lengthPrefixed(["s3rch-group-inbox-body-v1", "eph", "ct", "iv"]);
  const bodyHash = groupInboxBodyHash("eph", "ct", "iv");
  expectHash("group-inbox-body", bodyBytes, bodyHash);
  const sigBytes = groupInboxSigBytes({
    tag: "gtag",
    entryId: "entry1",
    senderPub: "sea-sender",
    bodyHash,
  });
  expectHash("group-inbox-ssig", sigBytes, sha256Hex(sigBytes));

  const first = genesis();
  const firstBytes = accountKeyLogBytes(first);
  const firstHash = accountKeyEntryHash(first);
  expectHash("account-key-genesis", firstBytes, firstHash);
  const second: AccountKeyLogEntry = {
    account: "provider:acct",
    keyPub: "sea-next",
    seq: 1,
    prev: firstHash,
  };
  const secondBytes = accountKeyLogBytes(second);
  const secondHash = accountKeyEntryHash(second);
  expectHash("account-key-next", secondBytes, secondHash);
  const headBytes = accountKeyHeadBytes(headFor("provider:acct", 1, secondHash));
  expectHash("account-key-head", headBytes, sha256Hex(headBytes));
  assert.equal(accountKeyHeadSignedBySea(), false);

  const epoch = {
    object:
      "chat_p_6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_11111111111111111111111111111111",
    epoch: 1,
    previousEpoch: 0,
    deviceId: "device-1",
    keyCommitment: "opaque-commitment",
    settleWindowMs: 86_400_000,
    aclSnapshot: "f9ac289c45e5e277cf0ecee22616a46b07d5ff92b83df0b13cacf8a9b5097449",
    statusAuthPub: "sea-status-pub",
  } as EpochManifestBody;
  expectHash("epoch-status-auth", epochRevisionBytes(epoch), epochRevisionId(epoch));
  const absent = { ...epoch, statusAuthPub: undefined } as EpochManifestBody;
  assert.equal(
    epochRevisionId(absent),
    "d068c39be0391bb64791839b21a21413392abe28f4e8f824d524884f07bd486f",
  );
  assert.throws(() => epochRevisionBytes({ ...absent, statusAuthPub: "" }));
  assert.throws(() => revisionManifestBytes(manifest(envDigest("itema", 1, "rev1", "aes-gcm", "aabb", "ccdd"), "")));
});

test("envelope path and manifest soul", () => {
  assert.equal(itemRevisionSoul("itema", "rev1"), "s3rch/items/itema/r/rev1");
  assert.equal(manifestSoul("itema", "rev1"), "s3rch/items/itema/m/rev1");
  assert.equal(itemRootSoul("itema"), "s3rch/items/itema");
  assert.equal(groupInboxSoul("gtag", "entry1"), "s3rch/ginbox/gtag/entry1");
  assert.throws(() => itemRevisionSoul("item/a", "rev1"));
  assert.throws(() => itemRevisionSoul(".", "rev1"));

  const digest = envDigest("itema", 1, "rev1", "aes-gcm", "aabb", "ccdd");
  assert.deepEqual(acceptItemLocator(2, 1, "rev1", "rev1", false), { ok: true });
  assert.deepEqual(acceptItemLocator(2, 1, "rev1", "rev1", true), {
    ok: false,
    reason: "root-ciphertext",
  });
  const envelope = {
    itemId: "itema",
    e: 1,
    rev: "rev1",
    fetchedSoul: "s3rch/items/itema/r/rev1",
    rootHasCiphertext: false,
    alg: "aes-gcm",
    iv: "aabb",
    ct: "ccdd",
    envDigest: digest,
  };
  assert.deepEqual(acceptEnvelope(envelope), { ok: true });
  assert.deepEqual(acceptEnvelope({ ...envelope, rootHasCiphertext: true }), {
    ok: false,
    reason: "root-ciphertext",
  });
  assert.deepEqual(acceptEnvelope({ ...envelope, fetchedSoul: "s3rch/items/itema" }), {
    ok: false,
    reason: "bad-soul",
  });
  assert.deepEqual(
    acceptEnvelope({
      ...envelope,
      envDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    }),
    { ok: false, reason: "digest-mismatch" },
  );

  const soul = manifestSoul("itema", "rev1");
  assert.deepEqual(
    acceptGrantManifest({ manifest: soul, itemId: "itema", rev: "rev1", authorLaneOnly: false }),
    { ok: true },
  );
  assert.deepEqual(
    acceptGrantManifest({ itemId: "itema", rev: "rev1", authorLaneOnly: false }),
    { ok: false, reason: "bad-soul" },
  );
  assert.deepEqual(
    acceptGrantManifest({ manifest: soul, itemId: "itema", rev: "rev1", authorLaneOnly: true }),
    { ok: false, reason: "author-lane" },
  );
  assert.deepEqual(
    acceptRevisionManifest({
      nodeV: 1,
      manifest: manifest(digest),
      itemId: "itema",
      rev: "rev1",
      envelopeDigest: digest,
      carriesAccountPub: false,
    }),
    { ok: true },
  );
  assert.deepEqual(
    acceptRevisionManifest({
      nodeV: 1,
      manifest: manifest(digest),
      itemId: "itema",
      rev: "rev1",
      envelopeDigest: digest,
      carriesAccountPub: true,
    }),
    { ok: false, reason: "bad-soul" },
  );
});

test("status authority, group inbox, and current key", () => {
  const binding = {
    account: "provider:acct",
    accountPub: "sea-account",
    statusAuthPub: "sea-status",
    seq: 4,
  };
  assert.deepEqual(
    acceptStatusSigner({
      signingPub: "sea-account",
      currentAccountPub: "sea-account",
      bindingSignedByCurrent: false,
      purpose: "status",
    }),
    { ok: true },
  );
  assert.deepEqual(
    acceptStatusSigner({
      signingPub: "sea-status",
      currentAccountPub: "sea-account",
      bindingSignedByCurrent: false,
      purpose: "status",
    }),
    { ok: false, reason: "missing-binding" },
  );
  assert.deepEqual(
    acceptStatusSigner({
      signingPub: "sea-status",
      currentAccountPub: "sea-account",
      binding,
      manifestStatusAuthPub: "sea-status",
      logHeadAccount: "provider:acct",
      logHeadSeq: 4,
      bindingSignedByCurrent: true,
      purpose: "status",
    }),
    { ok: true },
  );
  assert.deepEqual(
    acceptStatusSigner({
      signingPub: "sea-status",
      currentAccountPub: "sea-account",
      binding,
      manifestStatusAuthPub: "sea-status",
      logHeadAccount: "provider:other",
      logHeadSeq: 4,
      bindingSignedByCurrent: true,
      purpose: "status",
    }),
    { ok: false, reason: "authority-key" },
  );
  for (const purpose of ["manifest", "grant", "binding"]) {
    assert.deepEqual(
      acceptStatusSigner({
        signingPub: "sea-status",
        currentAccountPub: "sea-account",
        binding,
        manifestStatusAuthPub: "sea-status",
        logHeadAccount: "provider:acct",
        logHeadSeq: 4,
        bindingSignedByCurrent: true,
        purpose,
      }),
      { ok: false, reason: "authority-key" },
      purpose,
    );
  }
  assert.deepEqual(
    acceptGroupInboxSender({
      senderPub: "sea-sender",
      currentAccountPub: "sea-sender",
      member: true,
      signatureUnderSender: true,
      derivedFromGroupKey: false,
    }),
    { ok: true },
  );
  assert.deepEqual(
    acceptGroupInboxSender({
      senderPub: "sea-sender",
      currentAccountPub: "sea-sender",
      member: true,
      signatureUnderSender: true,
      derivedFromGroupKey: true,
    }),
    { ok: false, reason: "group-writer-key" },
  );
  assert.deepEqual(
    acceptGroupInboxSender({
      senderPub: "sea-old",
      currentAccountPub: "sea-sender",
      member: true,
      signatureUnderSender: true,
      derivedFromGroupKey: false,
    }),
    { ok: false, reason: "superseded" },
  );

  const first = genesis();
  const firstHash = accountKeyEntryHash(first);
  const second: AccountKeyLogEntry = {
    account: "provider:acct",
    keyPub: "sea-next",
    seq: 1,
    prev: firstHash,
  };
  const secondHash = accountKeyEntryHash(second);
  const head = headFor("provider:acct", 1, secondHash);
  const signed = signHead(head);
  assert.equal(signed.providerPub, document.inputs.providerPub);
  assert.equal(signed.headSignature, document.inputs.headSignature);
  assert.deepEqual(
    fresh({
      head,
      entries: [first, second],
      providerAnswered: true,
      providerPub: document.inputs.providerPub,
      headSignature: document.inputs.headSignature,
      expectedAccount: "provider:acct",
      statementKeyPub: "sea-next",
    }),
    { ok: true, keyPub: "sea-next" },
  );
  assert.deepEqual(
    fresh({
      head,
      entries: [first, second],
      providerAnswered: false,
      providerPub: signed.providerPub,
      headSignature: signed.headSignature,
      expectedAccount: "provider:acct",
      statementKeyPub: "sea-next",
    }),
    { ok: false, reason: "no-answer" },
  );
  assert.deepEqual(
    fresh({
      head,
      entries: [first, second],
      providerAnswered: true,
      providerPub: signed.providerPub,
      headSignature: "00",
      expectedAccount: "provider:acct",
      statementKeyPub: "sea-next",
    }),
    { ok: false, reason: "head-mismatch" },
  );
  assert.deepEqual(
    fresh({
      head,
      entries: [first, second],
      providerAnswered: true,
      expectedAccount: "provider:acct",
      ...signed,
      statementKeyPub: "sea-current",
    }),
    { ok: false, reason: "superseded" },
  );
  assert.deepEqual(
    fresh({
      head,
      entries: [{ ...first, keyPub: "sea-forged" }, second],
      providerAnswered: true,
      expectedAccount: "provider:acct",
      ...signed,
      statementKeyPub: "sea-next",
    }),
    { ok: false, reason: "prev-mismatch" },
  );
  const anchor: AccountKeyAnchor = { entry: first };
  assert.deepEqual(
    fresh({
      head,
      entries: [second],
      anchor,
      providerAnswered: true,
      expectedAccount: "provider:acct",
      ...signed,
      statementKeyPub: "sea-next",
    }),
    { ok: true, keyPub: "sea-next" },
  );
  const jumped: AccountKeyLogEntry = {
    account: "provider:acct",
    keyPub: "sea-nine",
    seq: 9,
    prev: firstHash,
  };
  const jumpedHead = headFor("provider:acct", 9, accountKeyEntryHash(jumped));
  assert.deepEqual(
    fresh({
      head: jumpedHead,
      entries: [first, jumped],
      anchor,
      providerAnswered: true,
      expectedAccount: "provider:acct",
      ...signHead(jumpedHead),
      statementKeyPub: "sea-nine",
    }),
    { ok: false, reason: "unlinked" },
  );
  const other: AccountKeyLogEntry = {
    account: "provider:other",
    keyPub: "sea-b",
    seq: 0,
    prev: "none",
  };
  const otherHash = accountKeyEntryHash(other);
  const crossed: AccountKeyLogEntry = {
    account: "provider:acct",
    keyPub: "sea-a",
    seq: 1,
    prev: otherHash,
  };
  const crossedHead = headFor("provider:acct", 1, accountKeyEntryHash(crossed));
  assert.deepEqual(
    fresh({
      head: crossedHead,
      entries: [other, crossed],
      anchor: { entry: other },
      providerAnswered: true,
      expectedAccount: "provider:acct",
      ...signHead(crossedHead),
      statementKeyPub: "sea-a",
    }),
    { ok: false, reason: "unlinked" },
  );
  const seaEntry: AccountKeyLogEntry = {
    account: "provider:acct",
    keyPub: signed.providerPub,
    seq: 0,
    prev: "none",
  };
  const seaHead = headFor("provider:acct", 0, accountKeyEntryHash(seaEntry));
  assert.deepEqual(
    fresh({
      head: seaHead,
      entries: [seaEntry],
      providerAnswered: true,
      expectedAccount: "provider:acct",
      ...signHead(seaHead),
      statementKeyPub: signed.providerPub,
    }),
    { ok: false, reason: "head-mismatch" },
  );
  const attackerGenesis: AccountKeyLogEntry = {
    account: "provider:other",
    keyPub: "sea-attacker-0",
    seq: 0,
    prev: "none",
  };
  const attackerNext: AccountKeyLogEntry = {
    account: "provider:other",
    keyPub: "sea-attacker",
    seq: 1,
    prev: accountKeyEntryHash(attackerGenesis),
  };
  const attackerHead = headFor("provider:other", 1, accountKeyEntryHash(attackerNext));
  const attackerSigned = signHead(attackerHead);
  assert.deepEqual(
    fresh({
      head: attackerHead,
      entries: [attackerGenesis, attackerNext],
      providerAnswered: true,
      expectedAccount: "provider:acct",
      ...attackerSigned,
      statementKeyPub: "sea-attacker",
    }),
    { ok: false, reason: "head-mismatch" },
  );
  assert.deepEqual(
    fresh({
      head: attackerHead,
      entries: [attackerGenesis, attackerNext],
      providerAnswered: true,
      expectedAccount: "provider:other",
      ...attackerSigned,
      statementKeyPub: "sea-attacker",
    }),
    { ok: true, keyPub: "sea-attacker" },
  );
  assert.deepEqual(
    fresh({
      head,
      entries: [first, second],
      providerAnswered: true,
      ...signed,
      expectedAccount: "",
      statementKeyPub: "sea-next",
    }),
    { ok: false, reason: "head-mismatch" },
  );
  const entries: AccountKeyLogEntry[] = [];
  let prev = "none";
  for (let seq = 0; seq <= KEYRING_HISTORY_MAX; seq += 1) {
    const entry = { account: "provider:acct", keyPub: `sea-${seq}`, seq, prev };
    prev = accountKeyEntryHash(entry);
    entries.push(entry);
  }
  const limitHead = headFor("provider:acct", KEYRING_HISTORY_MAX, prev);
  assert.deepEqual(
    fresh({
      head: limitHead,
      entries,
      providerAnswered: true,
      expectedAccount: "provider:acct",
      ...signHead(limitHead),
      statementKeyPub: `sea-${KEYRING_HISTORY_MAX}`,
    }),
    { ok: true, keyPub: `sea-${KEYRING_HISTORY_MAX}` },
  );
  for (const kind of ["hop", "status", "chat", "manifest", "binding", "ssig", "log"]) {
    assert.equal(consumeStatementMints(kind), false, kind);
  }
});

test("account key anchor is a floor", () => {
  const genesisEntry: AccountKeyLogEntry = {
    account: "provider:acct",
    keyPub: "k0",
    seq: 0,
    prev: "none",
  };
  const genesisHash = accountKeyEntryHash(genesisEntry);
  const first: AccountKeyLogEntry = {
    account: "provider:acct",
    keyPub: "k1",
    seq: 1,
    prev: genesisHash,
  };
  const firstHash = accountKeyEntryHash(first);
  const second: AccountKeyLogEntry = {
    account: "provider:acct",
    keyPub: "k2",
    seq: 2,
    prev: firstHash,
  };
  const secondHash = accountKeyEntryHash(second);
  const forkFirst: AccountKeyLogEntry = {
    account: "provider:acct",
    keyPub: "kf1",
    seq: 1,
    prev: genesisHash,
  };
  const forkSecond: AccountKeyLogEntry = {
    account: "provider:acct",
    keyPub: "kf2",
    seq: 2,
    prev: accountKeyEntryHash(forkFirst),
  };
  const oldHead = headFor("provider:acct", 1, firstHash);
  const floor: AccountKeyAnchor = { entry: second };
  assert.deepEqual(
    fresh({
      head: oldHead,
      entries: [genesisEntry, first, second],
      anchor: floor,
      providerAnswered: true,
      expectedAccount: "provider:acct",
      ...signHead(oldHead),
      statementKeyPub: "k1",
    }),
    { ok: false, reason: "superseded" },
  );
  const forkHead = headFor("provider:acct", 2, accountKeyEntryHash(forkSecond));
  const realFloor: AccountKeyAnchor = { entry: first };
  assert.deepEqual(
    fresh({
      head: forkHead,
      entries: [genesisEntry, forkFirst, forkSecond],
      anchor: realFloor,
      providerAnswered: true,
      expectedAccount: "provider:acct",
      ...signHead(forkHead),
      statementKeyPub: "kf2",
    }),
    { ok: false, reason: "unlinked" },
  );
  const current = headFor("provider:acct", 2, secondHash);
  assert.deepEqual(
    fresh({
      head: current,
      entries: [second],
      anchor: floor,
      providerAnswered: true,
      expectedAccount: "provider:acct",
      ...signHead(current),
      statementKeyPub: "k2",
    }),
    { ok: true, keyPub: "k2" },
  );
});

function chainFrom(spec: { account: string; lastSeq: number; keyPub: string }): AccountKeyLogEntry[] {
  assert.equal(spec.lastSeq, KEYRING_HISTORY_MAX);
  const entries: AccountKeyLogEntry[] = [];
  let prev = "none";
  for (let seq = 0; seq <= spec.lastSeq; seq += 1) {
    const row: AccountKeyLogEntry = {
      account: spec.account,
      keyPub: spec.keyPub.replace("{seq}", String(seq)),
      seq,
      prev,
    };
    prev = accountKeyEntryHash(row);
    entries.push(row);
  }
  return entries;
}

test("shared consume checks", () => {
  assert.equal(document.inputs.headMaxAgeMs, ACCOUNT_KEY_HEAD_MAX_AGE_MS);
  for (const row of document.checks) {
    let entries: AccountKeyLogEntry[];
    let head: AccountKeyLogHead;
    if (row.chain !== undefined) {
      entries = chainFrom(row.chain);
      const last = entries[entries.length - 1];
      assert.ok(last, row.name);
      head = headFor(last.account, last.seq, accountKeyEntryHash(last));
      head = { ...head, issuedAt: row.issuedAt ?? ISSUED_AT, maxAgeMs: row.maxAgeMs ?? MAX_AGE };
      assert.equal(head.entryHash, row.entryHash, row.name);
    } else {
      assert.ok(row.entries, row.name);
      assert.ok(row.head, row.name);
      entries = row.entries;
      head = row.head;
    }
    if (row.name === "account-key-head-signature") {
      assert.equal(row.headSignature, document.inputs.headSignature);
    }
    const decision = acceptCurrentKey({
      head,
      entries,
      ...(row.anchor === undefined ? {} : { anchor: { entry: row.anchor } }),
      providerAnswered: row.providerAnswered,
      providerPub: document.inputs.providerPub,
      headSignature: row.headSignature,
      expectedAccount: row.expectedAccount,
      statementKeyPub: row.statementKeyPub,
      now: row.now,
      skewAllowanceMs: row.skewAllowanceMs,
      policyMaxAgeMs: row.policyMaxAgeMs,
    });
    if (row.decision === "accept") {
      assert.deepEqual(decision, { ok: true, keyPub: row.keyPub }, row.name);
    } else {
      assert.deepEqual(decision, { ok: false, reason: row.decision }, row.name);
    }
  }
});
