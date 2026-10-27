import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import type { EpochManifestBody } from "../../docs/s3rch-check.js";
import { epochRevisionBytes, epochRevisionId, lengthPrefixed, sha256Hex } from "../contract/canonical.ts";
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
  type AccountKeyLogEntry,
  type RevisionManifest,
} from "../contract/consume.ts";

const document = JSON.parse(
  readFileSync(new URL("../../vectors/encrypted-discovery/consume.json", import.meta.url), "utf8"),
) as { cases: { name: string; encodedLen: number; sha256: string }[] };

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
  const headBytes = accountKeyHeadBytes({
    account: "provider:acct",
    seq: 1,
    entryHash: secondHash,
  });
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
      logHeadSeq: 4,
      bindingSignedByCurrent: true,
      purpose: "status",
    }),
    { ok: true },
  );
  for (const purpose of ["manifest", "grant", "binding"]) {
    assert.deepEqual(
      acceptStatusSigner({
        signingPub: "sea-status",
        currentAccountPub: "sea-account",
        binding,
        manifestStatusAuthPub: "sea-status",
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
  const head = { account: "provider:acct", seq: 1, entryHash: secondHash };
  assert.deepEqual(
    acceptCurrentKey({
      head,
      entries: [first, second],
      providerAnswered: true,
      statementKeyPub: "sea-next",
    }),
    { ok: true, keyPub: "sea-next" },
  );
  assert.deepEqual(
    acceptCurrentKey({
      head,
      entries: [first, second],
      providerAnswered: false,
      statementKeyPub: "sea-next",
    }),
    { ok: false, reason: "no-answer" },
  );
  assert.deepEqual(
    acceptCurrentKey({
      head,
      entries: [first, second],
      providerAnswered: true,
      statementKeyPub: "sea-current",
    }),
    { ok: false, reason: "superseded" },
  );
  assert.deepEqual(
    acceptCurrentKey({
      head,
      entries: [{ ...first, keyPub: "sea-forged" }, second],
      providerAnswered: true,
      statementKeyPub: "sea-next",
    }),
    { ok: false, reason: "prev-mismatch" },
  );
  assert.deepEqual(
    acceptCurrentKey({
      head,
      entries: [second],
      anchorHash: firstHash,
      providerAnswered: true,
      statementKeyPub: "sea-next",
    }),
    { ok: true, keyPub: "sea-next" },
  );
  for (const kind of ["hop", "status", "chat", "manifest", "binding", "ssig", "log"]) {
    assert.equal(consumeStatementMints(kind), false, kind);
  }
});
