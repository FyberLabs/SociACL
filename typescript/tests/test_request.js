import assert from "node:assert/strict";
import { test } from "node:test";
import { p256 } from "@noble/curves/nist.js";
import * as ids from "../ids/src/index.js";
import { issuerFromSeed, MemoryGroupGraph } from "../src/group.js";
import { admittedPost, checkPost, factorGrants } from "../src/post.js";
import * as postApi from "../src/post.js";
import { grantApprovedRequest } from "../src/request.js";
import { admitRow, admittedView, checkSee, isVerifiedRow, putObject } from "../src/see.js";
import * as seeApi from "../src/see.js";
import { b64 } from "../ids/scripts/vector-util.mjs";

const secret = (n) => { const b = new Uint8Array(32); b[31] = n; return b; };
const principal = (n) => {
  const pub = p256.getPublicKey(secret(n), false);
  const id = ids.parsePrincipalId(b64(pub.slice(1, 33)) + "." + b64(pub.slice(33)));
  if (!id.ok) throw new Error(id.reason);
  return id.value;
};
const p = principal(1);
const p2 = principal(2);
const at = 1700000000;
const now = at + 60;
const chat = ids.mintObjectId("chat", p, () => new Uint8Array(16).fill(0x11));
if (!chat.ok) throw new Error(chat.reason);

function context() {
  const history = (principalId, issued, until) => principalId === p || principalId === p2
    ? { ok: true, value: ids.historyState(principalId, [], issued, until) }
    : { ok: false, reason: "missing-history" };
  return {
    jwks: { keys: [] },
    links: new Map(),
    revocations: [],
    now,
    policy: { allowedDomains: ["s3r.ch"], allowedUris: ["https://s3r.ch/identity/link"], allowedChainIds: ["1"] },
    pinnedIss: new Set(),
    history,
    genesisEpubBindings: [],
  };
}

test("stateful toString on the object is not-string and writes nothing", () => {
  const graph = {};
  const ctx = context();
  const resolver = { rotations: () => [], ctx };
  const record = { object: chat.value, owner: p, issuedAt: at, sig: "" };
  record.sig = ids.signWithKeyring(secret(1), ids.objectRecordBytes(record), p).value;
  const put = putObject(graph, record, resolver);
  assert.equal(put.ok, true);
  let n = 0;
  const source = {
    toString() {
      n += 1;
      return n === 1 ? "doc-a" : "doc-b";
    },
  };
  const requestId = ids.requestId(p2, chat.value);
  assert.equal(requestId.ok, true);
  const result = grantApprovedRequest(
    graph,
    p,
    {
      requestId: requestId.value,
      requester: p2,
      object: source,
      scope: "read",
      status: "pending",
      message: "",
      issuedAt: now,
      sig: "aa",
    },
    { from: 0, until: 100 },
    null,
    { scalar: secret(1), resolver },
  );
  assert.equal(result.granted, false);
  assert.equal(result.reason, "not-string");
  assert.equal(admittedView(graph, chat.value, p2), undefined);
});

test("factorGrants stays false for a request", () => {
  assert.equal(factorGrants("request"), false);
  assert.equal(factorGrants("hop"), false);
  assert.equal(factorGrants("inbox"), false);
});

function objectRecord() {
  const record = { object: chat.value, owner: p, issuedAt: at, sig: "" };
  const sig = ids.signWithKeyring(secret(1), ids.objectRecordBytes(record), p);
  if (!sig.ok) throw new Error(sig.reason);
  record.sig = sig.value;
  return record;
}

function signRequest(fields, signer) {
  const id = ids.requestId(fields.requester, fields.object);
  if (!id.ok) throw new Error(id.reason);
  const bare = { ...fields, requestId: id.value, sig: "" };
  const sig = ids.signWithKeyring(secret(signer), ids.accessRequestBytes(bare), principal(signer));
  if (!sig.ok) throw new Error(sig.reason);
  return { ...bare, sig: sig.value };
}

test("resolver lookups stop at two and a later throw still writes both rows", () => {
  const request = signRequest({
    requester: p2,
    object: chat.value,
    scope: "read+post",
    status: "pending",
    message: "",
    issuedAt: now,
  }, 2);
  const window = { from: at, until: now + 100 };
  for (const throwAt of [0, 1, 2]) {
    const graph = {};
    let calls = 0;
    const resolver = {
      rotations() {
        if (calls >= throwAt) throw new Error("resolver");
        calls += 1;
        return [];
      },
      ctx: context(),
    };
    assert.equal(putObject(graph, objectRecord(), { rotations: () => [], ctx: context() }).ok, true);
    let thrown = false;
    let result;
    try {
      result = grantApprovedRequest(graph, p, request, window, null, { scalar: secret(1), resolver });
    } catch (error) {
      thrown = true;
      assert.equal(error instanceof Error ? error.message : "", "resolver");
    }
    if (throwAt < 2) {
      assert.equal(thrown, true);
      assert.equal(admittedView(graph, chat.value, p2), undefined);
      assert.equal(admittedPost(graph, chat.value, p2), undefined);
    } else {
      assert.equal(thrown, false);
      assert.equal(result.granted, true);
      assert.equal(calls, 2);
      assert.equal(admittedView(graph, chat.value, p2)?.stated, 1);
      assert.equal(admittedPost(graph, chat.value, p2)?.stated, 1);
    }
  }
});

test("a peer merge cannot auto-approve a non-member", () => {
  const owner = new MemoryGroupGraph();
  const mallory = new MemoryGroupGraph();
  const resolver = { rotations: () => [], ctx: context() };
  assert.equal(putObject(owner, objectRecord(), resolver).ok, true);
  mallory.putObject(chat.value, p2);
  owner.mergeFrom(mallory);
  const request = signRequest({
    requester: p2,
    object: chat.value,
    scope: "read",
    status: "pending",
    message: "",
    issuedAt: now,
  }, 2);
  const result = grantApprovedRequest(
    owner,
    p,
    request,
    { from: at, until: now + 100 },
    { predicate: "same-group", now },
    { scalar: secret(1), resolver },
  );
  assert.equal(result.granted, false);
  assert.equal(result.reason, "not-member");
  assert.equal(admittedView(owner, chat.value, p2), undefined);
  owner.putObject(chat.value, p2);
  assert.equal(owner.ownerOf(chat.value), p);
});

test("missing and non-string request fields are not-string", () => {
  const id = ids.requestId(p2, chat.value);
  assert.equal(id.ok, true);
  const base = {
    requestId: id.value,
    requester: p2,
    object: chat.value,
    scope: "read",
    status: "pending",
    message: "",
    issuedAt: now,
    sig: "aa",
  };
  for (const field of ["scope", "status", "message", "requester", "object"]) {
    for (const value of [undefined, null, 1, {}]) {
      const row = { ...base };
      if (value === undefined) delete row[field];
      else row[field] = value;
      const got = ids.parseAccessRequest(row);
      assert.equal(got.ok, false, field);
      assert.equal(got.reason, "not-string");
    }
  }
});

function signGrant(bytesOf, extra) {
  const fields = {
    owner: p,
    object: chat.value,
    accessor: p2,
    stated: 1,
    from: at,
    until: now + 100,
    hamState: 1,
    issuedAt: now,
    sig: "",
    ...extra,
  };
  const sig = ids.signWithKeyring(secret(1), bytesOf(fields), p);
  if (!sig.ok) throw new Error(sig.reason);
  return { ...fields, sig: sig.value };
}

function ed25519Seed(name) {
  const bytes = new Uint8Array(32);
  const raw = new TextEncoder().encode(name);
  for (let i = 0; i < raw.length; i += 1) bytes[i % 32] ^= (raw[i] + ((i * 17) & 255)) & 255;
  bytes[0] ^= raw.length;
  bytes[31] |= 1;
  return bytes;
}

test("an earlier grant cannot revive a cancel, and another graph stays closed", () => {
  assert.equal(seeApi.stageSee, undefined);
  assert.equal(seeApi.commitStagedSee, undefined);
  assert.equal(postApi.stagePost, undefined);
  assert.equal(postApi.commitStagedPost, undefined);
  const graph = {};
  const resolver = { rotations: () => [], ctx: context() };
  assert.equal(putObject(graph, objectRecord(), resolver).ok, true);
  const request = signRequest({
    requester: p2,
    object: chat.value,
    scope: "read+post",
    status: "pending",
    message: "",
    issuedAt: now,
  }, 2);
  const window = { from: at, until: now + 100 };
  const granted = grantApprovedRequest(graph, p, request, window, null, { scalar: secret(1), resolver });
  assert.equal(granted.granted, true);
  const seeCancel = admitRow(graph, signGrant(ids.seeGrantBytes, { stated: 0, hamState: 2 }), resolver);
  const postCancel = postApi.admitPost(graph, signGrant(ids.postGrantBytes, { stated: 0, hamState: 2 }), resolver);
  assert.equal(seeCancel.ok && seeCancel.kept, true);
  assert.equal(postCancel.ok && postCancel.kept, true);
  const seeAgain = admitRow(graph, granted.see.source, resolver);
  const postAgain = postApi.admitPost(graph, granted.post.source, resolver);
  assert.equal(seeAgain.ok && seeAgain.kept, false);
  assert.equal(postAgain.ok && postAgain.kept, false);
  assert.equal(checkSee(graph, chat.value, p2, now).allowed, false);
  assert.equal(checkPost(graph, chat.value, p2, now).allowed, false);
  const other = {};
  assert.equal(checkSee(other, chat.value, p2, now, granted.see).allowed, false);
  assert.equal(checkPost(other, chat.value, p2, now, granted.post).allowed, false);
});

test("the label plant setter is not on the published class", () => {
  assert.equal(MemoryGroupGraph.prototype.plantLabelOwnerForTest, undefined);
});

test("an alias label put keeps the signed owner spelling", () => {
  const graph = new MemoryGroupGraph();
  const resolver = { rotations: () => [], ctx: context() };
  assert.equal(putObject(graph, objectRecord(), resolver).ok, true);
  graph.putObject(chat.value, `s3rch/users/${p}`);
  graph.putObject(chat.value, p);
  assert.equal(graph.ownerOf(chat.value), p);
  const ownerKey = issuerFromSeed(ed25519Seed(p));
  const memberKey = issuerFromSeed(ed25519Seed(p2));
  const setKey = issuerFromSeed(ed25519Seed("alice"));
  graph.enrollSigner(p, ownerKey.publicKey);
  graph.enrollSigner(p2, memberKey.publicKey);
  graph.enrollSigner("alice", setKey.publicKey);
  graph.recordSetOwner("alice", "same-group", "alice/friends");
  graph.stateMembership(p2, "same-group", "alice/friends", p2, memberKey.privateKey);
  graph.stateMembership("alice", "same-group", "alice/friends", p2, setKey.privateKey);
  graph.nameObjectSet(p, chat.value, "same-group", "alice/friends", ownerKey.privateKey);
  const request = signRequest({
    requester: p2,
    object: chat.value,
    scope: "read",
    status: "pending",
    message: "",
    issuedAt: now,
  }, 2);
  const result = grantApprovedRequest(
    graph,
    p,
    request,
    { from: at, until: now + 100 },
    { predicate: "same-group", now },
    { scalar: secret(1), resolver },
  );
  assert.equal(result.granted, true);
  assert.equal(result.see.grant.hamState, 1);
});

test("no public path seals an unverified see or post row", () => {
  assert.equal(seeApi.snapshotRow, undefined);
  assert.equal(seeApi.restoreRow, undefined);
  assert.equal(postApi.snapshotPost, undefined);
  assert.equal(postApi.restorePost, undefined);
  assert.equal(seeApi.stageSee, undefined);
  assert.equal(seeApi.commitStagedSee, undefined);
  assert.equal(postApi.stagePost, undefined);
  assert.equal(postApi.commitStagedPost, undefined);
  assert.equal(isVerifiedRow({ mode: "present", grant: { stated: 1, from: 0, until: 1e12 } }), false);
  const graph = {};
  const resolver = { rotations: () => [], ctx: context() };
  assert.equal(putObject(graph, objectRecord(), resolver).ok, true);
  assert.equal(checkSee(graph, chat.value, p2, now).allowed, false);
  assert.equal(checkSee(graph, chat.value, p2, now).reason, "delegate");
});
