import assert from "node:assert/strict";
import { test } from "node:test";
import { p256 } from "@noble/curves/nist.js";
import * as ids from "../ids/src/index.js";
import { admitMembership, admitObjectSet, membershipAssentBytes, MemoryGroupGraph, objectSetBytes } from "../src/group.js";
import { admittedPost, checkPost, factorGrants } from "../src/post.js";
import * as postApi from "../src/post.js";
import { grantApprovedRequest } from "../src/request.js";
import { plantLabelOwnerForTest } from "../src/internal/label-test.js";
import { movePostRowForTest, moveSeeRowForTest, plantPlainPostForTest, plantPlainSeeForTest } from "../src/internal/row-test.js";
import { admitRow, admittedView, checkSee, isVerifiedRow, putObject } from "../src/see.js";
import * as seeApi from "../src/see.js";
import * as gunApi from "../src/gun.js";
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
const p3 = principal(3);
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
  plantLabelOwnerForTest(mallory, chat.value, p2);
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
  plantLabelOwnerForTest(owner, chat.value, p2);
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

test("an earlier grant cannot revive a cancel, and another graph stays closed", () => {
  assert.equal(seeApi.stageSee, undefined);
  assert.equal(seeApi.commitStagedSee, undefined);
  assert.equal(seeApi.prepareSee, undefined);
  assert.equal(seeApi.commitPreparedSee, undefined);
  assert.equal(seeApi.evaluateSee, undefined);
  assert.equal(seeApi.commitEvaluatedSee, undefined);
  assert.equal(postApi.stagePost, undefined);
  assert.equal(postApi.commitStagedPost, undefined);
  assert.equal(postApi.preparePost, undefined);
  assert.equal(postApi.commitPreparedPost, undefined);
  assert.equal(postApi.evaluatePost, undefined);
  assert.equal(postApi.commitEvaluatedPost, undefined);
  assert.equal(gunApi.prepareSee, undefined);
  assert.equal(gunApi.commitPreparedSee, undefined);
  assert.equal(gunApi.preparePost, undefined);
  assert.equal(gunApi.commitPreparedPost, undefined);
  assert.equal(gunApi.admitGrantPair, undefined);
  assert.equal(gunApi.admitResolvedPost, undefined);
  assert.equal(gunApi.postKeeps, undefined);
  assert.equal(gunApi.installPostGrant, undefined);
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

test("a see grant cannot revive a cancel on its own graph", () => {
  const graph = {};
  const resolver = { rotations: () => [], ctx: context() };
  assert.equal(putObject(graph, objectRecord(), resolver).ok, true);
  const live = signGrant(ids.seeGrantBytes, { hamState: 1 });
  assert.equal(admitRow(graph, live, resolver).ok, true);
  assert.equal(checkSee(graph, chat.value, p2, now).allowed, true);
  const cancel = admitRow(graph, signGrant(ids.seeGrantBytes, { stated: 0, hamState: 2 }), resolver);
  assert.equal(cancel.ok && cancel.kept, true);
  const again = admitRow(graph, live, resolver);
  assert.equal(again.ok && again.kept, false);
  assert.equal(checkSee(graph, chat.value, p2, now).allowed, false);
  assert.equal(admittedView(graph, chat.value, p2)?.stated, 0);
  assert.equal(admittedView(graph, chat.value, p2)?.hamState, 2);
});

test("a post grant cannot revive a cancel on its own graph", () => {
  const graph = {};
  const resolver = { rotations: () => [], ctx: context() };
  assert.equal(putObject(graph, objectRecord(), resolver).ok, true);
  assert.equal(admitRow(graph, signGrant(ids.seeGrantBytes, { hamState: 1 }), resolver).ok, true);
  const live = signGrant(ids.postGrantBytes, { hamState: 1 });
  assert.equal(postApi.admitPost(graph, live, resolver).ok, true);
  assert.equal(checkPost(graph, chat.value, p2, now).allowed, true);
  const cancel = postApi.admitPost(graph, signGrant(ids.postGrantBytes, { stated: 0, hamState: 2 }), resolver);
  assert.equal(cancel.ok && cancel.kept, true);
  const again = postApi.admitPost(graph, live, resolver);
  assert.equal(again.ok && again.kept, false);
  assert.equal(checkPost(graph, chat.value, p2, now).allowed, false);
  assert.equal(postApi.admittedPost(graph, chat.value, p2)?.stated, 0);
  assert.equal(postApi.admittedPost(graph, chat.value, p2)?.hamState, 2);
});

test("a grant verified on one graph cannot replace a cancel on another", () => {
  const resolver = { rotations: () => [], ctx: context() };
  const open = {};
  const closed = {};
  assert.equal(putObject(open, objectRecord(), resolver).ok, true);
  assert.equal(putObject(closed, objectRecord(), resolver).ok, true);
  const seeLive = signGrant(ids.seeGrantBytes, { hamState: 1 });
  const postLive = signGrant(ids.postGrantBytes, { hamState: 1 });
  assert.equal(admitRow(open, seeLive, resolver).ok, true);
  assert.equal(postApi.admitPost(open, postLive, resolver).ok, true);
  assert.equal(admitRow(closed, signGrant(ids.seeGrantBytes, { stated: 0, hamState: 2 }), resolver).kept, true);
  assert.equal(postApi.admitPost(closed, signGrant(ids.postGrantBytes, { stated: 0, hamState: 2 }), resolver).kept, true);
  const paired = seeApi.admitGrantPair(closed, seeLive, postLive, resolver);
  assert.equal(paired.ok, false);
  assert.equal(paired.reason, "not-kept");
  assert.equal(checkSee(closed, chat.value, p2, now).allowed, false);
  assert.equal(checkPost(closed, chat.value, p2, now).allowed, false);
  assert.equal(admittedView(closed, chat.value, p2)?.hamState, 2);
  assert.equal(postApi.admittedPost(closed, chat.value, p2)?.hamState, 2);
  assert.equal(checkSee(open, chat.value, p2, now).allowed, true);
  assert.equal(checkPost(open, chat.value, p2, now).allowed, true);
});

test("a caller cannot flip kept to write over a cancel", () => {
  const graph = {};
  const resolver = { rotations: () => [], ctx: context() };
  assert.equal(putObject(graph, objectRecord(), resolver).ok, true);
  const live = signGrant(ids.seeGrantBytes, { hamState: 1 });
  const postLive = signGrant(ids.postGrantBytes, { hamState: 1 });
  assert.equal(admitRow(graph, signGrant(ids.seeGrantBytes, { stated: 0, hamState: 2 }), resolver).kept, true);
  assert.equal(postApi.admitPost(graph, signGrant(ids.postGrantBytes, { stated: 0, hamState: 2 }), resolver).kept, true);
  const flipped = { ...live, kept: true, key: ids.grantSoul(p, chat.value, p3) };
  const again = admitRow(graph, flipped, resolver);
  assert.equal(again.ok && again.kept, false);
  const ticket = { kept: true, key: ids.grantSoul(p, chat.value, p2), sealed: live, used: false };
  const planted = seeApi.admitGrantPair(graph, ticket, { ...postLive, kept: true }, resolver);
  assert.equal(planted.ok, false);
  assert.equal(checkSee(graph, chat.value, p2, now).allowed, false);
  assert.equal(checkPost(graph, chat.value, p2, now).allowed, false);
  assert.equal(admittedView(graph, chat.value, p2)?.stated, 0);
  assert.equal(checkSee(graph, chat.value, p3, now).allowed, false);
});

test("a see row moved under another accessor does not allow", () => {
  const graph = {};
  const resolver = { rotations: () => [], ctx: context() };
  assert.equal(putObject(graph, objectRecord(), resolver).ok, true);
  assert.equal(admitRow(graph, signGrant(ids.seeGrantBytes, { hamState: 1 }), resolver).kept, true);
  const from = ids.grantSoul(p, chat.value, p2);
  const to = ids.grantSoul(p, chat.value, p3);
  assert.equal(moveSeeRowForTest(graph, from, to), true);
  assert.equal(checkSee(graph, chat.value, p2, now).allowed, false);
  assert.equal(checkSee(graph, chat.value, p3, now).allowed, false);
  assert.equal(admittedView(graph, chat.value, p2), undefined);
  assert.equal(admittedView(graph, chat.value, p3), undefined);
});

test("a post row moved under another accessor does not allow", () => {
  const graph = {};
  const resolver = { rotations: () => [], ctx: context() };
  assert.equal(putObject(graph, objectRecord(), resolver).ok, true);
  assert.equal(admitRow(graph, signGrant(ids.seeGrantBytes, { hamState: 1 }), resolver).kept, true);
  assert.equal(admitRow(graph, signGrant(ids.seeGrantBytes, { accessor: p3, hamState: 1 }), resolver).kept, true);
  assert.equal(postApi.admitPost(graph, signGrant(ids.postGrantBytes, { hamState: 1 }), resolver).kept, true);
  assert.equal(checkSee(graph, chat.value, p3, now).allowed, true);
  const from = ids.postSoul(p, chat.value, p2);
  const to = ids.postSoul(p, chat.value, p3);
  assert.equal(movePostRowForTest(graph, from, to), true);
  const moved = checkPost(graph, chat.value, p3, now);
  assert.equal(moved.allowed, false);
  assert.equal(moved.reason, "missing");
  assert.equal(checkPost(graph, chat.value, p2, now).allowed, false);
  assert.equal(postApi.admittedPost(graph, chat.value, p3), undefined);
  assert.equal(checkSee(graph, chat.value, p3, now).allowed, true);
});

test("a plain see object stored under the soul key does not allow", () => {
  const graph = {};
  const resolver = { rotations: () => [], ctx: context() };
  assert.equal(putObject(graph, objectRecord(), resolver).ok, true);
  plantPlainSeeForTest(graph, ids.grantSoul(p, chat.value, p2), {
    owner: p,
    object: chat.value,
    accessor: p2,
    stated: 1,
    from: at,
    until: now + 100,
    hamState: 1,
    issuedAt: now,
    sig: "",
  });
  const see = checkSee(graph, chat.value, p2, now);
  assert.equal(see.allowed, false);
  assert.equal(see.reason, "delegate");
  assert.equal(admittedView(graph, chat.value, p2), undefined);
});

test("a plain post object stored under the soul key does not allow", () => {
  const graph = {};
  const resolver = { rotations: () => [], ctx: context() };
  assert.equal(putObject(graph, objectRecord(), resolver).ok, true);
  assert.equal(admitRow(graph, signGrant(ids.seeGrantBytes, { hamState: 1 }), resolver).kept, true);
  plantPlainPostForTest(graph, ids.postSoul(p, chat.value, p2), {
    owner: p,
    object: chat.value,
    accessor: p2,
    stated: 1,
    from: at,
    until: now + 100,
    hamState: 1,
    issuedAt: now,
    sig: "",
  });
  const post = checkPost(graph, chat.value, p2, now);
  assert.equal(post.allowed, false);
  assert.equal(post.reason, "missing");
  assert.equal(postApi.admittedPost(graph, chat.value, p2), undefined);
  assert.equal(checkSee(graph, chat.value, p2, now).allowed, true);
});

test("one row that would not replace writes neither grant", () => {
  const resolver = { rotations: () => [], ctx: context() };
  const graph = {};
  assert.equal(putObject(graph, objectRecord(), resolver).ok, true);
  assert.equal(postApi.admitPost(graph, signGrant(ids.postGrantBytes, { stated: 0, hamState: 2 }), resolver).kept, true);
  const paired = seeApi.admitGrantPair(
    graph,
    signGrant(ids.seeGrantBytes, { hamState: 1 }),
    signGrant(ids.postGrantBytes, { hamState: 1 }),
    resolver,
  );
  assert.equal(paired.ok, false);
  assert.equal(paired.reason, "not-kept");
  assert.equal(admittedView(graph, chat.value, p2), undefined);
  assert.equal(checkSee(graph, chat.value, p2, now).allowed, false);
  assert.equal(postApi.admittedPost(graph, chat.value, p2)?.stated, 0);
  assert.equal(postApi.admittedPost(graph, chat.value, p2)?.hamState, 2);
});

test("postKeeps does not write and a presented row is not a ticket", () => {
  const resolver = { rotations: () => [], ctx: context() };
  const graph = {};
  const other = {};
  assert.equal(putObject(graph, objectRecord(), resolver).ok, true);
  assert.equal(putObject(other, objectRecord(), resolver).ok, true);
  const see = admitRow(graph, signGrant(ids.seeGrantBytes, { hamState: 1 }), resolver);
  assert.equal(see.ok, true);
  const live = signGrant(ids.postGrantBytes, { hamState: 1 });
  const seen = postApi.postKeeps(graph, live, resolver);
  assert.equal(seen.ok && seen.kept, true);
  assert.equal(postApi.admittedPost(graph, chat.value, p2), undefined);
  const wrote = postApi.admitResolvedPost(graph, { ...live, kept: true, key: ids.postSoul(p, chat.value, p3) }, resolver);
  assert.equal(wrote.ok && wrote.kept, true);
  assert.equal(checkPost(graph, chat.value, p2, now).allowed, true);
  assert.equal(checkPost(graph, chat.value, p3, now).allowed, false);
  assert.equal(isVerifiedRow(see.value), false);
  assert.equal(seeApi.admitGrantPair(other, see.value, wrote.value, resolver).ok, false);
  assert.equal(checkSee(other, chat.value, p2, now).allowed, false);
  assert.equal(checkPost(other, chat.value, p2, now).allowed, false);
  assert.equal(postApi.admitPost(other, signGrant(ids.postGrantBytes, { stated: 0, hamState: 4 }), resolver).kept, true);
  const replay = postApi.admitResolvedPost(other, live, resolver);
  assert.equal(replay.ok && replay.kept, false);
  assert.equal(postApi.admittedPost(other, chat.value, p2)?.hamState, 4);
});

test("the label plant setter is not on the published class", () => {
  assert.equal(MemoryGroupGraph.prototype.plantLabelOwnerForTest, undefined);
});

test("an alias label put keeps the signed owner spelling", () => {
  const graph = new MemoryGroupGraph();
  const resolver = { rotations: () => [], ctx: context() };
  assert.equal(putObject(graph, objectRecord(), resolver).ok, true);
  plantLabelOwnerForTest(graph, chat.value, `s3rch/users/${p}`);
  plantLabelOwnerForTest(graph, chat.value, p);
  assert.equal(graph.ownerOf(chat.value), p);
  const friends = ids.mintObjectId("set", p, () => new Uint8Array(16).fill(0x33));
  if (!friends.ok) throw new Error(friends.reason);
  const assent = (role, signer) => {
    const row = { role, predicate: "same-group", set: friends.value, member: p2, setOwner: p, stated: 1, hamState: 1, issuedAt: now, cancels: [] };
    const sig = ids.signWithKeyring(secret(signer), membershipAssentBytes(row), principal(signer));
    if (!sig.ok) throw new Error(sig.reason);
    return { ...row, sig: sig.value };
  };
  const edge = { owner: p, object: chat.value, predicate: "same-group", set: friends.value, stated: 1, hamState: 1, issuedAt: now, cancels: [] };
  const edgeSig = ids.signWithKeyring(secret(1), objectSetBytes(edge), p);
  if (!edgeSig.ok) throw new Error(edgeSig.reason);
  assert.equal(admitMembership(graph, assent("member", 2), resolver).ok, true);
  assert.equal(admitMembership(graph, assent("set", 1), resolver).ok, true);
  assert.equal(admitObjectSet(graph, { ...edge, sig: edgeSig.value }, resolver).ok, true);
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

test("a bare history array is missing-history and writes nothing", () => {
  const graph = {};
  const resolver = { rotations: () => [], ctx: context() };
  assert.equal(putObject(graph, objectRecord(), resolver).ok, true);
  const see = signGrant(ids.seeGrantBytes, { hamState: 1 });
  const post = signGrant(ids.postGrantBytes, { hamState: 1 });
  for (const got of [
    seeApi.admitGrantPair(graph, see, post, []),
    postApi.postKeeps(graph, post, []),
    postApi.admitResolvedPost(graph, post, []),
  ]) {
    assert.equal(got.ok, false);
    assert.equal(got.reason, "missing-history");
  }
  assert.equal(admittedView(graph, chat.value, p2), undefined);
  assert.equal(admittedPost(graph, chat.value, p2), undefined);
  assert.equal(checkSee(graph, chat.value, p2, now).allowed, false);
  assert.equal(checkPost(graph, chat.value, p2, now).allowed, false);
});

test("reverify drops the group label with the owner", () => {
  const graph = new MemoryGroupGraph();
  const resolver = { rotations: () => [], ctx: context() };
  assert.equal(putObject(graph, objectRecord(), resolver).ok, true);
  assert.equal(graph.ownerOf(chat.value), p);
  const dropped = seeApi.reverifyPrincipal(graph, p, { rotations: () => undefined, ctx: context() });
  assert.equal(dropped.ok, false);
  assert.equal(dropped.reason, "missing-history");
  assert.equal(graph.ownerOf(chat.value), undefined);
  assert.equal(seeApi.admittedOwner(graph, chat.value), undefined);
  assert.equal(checkSee(graph, chat.value, p2, now).reason, "unknown");
});

function throwingContext(failAt) {
  const base = context();
  let reads = 0;
  return new Proxy(base, {
    get(target, prop, receiver) {
      reads += 1;
      if (reads === failAt) throw new Error("injected");
      return Reflect.get(target, prop, receiver);
    },
  });
}

test("a throw while reading the resolver context writes neither grant", () => {
  const request = signRequest({
    requester: p2,
    object: chat.value,
    scope: "read+post",
    status: "pending",
    message: "",
    issuedAt: now,
  }, 2);
  const window = { from: at, until: now + 100 };
  const see = signGrant(ids.seeGrantBytes, { hamState: 1 });
  const post = signGrant(ids.postGrantBytes, { hamState: 1 });
  for (const failAt of [1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 16, 24, 10000]) {
    const graph = {};
    assert.equal(putObject(graph, objectRecord(), { rotations: () => [], ctx: context() }).ok, true);
    const resolver = { rotations: () => [], ctx: throwingContext(failAt) };
    let thrown = null;
    let result;
    try {
      result = grantApprovedRequest(graph, p, request, window, null, { scalar: secret(1), resolver });
    } catch (error) {
      thrown = error;
    }
    const seeRow = admittedView(graph, chat.value, p2);
    const postRow = admittedPost(graph, chat.value, p2);
    if (thrown) {
      assert.equal(thrown instanceof Error ? thrown.message : "", "injected");
      assert.equal(seeRow, undefined);
      assert.equal(postRow, undefined);
    } else {
      assert.equal(result.granted, true);
      assert.equal(checkSee(graph, chat.value, p2, now).allowed, true);
      assert.equal(checkPost(graph, chat.value, p2, now).allowed, true);
    }
    assert.equal(Boolean(seeRow), Boolean(postRow));
    const direct = {};
    assert.equal(putObject(direct, objectRecord(), { rotations: () => [], ctx: context() }).ok, true);
    let directThrown = null;
    let paired;
    try {
      paired = seeApi.admitGrantPair(direct, see, post, { rotations: () => [], ctx: throwingContext(failAt) });
    } catch (error) {
      directThrown = error;
    }
    const directSee = admittedView(direct, chat.value, p2);
    const directPost = admittedPost(direct, chat.value, p2);
    if (directThrown) {
      assert.equal(directThrown instanceof Error ? directThrown.message : "", "injected");
      assert.equal(directSee, undefined);
      assert.equal(directPost, undefined);
    } else {
      assert.equal(paired.ok, true);
      assert.equal(checkSee(direct, chat.value, p2, now).allowed, true);
      assert.equal(checkPost(direct, chat.value, p2, now).allowed, true);
    }
    assert.equal(Boolean(directSee), Boolean(directPost));
  }
});
