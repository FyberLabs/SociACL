import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { createHash } from "node:crypto";
import {
  ACCESS_MESSAGE_MAX,
  ACCESS_REQUEST_DOMAIN,
  ACCESS_REQUEST_ID_DOMAIN,
  ACCESS_SCOPE_READ,
  ACCESS_SCOPE_READ_POST,
  ACCESS_STATUS_PENDING,
  ACCESS_STATUS_WITHDRAWN,
  MemoryGroupGraph,
  acceptAccessRequest,
  accessRequestId,
  accessRequestSigningBytes,
  canonicalRequestAccessor,
  checkPost,
  factorGrants,
  aclKey,
  grantApprovedRequest,
  issuerFromSeed,
  postGrantSigningBytes,
  requestIssuerFromSeed,
  signAccessRequest,
} from "../src/group.js";
import { canonicalAccessorId } from "../src/post.js";
import { checkSee } from "../src/gun.js";

const fixture = JSON.parse(
  readFileSync(new URL("../../vectors/mesh/access-request.json", import.meta.url), "utf8"),
);

function hex(bytes) {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function messageOf(row) {
  if (row.messageRepeat != null) return String(row.messageUnit ?? "").repeat(row.messageRepeat);
  return row.message ?? "";
}

function requestOf(row) {
  return {
    requester: row.requester,
    source: row.source,
    scope: row.scope,
    message: messageOf(row),
    status: row.status,
  };
}

function signer(name) {
  return issuerFromSeed(createHash("sha256").update("sociacl-test-signer-v1").update(name).digest());
}

function seeResult(graph, object, accessor, now) {
  const owner = graph.ownerOf(object);
  if (!owner) return { allowed: false, reason: "missing" };
  const ownerKey = canonicalAccessorId(owner);
  const accessorKey = canonicalAccessorId(accessor);
  if (ownerKey != null && ownerKey === accessorKey) {
    return { allowed: true, reason: "owner" };
  }
  const live = graph.seeGrants(object).some((grant) => {
    return (
      canonicalAccessorId(grant.accessor) != null &&
      canonicalAccessorId(grant.accessor) === accessorKey &&
      grant.stated !== 0 &&
      now >= grant.from &&
      now < grant.until
    );
  });
  return live ? { allowed: true, reason: "delegate" } : { allowed: false, reason: "missing" };
}

function prepare(graph, row) {
  if (!row.object) return;
  graph.putObject(row.object, row.owner);
  if (row.mode !== "members") return;
  const predicate = row.predicate;
  const setId = row.setId;
  const alice = signer("0xalice");
  const bob = signer("0xbob");
  graph.enrollSigner("0xalice", alice.publicKey);
  graph.enrollSigner("0xbob", bob.publicKey);
  graph.recordSetOwner(row.owner, predicate, setId);
  graph.nameObjectSet(row.owner, row.object, predicate, setId, alice.privateKey);
  if (row.member) {
    graph.stateMembership("0xbob", predicate, setId, "0xbob", bob.privateKey);
    graph.stateMembership(row.owner, predicate, setId, "0xbob", alice.privateKey);
  }
  if (row.cancelled) {
    graph.cancelMembership(row.owner, predicate, setId, "0xbob", alice.privateKey);
  }
}

function attachSignature(graph, row, request) {
  const mode = row.signature ?? "ok";
  if (mode === "missing") return request;
  const bob = signer("0xbob");
  if (mode !== "unenrolled") graph.enrollSigner("0xbob", bob.publicKey);
  let signature;
  try {
    signature = signAccessRequest(bob.privateKey, request);
  } catch (err) {
    if (err instanceof Error && err.message === "access request field is not canonical") return request;
    throw err;
  }
  if (mode === "bad") signature[0] ^= 0xff;
  return { ...request, signature };
}

function approve(graph, row) {
  const members =
    row.mode === "members"
      ? { predicate: row.queryPredicate ?? row.predicate, now: row.now }
      : undefined;
  const request = attachSignature(graph, row, requestOf(row));
  try {
    return grantApprovedRequest(graph, row.caller ?? row.owner, request, { from: row.from, until: row.until }, members);
  } catch (err) {
    if (err instanceof Error && err.message === "access request field is not canonical") {
      return { granted: false, reason: "field" };
    }
    if (err instanceof Error && err.message === "see grant cannot advance") {
      return { granted: false, reason: "see" };
    }
    throw err;
  }
}

function assertNoRows(graph, row) {
  assert.equal(graph.seeGrant(row.object, row.requester), undefined, row.name);
  assert.equal(graph.postGrant(row.object, row.requester), undefined, row.name);
}

function assertGranted(graph, row, result, ham) {
  assert.equal(result.granted, true, row.name);
  const accessor = canonicalRequestAccessor(row.requester);
  assert.equal(result.requestId, accessRequestId(row.requester, row.source));
  assert.equal(result.see.grant.object, row.object);
  assert.equal(result.see.grant.accessor, accessor);
  assert.equal(result.see.grant.stated, 1);
  assert.equal(result.see.hamState, ham);
  assert.equal(result.see.owner, row.owner);
  assert.equal(
    result.see.soul,
    `s3rch/acl/${canonicalRequestAccessor(row.owner)}/${aclKey(row.object)}/${accessor}`,
  );
  const see = seeResult(graph, row.source, row.requester, row.now);
  assert.equal(see.allowed, true, row.name);
  assert.equal(see.reason, "delegate");
  const post = checkPost(graph, row.source, row.requester, row.now);
  if (row.expect === "both") {
    assert.ok(result.post, row.name);
    assert.equal(result.post.grant.object, row.object);
    assert.equal(result.post.grant.accessor, accessor);
    assert.equal(result.post.hamState, ham);
    assert.equal(hex(result.postSigningBytes), hex(postGrantSigningBytes(result.post)));
    assert.equal(post.allowed, true, row.name);
    assert.equal(post.reason, "post");
  } else {
    assert.equal(result.post, null, row.name);
    assert.equal(result.postSigningBytes, null, row.name);
    assert.equal(post.allowed, false, row.name);
    assert.equal(post.reason, "missing");
    assert.equal(graph.postGrant(row.object, accessor), undefined);
  }
  const bySource = graph.seeGrant(row.source, row.requester);
  const byObject = graph.seeGrant(row.object, accessor);
  assert.equal(bySource.soul, byObject.soul, row.name);
}

test("vectors name the request encoding", () => {
  assert.equal(fixture.domain, ACCESS_REQUEST_DOMAIN);
  assert.equal(fixture.idDomain, ACCESS_REQUEST_ID_DOMAIN);
  assert.deepEqual(fixture.scopes, [ACCESS_SCOPE_READ, ACCESS_SCOPE_READ_POST]);
  assert.deepEqual(fixture.statuses, [ACCESS_STATUS_PENDING, ACCESS_STATUS_WITHDRAWN]);
  assert.equal(fixture.messageMax, ACCESS_MESSAGE_MAX);
  assert.deepEqual(fixture.factors, ["hop", "hint", "wrap", "inbox", "request"]);
  for (const factor of fixture.factors) assert.equal(factorGrants(factor), false, factor);
});

test("shared ids have no spelling variant", () => {
  for (const row of fixture.ids) {
    const id = accessRequestId(row.requester, row.source);
    assert.equal(id.length, 64, row.name);
    assert.equal(id, row.id, row.name);
  }
});

test("shared signing bytes match", () => {
  for (const row of fixture.signing) {
    const request = requestOf(row);
    const bytes = accessRequestSigningBytes(request);
    const accepted = acceptAccessRequest(request);
    assert.equal(hex(accepted.signingBytes), hex(bytes), row.name);
    if (row.id) assert.equal(accepted.id, row.id, row.name);
    if (row.hex) assert.equal(hex(bytes), row.hex, row.name);
    assert.equal(accepted.id.length, 64);
  }
});

test("rejected spellings do not encode", () => {
  for (const row of fixture.rejected) {
    assert.throws(() => accessRequestSigningBytes(requestOf(row)), /access request field is not canonical/, row.name);
    assert.throws(() => acceptAccessRequest(requestOf(row)), /access request field is not canonical/, row.name);
  }
});

test("user soul segments and a non-http uri share one id", () => {
  const bob = accessRequestId("bob", "room:alpha");
  assert.equal(accessRequestId("s3rch/users/ bob ", "room:alpha"), bob);
  assert.equal(accessRequestId("s3rch/users//bob", "room:alpha"), bob);
  const ipfs = accessRequestId("0xbob", "ipfs://cid");
  assert.equal(ipfs.length, 64);
  assert.notEqual(ipfs, accessRequestId("0xbob", "room:alpha"));
  assert.throws(
    () => accessRequestId("0xbob", "https://gi.rss3.io/decentralized/0xalice"),
    /access request field is not canonical/,
  );
});

test("a surrogate pair is one scalar and an unpaired surrogate is rejected", () => {
  const pair = accessRequestSigningBytes({
    requester: "0xbob",
    source: "room:alpha",
    scope: "read",
    message: "hi\u{1F600}!",
    status: "pending",
  });
  assert.ok(pair.length > 0);
  for (const message of ["\ud800", "\udc00", "\ud83d\ud83d", "\udc00\ud83d", "a\ud800"]) {
    assert.throws(
      () =>
        accessRequestSigningBytes({
          requester: "0xbob",
          source: "room:alpha",
          scope: "read",
          message,
          status: "pending",
        }),
      /access request field is not canonical/,
      message,
    );
  }
});

test("a slash id does not share a request with the underscore item soul", () => {
  const slash = accessRequestId("0xbob", "a/b");
  const flat = accessRequestId("0xbob", "a_b");
  const soul = accessRequestId("0xbob", "s3rch/items/a_b");
  const dotted = accessRequestId("0xbob", "room.alpha");
  const under = accessRequestId("0xbob", "room_alpha");
  const underSoul = accessRequestId("0xbob", "s3rch/items/room_alpha");
  assert.notEqual(slash, flat);
  assert.equal(flat, soul);
  assert.notEqual(slash, soul);
  assert.equal(under, underSoul);
  assert.notEqual(under, dotted);
  const graph = new MemoryGroupGraph();
  graph.putObject("a/b", "0xalice");
  graph.putObject("s3rch/items/a_b", "0xalice");
  const bob = signer("0xbob");
  graph.enrollSigner("0xbob", bob.publicKey);
  const signed = {
    requester: "0xbob",
    source: "a/b",
    scope: "read",
    message: "",
    status: "pending",
  };
  signed.signature = signAccessRequest(bob.privateKey, signed);
  const swapped = { ...signed, source: "s3rch/items/a_b" };
  const denied = grantApprovedRequest(graph, "0xalice", swapped, { from: 0, until: 80 }, null);
  assert.equal(denied.granted, false);
  assert.equal(denied.reason, "signature");
  assert.equal(graph.seeGrant("a/b", "0xbob"), undefined);
  assert.equal(graph.seeGrant("s3rch/items/a_b", "0xbob"), undefined);
  const granted = grantApprovedRequest(graph, "0xalice", signed, { from: 0, until: 80 }, null);
  assert.equal(granted.granted, true);
  assert.ok(graph.seeGrant("a/b", "0xbob"));
  assert.equal(graph.seeGrant("s3rch/items/a_b", "0xbob"), undefined);
});

test("an unpaired surrogate in the requester or source is rejected", () => {
  const graph = new MemoryGroupGraph();
  graph.putObject("room\uFFFD", "0xalice");
  graph.putObject("room\ud800", "0xalice");
  const bob = signer("0xbob");
  graph.enrollSigner("0xbob", bob.publicKey);
  const signed = {
    requester: "0xbob",
    source: "room\uFFFD",
    scope: "read",
    message: "",
    status: "pending",
  };
  signed.signature = signAccessRequest(bob.privateKey, signed);
  assert.notEqual(accessRequestId("0xbob", "room\uFFFD"), "");
  for (const request of [
    { ...signed, source: "room\ud800" },
    { ...signed, requester: "\ud800" },
    { ...signed, requester: "s3rch/users/\ud800" },
  ]) {
    assert.throws(
      () => grantApprovedRequest(graph, "0xalice", request, { from: 0, until: 80 }, null),
      /access request field is not canonical/,
    );
  }
  assert.equal(graph.seeGrant("room\uFFFD", "0xbob"), undefined);
  assert.equal(graph.seeGrant("room\ud800", "0xbob"), undefined);
});

test("a spaced item soul does not authorize the trimmed object", () => {
  const spaced = accessRequestId("0xbob", "s3rch/items/ foo");
  const raw = accessRequestId("0xbob", "foo");
  assert.notEqual(spaced, raw);
  const graph = new MemoryGroupGraph();
  graph.putObject("foo", "0xalice");
  graph.putObject("s3rch/items/ foo", "0xalice");
  const bob = signer("0xbob");
  graph.enrollSigner("0xbob", bob.publicKey);
  const signed = {
    requester: "0xbob",
    source: "foo",
    scope: "read",
    message: "",
    status: "pending",
  };
  const signature = signAccessRequest(bob.privateKey, signed);
  const swapped = grantApprovedRequest(
    graph,
    "0xalice",
    { ...signed, source: "s3rch/items/ foo", signature },
    { from: 0, until: 80 },
  );
  assert.equal(swapped.granted, false);
  assert.equal(swapped.reason, "signature");
  assert.equal(graph.seeGrant("foo", "0xbob"), undefined);
  assert.equal(graph.seeGrant("s3rch/items/ foo", "0xbob"), undefined);
});

test("approval keeps the source captured before verification", () => {
  const graph = new MemoryGroupGraph();
  graph.putObject("doc-a", "0xalice");
  graph.putObject("doc-b", "0xalice");
  const bob = signer("0xbob");
  graph.enrollSigner("0xbob", bob.publicKey);
  const plain = {
    requester: "0xbob",
    source: "doc-a",
    scope: "read",
    message: "",
    status: "pending",
  };
  const signature = signAccessRequest(bob.privateKey, plain);
  let sourceReads = 0;
  const request = {
    get requester() {
      return "0xbob";
    },
    get source() {
      sourceReads += 1;
      return sourceReads === 1 ? "doc-a" : "doc-b";
    },
    get scope() {
      return "read";
    },
    get message() {
      return "";
    },
    get status() {
      return "pending";
    },
    get signature() {
      return signature;
    },
  };
  const result = grantApprovedRequest(graph, "0xalice", request, { from: 0, until: 80 });
  assert.equal(result.granted, true);
  assert.equal(result.see.grant.object, "doc-a");
  assert.equal(graph.seeGrant("doc-b", "0xbob"), undefined);
});

test("a cancelled see at the ham ceiling does not grow a post", () => {
  const graph = new MemoryGroupGraph();
  graph.putObject("room:alpha", "0xalice");
  const bob = signer("0xbob");
  graph.enrollSigner("0xbob", bob.publicKey);
  graph.grants.set("0xalice\0room:alpha\0bob", {
    object: "room:alpha",
    accessor: "0xbob",
    from: 0,
    until: 80,
    stated: 0,
    hamState: Number.MAX_VALUE,
    owner: "0xalice",
  });
  const request = {
    requester: "0xbob",
    source: "room:alpha",
    scope: "read+post",
    message: "",
    status: "pending",
    signature: signAccessRequest(bob.privateKey, {
      requester: "0xbob",
      source: "room:alpha",
      scope: "read+post",
      message: "",
      status: "pending",
    }),
  };
  assert.throws(
    () => grantApprovedRequest(graph, "0xalice", request, { from: 0, until: 80 }),
    /see grant cannot advance/,
  );
  assert.equal(graph.postGrant("room:alpha", "0xbob"), undefined);
  assert.equal(graph.seeGrant("room:alpha", "0xbob").grant.stated, 0);
});

test("a see row at the safe integer ceiling does not grow a post", () => {
  const graph = new MemoryGroupGraph();
  graph.putObject("room:alpha", "0xalice");
  const bob = signer("0xbob");
  graph.enrollSigner("0xbob", bob.publicKey);
  graph.grants.set(`0xalice\0room:alpha\0${"0xbob"}`, {
    object: "room:alpha",
    accessor: "0xbob",
    from: 0,
    until: 80,
    stated: 1,
    hamState: Number.MAX_SAFE_INTEGER,
    owner: "0xalice",
  });
  const request = {
    requester: "0xbob",
    source: "room:alpha",
    scope: "read+post",
    message: "",
    status: "pending",
    signature: signAccessRequest(bob.privateKey, {
      requester: "0xbob",
      source: "room:alpha",
      scope: "read+post",
      message: "",
      status: "pending",
    }),
  };
  assert.throws(
    () => grantApprovedRequest(graph, "0xalice", request, { from: 0, until: 80 }),
    /see grant cannot advance/,
  );
  assert.equal(graph.postGrant("room:alpha", "0xbob"), undefined);
  const see = graph.seeGrant("room:alpha", "0xbob");
  assert.equal(see.grant.stated, 1);
  assert.equal(see.hamState, Number.MAX_SAFE_INTEGER);
});

test("requester signature matches the enrolled key", () => {
  for (const row of fixture.signatures) {
    const seed = Uint8Array.from(row.seed.match(/../g).map((byte) => Number.parseInt(byte, 16)));
    const issuer = requestIssuerFromSeed(seed);
    assert.equal(hex(issuer.publicKey), row.publicKey, row.name);
    const request = {
      requester: row.requester,
      source: row.source,
      scope: row.scope,
      message: row.message,
      status: row.status,
    };
    const signature = signAccessRequest(issuer.privateKey, request);
    assert.equal(hex(signature), row.signature, row.name);
    const graph = new MemoryGroupGraph();
    graph.putObject(row.source, "0xalice");
    graph.enrollSigner(row.requester, issuer.publicKey);
    const granted = grantApprovedRequest(graph, "0xalice", { ...request, signature }, { from: 0, until: 80 });
    assert.equal(granted.granted, true, row.name);
    const bad = new Uint8Array(signature);
    bad[0] ^= 0xff;
    const fresh = new MemoryGroupGraph();
    fresh.putObject(row.source, "0xalice");
    fresh.enrollSigner(row.requester, issuer.publicKey);
    const denied = grantApprovedRequest(fresh, "0xalice", { ...request, signature: bad }, { from: 0, until: 80 });
    assert.equal(denied.granted, false, row.name);
    assert.equal(denied.reason, "signature");
    const unsigned = grantApprovedRequest(fresh, "0xalice", request, { from: 0, until: 80 });
    assert.equal(unsigned.reason, "signature");
    assert.equal(fresh.seeGrant(row.source, row.requester), undefined);
    assert.equal(fresh.postGrant(row.source, row.requester), undefined);
  }
});

test("owner client writes rows and a request does not", () => {
  for (const row of fixture.approvals) {
    const graph = new MemoryGroupGraph();
    prepare(graph, row);
    if (row.expect === "accept") {
      const accepted = acceptAccessRequest(requestOf(row));
      assert.equal(accepted.id.length, 64);
      const see = checkSee(
        graph,
        row.source,
        row.requester,
        row.now,
        row.hint ? { principal: row.requester } : undefined,
        row.hop ? { channel: "convention-badge" } : undefined,
      );
      assert.equal(see.allowed, false, row.name);
      for (const factor of fixture.factors) assert.equal(factorGrants(factor), false);
      assertNoRows(graph, row);
      continue;
    }
    const first = approve(graph, row);
    if (row.expect === "see" || row.expect === "both") {
      assertGranted(graph, row, first, 1);
      if (row.repeat) assertGranted(graph, row, approve(graph, row), 2);
    } else {
      assert.equal(first.granted, false, row.name);
      assert.equal(first.reason, row.expect, row.name);
      assertNoRows(graph, row);
    }
  }
});

test("an encoded item soul shares the raw object's request id", () => {
  const raw = accessRequestId("0xbob", "room.alpha");
  const soul = accessRequestId("0xbob", "s3rch/items/room~1alpha");
  assert.equal(soul, raw);
  assert.notEqual(aclKey(aclKey("room.alpha")), aclKey("room.alpha"));
});

test("a dotted principal round-trips through enroll and approval", () => {
  const graph = new MemoryGroupGraph();
  graph.putObject("room:alpha", "0xalice");
  const bob = signer("bob.name");
  graph.enrollSigner("bob.name", bob.publicKey);
  const canonical = canonicalRequestAccessor("bob.name");
  assert.equal(canonical, "bob.name");
  assert.ok(graph.enrolledKey(canonical));
  const request = {
    requester: "bob.name",
    source: "room:alpha",
    scope: "read",
    message: "",
    status: "pending",
  };
  assert.equal(accessRequestId(canonical, request.source), accessRequestId(request.requester, request.source));
  request.signature = signAccessRequest(bob.privateKey, request);
  const granted = grantApprovedRequest(graph, "0xalice", request, { from: 0, until: 80 });
  assert.equal(granted.granted, true);
  assert.equal(granted.see.grant.accessor, "bob.name");
  assert.equal(graph.seeGrant("room:alpha", "bob.name").grant.stated, 1);
  assert.equal(graph.seeGrant("room:alpha", canonical).grant.stated, 1);
});

test("a gun chain does not canonicalize to the inner wallet", () => {
  const spoof = "0xattacker.get('s3rch').get('users').get('0xvictim')";
  assert.notEqual(canonicalAccessorId(spoof), "0xvictim");
  assert.throws(() => canonicalRequestAccessor(spoof), /access request field is not canonical/);
});

test("a stateful toString source is rejected before any grant", () => {
  const graph = new MemoryGroupGraph();
  graph.putObject("doc-a", "0xalice");
  graph.putObject("doc-b", "0xalice");
  let calls = 0;
  const source = {
    toString() {
      calls += 1;
      return calls < 3 ? "doc-a" : "doc-b";
    },
  };
  const bob = signer("0xbob");
  graph.enrollSigner("0xbob", bob.publicKey);
  assert.throws(
    () =>
      grantApprovedRequest(
        graph,
        "0xalice",
        { requester: "0xbob", source, scope: "read", message: "", status: "pending" },
        { from: 0, until: 80 },
      ),
    /access request field is not canonical/,
  );
  assert.equal(graph.seeGrant("doc-a", "0xbob"), undefined);
  assert.equal(graph.seeGrant("doc-b", "0xbob"), undefined);
});

test("folded see rows at the ham ceiling do not grow a post", () => {
  const graph = new MemoryGroupGraph();
  const row = (object, hamState) => ({
    object,
    accessor: "0xbob",
    from: 0,
    until: 80,
    stated: 1,
    hamState,
    owner: "0xalice",
  });
  graph.grants.set("low", row("room", 1));
  graph.grants.set("high", row("s3rch/items/room", Number.MAX_SAFE_INTEGER));
  graph.putObject("room", "0xalice");
  const bob = signer("0xbob");
  graph.enrollSigner("0xbob", bob.publicKey);
  const request = {
    requester: "0xbob",
    source: "room",
    scope: "read+post",
    message: "",
    status: "pending",
    signature: undefined,
  };
  request.signature = signAccessRequest(bob.privateKey, request);
  assert.throws(
    () => grantApprovedRequest(graph, "0xalice", request, { from: 0, until: 80 }),
    /see grant cannot advance/,
  );
  assert.equal(graph.postGrant("room", "0xbob"), undefined);
  assert.equal(graph.seeGrant("room", "0xbob").hamState, Number.MAX_SAFE_INTEGER);
});

test("members auto-approve uses the stored object id", () => {
  const graph = new MemoryGroupGraph();
  graph.putObject("room", "0xalice");
  const alice = signer("0xalice");
  const bob = signer("0xbob");
  graph.enrollSigner("0xalice", alice.publicKey);
  graph.enrollSigner("0xbob", bob.publicKey);
  graph.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  graph.nameObjectSet("0xalice", "room", "same-group", "0xalice/ops", alice.privateKey);
  graph.stateMembership("0xbob", "same-group", "0xalice/ops", "0xbob", bob.privateKey);
  graph.stateMembership("0xalice", "same-group", "0xalice/ops", "0xbob", alice.privateKey);
  const request = {
    requester: "0xbob",
    source: "s3rch/items/room",
    scope: "read",
    message: "",
    status: "pending",
  };
  request.signature = signAccessRequest(bob.privateKey, request);
  const granted = grantApprovedRequest(
    graph,
    "0xalice",
    request,
    { from: 0, until: 80 },
    { predicate: "same-group", now: 10 },
  );
  assert.equal(granted.granted, true);
  assert.equal(granted.see.grant.object, "room");
});
