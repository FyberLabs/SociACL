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
  grantApprovedRequest,
  issuerFromSeed,
  postGrantSigningBytes,
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
  if (canonicalAccessorId(owner) === canonicalAccessorId(accessor)) {
    return { allowed: true, reason: "owner" };
  }
  const live = graph.seeGrants(object).some((grant) => {
    return (
      canonicalAccessorId(grant.accessor) === canonicalAccessorId(accessor) &&
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

function approve(graph, row) {
  const members =
    row.mode === "members"
      ? { predicate: row.queryPredicate ?? row.predicate, now: row.now }
      : undefined;
  try {
    return grantApprovedRequest(graph, row.caller ?? row.owner, requestOf(row), { from: row.from, until: row.until }, members);
  } catch (err) {
    if (err instanceof Error && err.message === "access request field is not canonical") {
      return { granted: false, reason: "field" };
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
