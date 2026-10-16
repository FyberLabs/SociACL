import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { createHash } from "node:crypto";
import {
  MemoryGroupGraph,
  checkGroupSee,
  issuerFromSeed,
  postGrantSigningBytes,
  postSoul,
  checkPost,
  factorGrants,
  POST_GRANT_DOMAIN,
  POST_GRANT_SCOPE,
} from "../src/group.js";
import { postRowEncodable, preferPost } from "../src/post.js";
import {
  MemorySeeAcl,
  applyPostGrant,
  applySeeGrant,
  cancelPost,
  checkPost as gunCheckPost,
  factorGrants as gunFactorGrants,
  postGrantSigningBytes as gunSigningBytes,
  postSoul as gunPostSoul,
} from "../src/gun.js";

const fixture = JSON.parse(
  readFileSync(new URL("../../vectors/mesh/post-grant.json", import.meta.url), "utf8"),
);

function hex(bytes) {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function edgeFor(row) {
  return {
    soul: postSoul("0xalice", row.object, row.accessor),
    owner: "0xalice",
    hamState: row.hamState,
    grant: {
      object: row.object,
      accessor: row.accessor,
      from: row.from,
      until: row.until,
      stated: row.stated,
    },
  };
}

function applySee(graph, row) {
  if (!row.see) return;
  graph.stateSeeGrant(row.owner, {
    object: row.object,
    accessor: row.accessor,
    from: row.see.from,
    until: row.see.until,
  });
  if (row.see.stated === 0) graph.unstateSeeGrant(row.owner, row.accessor, row.object);
}

function applyPost(graph, row) {
  if (!row.post) return;
  graph.statePostGrant(row.owner, {
    object: row.object,
    accessor: row.accessor,
    from: row.post.from,
    until: row.post.until,
  });
  if (row.post.stated === 0) graph.unstatePostGrant(row.owner, row.accessor, row.object);
}

function applyMerge(graph, row, edges) {
  for (const edge of edges) {
    graph.mergePost({
      soul: "s3rch/acl/forged",
      owner: row.owner,
      hamState: edge.hamState,
      grant: {
        object: row.object,
        accessor: row.accessor,
        from: edge.from,
        until: edge.until,
        stated: edge.stated,
      },
    });
  }
}

function runCase(row, merge) {
  const graph = new MemoryGroupGraph();
  graph.putObject(row.object, row.owner);
  applySee(graph, row);
  applyPost(graph, row);
  if (merge) applyMerge(graph, row, merge);
  const hint = row.hint ? { principal: row.accessor, target: row.object } : undefined;
  const hop = row.hop ? { channel: "convention-badge" } : undefined;
  const got = checkPost(graph, row.object, row.accessor, row.now, hint, hop);
  assert.equal(got.allowed, row.allowed, row.name);
  assert.equal(got.reason, row.reason, row.name);
  assert.equal(factorGrants("hop"), false);
  assert.equal(factorGrants("hint"), false);
  assert.equal(factorGrants("wrap"), false);
  assert.equal(factorGrants("inbox"), false);
  if (!row.post && !merge) {
    assert.equal(graph.postGrant(row.object, row.accessor), undefined, row.name);
  }
  if (row.winner) {
    const stored = graph.postGrant(row.object, row.accessor);
    assert.equal(stored.grant.from, row.winner.from, row.name);
    assert.equal(stored.grant.until, row.winner.until, row.name);
    assert.equal(stored.grant.stated, row.winner.stated, row.name);
    assert.equal(stored.soul, postSoul(row.owner, row.object, row.accessor), row.name);
  }
}

test("post grant vectors match the shared fixture", () => {
  assert.equal(fixture.domain, POST_GRANT_DOMAIN);
  assert.equal(fixture.scope, POST_GRANT_SCOPE);
  for (const kind of fixture.factors) assert.equal(factorGrants(kind), false, kind);
  for (const row of fixture.signing) {
    const bytes = postGrantSigningBytes(edgeFor(row));
    assert.equal(hex(bytes), row.hex, row.name);
    assert.equal(hex(gunSigningBytes(edgeFor(row))), row.hex, row.name);
    assert.equal(!Buffer.from(bytes).toString("utf8").includes("0xalice"), true, row.name);
  }
  for (const row of fixture.graphs) {
    runCase(row, row.merge);
    if (row.eitherOrder) runCase(row, [...row.merge].reverse());
  }
});

test("post soul is not the see soul", () => {
  assert.equal(postSoul("0xalice", "room:alpha", "0xbob"), "s3rch/acl/0xalice/post/room:alpha/0xbob");
  assert.equal(gunPostSoul("0xalice", "room:alpha", "s3rch/users/0xbob"), "s3rch/acl/0xalice/post/room:alpha/0xbob");
  const graph = new MemoryGroupGraph();
  graph.putObject("room:alpha", "0xalice");
  graph.statePostGrant("0xalice", { object: "room:alpha", accessor: "0xbob", from: 0, until: 80 });
  assert.equal(graph.seeGrants("room:alpha").length, 0);
  assert.equal(checkPost(graph, "room:alpha", "0xbob", 1).allowed, false);
});

test("a foreign owner cannot write a post grant", () => {
  const graph = new MemoryGroupGraph();
  graph.putObject("room:alpha", "0xalice");
  graph.statePostGrant("0xbob", { object: "room:alpha", accessor: "0xbob", from: 0, until: 80 });
  assert.equal(graph.postGrant("room:alpha", "0xbob"), undefined);
});

test("cancel then restate; a stale peer does not restore the allow", () => {
  const graph = new MemoryGroupGraph();
  graph.putObject("room:alpha", "0xalice");
  graph.stateSeeGrant("0xalice", { object: "room:alpha", accessor: "0xbob", from: 0, until: 80 });
  graph.statePostGrant("0xalice", { object: "room:alpha", accessor: "0xbob", from: 0, until: 80 });
  assert.equal(checkPost(graph, "room:alpha", "0xbob", 1).allowed, true);
  const stale = graph.postGrant("room:alpha", "0xbob");
  graph.unstatePostGrant("0xalice", "0xbob", "room:alpha");
  assert.equal(checkPost(graph, "room:alpha", "0xbob", 1).reason, "cancelled");
  graph.mergePost(stale);
  assert.equal(checkPost(graph, "room:alpha", "0xbob", 1).reason, "cancelled");
  graph.statePostGrant("0xalice", { object: "room:alpha", accessor: "0xbob", from: 0, until: 80 });
  assert.equal(checkPost(graph, "room:alpha", "0xbob", 1).reason, "post");
});

test("group see does not satisfy checkPost", () => {
  const graph = new MemoryGroupGraph();
  const alice = issuerFromSeed(createHash("sha256").update("sociacl-test-signer-v1").update("0xalice").digest());
  const bob = issuerFromSeed(createHash("sha256").update("sociacl-test-signer-v1").update("0xbob").digest());
  graph.enrollSigner("0xalice", alice.publicKey);
  graph.enrollSigner("0xbob", bob.publicKey);
  graph.putObject("doc", "0xalice");
  graph.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  graph.nameObjectSet("0xalice", "doc", "same-group", "0xalice/ops", alice.privateKey);
  graph.stateMembership("0xbob", "same-group", "0xalice/ops", "0xbob", bob.privateKey);
  graph.stateMembership("0xalice", "same-group", "0xalice/ops", "0xbob", alice.privateKey);
  graph.statePostGrant("0xalice", { object: "doc", accessor: "0xbob", from: 0, until: 80 });
  assert.equal(checkGroupSee(graph, "same-group", "doc", "0xbob", 1).allowed, true);
  assert.equal(checkPost(graph, "doc", "0xbob", 1).allowed, false);
  assert.equal(checkPost(graph, "doc", "0xalice", 1).reason, "owner");
});

test("post lookup follows the current object owner", () => {
  const graph = new MemoryGroupGraph();
  graph.putObject("room:alpha", "0xalice");
  graph.stateSeeGrant("0xalice", { object: "room:alpha", accessor: "0xbob", from: 0, until: 80 });
  graph.statePostGrant("0xalice", { object: "room:alpha", accessor: "0xbob", from: 0, until: 80 });
  graph.putObject("room:alpha", "0xcarol");
  graph.stateSeeGrant("0xcarol", { object: "room:alpha", accessor: "0xbob", from: 0, until: 80 });
  graph.statePostGrant("0xcarol", { object: "room:alpha", accessor: "0xbob", from: 0, until: 80 });
  assert.equal(graph.postGrant("room:alpha", "0xbob").owner, "0xcarol");
  assert.equal(checkPost(graph, "room:alpha", "0xbob", 10).reason, "post");
});

test("a noncanonical post row is dropped and does not abort merge", () => {
  const graph = new MemoryGroupGraph();
  graph.putObject("room:alpha", "0xalice");
  graph.stateSeeGrant("0xalice", { object: "room:alpha", accessor: "0xbob", from: 0, until: 80 });
  graph.statePostGrant("0xalice", { object: "room:alpha", accessor: "0xbob", from: 0, until: 80 });
  const local = graph.postGrant("room:alpha", "0xbob");
  const peer = new MemoryGroupGraph();
  peer.putObject("room:alpha", "0xalice");
  peer.posts.set("bad-equal", {
    soul: "s3rch/acl/forged",
    owner: "0xalice",
    hamState: local.hamState,
    grant: { object: "room:alpha", accessor: "0xbob", from: 1.5, until: 90, stated: 1 },
  });
  peer.posts.set("bad-higher", {
    soul: "s3rch/acl/forged",
    owner: "0xalice",
    hamState: local.hamState + 8,
    grant: { object: "room:alpha", accessor: "0xbob", from: 0.5, until: 80, stated: 1 },
  });
  peer.stateSeeGrant("0xalice", { object: "room:alpha", accessor: "0xcarol", from: 0, until: 80 });
  assert.equal(postRowEncodable(peer.posts.get("bad-equal")), false);
  assert.doesNotThrow(() => preferPost(local, peer.posts.get("bad-equal")));
  assert.doesNotThrow(() => graph.mergeFrom(peer));
  const kept = graph.postGrant("room:alpha", "0xbob");
  assert.equal(kept.grant.from, 0);
  assert.equal(kept.grant.until, 80);
  assert.equal(kept.grant.stated, 1);
  assert.equal(checkPost(graph, "room:alpha", "0xbob", 10).reason, "post");
  assert.equal(graph.seeGrants("room:alpha").some((grant) => grant.accessor === "0xcarol"), true);
  const empty = new MemoryGroupGraph();
  empty.putObject("room:alpha", "0xalice");
  assert.doesNotThrow(() => empty.mergeFrom(peer));
  assert.equal(empty.postGrant("room:alpha", "0xbob"), undefined);
});

test("light acl: post requires see, and cancel is the next check", () => {
  const acl = new MemorySeeAcl();
  const object = "room:alpha";
  acl.putObject(object, "0xalice");
  applyPostGrant(acl, "0xalice", { object, accessor: "0xbob", from: 0, until: 80 });
  assert.equal(gunCheckPost(acl, object, "0xbob", 10, { principal: "0xbob" }, { channel: "convention-badge" }).allowed, false);
  applySeeGrant(acl, "0xalice", { claimId: object, accessor: "0xbob", from: 0, until: 80 });
  assert.equal(gunCheckPost(acl, object, "0xbob", 10).reason, "post");
  cancelPost(acl, "0xalice", "0xbob", object);
  assert.equal(gunCheckPost(acl, object, "0xbob", 10).reason, "cancelled");
  assert.equal(gunCheckPost(acl, object, "0xalice", 10).reason, "owner");
  assert.equal(gunFactorGrants("inbox"), false);
  applyPostGrant(acl, "0xbob", { object, accessor: "0xbob", from: 0, until: 80 });
  assert.equal(gunCheckPost(acl, object, "0xbob", 10).reason, "cancelled");
});

test("light acl cancel finds the row when the accessor is a user soul", () => {
  const acl = new MemorySeeAcl();
  const object = "room:alpha";
  acl.putObject(object, "0xalice");
  applySeeGrant(acl, "0xalice", { claimId: object, accessor: "s3rch/users/0xbob", from: 0, until: 80 });
  applyPostGrant(acl, "0xalice", { object, accessor: "s3rch/users/0xbob", from: 0, until: 80 });
  assert.equal(gunCheckPost(acl, object, "s3rch/users/0xbob", 10).reason, "post");
  cancelPost(acl, "0xalice", "0xbob", object);
  assert.equal(acl.posts.size, 1);
  assert.equal(gunCheckPost(acl, object, "s3rch/users/0xbob", 10).reason, "cancelled");
});
