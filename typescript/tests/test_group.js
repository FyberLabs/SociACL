import assert from "node:assert/strict";
import { test } from "node:test";
import {
  MemoryGroupGraph,
  checkGroupPresentation,
  checkGroupSee,
  aclKey,
  membershipSoul,
  objectSetSoul,
  snapshotUnderstatesGroup,
} from "../src/group.js";

import { createHash } from "node:crypto";
import { issuerFromSeed } from "../src/group.js";

const FIXTURE = ["0xalice", "0xbob", "0xcarol", "0xmallory", "0xdave"];

function secret(name) {
  const seed = createHash("sha256").update("sociacl-test-signer-v1").update(name).digest();
  return issuerFromSeed(seed);
}

function openGraph() {
  const graph = new MemoryGroupGraph();
  for (const name of FIXTURE) graph.enrollSigner(name, secret(name).publicKey);
  return graph;
}

function liveGraph() {
  const graph = openGraph();
  graph.putObject("doc", "0xalice");
  graph.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  graph.nameObjectSet("0xalice", "doc", "same-group", "0xalice/ops", secret("0xalice").privateKey);
  graph.stateMembership("0xbob", "same-group", "0xalice/ops", "0xbob", secret("0xbob").privateKey);
  graph.stateMembership("0xalice", "same-group", "0xalice/ops", "0xbob", secret("0xalice").privateKey);
  return graph;
}

const livePayload = { stated: 1, from: 10, until: 20 };
const group = { predicate: "same-group", setId: "0xalice/ops" };

test("same-group allows a jointly stated member and not a friend", () => {
  const graph = liveGraph();
  const allowed = checkGroupSee(graph, "same-group", "doc", "0xbob", 1);
  assert.equal(allowed.allowed, true);
  assert.equal(allowed.reason, "same-group");
  assert.equal(checkGroupSee(graph, "same-group", "doc", "0xalice", 1).reason, "owner");
  assert.equal(checkGroupSee(graph, "same-group", "doc", "0xcarol", 1, { principal: "0xcarol" }).allowed, false);
});

test("one-sided membership is stored and is not a grant", () => {
  const graph = openGraph();
  graph.putObject("doc", "0xalice");
  graph.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  graph.nameObjectSet("0xalice", "doc", "same-group", "0xalice/ops", secret("0xalice").privateKey);
  graph.stateMembership("0xbob", "same-group", "0xalice/ops", "0xbob", secret("0xbob").privateKey);
  assert.equal(graph.membership("same-group", "0xalice/ops", "0xbob")?.stated, 0);
  assert.equal(checkGroupSee(graph, "same-group", "doc", "0xbob", 5).reason, "missing");
});

test("named-circle does not inherit a same-group edge", () => {
  const graph = openGraph();
  graph.putObject("album", "0xalice");
  graph.recordSetOwner("0xalice", "named-circle", "0xalice/friends");
  graph.recordSetOwner("0xalice", "same-group", "0xalice/friends");
  graph.nameObjectSet("0xalice", "album", "named-circle", "0xalice/friends", secret("0xalice").privateKey);
  graph.stateMembership("0xbob", "same-group", "0xalice/friends", "0xbob", secret("0xbob").privateKey);
  graph.stateMembership("0xalice", "same-group", "0xalice/friends", "0xbob", secret("0xalice").privateKey);
  assert.equal(checkGroupSee(graph, "named-circle", "album", "0xbob", 0).allowed, false);
  graph.stateMembership("0xbob", "named-circle", "0xalice/friends", "0xbob", secret("0xbob").privateKey);
  graph.stateMembership("0xalice", "named-circle", "0xalice/friends", "0xbob", secret("0xalice").privateKey);
  assert.equal(checkGroupSee(graph, "named-circle", "album", "0xbob", 0).reason, "named-circle");
});

test("hop alone never allows and a cancel is immediate", () => {
  const hop = { channel: "convention-badge" };
  const graph = openGraph();
  graph.putObject("doc", "0xalice");
  const alone = checkGroupSee(graph, "same-group", "doc", "0xcarol", 1, null, hop);
  assert.equal(alone.allowed, false);
  assert.equal(alone.hop, hop);

  const live = liveGraph();
  const factored = checkGroupSee(graph, "same-group", "doc", "0xbob", 1, null, hop);
  assert.equal(factored.allowed, false);
  const named = checkGroupSee(live, "same-group", "doc", "0xbob", 1, null, hop);
  assert.equal(named.allowed, true);
  live.cancelMembership("0xalice", "same-group", "0xalice/ops", "0xbob", secret("0xalice").privateKey);
  const after = checkGroupSee(live, "same-group", "doc", "0xbob", 1, null, hop);
  assert.equal(after.allowed, false);
  assert.equal(after.reason, "cancelled");
});

test("membership in one set does not grant another", () => {
  const graph = liveGraph();
  graph.recordSetOwner("0xalice", "same-group", "0xalice/ops-core");
  graph.nameObjectSet("0xalice", "doc", "same-group", "0xalice/ops-core", secret("0xalice").privateKey);
  assert.equal(checkGroupSee(graph, "same-group", "doc", "0xbob", 1).allowed, false);
});

test("presented-group-check and presented-group-cancel", () => {
  const graph = liveGraph();
  graph.stateSeeGrant("0xalice", { object: "doc", accessor: "0xbob", from: 0, until: 80 });
  const allowed = checkGroupPresentation(graph, group, "doc", "0xbob", livePayload, 10);
  assert.equal(allowed.allowed, true);
  assert.equal(allowed.reason, "same-group");
  assert.equal(allowed.storeCancel, false);
  const owner = checkGroupPresentation(graph, group, "doc", "0xalice", livePayload, 10);
  assert.equal(owner.allowed, true);
  assert.equal(owner.reason, "owner");
  const ownerCancel = checkGroupPresentation(graph, group, "doc", "0xalice", { stated: 0, from: 10, until: 20 }, 10);
  assert.equal(ownerCancel.allowed, false);
  assert.equal(ownerCancel.storeCancel, true);

  const noGroup = checkGroupPresentation(graph, null, "doc", "0xbob", livePayload, 10);
  assert.equal(noGroup.allowed, false);
  assert.equal(noGroup.reason, "missing");

  const outside = checkGroupPresentation(graph, group, "doc", "0xbob", livePayload, 20);
  assert.equal(outside.allowed, false);
  assert.equal(outside.reason, "cancelled");

  const cancel = checkGroupPresentation(
    graph,
    group,
    "doc",
    "0xbob",
    { stated: 0, from: 10, until: 20 },
    10,
    null,
    { channel: "convention-badge" },
  );
  assert.equal(cancel.allowed, false);
  assert.equal(cancel.storeCancel, true);
  assert.equal(cancel.hop?.channel, "convention-badge");

  const plain = openGraph();
  plain.putObject("claim-1", "0xalice");
  plain.stateSeeGrant("0xalice", { object: "claim-1", accessor: "0xbob", from: 0, until: 80 });
  const ordinary = checkGroupPresentation(plain, null, "claim-1", "0xbob", { stated: 1, from: 0, until: 80 }, 10);
  assert.equal(ordinary.allowed, true);
  assert.equal(ordinary.reason, "delegate");
  const ordinaryCancel = checkGroupPresentation(
    plain,
    null,
    "claim-1",
    "0xbob",
    { stated: 0, from: 0, until: 80 },
    10,
  );
  assert.equal(ordinaryCancel.allowed, false);
  assert.equal(ordinaryCancel.storeCancel, true);
});

test("a lower hamState does not hide a removal", () => {
  const graph = liveGraph();
  graph.cancelMembership("0xalice", "same-group", "0xalice/ops", "0xbob", secret("0xalice").privateKey);
  graph.cancelMembership("0xalice", "same-group", "0xalice/ops", "0xbob", secret("0xalice").privateKey);
  const ham = graph.membership("same-group", "0xalice/ops", "0xbob")?.hamState ?? 0;
  assert.ok(ham >= 4);
  const edge = { predicate: "same-group", setId: "0xalice/ops", stated: 1, hamState: 1 };
  assert.equal(
    snapshotUnderstatesGroup(
      graph,
      "doc",
      [{ accessor: "0xbob", predicate: "same-group", setId: "0xalice/ops", stated: 1, hamState: 2 }],
      edge,
    ),
    true,
  );
  assert.equal(snapshotUnderstatesGroup(graph, "doc", [], edge), true);
  assert.equal(
    snapshotUnderstatesGroup(
      graph,
      "doc",
      [{ accessor: "0xbob", predicate: "same-group", setId: "0xalice/ops", stated: 0, hamState: ham }],
      edge,
    ),
    false,
  );

  const stale = liveGraph();
  graph.nameObjectSet("0xalice", "doc", "same-group", "0xalice/labs", secret("0xalice").privateKey);
  graph.mergeFrom(stale);
  assert.equal(graph.objectSet("doc")?.setId, "0xalice/labs");
  assert.equal(graph.membership("same-group", "0xalice/ops", "0xbob")?.stated, 0);
  assert.equal(
    snapshotUnderstatesGroup(graph, "doc", [], {
      predicate: "same-group",
      setId: "0xalice/ops",
      stated: 1,
      hamState: 1,
    }),
    true,
  );
});

test("group rows are not grant souls", () => {
  const graph = liveGraph();
  const member = membershipSoul("0xalice", "same-group", "0xalice/ops", "0xbob");
  assert.equal(member.split("/").length, 7);
  assert.equal(member.startsWith("s3rch/acl/"), true);
  assert.equal(member.includes("/membership/"), true);
  const edge = objectSetSoul("0xalice", "doc");
  assert.equal(edge.split("/").length === 5, false);
  assert.equal(edge.includes("/object-set/edge/"), true);
  assert.equal(graph.ownerOfSet("same-group", "0xalice/ops"), "0xalice");
  assert.equal(graph.ownerOfSet("named-circle", "0xalice/ops"), undefined);
});

test("rejoin waits until both sides state again", () => {
  const graph = liveGraph();
  graph.cancelMembership("0xbob", "same-group", "0xalice/ops", "0xbob", secret("0xbob").privateKey);
  graph.stateMembership("0xbob", "same-group", "0xalice/ops", "0xbob", secret("0xbob").privateKey);
  assert.equal(checkGroupSee(graph, "same-group", "doc", "0xbob", 1).reason, "cancelled");
  graph.stateMembership("0xalice", "same-group", "0xalice/ops", "0xbob", secret("0xalice").privateKey);
  assert.equal(checkGroupSee(graph, "same-group", "doc", "0xbob", 1).allowed, true);
});

test("closed objects and a cleared edge fail closed", () => {
  const graph = liveGraph();
  assert.equal(checkGroupSee(graph, "same-group", "s3rch/meta", "0xalice", 1).reason, "meta");
  assert.equal(checkGroupSee(graph, "same-group", "s3rch/acl/0xalice", "0xalice", 1).reason, "acl");
  graph.clearObjectSet("0xalice", "doc", secret("0xalice").privateKey);
  assert.equal(checkGroupSee(graph, "same-group", "doc", "0xbob", 1).reason, "cancelled");
});

function stateBoth(graph, predicate, setId, accessor) {
  graph.stateMembership(accessor, predicate, setId, accessor, secret(accessor).privateKey);
  graph.stateMembership("0xalice", predicate, setId, accessor, secret("0xalice").privateKey);
}

test("merge drops a membership from a conflicting set owner", () => {
  const alice = openGraph();
  alice.putObject("doc", "0xalice");
  alice.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  alice.nameObjectSet("0xalice", "doc", "same-group", "0xalice/ops", secret("0xalice").privateKey);

  const mallory = openGraph();
  assert.throws(() => mallory.recordSetOwner("0xmallory", "same-group", "0xalice/ops"), /not bound/);
  mallory.recordSetOwner("0xmallory", "same-group", "0xmallory/ops");
  mallory.stateMembership("0xmallory", "same-group", "0xmallory/ops", "0xmallory", secret("0xmallory").privateKey);

  alice.mergeFrom(mallory);
  assert.equal(alice.ownerOfSet("same-group", "0xalice/ops"), "0xalice");
  assert.equal(alice.membership("same-group", "0xalice/ops", "0xbob"), undefined);
  assert.equal(checkGroupSee(alice, "same-group", "doc", "0xbob", 1).allowed, false);

  const sameOwner = openGraph();
  sameOwner.recordSetOwner("s3rch/users/0xalice", "same-group", "0xalice/ops");
  stateBoth(sameOwner, "same-group", "0xalice/ops", "0xbob");
  alice.mergeFrom(sameOwner);
  assert.equal(alice.membership("same-group", "0xalice/ops", "0xbob")?.stated, 1);
});

test("equal ham membership merge keeps the cancel", () => {
  const cancelled = liveGraph();
  cancelled.cancelMembership("0xalice", "same-group", "0xalice/ops", "0xbob", secret("0xalice").privateKey);
  const restated = liveGraph();
  restated.stateMembership("0xbob", "same-group", "0xalice/ops", "0xbob", secret("0xbob").privateKey);
  assert.equal(
    cancelled.membership("same-group", "0xalice/ops", "0xbob")?.hamState,
    restated.membership("same-group", "0xalice/ops", "0xbob")?.hamState,
  );
  const fromCancel = liveGraph();
  fromCancel.cancelMembership("0xalice", "same-group", "0xalice/ops", "0xbob", secret("0xalice").privateKey);
  fromCancel.mergeFrom(restated);
  const fromRestate = liveGraph();
  fromRestate.stateMembership("0xbob", "same-group", "0xalice/ops", "0xbob", secret("0xbob").privateKey);
  fromRestate.mergeFrom(cancelled);
  for (const graph of [fromCancel, fromRestate]) {
    assert.equal(graph.membership("same-group", "0xalice/ops", "0xbob")?.stated, 0);
    assert.equal(checkGroupSee(graph, "same-group", "doc", "0xbob", 1).allowed, false);
  }
});

test("equal ham object-set merge keeps privilege-down", () => {
  const cleared = liveGraph();
  cleared.clearObjectSet("0xalice", "doc", secret("0xalice").privateKey);
  const renamed = liveGraph();
  renamed.nameObjectSet("0xalice", "doc", "same-group", "0xalice/labs", secret("0xalice").privateKey);
  assert.equal(cleared.objectSet("doc")?.hamState, renamed.objectSet("doc")?.hamState);
  const fromClear = liveGraph();
  fromClear.clearObjectSet("0xalice", "doc", secret("0xalice").privateKey);
  fromClear.mergeFrom(renamed);
  const fromRename = liveGraph();
  fromRename.nameObjectSet("0xalice", "doc", "same-group", "0xalice/labs", secret("0xalice").privateKey);
  fromRename.mergeFrom(cleared);
  for (const graph of [fromClear, fromRename]) {
    assert.equal(graph.objectSet("doc")?.stated, 0);
    assert.equal(checkGroupSee(graph, "same-group", "doc", "0xbob", 1).allowed, false);
  }
});

test("merge drops an object-set row from a conflicting object owner", () => {
  const alice = openGraph();
  alice.putObject("doc", "0xalice");
  alice.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  stateBoth(alice, "same-group", "0xalice/ops", "0xbob");

  const mallory = openGraph();
  mallory.putObject("doc", "0xmallory");
  mallory.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  mallory.nameObjectSet("0xmallory", "doc", "same-group", "0xalice/ops", secret("0xmallory").privateKey);

  alice.mergeFrom(mallory);
  assert.equal(alice.ownerOf("doc"), "0xalice");
  assert.equal(alice.objectSet("doc"), undefined);
  assert.equal(checkGroupSee(alice, "same-group", "doc", "0xbob", 1).allowed, false);
});

test("clear of an unseen object-set writes a tombstone", () => {
  const clearer = openGraph();
  clearer.putObject("doc", "0xalice");
  clearer.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  stateBoth(clearer, "same-group", "0xalice/ops", "0xbob");
  clearer.clearObjectSet("0xalice", "doc", secret("0xalice").privateKey);
  assert.equal(clearer.objectSet("doc")?.stated, 0);
  assert.equal(clearer.objectSet("doc")?.hamState, 1);

  const peer = openGraph();
  peer.putObject("doc", "0xalice");
  peer.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  peer.nameObjectSet("0xalice", "doc", "same-group", "0xalice/ops", secret("0xalice").privateKey);
  stateBoth(peer, "same-group", "0xalice/ops", "0xbob");
  clearer.mergeFrom(peer);
  assert.equal(clearer.objectSet("doc")?.stated, 0);
  assert.equal(checkGroupSee(clearer, "same-group", "doc", "0xbob", 1).reason, "cancelled");
  peer.mergeFrom(clearer);
  assert.equal(peer.objectSet("doc")?.stated, 0);
  assert.equal(checkGroupSee(peer, "same-group", "doc", "0xbob", 1).allowed, false);
});

test("one party cannot advance a stale live membership past a cancel", () => {
  const ownerPeer = liveGraph();
  ownerPeer.cancelMembership("0xalice", "same-group", "0xalice/ops", "0xbob", secret("0xalice").privateKey);
  const memberPeer = liveGraph();
  memberPeer.stateMembership("0xbob", "same-group", "0xalice/ops", "0xbob", secret("0xbob").privateKey);
  memberPeer.stateMembership("0xbob", "same-group", "0xalice/ops", "0xbob", secret("0xbob").privateKey);
  assert.equal(memberPeer.membership("same-group", "0xalice/ops", "0xbob")?.stated, 1);
  assert.ok(
    (memberPeer.membership("same-group", "0xalice/ops", "0xbob")?.hamState ?? 0) >
      (ownerPeer.membership("same-group", "0xalice/ops", "0xbob")?.hamState ?? 0),
  );
  const fromOwner = liveGraph();
  fromOwner.cancelMembership("0xalice", "same-group", "0xalice/ops", "0xbob", secret("0xalice").privateKey);
  fromOwner.mergeFrom(memberPeer);
  const fromMember = liveGraph();
  fromMember.stateMembership("0xbob", "same-group", "0xalice/ops", "0xbob", secret("0xbob").privateKey);
  fromMember.stateMembership("0xbob", "same-group", "0xalice/ops", "0xbob", secret("0xbob").privateKey);
  fromMember.mergeFrom(ownerPeer);
  for (const graph of [fromOwner, fromMember]) {
    assert.equal(graph.membership("same-group", "0xalice/ops", "0xbob")?.stated, 0);
    assert.equal(checkGroupSee(graph, "same-group", "doc", "0xbob", 1).reason, "cancelled");
  }
});

test("mergeFrom copies objects and ordinary see grants", () => {
  const source = openGraph();
  source.putObject("doc", "0xalice");
  source.putObject("claim-1", "0xalice");
  source.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  source.nameObjectSet("0xalice", "doc", "same-group", "0xalice/ops", secret("0xalice").privateKey);
  stateBoth(source, "same-group", "0xalice/ops", "0xbob");
  source.stateSeeGrant("0xalice", { object: "claim-1", accessor: "0xbob", from: 0, until: 80 });

  const fresh = openGraph();
  fresh.mergeFrom(source);
  assert.equal(fresh.ownerOf("doc"), "0xalice");
  assert.equal(checkGroupSee(fresh, "same-group", "doc", "0xbob", 1).allowed, true);
  const ordinary = checkGroupPresentation(fresh, null, "claim-1", "0xbob", { stated: 1, from: 0, until: 80 }, 10);
  assert.equal(ordinary.allowed, true);
  assert.equal(ordinary.reason, "delegate");

  const local = openGraph();
  local.putObject("doc", "0xalice");
  const other = openGraph();
  other.putObject("doc", "0xmallory");
  local.mergeFrom(other);
  assert.equal(local.ownerOf("doc"), "0xalice");
});

test("cancel of an unseen membership dominates a higher restate", () => {
  const clearer = openGraph();
  clearer.putObject("doc", "0xalice");
  clearer.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  clearer.nameObjectSet("0xalice", "doc", "same-group", "0xalice/ops", secret("0xalice").privateKey);
  clearer.cancelMembership("0xalice", "same-group", "0xalice/ops", "0xbob", secret("0xalice").privateKey);

  const peer = openGraph();
  peer.putObject("doc", "0xalice");
  peer.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  peer.nameObjectSet("0xalice", "doc", "same-group", "0xalice/ops", secret("0xalice").privateKey);
  stateBoth(peer, "same-group", "0xalice/ops", "0xbob");
  peer.stateMembership("0xbob", "same-group", "0xalice/ops", "0xbob", secret("0xbob").privateKey);
  peer.stateMembership("0xbob", "same-group", "0xalice/ops", "0xbob", secret("0xbob").privateKey);
  peer.stateMembership("0xalice", "same-group", "0xalice/ops", "0xbob", secret("0xalice").privateKey);
  peer.stateMembership("0xalice", "same-group", "0xalice/ops", "0xbob", secret("0xalice").privateKey);
  assert.equal(peer.membership("same-group", "0xalice/ops", "0xbob")?.stated, 1);
  assert.ok(
    (peer.membership("same-group", "0xalice/ops", "0xbob")?.hamState ?? 0) >
      (clearer.membership("same-group", "0xalice/ops", "0xbob")?.hamState ?? 0),
  );

  const fromClear = openGraph();
  fromClear.putObject("doc", "0xalice");
  fromClear.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  fromClear.nameObjectSet("0xalice", "doc", "same-group", "0xalice/ops", secret("0xalice").privateKey);
  fromClear.cancelMembership("0xalice", "same-group", "0xalice/ops", "0xbob", secret("0xalice").privateKey);
  fromClear.mergeFrom(peer);
  const fromPeer = openGraph();
  fromPeer.putObject("doc", "0xalice");
  fromPeer.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  fromPeer.nameObjectSet("0xalice", "doc", "same-group", "0xalice/ops", secret("0xalice").privateKey);
  stateBoth(fromPeer, "same-group", "0xalice/ops", "0xbob");
  fromPeer.stateMembership("0xbob", "same-group", "0xalice/ops", "0xbob", secret("0xbob").privateKey);
  fromPeer.stateMembership("0xbob", "same-group", "0xalice/ops", "0xbob", secret("0xbob").privateKey);
  fromPeer.stateMembership("0xalice", "same-group", "0xalice/ops", "0xbob", secret("0xalice").privateKey);
  fromPeer.stateMembership("0xalice", "same-group", "0xalice/ops", "0xbob", secret("0xalice").privateKey);
  fromPeer.mergeFrom(clearer);
  for (const graph of [fromClear, fromPeer]) {
    assert.equal(graph.membership("same-group", "0xalice/ops", "0xbob")?.stated, 0);
    assert.equal(checkGroupSee(graph, "same-group", "doc", "0xbob", 1).reason, "cancelled");
  }
  fromClear.stateMembership("0xbob", "same-group", "0xalice/ops", "0xbob", secret("0xbob").privateKey);
  fromClear.stateMembership("0xalice", "same-group", "0xalice/ops", "0xbob", secret("0xalice").privateKey);
  assert.equal(checkGroupSee(fromClear, "same-group", "doc", "0xbob", 1).allowed, true);
});

test("a predictable set id is not owned by the first peer", () => {
  const early = openGraph();
  assert.throws(() => early.recordSetOwner("0xmallory", "same-group", "ops"), /not bound/);
  const verifier = openGraph();
  verifier.putObject("doc", "0xalice");
  const mallory = openGraph();
  mallory.recordSetOwner("0xmallory", "same-group", "0xmallory/ops");
  mallory.stateMembership("0xmallory", "same-group", "0xmallory/ops", "0xmallory", secret("0xmallory").privateKey);
  verifier.mergeFrom(mallory);
  verifier.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  verifier.nameObjectSet("0xalice", "doc", "same-group", "0xalice/ops", secret("0xalice").privateKey);
  assert.equal(verifier.ownerOfSet("same-group", "0xalice/ops"), "0xalice");
  assert.equal(verifier.ownerOfSet("same-group", "ops"), undefined);
  assert.equal(checkGroupSee(verifier, "same-group", "doc", "0xmallory", 1).allowed, false);
});

test("object owner checks use the canonical object key", () => {
  const alice = openGraph();
  alice.putObject("foo/bar", "0xalice");
  alice.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  stateBoth(alice, "same-group", "0xalice/ops", "0xbob");
  const mallory = openGraph();
  mallory.putObject("foo_bar", "0xmallory");
  mallory.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  mallory.nameObjectSet("0xmallory", "foo_bar", "same-group", "0xalice/ops", secret("0xmallory").privateKey);
  alice.mergeFrom(mallory);
  assert.equal(alice.ownerOf("foo/bar"), "0xalice");
  assert.equal(alice.ownerOf("foo_bar"), "0xalice");
  assert.equal(alice.objectSet("foo/bar"), undefined);
  assert.equal(checkGroupSee(alice, "same-group", "foo/bar", "0xbob", 1).allowed, false);
});

test("mergeFrom drops a see grant from a conflicting object owner", () => {
  const alice = openGraph();
  alice.putObject("doc", "0xalice");
  const mallory = openGraph();
  mallory.putObject("doc", "0xmallory");
  mallory.stateSeeGrant("0xmallory", { object: "doc", accessor: "0xbob", from: 0, until: 80 });
  alice.mergeFrom(mallory);
  assert.equal(alice.ownerOf("doc"), "0xalice");
  const ordinary = checkGroupPresentation(alice, null, "doc", "0xbob", { stated: 1, from: 0, until: 80 }, 1);
  assert.equal(ordinary.allowed, false);
});

test("stateSeeGrant accepts claimId", () => {
  const graph = openGraph();
  graph.putObject("claim-1", "0xalice");
  graph.stateSeeGrant("0xalice", { claimId: "claim-1", accessor: "0xbob", from: 0, until: 80 });
  const ordinary = checkGroupPresentation(graph, null, "claim-1", "0xbob", { stated: 1, from: 0, until: 80 }, 10);
  assert.equal(ordinary.allowed, true);
  assert.equal(ordinary.reason, "delegate");
});

test("checkGroupSee reads membership through the graph interface", () => {
  const real = liveGraph();
  const graph = {
    ownerOf: (object) => real.ownerOf(object),
    ownerOfSet: (predicate, setId) => real.ownerOfSet(predicate, setId),
    objectSet: (object) => real.objectSet(object),
    seeGrants: (object) => real.seeGrants(object),
    enrolledKey: (principal) => real.enrolledKey(principal),
    membership(predicate, setId, accessor) {
      assert.equal(predicate, "same-group");
      assert.equal(setId, "0xalice/ops");
      assert.equal(accessor, "0xbob");
      return real.membership(predicate, setId, accessor);
    },
  };
  const allowed = checkGroupSee(graph, "same-group", "doc", "0xbob", 1);
  assert.equal(allowed.allowed, true);
  assert.equal(allowed.reason, "same-group");
  graph.membership = () => ({
    predicate: "same-group",
    setId: "0xalice/ops",
    accessor: "0xbob",
    stated: 0,
    hamState: 3,
    removed: true,
    setOwner: "0xalice",
  });
  assert.equal(checkGroupSee(graph, "same-group", "doc", "0xbob", 1).reason, "cancelled");
});

test("a stated-0 object-set does not block an ordinary see grant", () => {
  const graph = liveGraph();
  graph.stateSeeGrant("0xalice", { object: "doc", accessor: "0xcarol", from: 0, until: 80 });
  graph.clearObjectSet("0xalice", "doc", secret("0xalice").privateKey);
  assert.equal(graph.objectSet("doc")?.stated, 0);
  const ordinary = checkGroupPresentation(graph, null, "doc", "0xcarol", { stated: 1, from: 0, until: 80 }, 1);
  assert.equal(ordinary.allowed, true);
  assert.equal(ordinary.reason, "delegate");
});

test("unseen object-set clear dominates a remote edge advanced twice", () => {
  const peer = liveGraph();
  peer.nameObjectSet("0xalice", "doc", "same-group", "0xalice/labs", secret("0xalice").privateKey);
  peer.nameObjectSet("0xalice", "doc", "same-group", "0xalice/ops", secret("0xalice").privateKey);
  assert.equal(peer.objectSet("doc")?.stated, 1);
  assert.ok((peer.objectSet("doc")?.hamState ?? 0) >= 3);

  const clearer = openGraph();
  clearer.putObject("doc", "0xalice");
  clearer.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  stateBoth(clearer, "same-group", "0xalice/ops", "0xbob");
  clearer.clearObjectSet("0xalice", "doc", secret("0xalice").privateKey);
  assert.equal(clearer.objectSet("doc")?.stated, 0);
  assert.ok((clearer.objectSet("doc")?.hamState ?? 0) < (peer.objectSet("doc")?.hamState ?? 0));

  const fromClear = openGraph();
  fromClear.putObject("doc", "0xalice");
  fromClear.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  stateBoth(fromClear, "same-group", "0xalice/ops", "0xbob");
  fromClear.clearObjectSet("0xalice", "doc", secret("0xalice").privateKey);
  fromClear.mergeFrom(peer);

  const fromPeer = liveGraph();
  fromPeer.nameObjectSet("0xalice", "doc", "same-group", "0xalice/labs", secret("0xalice").privateKey);
  fromPeer.nameObjectSet("0xalice", "doc", "same-group", "0xalice/ops", secret("0xalice").privateKey);
  fromPeer.mergeFrom(clearer);

  for (const graph of [fromClear, fromPeer]) {
    assert.equal(graph.objectSet("doc")?.stated, 0);
    assert.equal(checkGroupSee(graph, "same-group", "doc", "0xbob", 1).reason, "cancelled");
  }

  fromClear.nameObjectSet("0xalice", "doc", "same-group", "0xalice/ops", secret("0xalice").privateKey);
  assert.equal(fromClear.objectSet("doc")?.stated, 1);
  assert.equal(checkGroupSee(fromClear, "same-group", "doc", "0xbob", 1).allowed, true);
});

test("concurrent membership cancels stay cancelled in both directions", () => {
  const left = liveGraph();
  const right = liveGraph();
  left.cancelMembership("0xalice", "same-group", "0xalice/ops", "0xbob", secret("0xalice").privateKey);
  right.cancelMembership("0xbob", "same-group", "0xalice/ops", "0xbob", secret("0xbob").privateKey);
  left.stateMembership("0xbob", "same-group", "0xalice/ops", "0xbob", secret("0xbob").privateKey);
  left.stateMembership("0xalice", "same-group", "0xalice/ops", "0xbob", secret("0xalice").privateKey);
  assert.equal(left.membership("same-group", "0xalice/ops", "0xbob")?.stated, 1);

  const fromLeft = liveGraph();
  fromLeft.cancelMembership("0xalice", "same-group", "0xalice/ops", "0xbob", secret("0xalice").privateKey);
  fromLeft.stateMembership("0xbob", "same-group", "0xalice/ops", "0xbob", secret("0xbob").privateKey);
  fromLeft.stateMembership("0xalice", "same-group", "0xalice/ops", "0xbob", secret("0xalice").privateKey);
  fromLeft.mergeFrom(right);

  const fromRight = liveGraph();
  fromRight.cancelMembership("0xbob", "same-group", "0xalice/ops", "0xbob", secret("0xbob").privateKey);
  fromRight.mergeFrom(left);

  for (const graph of [fromLeft, fromRight]) {
    assert.equal(graph.membership("same-group", "0xalice/ops", "0xbob")?.stated, 0);
    assert.equal(checkGroupSee(graph, "same-group", "doc", "0xbob", 1).reason, "cancelled");
  }
  fromLeft.stateMembership("0xbob", "same-group", "0xalice/ops", "0xbob", secret("0xbob").privateKey);
  fromLeft.stateMembership("0xalice", "same-group", "0xalice/ops", "0xbob", secret("0xalice").privateKey);
  assert.equal(checkGroupSee(fromLeft, "same-group", "doc", "0xbob", 1).allowed, true);
});

test("concurrent object-set clears stay cleared in both directions", () => {
  const left = liveGraph();
  const right = liveGraph();
  left.clearObjectSet("0xalice", "doc", secret("0xalice").privateKey);
  right.clearObjectSet("0xalice", "doc", secret("0xalice").privateKey);
  left.nameObjectSet("0xalice", "doc", "same-group", "0xalice/ops", secret("0xalice").privateKey);
  assert.equal(left.objectSet("doc")?.stated, 1);

  const fromLeft = liveGraph();
  fromLeft.clearObjectSet("0xalice", "doc", secret("0xalice").privateKey);
  fromLeft.nameObjectSet("0xalice", "doc", "same-group", "0xalice/ops", secret("0xalice").privateKey);
  fromLeft.mergeFrom(right);

  const fromRight = liveGraph();
  fromRight.clearObjectSet("0xalice", "doc", secret("0xalice").privateKey);
  fromRight.mergeFrom(left);

  for (const graph of [fromLeft, fromRight]) {
    assert.equal(graph.objectSet("doc")?.stated, 0);
    assert.equal(checkGroupSee(graph, "same-group", "doc", "0xbob", 1).reason, "cancelled");
  }
  fromLeft.nameObjectSet("0xalice", "doc", "same-group", "0xalice/ops", secret("0xalice").privateKey);
  assert.equal(fromLeft.objectSet("doc")?.stated, 1);
  assert.equal(checkGroupSee(fromLeft, "same-group", "doc", "0xbob", 1).allowed, true);
});

test("replacing the object owner drops the previous edge", () => {
  const graph = liveGraph();
  assert.equal(checkGroupSee(graph, "same-group", "doc", "0xbob", 1).allowed, true);
  graph.putObject("doc", "s3rch/users/0xalice");
  assert.ok(graph.objectSet("doc"));
  graph.putObject("doc", "0xcarol");
  assert.equal(graph.ownerOf("doc"), "0xcarol");
  assert.equal(graph.objectSet("doc"), undefined);
  assert.equal(checkGroupSee(graph, "same-group", "doc", "0xbob", 1).allowed, false);
});

test("check fails closed when ownerOfSet is missing or the row owner disagrees", () => {
  const real = liveGraph();
  const edge = real.objectSet("doc");
  const membership = real.membership("same-group", "0xalice/ops", "0xbob");
  const base = {
    ownerOf: () => "0xalice",
    objectSet: () => edge,
    membership: () => membership,
    enrolledKey: (principal) => real.enrolledKey(principal),
    enrolled: real.enrolled,
    seeGrants: () => [],
  };
  const missingOwner = { ...base, ownerOfSet: () => undefined };
  assert.equal(checkGroupSee(missingOwner, "same-group", "doc", "0xbob", 1).allowed, false);
  assert.equal(checkGroupSee(missingOwner, "same-group", "doc", "0xbob", 1).reason, "missing");

  const staleOwner = {
    ...base,
    ownerOf: () => "0xcarol",
    ownerOfSet: () => "0xalice",
    objectSet: () => ({ ...edge, objectOwner: "0xalice" }),
  };
  assert.equal(checkGroupSee(staleOwner, "same-group", "doc", "0xbob", 1).allowed, false);

  const wrongSet = {
    ...base,
    ownerOfSet: () => "0xalice",
    membership: () => ({ ...membership, setId: "0xalice/other" }),
  };
  assert.equal(checkGroupSee(wrongSet, "same-group", "doc", "0xbob", 1).allowed, false);
});

test("colliding set ids are rejected", () => {
  const graph = openGraph();
  assert.throws(() => graph.recordSetOwner("0xalice", "same-group", "0xalice/ops/core"), /not bound/);
  assert.throws(() => graph.recordSetOwner("0xalice", "same-group", "0xalice/ops_core"), /not bound/);
  graph.putObject("doc", "0xalice");
  graph.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  stateBoth(graph, "same-group", "0xalice/ops", "0xbob");
  const soul = membershipSoul("0xalice", "same-group", "0xalice/ops", "0xbob");
  assert.match(soul, /\/0xalice_ops\//);
  assert.equal(graph.membership("same-group", "0xalice/ops", "0xbob")?.setId, "0xalice/ops");
});

test("merge rejects a row signed for a different enrolled key", () => {
  const sender = liveGraph();
  const receiver = new MemoryGroupGraph();
  receiver.putObject("doc", "0xalice");
  receiver.enrollSigner("0xalice", secret("not-alice").publicKey);
  receiver.enrollSigner("0xbob", secret("0xbob").publicKey);
  receiver.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  receiver.mergeFrom(sender);
  assert.equal(receiver.objectSet("doc"), undefined);
  assert.equal(receiver.membership("same-group", "0xalice/ops", "0xbob")?.stated, 0);
  assert.equal(checkGroupSee(receiver, "same-group", "doc", "0xbob", 1).allowed, false);

  const unsigned = new MemoryGroupGraph();
  unsigned.putObject("doc", "0xalice");
  unsigned.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  unsigned.mergeFrom(sender);
  assert.equal(unsigned.objectSet("doc"), undefined);
  assert.equal(unsigned.membership("same-group", "0xalice/ops", "0xbob"), undefined);
});

test("mergeFrom stores rows under the signed identity", () => {
  const source = liveGraph();
  source.putObject("other", "0xalice");
  const nul = "\u0000";
  const memberKey = `same-group${nul}${aclKey("0xalice/ops")}${nul}0xbob`;
  const carolKey = `same-group${nul}${aclKey("0xalice/ops")}${nul}0xcarol`;
  const membership = source.memberships.get(memberKey);
  source.memberships.set(carolKey, membership);
  const edge = source.objectSets.get(aclKey("doc"));
  source.objectSets.set(aclKey("other"), edge);
  const grantKey = `0xalice${nul}doc${nul}0xbob`;
  source.stateSeeGrant("0xalice", { object: "doc", accessor: "0xbob", from: 0, until: 80 });
  const grant = source.grants.get(grantKey);
  source.grants.delete(grantKey);
  source.grants.set(`0xalice${nul}doc${nul}0xcarol`, grant);

  assert.equal(checkGroupSee(source, "same-group", "other", "0xbob", 1).allowed, false);
  assert.equal(checkGroupSee(source, "same-group", "doc", "0xcarol", 1).allowed, false);
  assert.equal(checkGroupSee(source, "same-group", "doc", "0xbob", 1).allowed, true);

  const dest = openGraph();
  dest.putObject("doc", "0xalice");
  dest.putObject("other", "0xalice");
  dest.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  dest.mergeFrom(source);
  assert.equal(dest.membership("same-group", "0xalice/ops", "0xcarol"), undefined);
  assert.equal(dest.membership("same-group", "0xalice/ops", "0xbob")?.accessor, "0xbob");
  assert.equal(dest.objectSet("other"), undefined);
  assert.equal(dest.objectSet("doc")?.object, "doc");
  assert.equal(dest.seeGrants("doc").some((row) => row.accessor === "0xcarol"), false);
  assert.equal(checkGroupSee(dest, "same-group", "doc", "0xbob", 1).allowed, true);
  assert.equal(checkGroupSee(dest, "same-group", "other", "0xbob", 1).allowed, false);
});

test("check compares the returned accessor and object to the request", () => {
  const real = liveGraph();
  const graph = {
    ownerOf: (object) => (object === "other" ? "0xalice" : real.ownerOf(object)),
    ownerOfSet: (predicate, setId) => real.ownerOfSet(predicate, setId),
    objectSet: () => real.objectSet("doc"),
    seeGrants: () => [],
    enrolledKey: (principal) => real.enrolledKey(principal),
    membership: () => real.membership("same-group", "0xalice/ops", "0xbob"),
  };
  assert.equal(checkGroupSee(graph, "same-group", "other", "0xbob", 1).allowed, false);
  assert.equal(checkGroupSee(graph, "same-group", "doc", "0xcarol", 1).allowed, false);
  assert.equal(checkGroupSee(graph, "same-group", "doc", "0xbob", 1).reason, "same-group");
});

test("equal ham see grants keep the narrower window", () => {
  const wide = openGraph();
  wide.putObject("doc", "0xalice");
  wide.stateSeeGrant("0xalice", { object: "doc", accessor: "0xbob", from: 0, until: 100 });
  const narrow = openGraph();
  narrow.putObject("doc", "0xalice");
  narrow.stateSeeGrant("0xalice", { object: "doc", accessor: "0xbob", from: 0, until: 5 });
  const fromWide = openGraph();
  fromWide.putObject("doc", "0xalice");
  fromWide.stateSeeGrant("0xalice", { object: "doc", accessor: "0xbob", from: 0, until: 100 });
  fromWide.mergeFrom(narrow);
  const fromNarrow = openGraph();
  fromNarrow.putObject("doc", "0xalice");
  fromNarrow.stateSeeGrant("0xalice", { object: "doc", accessor: "0xbob", from: 0, until: 5 });
  fromNarrow.mergeFrom(wide);
  for (const graph of [fromWide, fromNarrow]) {
    assert.equal(
      checkGroupPresentation(graph, null, "doc", "0xbob", { stated: 1, from: 0, until: 100 }, 10).allowed,
      false,
    );
    const early = checkGroupPresentation(graph, null, "doc", "0xbob", { stated: 1, from: 0, until: 100 }, 1);
    assert.equal(early.allowed, true);
    assert.equal(early.reason, "delegate");
    assert.equal(graph.seeGrants("doc")[0]?.until, 5);
  }
});

test("a corrupt party signature does not drop a valid cancel", () => {
  const live = liveGraph();
  const cancelled = liveGraph();
  cancelled.cancelMembership("0xalice", "same-group", "0xalice/ops", "0xbob", secret("0xalice").privateKey);
  const key = `same-group${"\u0000"}${aclKey("0xalice/ops")}${"\u0000"}0xbob`;
  const row = cancelled.memberships.get(key);
  row.member.signature = new Uint8Array(64);

  const fromCancel = openGraph();
  fromCancel.putObject("doc", "0xalice");
  fromCancel.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  fromCancel.mergeFrom(cancelled);
  fromCancel.mergeFrom(live);

  const fromLive = openGraph();
  fromLive.putObject("doc", "0xalice");
  fromLive.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  fromLive.mergeFrom(live);
  fromLive.mergeFrom(cancelled);

  for (const graph of [fromCancel, fromLive]) {
    const result = checkGroupSee(graph, "same-group", "doc", "0xbob", 1);
    assert.equal(result.allowed, false);
    assert.equal(result.reason, "cancelled");
  }
});
