import assert from "node:assert/strict";
import { test } from "node:test";
import {
  MemoryGroupGraph,
  checkGroupPresentation,
  checkGroupSee,
  membershipSoul,
  objectSetSoul,
  snapshotUnderstatesGroup,
} from "../src/group.js";

function liveGraph() {
  const graph = new MemoryGroupGraph();
  graph.putObject("doc", "0xalice");
  graph.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  graph.nameObjectSet("0xalice", "doc", "same-group", "0xalice/ops");
  graph.stateMembership("0xbob", "same-group", "0xalice/ops", "0xbob");
  graph.stateMembership("0xalice", "same-group", "0xalice/ops", "0xbob");
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
  const graph = new MemoryGroupGraph();
  graph.putObject("doc", "0xalice");
  graph.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  graph.nameObjectSet("0xalice", "doc", "same-group", "0xalice/ops");
  graph.stateMembership("0xbob", "same-group", "0xalice/ops", "0xbob");
  assert.equal(graph.membership("same-group", "0xalice/ops", "0xbob")?.stated, 0);
  assert.equal(checkGroupSee(graph, "same-group", "doc", "0xbob", 5).reason, "missing");
});

test("named-circle does not inherit a same-group edge", () => {
  const graph = new MemoryGroupGraph();
  graph.putObject("album", "0xalice");
  graph.recordSetOwner("0xalice", "named-circle", "0xalice/friends");
  graph.recordSetOwner("0xalice", "same-group", "0xalice/friends");
  graph.nameObjectSet("0xalice", "album", "named-circle", "0xalice/friends");
  graph.stateMembership("0xbob", "same-group", "0xalice/friends", "0xbob");
  graph.stateMembership("0xalice", "same-group", "0xalice/friends", "0xbob");
  assert.equal(checkGroupSee(graph, "named-circle", "album", "0xbob", 0).allowed, false);
  graph.stateMembership("0xbob", "named-circle", "0xalice/friends", "0xbob");
  graph.stateMembership("0xalice", "named-circle", "0xalice/friends", "0xbob");
  assert.equal(checkGroupSee(graph, "named-circle", "album", "0xbob", 0).reason, "named-circle");
});

test("hop alone never allows and a cancel is immediate", () => {
  const hop = { channel: "convention-badge" };
  const graph = new MemoryGroupGraph();
  graph.putObject("doc", "0xalice");
  const alone = checkGroupSee(graph, "same-group", "doc", "0xcarol", 1, null, hop);
  assert.equal(alone.allowed, false);
  assert.equal(alone.hop, hop);

  const live = liveGraph();
  const factored = checkGroupSee(graph, "same-group", "doc", "0xbob", 1, null, hop);
  assert.equal(factored.allowed, false);
  const named = checkGroupSee(live, "same-group", "doc", "0xbob", 1, null, hop);
  assert.equal(named.allowed, true);
  live.cancelMembership("0xalice", "same-group", "0xalice/ops", "0xbob");
  const after = checkGroupSee(live, "same-group", "doc", "0xbob", 1, null, hop);
  assert.equal(after.allowed, false);
  assert.equal(after.reason, "cancelled");
});

test("membership in one set does not grant another", () => {
  const graph = liveGraph();
  graph.recordSetOwner("0xalice", "same-group", "0xalice/ops-core");
  graph.nameObjectSet("0xalice", "doc", "same-group", "0xalice/ops-core");
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

  const plain = new MemoryGroupGraph();
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
  graph.cancelMembership("0xalice", "same-group", "0xalice/ops", "0xbob");
  graph.cancelMembership("0xalice", "same-group", "0xalice/ops", "0xbob");
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
  graph.nameObjectSet("0xalice", "doc", "same-group", "0xalice/labs");
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
  graph.cancelMembership("0xbob", "same-group", "0xalice/ops", "0xbob");
  graph.stateMembership("0xbob", "same-group", "0xalice/ops", "0xbob");
  assert.equal(checkGroupSee(graph, "same-group", "doc", "0xbob", 1).reason, "cancelled");
  graph.stateMembership("0xalice", "same-group", "0xalice/ops", "0xbob");
  assert.equal(checkGroupSee(graph, "same-group", "doc", "0xbob", 1).allowed, true);
});

test("closed objects and a cleared edge fail closed", () => {
  const graph = liveGraph();
  assert.equal(checkGroupSee(graph, "same-group", "s3rch/meta", "0xalice", 1).reason, "meta");
  assert.equal(checkGroupSee(graph, "same-group", "s3rch/acl/0xalice", "0xalice", 1).reason, "acl");
  graph.clearObjectSet("0xalice", "doc");
  assert.equal(checkGroupSee(graph, "same-group", "doc", "0xbob", 1).reason, "cancelled");
});

function stateBoth(graph, predicate, setId, accessor) {
  graph.stateMembership(accessor, predicate, setId, accessor);
  graph.stateMembership("0xalice", predicate, setId, accessor);
}

test("merge drops a membership from a conflicting set owner", () => {
  const alice = new MemoryGroupGraph();
  alice.putObject("doc", "0xalice");
  alice.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  alice.nameObjectSet("0xalice", "doc", "same-group", "0xalice/ops");

  const mallory = new MemoryGroupGraph();
  assert.throws(() => mallory.recordSetOwner("0xmallory", "same-group", "0xalice/ops"), /not bound/);
  mallory.recordSetOwner("0xmallory", "same-group", "0xmallory/ops");
  mallory.stateMembership("0xmallory", "same-group", "0xmallory/ops", "0xmallory");

  alice.mergeFrom(mallory);
  assert.equal(alice.ownerOfSet("same-group", "0xalice/ops"), "0xalice");
  assert.equal(alice.membership("same-group", "0xalice/ops", "0xbob"), undefined);
  assert.equal(checkGroupSee(alice, "same-group", "doc", "0xbob", 1).allowed, false);

  const sameOwner = new MemoryGroupGraph();
  sameOwner.recordSetOwner("s3rch/users/0xalice", "same-group", "0xalice/ops");
  stateBoth(sameOwner, "same-group", "0xalice/ops", "0xbob");
  alice.mergeFrom(sameOwner);
  assert.equal(alice.membership("same-group", "0xalice/ops", "0xbob")?.stated, 1);
});

test("equal ham membership merge keeps the cancel", () => {
  const cancelled = liveGraph();
  cancelled.cancelMembership("0xalice", "same-group", "0xalice/ops", "0xbob");
  const restated = liveGraph();
  restated.stateMembership("0xbob", "same-group", "0xalice/ops", "0xbob");
  assert.equal(
    cancelled.membership("same-group", "0xalice/ops", "0xbob")?.hamState,
    restated.membership("same-group", "0xalice/ops", "0xbob")?.hamState,
  );
  const fromCancel = liveGraph();
  fromCancel.cancelMembership("0xalice", "same-group", "0xalice/ops", "0xbob");
  fromCancel.mergeFrom(restated);
  const fromRestate = liveGraph();
  fromRestate.stateMembership("0xbob", "same-group", "0xalice/ops", "0xbob");
  fromRestate.mergeFrom(cancelled);
  for (const graph of [fromCancel, fromRestate]) {
    assert.equal(graph.membership("same-group", "0xalice/ops", "0xbob")?.stated, 0);
    assert.equal(checkGroupSee(graph, "same-group", "doc", "0xbob", 1).allowed, false);
  }
});

test("equal ham object-set merge keeps privilege-down", () => {
  const cleared = liveGraph();
  cleared.clearObjectSet("0xalice", "doc");
  const renamed = liveGraph();
  renamed.nameObjectSet("0xalice", "doc", "same-group", "0xalice/labs");
  assert.equal(cleared.objectSet("doc")?.hamState, renamed.objectSet("doc")?.hamState);
  const fromClear = liveGraph();
  fromClear.clearObjectSet("0xalice", "doc");
  fromClear.mergeFrom(renamed);
  const fromRename = liveGraph();
  fromRename.nameObjectSet("0xalice", "doc", "same-group", "0xalice/labs");
  fromRename.mergeFrom(cleared);
  for (const graph of [fromClear, fromRename]) {
    assert.equal(graph.objectSet("doc")?.stated, 0);
    assert.equal(checkGroupSee(graph, "same-group", "doc", "0xbob", 1).allowed, false);
  }
});

test("merge drops an object-set row from a conflicting object owner", () => {
  const alice = new MemoryGroupGraph();
  alice.putObject("doc", "0xalice");
  alice.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  stateBoth(alice, "same-group", "0xalice/ops", "0xbob");

  const mallory = new MemoryGroupGraph();
  mallory.putObject("doc", "0xmallory");
  mallory.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  mallory.nameObjectSet("0xmallory", "doc", "same-group", "0xalice/ops");

  alice.mergeFrom(mallory);
  assert.equal(alice.ownerOf("doc"), "0xalice");
  assert.equal(alice.objectSet("doc"), undefined);
  assert.equal(checkGroupSee(alice, "same-group", "doc", "0xbob", 1).allowed, false);
});

test("clear of an unseen object-set writes a tombstone", () => {
  const clearer = new MemoryGroupGraph();
  clearer.putObject("doc", "0xalice");
  clearer.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  stateBoth(clearer, "same-group", "0xalice/ops", "0xbob");
  clearer.clearObjectSet("0xalice", "doc");
  assert.equal(clearer.objectSet("doc")?.stated, 0);
  assert.equal(clearer.objectSet("doc")?.hamState, 1);

  const peer = new MemoryGroupGraph();
  peer.putObject("doc", "0xalice");
  peer.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  peer.nameObjectSet("0xalice", "doc", "same-group", "0xalice/ops");
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
  ownerPeer.cancelMembership("0xalice", "same-group", "0xalice/ops", "0xbob");
  const memberPeer = liveGraph();
  memberPeer.stateMembership("0xbob", "same-group", "0xalice/ops", "0xbob");
  memberPeer.stateMembership("0xbob", "same-group", "0xalice/ops", "0xbob");
  assert.equal(memberPeer.membership("same-group", "0xalice/ops", "0xbob")?.stated, 1);
  assert.ok(
    (memberPeer.membership("same-group", "0xalice/ops", "0xbob")?.hamState ?? 0) >
      (ownerPeer.membership("same-group", "0xalice/ops", "0xbob")?.hamState ?? 0),
  );
  const fromOwner = liveGraph();
  fromOwner.cancelMembership("0xalice", "same-group", "0xalice/ops", "0xbob");
  fromOwner.mergeFrom(memberPeer);
  const fromMember = liveGraph();
  fromMember.stateMembership("0xbob", "same-group", "0xalice/ops", "0xbob");
  fromMember.stateMembership("0xbob", "same-group", "0xalice/ops", "0xbob");
  fromMember.mergeFrom(ownerPeer);
  for (const graph of [fromOwner, fromMember]) {
    assert.equal(graph.membership("same-group", "0xalice/ops", "0xbob")?.stated, 0);
    assert.equal(checkGroupSee(graph, "same-group", "doc", "0xbob", 1).reason, "cancelled");
  }
});

test("mergeFrom copies objects and ordinary see grants", () => {
  const source = new MemoryGroupGraph();
  source.putObject("doc", "0xalice");
  source.putObject("claim-1", "0xalice");
  source.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  source.nameObjectSet("0xalice", "doc", "same-group", "0xalice/ops");
  stateBoth(source, "same-group", "0xalice/ops", "0xbob");
  source.stateSeeGrant("0xalice", { object: "claim-1", accessor: "0xbob", from: 0, until: 80 });

  const fresh = new MemoryGroupGraph();
  fresh.mergeFrom(source);
  assert.equal(fresh.ownerOf("doc"), "0xalice");
  assert.equal(checkGroupSee(fresh, "same-group", "doc", "0xbob", 1).allowed, true);
  const ordinary = checkGroupPresentation(fresh, null, "claim-1", "0xbob", { stated: 1, from: 0, until: 80 }, 10);
  assert.equal(ordinary.allowed, true);
  assert.equal(ordinary.reason, "delegate");

  const local = new MemoryGroupGraph();
  local.putObject("doc", "0xalice");
  const other = new MemoryGroupGraph();
  other.putObject("doc", "0xmallory");
  local.mergeFrom(other);
  assert.equal(local.ownerOf("doc"), "0xalice");
});

test("cancel of an unseen membership dominates a higher restate", () => {
  const clearer = new MemoryGroupGraph();
  clearer.putObject("doc", "0xalice");
  clearer.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  clearer.nameObjectSet("0xalice", "doc", "same-group", "0xalice/ops");
  clearer.cancelMembership("0xalice", "same-group", "0xalice/ops", "0xbob");

  const peer = new MemoryGroupGraph();
  peer.putObject("doc", "0xalice");
  peer.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  peer.nameObjectSet("0xalice", "doc", "same-group", "0xalice/ops");
  stateBoth(peer, "same-group", "0xalice/ops", "0xbob");
  peer.stateMembership("0xbob", "same-group", "0xalice/ops", "0xbob");
  peer.stateMembership("0xbob", "same-group", "0xalice/ops", "0xbob");
  peer.stateMembership("0xalice", "same-group", "0xalice/ops", "0xbob");
  peer.stateMembership("0xalice", "same-group", "0xalice/ops", "0xbob");
  assert.equal(peer.membership("same-group", "0xalice/ops", "0xbob")?.stated, 1);
  assert.ok(
    (peer.membership("same-group", "0xalice/ops", "0xbob")?.hamState ?? 0) >
      (clearer.membership("same-group", "0xalice/ops", "0xbob")?.hamState ?? 0),
  );

  const fromClear = new MemoryGroupGraph();
  fromClear.putObject("doc", "0xalice");
  fromClear.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  fromClear.nameObjectSet("0xalice", "doc", "same-group", "0xalice/ops");
  fromClear.cancelMembership("0xalice", "same-group", "0xalice/ops", "0xbob");
  fromClear.mergeFrom(peer);
  const fromPeer = new MemoryGroupGraph();
  fromPeer.putObject("doc", "0xalice");
  fromPeer.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  fromPeer.nameObjectSet("0xalice", "doc", "same-group", "0xalice/ops");
  stateBoth(fromPeer, "same-group", "0xalice/ops", "0xbob");
  fromPeer.stateMembership("0xbob", "same-group", "0xalice/ops", "0xbob");
  fromPeer.stateMembership("0xbob", "same-group", "0xalice/ops", "0xbob");
  fromPeer.stateMembership("0xalice", "same-group", "0xalice/ops", "0xbob");
  fromPeer.stateMembership("0xalice", "same-group", "0xalice/ops", "0xbob");
  fromPeer.mergeFrom(clearer);
  for (const graph of [fromClear, fromPeer]) {
    assert.equal(graph.membership("same-group", "0xalice/ops", "0xbob")?.stated, 0);
    assert.equal(checkGroupSee(graph, "same-group", "doc", "0xbob", 1).reason, "cancelled");
  }
  fromClear.stateMembership("0xbob", "same-group", "0xalice/ops", "0xbob");
  fromClear.stateMembership("0xalice", "same-group", "0xalice/ops", "0xbob");
  assert.equal(checkGroupSee(fromClear, "same-group", "doc", "0xbob", 1).allowed, true);
});

test("a predictable set id is not owned by the first peer", () => {
  const early = new MemoryGroupGraph();
  assert.throws(() => early.recordSetOwner("0xmallory", "same-group", "ops"), /not bound/);
  const verifier = new MemoryGroupGraph();
  verifier.putObject("doc", "0xalice");
  const mallory = new MemoryGroupGraph();
  mallory.recordSetOwner("0xmallory", "same-group", "0xmallory/ops");
  mallory.stateMembership("0xmallory", "same-group", "0xmallory/ops", "0xmallory");
  verifier.mergeFrom(mallory);
  verifier.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  verifier.nameObjectSet("0xalice", "doc", "same-group", "0xalice/ops");
  assert.equal(verifier.ownerOfSet("same-group", "0xalice/ops"), "0xalice");
  assert.equal(verifier.ownerOfSet("same-group", "ops"), undefined);
  assert.equal(checkGroupSee(verifier, "same-group", "doc", "0xmallory", 1).allowed, false);
});

test("object owner checks use the canonical object key", () => {
  const alice = new MemoryGroupGraph();
  alice.putObject("foo/bar", "0xalice");
  alice.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  stateBoth(alice, "same-group", "0xalice/ops", "0xbob");
  const mallory = new MemoryGroupGraph();
  mallory.putObject("foo_bar", "0xmallory");
  mallory.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  mallory.nameObjectSet("0xmallory", "foo_bar", "same-group", "0xalice/ops");
  alice.mergeFrom(mallory);
  assert.equal(alice.ownerOf("foo/bar"), "0xalice");
  assert.equal(alice.ownerOf("foo_bar"), "0xalice");
  assert.equal(alice.objectSet("foo/bar"), undefined);
  assert.equal(checkGroupSee(alice, "same-group", "foo/bar", "0xbob", 1).allowed, false);
});

test("mergeFrom drops a see grant from a conflicting object owner", () => {
  const alice = new MemoryGroupGraph();
  alice.putObject("doc", "0xalice");
  const mallory = new MemoryGroupGraph();
  mallory.putObject("doc", "0xmallory");
  mallory.stateSeeGrant("0xmallory", { object: "doc", accessor: "0xbob", from: 0, until: 80 });
  alice.mergeFrom(mallory);
  assert.equal(alice.ownerOf("doc"), "0xalice");
  const ordinary = checkGroupPresentation(alice, null, "doc", "0xbob", { stated: 1, from: 0, until: 80 }, 1);
  assert.equal(ordinary.allowed, false);
});

test("stateSeeGrant accepts claimId", () => {
  const graph = new MemoryGroupGraph();
  graph.putObject("claim-1", "0xalice");
  graph.stateSeeGrant("0xalice", { claimId: "claim-1", accessor: "0xbob", from: 0, until: 80 });
  const ordinary = checkGroupPresentation(graph, null, "claim-1", "0xbob", { stated: 1, from: 0, until: 80 }, 10);
  assert.equal(ordinary.allowed, true);
  assert.equal(ordinary.reason, "delegate");
});

test("checkGroupSee reads membership through the graph interface", () => {
  const graph = {
    ownerOf: () => "0xalice",
    ownerOfSet: () => "0xalice",
    objectSet: () => ({ object: "doc", predicate: "same-group", setId: "0xalice/ops", stated: 1, hamState: 1 }),
    membership(predicate, setId, accessor) {
      assert.equal(predicate, "same-group");
      assert.equal(setId, "0xalice/ops");
      assert.equal(accessor, "0xbob");
      return { predicate, setId, accessor, stated: 1, hamState: 2 };
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
  });
  assert.equal(checkGroupSee(graph, "same-group", "doc", "0xbob", 1).reason, "cancelled");
});

test("a stated-0 object-set does not block an ordinary see grant", () => {
  const graph = liveGraph();
  graph.stateSeeGrant("0xalice", { object: "doc", accessor: "0xcarol", from: 0, until: 80 });
  graph.clearObjectSet("0xalice", "doc");
  assert.equal(graph.objectSet("doc")?.stated, 0);
  const ordinary = checkGroupPresentation(graph, null, "doc", "0xcarol", { stated: 1, from: 0, until: 80 }, 1);
  assert.equal(ordinary.allowed, true);
  assert.equal(ordinary.reason, "delegate");
});

test("unseen object-set clear dominates a remote edge advanced twice", () => {
  const peer = liveGraph();
  peer.nameObjectSet("0xalice", "doc", "same-group", "0xalice/labs");
  peer.nameObjectSet("0xalice", "doc", "same-group", "0xalice/ops");
  assert.equal(peer.objectSet("doc")?.stated, 1);
  assert.ok((peer.objectSet("doc")?.hamState ?? 0) >= 3);

  const clearer = new MemoryGroupGraph();
  clearer.putObject("doc", "0xalice");
  clearer.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  stateBoth(clearer, "same-group", "0xalice/ops", "0xbob");
  clearer.clearObjectSet("0xalice", "doc");
  assert.equal(clearer.objectSet("doc")?.stated, 0);
  assert.ok((clearer.objectSet("doc")?.hamState ?? 0) < (peer.objectSet("doc")?.hamState ?? 0));

  const fromClear = new MemoryGroupGraph();
  fromClear.putObject("doc", "0xalice");
  fromClear.recordSetOwner("0xalice", "same-group", "0xalice/ops");
  stateBoth(fromClear, "same-group", "0xalice/ops", "0xbob");
  fromClear.clearObjectSet("0xalice", "doc");
  fromClear.mergeFrom(peer);

  const fromPeer = liveGraph();
  fromPeer.nameObjectSet("0xalice", "doc", "same-group", "0xalice/labs");
  fromPeer.nameObjectSet("0xalice", "doc", "same-group", "0xalice/ops");
  fromPeer.mergeFrom(clearer);

  for (const graph of [fromClear, fromPeer]) {
    assert.equal(graph.objectSet("doc")?.stated, 0);
    assert.equal(checkGroupSee(graph, "same-group", "doc", "0xbob", 1).reason, "cancelled");
  }

  fromClear.nameObjectSet("0xalice", "doc", "same-group", "0xalice/ops");
  assert.equal(fromClear.objectSet("doc")?.stated, 1);
  assert.equal(checkGroupSee(fromClear, "same-group", "doc", "0xbob", 1).allowed, true);
});
