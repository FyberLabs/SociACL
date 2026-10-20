import assert from "node:assert/strict";
import { test } from "node:test";
import { admitMembership, checkGroupSee, MemoryGroupGraph } from "../src/group.js";

test("a bare history array is missing-history for group admission", () => {
  const graph = new MemoryGroupGraph();
  const got = admitMembership(graph, { sig: "aa" }, []);
  assert.equal(got.ok, false);
  if (!got.ok) assert.equal(got.reason, "missing-history");
});

test("alice/friends is not a minted set id", () => {
  const graph = new MemoryGroupGraph();
  const got = admitMembership(graph, {
    role: "member",
    predicate: "same-group",
    set: "alice/friends",
    member: "p",
    setOwner: "p",
    stated: 1,
    hamState: 1,
    issuedAt: 1,
    cancels: [],
    sig: "aa",
  }, { rotations: () => [], ctx: { now: 1 } });
  assert.equal(got.ok, false);
  if (!got.ok) assert.equal(got.reason, "bad-alphabet");
});

test("a hop alone does not grant group see", () => {
  const graph = new MemoryGroupGraph();
  const got = checkGroupSee(graph, "same-group", "chat_ab", "bob", 1, null, { channel: "convention-badge" });
  assert.equal(got.allowed, false);
  assert.equal(got.hop?.channel, "convention-badge");
});
