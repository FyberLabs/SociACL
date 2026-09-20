import assert from "node:assert/strict";
import { test } from "node:test";
import { Plane, SociaclError } from "../src/index.js";

function mesh() {
  const plane = new Plane();
  plane.addPerson("alice");
  plane.addPerson("bob");
  plane.addPerson("mallory");
  plane.addNetwork("panopticon");
  plane.addObject("panopticon", "alice");
  plane.setObjectProperty("panopticon", "predicate", "same-network");
  plane.admitMember("alice", "panopticon");
  plane.admitMember("bob", "panopticon");
  return plane;
}

test("same-network allows a member and denies an outsider", () => {
  const plane = mesh();
  assert.equal(plane.check("read", "panopticon", "bob", "same-network").allowed, true);
  assert.equal(plane.check("read", "panopticon", "mallory", "same-network").allowed, false);
  assert.equal(plane.remint("panopticon", "bob"), "remint");
});

test("one-sided in-network is not a grant", () => {
  const plane = new Plane();
  plane.addPerson("alice");
  plane.addPerson("bob");
  plane.addNetwork("mesh");
  plane.addObject("mesh", "alice");
  plane.setObjectProperty("mesh", "predicate", "same-network");
  plane.stateEdge("bob", "bob", "mesh", "in-network");
  assert.equal(plane.isMember("bob", "mesh"), false);
  assert.equal(plane.check("read", "mesh", "bob", "same-network").allowed, false);
});

test("owner censure for sabotage drops the member", () => {
  const plane = mesh();
  plane.censure("alice", "panopticon", "bob", "active-sabotage");
  assert.equal(plane.isMember("bob", "panopticon"), false);
  assert.equal(plane.audit("panopticon").length, 1);
});

test("member may self-leave", () => {
  const plane = mesh();
  plane.censure("bob", "panopticon", "bob", "self-leave");
  assert.equal(plane.isMember("bob", "panopticon"), false);
});

test("member cannot censure another", () => {
  const plane = mesh();
  assert.throws(
    () => plane.censure("bob", "panopticon", "alice", "policy-violation"),
    SociaclError,
  );
  assert.equal(plane.isMember("alice", "panopticon"), true);
});

test("owner cannot record self-leave for another", () => {
  const plane = mesh();
  assert.throws(
    () => plane.censure("alice", "panopticon", "bob", "self-leave"),
    SociaclError,
  );
  assert.equal(plane.isMember("bob", "panopticon"), true);
});

test("outsider cannot censure", () => {
  const plane = mesh();
  assert.throws(
    () => plane.censure("mallory", "panopticon", "bob", "active-sabotage"),
    SociaclError,
  );
});
