import assert from "node:assert/strict";
import { test } from "node:test";
import { Plane, SociaclError } from "../src/index.js";

test("posix-mode owner / group / other", () => {
  const plane = new Plane();
  plane.addPerson("alice");
  plane.addPerson("bob");
  plane.addPerson("carol");
  plane.addGroup("ops");
  plane.addObject("doc", "alice");
  plane.setObjectProperty("doc", "predicate", "posix-mode");
  plane.setObjectProperty("doc", "group", "ops");
  plane.setObjectProperty("doc", "mode", "0640");
  plane.jointlyState("bob", "ops", "member-of");
  assert.equal(plane.check("read", "doc", "alice", "posix-mode").allowed, true);
  assert.equal(plane.check("read", "doc", "bob", "posix-mode").allowed, true);
  assert.equal(plane.check("read", "doc", "carol", "posix-mode").allowed, false);
});

test("named-circle is hopcap 1", () => {
  const plane = new Plane();
  plane.addPerson("alice");
  plane.addPerson("bob");
  plane.addPerson("carol");
  plane.addCircle("friends");
  plane.addObject("album", "alice");
  plane.setObjectProperty("album", "predicate", "named-circle");
  plane.setObjectProperty("album", "circle", "friends");
  plane.jointlyState("bob", "friends", "in-circle");
  assert.equal(plane.check("read", "album", "bob", "named-circle").allowed, true);
  assert.equal(plane.check("read", "album", "carol", "named-circle").allowed, false);
});

test("trustee only when the object names it", () => {
  const plane = new Plane();
  plane.addPerson("alice");
  plane.addPerson("bob");
  plane.addObject("vault", "alice");
  plane.setObjectProperty("vault", "predicate", "trustee");
  plane.jointlyState("bob", "vault", "trustee");
  const result = plane.check("read", "vault", "bob", "trustee");
  assert.equal(result.allowed, true);
  assert.equal(result.reason, "trustee");
});

test("delegate execute-without-read, then undelegate", () => {
  const plane = new Plane();
  plane.addPerson("alice");
  plane.addPerson("bob");
  plane.addObject("doc", "alice");
  plane.setObjectProperty("doc", "predicate", "delegate");
  plane.jointlyDelegate("alice", "bob", "doc", "execute");
  assert.equal(plane.check("execute", "doc", "bob", "delegate").allowed, true);
  assert.equal(plane.check("read", "doc", "bob", "delegate").allowed, false);
  plane.undelegate("alice", "bob", "doc");
  assert.equal(plane.check("execute", "doc", "bob", "delegate").allowed, false);
});

test("privilege-up waits; unstate is immediate", () => {
  const plane = new Plane();
  plane.addPerson("alice");
  plane.addPerson("bob");
  plane.addGroup("ops");
  plane.addObject("doc", "alice");
  plane.setObjectProperty("doc", "predicate", "same-group");
  plane.setObjectProperty("doc", "group", "ops");
  plane.stateEdge("bob", "bob", "ops", "member-of");
  assert.equal(plane.check("read", "doc", "bob", "same-group").allowed, false);
  plane.stateEdge("ops", "bob", "ops", "member-of");
  assert.equal(plane.check("read", "doc", "bob", "same-group").allowed, false);
  plane.setNow(plane.now() + 1);
  assert.equal(plane.check("read", "doc", "bob", "same-group").allowed, true);
  plane.unstateEdge("bob", "bob", "ops", "member-of");
  assert.equal(plane.check("read", "doc", "bob", "same-group").allowed, false);
});

test("Discover / Destroy on stay-secret; Elect refuses while owner is live", () => {
  const plane = new Plane();
  plane.addPerson("alice");
  plane.addPerson("bob");
  plane.addPerson("executor");
  plane.addObject("doc", "alice");
  plane.writeWill("will secret for object doc\nwritten-by alice\ndestroy if-no-heir keys\n");
  assert.equal(plane.discover("doc"), "stay-secret");
  assert.throws(() => plane.elect("doc"), SociaclError);
  assert.equal(plane.destroy("doc"), "destroy");
});

test("Elect is pending until commit after the wait", () => {
  const plane = new Plane();
  plane.addPerson("alice");
  plane.addPerson("bob");
  plane.addPerson("executor");
  plane.addObject("doc", "alice");
  plane.writeWill(
    "will heir-doc for object doc\nwritten-by alice\ncancelable-by executor\ndiscover heir bob\n",
  );
  plane.setAuthn("alice", "gone");
  assert.equal(plane.elect("doc"), "pending bob");
  assert.equal(plane.check("read", "doc", "bob", "owner").allowed, false);
  assert.throws(() => plane.commitElect("doc"), SociaclError);
  plane.setNow(plane.now() + 10);
  assert.equal(plane.commitElect("doc"), "installed bob");
  assert.equal(plane.check("read", "doc", "bob", "owner").allowed, true);
});

test("live canceler stops a pending Elect", () => {
  const plane = new Plane();
  plane.addPerson("alice");
  plane.addPerson("bob");
  plane.addPerson("executor");
  plane.addObject("doc", "alice");
  plane.writeWill(
    "will heir-doc for object doc\nwritten-by alice\ncancelable-by executor\ndiscover heir bob\n",
  );
  plane.setAuthn("alice", "gone");
  plane.elect("doc");
  assert.equal(plane.cancelWill("doc", "executor"), "canceled");
  plane.setNow(plane.now() + 10);
  assert.throws(() => plane.commitElect("doc"), SociaclError);
  assert.equal(plane.check("read", "doc", "alice", "owner").allowed, true);
});
