import assert from "node:assert/strict";
import { Plane, SociaclError } from "../src/index.js";
import {
  MemorySeeAcl,
  checkSee,
  encodeKey,
  itemSoul,
  userSoul,
  cancelSee,
  applySeeGrant,
} from "../src/gun.js";
import {
  MemoryDelegateAcl,
  checkDelegate,
  remintCapability,
  isSiteObjectId,
} from "../src/ir.js";

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

{
  const plane = mesh();
  assert.equal(plane.check("read", "panopticon", "bob", "same-network").allowed, true);
  assert.equal(plane.check("read", "panopticon", "mallory", "same-network").allowed, false);
  assert.equal(plane.remint("panopticon", "bob"), "remint");
  plane.censure("alice", "panopticon", "bob", "active-sabotage");
  assert.equal(plane.isMember("bob", "panopticon"), false);
  assert.equal(plane.audit("panopticon").length, 1);
}

{
  const plane = new Plane();
  plane.addPerson("alice");
  plane.addPerson("bob");
  plane.addObject("doc", "alice");
  plane.setObjectProperty("doc", "predicate", "posix-mode");
  plane.setObjectProperty("doc", "group", "ops");
  plane.setObjectProperty("doc", "mode", "0640");
  plane.addGroup("ops");
  plane.jointlyState("bob", "ops", "member-of");
  assert.equal(plane.check("read", "doc", "alice", "posix-mode").allowed, true);
  assert.equal(plane.check("read", "doc", "bob", "posix-mode").allowed, true);
  plane.addPerson("carol");
  assert.equal(plane.check("read", "doc", "carol", "posix-mode").allowed, false);
}

{
  const plane = new Plane();
  plane.addPerson("alice");
  plane.addPerson("bob");
  plane.addPerson("executor");
  plane.addObject("doc", "alice");
  plane.writeWill("will secret for object doc\nwritten-by alice\ndestroy if-no-heir keys\n");
  assert.equal(plane.discover("doc"), "stay-secret");
  assert.throws(() => plane.elect("doc"), SociaclError);
  assert.equal(plane.destroy("doc"), "destroy");
}

{
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
}

{
  const acl = new MemorySeeAcl();
  const object = itemSoul("rss3:act/1#x");
  assert.equal(encodeKey("rss3:act/1#x"), "rss3:act/1_x");
  assert.equal(userSoul("0xalice"), "s3rch/users/0xalice");
  acl.putObject(object, "0xalice");
  applySeeGrant(acl, "0xalice", {
    claimId: object,
    accessor: "0xbob",
    from: 0,
    until: 100,
  });
  assert.equal(checkSee(acl, object, "0xalice", 10).allowed, true);
  assert.equal(checkSee(acl, object, "0xbob", 10).allowed, true);
  assert.equal(checkSee(acl, object, "0xbob", 100).allowed, false);
  cancelSee(acl, "0xalice", "0xbob", object);
  assert.equal(checkSee(acl, object, "0xbob", 10).allowed, false);
  assert.equal(checkSee(acl, "s3rch/meta", "0xalice", 10).allowed, false);
}

{
  assert.equal(isSiteObjectId("site:alpha"), true);
  assert.equal(isSiteObjectId("site:alpha:ir"), true);
  assert.equal(isSiteObjectId("site:alpha:host"), false);
  const acl = new MemoryDelegateAcl();
  acl.putObject("site:alpha:ir", "alice");
  acl.stateDelegateGrant("alice", {
    object: "site:alpha:ir",
    accessor: "bob",
    mask: "execute",
  });
  assert.equal(checkDelegate(acl, "site:alpha:ir", "alice", "write", 1).allowed, true);
  assert.equal(checkDelegate(acl, "site:alpha:ir", "bob", "execute", 1).allowed, true);
  assert.equal(checkDelegate(acl, "site:alpha:ir", "bob", "read", 1).allowed, false);
  assert.deepEqual(remintCapability(acl, "site:alpha:ir", "bob", "execute", 1), {
    refreshed: true,
  });
}

console.log("ok");
