import assert from "node:assert/strict";
import { test } from "node:test";
import {
  MemoryDelegateAcl,
  cancelDelegate,
  checkDelegate,
  isSiteObjectId,
  remintCapability,
} from "../src/ir.js";

test("site object ids fail closed on :host and :incident:", () => {
  assert.equal(isSiteObjectId("site:alpha"), true);
  assert.equal(isSiteObjectId("site:alpha:ir"), true);
  assert.equal(isSiteObjectId("site:alpha:host"), false);
  assert.equal(isSiteObjectId("site:alpha:incident:1"), false);
});

test("checkDelegate: owner, mask, remint, cancel", () => {
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
  cancelDelegate(acl, "alice", "bob", "site:alpha:ir");
  assert.equal(checkDelegate(acl, "site:alpha:ir", "bob", "execute", 1).allowed, false);
  assert.deepEqual(remintCapability(acl, "site:alpha:ir", "bob", "execute", 1), {
    denied: true,
  });
});
