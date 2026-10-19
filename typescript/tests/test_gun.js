import assert from "node:assert/strict";
import { test } from "node:test";
import { checkSee } from "../src/gun.js";
import { seeAccessorEdge, seeObjectEdge } from "../src/see.js";
import {
  MemorySeeAcl,
  aclKey,
  aclSoul,
  applySeeGrant,
  applyPostGrant,
  cancelPost,
  cancelSee,
  checkSeeGrant,
  checkSeeLabel,
  encodeKey,
  grantSoul,
  itemSoul,
  userSoul,
} from "../src/legacy/gun-legacy.js";
import { canonicalAccessorId, postGrantKey, postSoul, sameObjectId } from "../src/legacy/post-label.js";

test("souls match the s3r.ch consume contract", () => {
  assert.equal(encodeKey("rss3:act/1#x"), "rss3:act/1~2x");
  assert.equal(itemSoul("rss3:act/1#x"), "s3rch/items/rss3:act/1~2x");
  assert.equal(userSoul("0xalice"), "s3rch/users/0xalice");
});

test("checkSee: owner and live grant; hint never allows", () => {
  const acl = new MemorySeeAcl();
  const object = itemSoul("rss3:act/1#x");
  acl.putObject(object, "0xalice");
  applySeeGrant(acl, "0xalice", {
    claimId: object,
    accessor: "0xbob",
    from: 0,
    until: 100,
  });
  assert.equal(checkSeeLabel(acl, object, "0xalice", 10).allowed, true);
  assert.equal(checkSeeLabel(acl, object, "0xbob", 10).allowed, true);
  assert.equal(
    checkSeeLabel(acl, object, "0xcarol", 10, { principal: "0xcarol", target: object }).allowed,
    false,
  );
  assert.equal(checkSeeLabel(acl, object, "0xbob", 100).allowed, false);
  assert.equal(checkSeeLabel(acl, "s3rch/meta", "0xalice", 10).allowed, false);
});

test("checkSeeGrant ANDs the window; cancel is immediate", () => {
  const acl = new MemorySeeAcl();
  const object = itemSoul("ens:alice.eth");
  acl.putObject(object, "0xalice");
  const grant = { claimId: object, accessor: "0xbob", from: 10, until: 20 };
  applySeeGrant(acl, "0xalice", grant);
  assert.equal(checkSeeGrant(acl, grant, object, "0xbob", 5).allowed, false);
  assert.equal(checkSeeGrant(acl, grant, object, "0xbob", 10).allowed, true);
  cancelSee(acl, "0xalice", "0xbob", object);
  assert.equal(checkSeeLabel(acl, object, "0xbob", 10).allowed, false);
});

test("label post rows stay on the label graph until request migrates", () => {
  const acl = new MemorySeeAcl();
  const object = itemSoul("room:alpha");
  acl.putObject(object, "0xalice");
  applyPostGrant(acl, "0xalice", { object, accessor: "0xbob", from: 0, until: 80 });
  assert.equal(acl.postGrant(object, "0xbob").grant.stated, 1);
  applySeeGrant(acl, "0xalice", { claimId: object, accessor: "0xbob", from: 0, until: 80 });
  cancelPost(acl, "0xalice", "0xbob", object);
  assert.equal(acl.postGrant(object, "0xbob").grant.stated, 0);
  assert.equal(checkSeeLabel(acl, object, "0xbob", 10).allowed, true);
});

test("acl keys for dot, underscore, and slash stay distinct", () => {
  const dot = aclKey("room.alpha");
  const under = aclKey("room_alpha");
  const slash = aclKey("room/alpha");
  assert.notEqual(dot, under);
  assert.notEqual(dot, slash);
  assert.notEqual(under, slash);
  assert.equal(encodeKey("a/b"), "a/b");
  assert.notEqual(aclKey("a/b"), aclKey("a_b"));
});

test("a grant names one object and a gun chain is not the inner wallet", () => {
  const acl = new MemorySeeAcl();
  for (const object of ["room.alpha", "room_alpha", "room/alpha", "alpha", "room/chat/alpha"]) {
    acl.putObject(object, "0xalice");
  }
  const window = { accessor: "0xbob", from: 0, until: 100 };
  applySeeGrant(acl, "0xalice", { ...window, claimId: "room.alpha" });
  applySeeGrant(acl, "0xalice", { ...window, claimId: "alpha" });
  assert.equal(checkSeeLabel(acl, "room.alpha", "0xbob", 10).allowed, true);
  assert.equal(checkSeeLabel(acl, "alpha", "0xbob", 10).allowed, true);
  assert.equal(checkSeeLabel(acl, "room_alpha", "0xbob", 10).allowed, false);
  assert.equal(checkSeeLabel(acl, "room/alpha", "0xbob", 10).allowed, false);
  assert.equal(checkSeeLabel(acl, "room/chat/alpha", "0xbob", 10).allowed, false);
  const spoof = "0xattacker.get('s3rch').get('users').get('0xvictim')";
  assert.equal(canonicalAccessorId(spoof), null);
  assert.notEqual(canonicalAccessorId(spoof), "0xvictim");
  acl.putObject("doc", "0xvictim");
  assert.equal(checkSeeLabel(acl, "doc", spoof, 10).allowed, false);
  assert.equal(checkSeeLabel(acl, "doc", "0xvictim", 10).allowed, true);
});

test("a rejected principal is not a grant path", () => {
  const injected = "s3rch/acl/0xalice/doc/0xbob/x";
  assert.equal(grantSoul("0xalice", "doc", "0xbob/x"), null);
  assert.equal(grantSoul("0xalice/doc", "0xbob", "x"), null);
  assert.notEqual(grantSoul("0xalice", "doc", "0xbob/x"), injected);
  assert.equal(grantSoul("0xalice", "doc", "0xbob"), "s3rch/acl/0xalice/doc/0xbob");
  assert.equal(aclSoul("../meta"), null);
  assert.equal(canonicalAccessorId("a\u0000b"), null);
  assert.equal(postGrantKey("0xalice", "doc", "a\u0000b"), null);
  assert.notEqual(postGrantKey("0xalice", "doc", "a\u0000b"), "0xalice\0doc\0a\u0000b");
  assert.equal(postSoul("0xalice", "doc", "a\u0000b"), null);
  assert.equal(canonicalAccessorId("bob~name"), null);
  assert.equal(canonicalAccessorId("x~1get('s3rch')"), null);
  assert.equal(grantSoul("0xalice", "doc", "x~1get('s3rch')"), null);
  assert.equal(canonicalAccessorId("."), null);
  assert.equal(canonicalAccessorId(".."), null);
  assert.equal(canonicalAccessorId("0x bob"), null);
  assert.equal(canonicalAccessorId("a".repeat(257)), null);
  assert.equal(canonicalAccessorId("a".repeat(256)), "a".repeat(256));
  assert.equal(canonicalAccessorId("\uFEFF0xvictim"), null);
  assert.equal(canonicalAccessorId("0xvictim\uFEFF"), null);
  assert.equal(canonicalAccessorId("\u00850xvictim"), null);
  assert.equal(sameObjectId("\uFEFFroom", "room"), false);
  assert.equal(sameObjectId(" room ", "room"), false);
  assert.equal(canonicalAccessorId("..."), null);
  assert.equal(canonicalAccessorId("0x\ud800victim"), null);
  assert.equal(canonicalAccessorId("bob.name"), "bob.name");
  assert.equal(canonicalAccessorId("s3rch/users/0xbob"), "0xbob");
  assert.equal(canonicalAccessorId("s3rch/users/ 0xbob "), "0xbob");
  const acl = new MemorySeeAcl();
  acl.putObject("doc", "../meta");
  assert.equal(checkSeeLabel(acl, "doc", "a\u0000b", 10).allowed, false);
  assert.equal(checkSeeLabel(acl, "doc", "../meta", 10).allowed, false);
  assert.equal(checkSeeLabel(acl, "doc", "\uFEFF../meta", 10).allowed, false);
  acl.putObject("owned", "0xalice");
  assert.equal(checkSeeLabel(acl, "owned", "\uFEFF0xalice", 10).allowed, false);
  assert.equal(checkSeeLabel(acl, "owned", "0xalice\uFEFF", 10).allowed, false);
  assert.equal(checkSeeLabel(acl, "owned", "\u00850xalice", 10).allowed, false);
});

test("stored-id checkSee returns the edge reject and does not alias", () => {
  const acl = new MemorySeeAcl();
  acl.putObject("room.alpha", "0xalice");
  applySeeGrant(acl, "0xalice", { claimId: "room.alpha", accessor: "0xbob", from: 0, until: 100 });
  const folded = checkSee(acl, "room.alpha", "0xbob", 10);
  assert.equal(folded.allowed, false);
  assert.equal(folded.reason, "bad-alphabet");
  const chain = checkSee(
    acl,
    "chat_" + "11".repeat(16),
    "0xattacker.get('s3rch').get('users').get('0xvictim')",
    10,
  );
  assert.equal(chain.allowed, false);
  assert.equal(chain.reason, "gun-chain");
});

test("alias strings are an edge reject", () => {
  for (const value of ["room.alpha", "room_alpha", "room/alpha", "item-1", "doc", "room"]) {
    const parsed = seeObjectEdge(value);
    assert.equal(parsed.ok, false, value);
    if (!parsed.ok) assert.equal(parsed.reason, "bad-alphabet", value);
  }
  const reasons = {
    "0xbob": "bad-length",
    "0xalice": "bad-length",
    "0xbob/x": "bad-length",
    "0xattacker.get('s3rch').get('users').get('0xvictim')": "gun-chain",
    "x~1get('s3rch')": "gun-chain",
    "../meta": "bad-length",
    "...": "bad-length",
    "s3rch/users/0xbob": "bad-length",
  };
  for (const [value, reason] of Object.entries(reasons)) {
    const parsed = seeAccessorEdge(value);
    assert.equal(parsed.ok, false, value);
    if (!parsed.ok) assert.equal(parsed.reason, reason, value);
  }
});

