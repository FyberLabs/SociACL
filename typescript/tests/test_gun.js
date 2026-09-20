import assert from "node:assert/strict";
import { test } from "node:test";
import {
  MemorySeeAcl,
  applySeeGrant,
  cancelSee,
  checkSee,
  checkSeeGrant,
  encodeKey,
  itemSoul,
  userSoul,
} from "../src/gun.js";

test("souls match the s3r.ch consume contract", () => {
  assert.equal(encodeKey("rss3:act/1#x"), "rss3:act/1_x");
  assert.equal(itemSoul("rss3:act/1#x"), "s3rch/items/rss3:act/1_x");
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
  assert.equal(checkSee(acl, object, "0xalice", 10).allowed, true);
  assert.equal(checkSee(acl, object, "0xbob", 10).allowed, true);
  assert.equal(
    checkSee(acl, object, "0xcarol", 10, { principal: "0xcarol", target: object }).allowed,
    false,
  );
  assert.equal(checkSee(acl, object, "0xbob", 100).allowed, false);
  assert.equal(checkSee(acl, "s3rch/meta", "0xalice", 10).allowed, false);
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
  assert.equal(checkSee(acl, object, "0xbob", 10).allowed, false);
});
