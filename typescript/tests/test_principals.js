import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { MemorySeeAcl, checkSeeLabel, grantSoul } from "../src/legacy/gun-legacy.js";
import { canonicalAccessorId } from "../src/legacy/post-label.js";

const vectors = JSON.parse(
  readFileSync(new URL("../../vectors/mesh/principals.json", import.meta.url), "utf8"),
);

function principalId(row) {
  if (row.repeat != null) return row.repeat.repeat(row.count);
  return row.id;
}

function expectedPrincipal(row) {
  if (row.canonical === "repeat") return row.repeat.repeat(row.count);
  return row.canonical;
}

test("shared principal vectors", () => {
  for (const row of vectors.principals) {
    const id = principalId(row);
    assert.equal(canonicalAccessorId(id), expectedPrincipal(row), id);
  }
  assert.equal(canonicalAccessorId("0x\ud800victim"), null);
});

test("shared grant soul vectors", () => {
  for (const row of vectors.grants) {
    assert.equal(grantSoul(row.owner, row.object, row.accessor), row.soul, row.accessor);
  }
});

test("shared object id vectors", () => {
  for (const row of vectors.objects) {
    const acl = new MemorySeeAcl();
    acl.putObject(row.stored, row.owner);
    if (row.put != null) acl.putObject(row.put, row.putOwner);
    if (row.hasPutId != null) assert.equal(acl.hasObject(row.put), row.hasPutId, row.name);
    assert.equal(acl.ownerOf(row.stored), row.ownerAfter, row.name);
    if (row.query != null) {
      assert.equal(checkSeeLabel(acl, row.query, row.accessor, 10).allowed, row.allowed, row.name);
    }
  }
});

test("a null grant key does not return another object's grant", () => {
  for (const row of vectors.nullKeys) {
    const acl = new MemorySeeAcl();
    acl.putObject(row.other, "0xmallory");
    acl.putObject(row.secret, "0xalice");
    acl.stateSeeGrant("0xmallory", {
      object: row.other,
      accessor: row.accessor,
      from: 0,
      until: 80,
    });
    assert.equal(acl.seeGrant(row.secret, row.accessor), undefined, row.accessor);
    assert.equal(acl.seeGrant(row.other, row.accessor), undefined, row.accessor);
    assert.equal(checkSeeLabel(acl, row.secret, row.accessor, 10).allowed, false);
  }
});
