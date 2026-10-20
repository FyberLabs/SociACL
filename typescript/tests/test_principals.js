import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { parseObjectId, parsePrincipalId } from "../ids/src/index.js";
import { seeAccessorEdge, seeObjectEdge } from "../src/see.js";

const vectors = JSON.parse(
  readFileSync(new URL("../../vectors/mesh/principals.json", import.meta.url), "utf8"),
);

function principalId(row) {
  if (row.repeat != null) return row.repeat.repeat(row.count);
  return row.id;
}

test("label principals are not PrincipalIds", () => {
  for (const row of vectors.principals) {
    const id = principalId(row);
    const parsed = parsePrincipalId(id);
    assert.equal(parsed.ok, false, id);
    const edge = seeAccessorEdge(id);
    assert.equal(edge.ok, false, id);
  }
  assert.equal(parsePrincipalId("0x\ud800victim").ok, false);
});

test("label grant endpoints do not parse", () => {
  for (const row of vectors.grants) {
    assert.equal(parsePrincipalId(row.owner).ok, false, row.owner);
    assert.equal(parseObjectId(row.object).ok, false, row.object);
    assert.equal(parsePrincipalId(row.accessor).ok, false, row.accessor);
  }
});

test("label object ids do not parse and do not alias", () => {
  for (const row of vectors.objects) {
    assert.equal(parseObjectId(row.stored).ok, false, row.name);
    assert.equal(seeObjectEdge(row.stored).ok, false, row.name);
    if (row.query != null) assert.equal(parseObjectId(row.query).ok, false, row.name);
    if (row.put != null) assert.equal(parseObjectId(row.put).ok, false, row.name);
  }
});
