import assert from "node:assert/strict";
import { test } from "node:test";
import { checkSee } from "../src/gun.js";
import { seeAccessorEdge, seeObjectEdge } from "../src/see.js";
import { parseObjectId, parsePrincipalId } from "../ids/src/index.js";

test("stored-id checkSee rejects an unbound object and a gun chain", () => {
  const graph = { rows: new Map(), objects: new Map() };
  const folded = checkSee(graph, "room.alpha", "0xbob", 10);
  assert.equal(folded.allowed, false);
  assert.equal(folded.reason, "bad-alphabet");
  const chain = checkSee(
    graph,
    "chat_" + "11".repeat(16),
    "0xattacker.get('s3rch').get('users').get('0xvictim')",
    10,
  );
  assert.equal(chain.allowed, false);
  assert.equal(chain.reason, "bad-alphabet");
});

test("alias strings are an edge reject", () => {
  for (const value of [
    "room.alpha",
    "room_alpha",
    "room/alpha",
    "item-1",
    "doc",
    "room",
    "chat_" + "11".repeat(16),
    "s3rch/items/post",
  ]) {
    const parsed = seeObjectEdge(value);
    assert.equal(parsed.ok, false, value);
    if (!parsed.ok) assert.equal(parsed.reason, "bad-alphabet", value);
    const object = parseObjectId(value);
    assert.equal(object.ok, false, value);
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
    "bob.name": "bad-length",
  };
  for (const [value, reason] of Object.entries(reasons)) {
    const parsed = seeAccessorEdge(value);
    assert.equal(parsed.ok, false, value);
    if (!parsed.ok) assert.equal(parsed.reason, reason, value);
    const principal = parsePrincipalId(value);
    assert.equal(principal.ok, false, value);
  }
});
