import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import * as ids from "../ids/src/index.js";
import { checkPost, runPostCase } from "../src/post.js";
import { admitRow, postRows, putObject } from "../src/see.js";

function contextOf(raw) {
  const history = (principal, at, until) => (raw.authenticatedAccounts ?? []).includes(principal)
    ? { ok: true, value: ids.historyState(principal, [], at, until) }
    : { ok: false, reason: "missing-history" };
  return {
    jwks: raw.jwks,
    links: new Map(raw.links ?? []),
    revocations: raw.revocations ?? [],
    now: raw.now,
    policy: raw.policy,
    pinnedIss: new Set(raw.pinnedIss ?? []),
    history,
    genesisEpubBindings: raw.genesisEpubBindings ?? [],
  };
}

test("post vectors", () => {
  const file = JSON.parse(readFileSync(new URL("../../vectors/mesh/v2/post.json", import.meta.url), "utf8"));
  const ctx = contextOf(file.context);
  for (const side of ["accept", "reject"]) {
    for (const entry of file[side]) {
      runPostCase(entry.steps, { ctx, rotations: (name) => file.context.rotationSets[name] });
    }
  }
});

test("mutating postRows does not grant", () => {
  const file = JSON.parse(readFileSync(new URL("../../vectors/mesh/v2/post.json", import.meta.url), "utf8"));
  const entry = file.accept.find((row) => row.name === "cancel-see-denies-post");
  const placed = entry.steps.find((step) => step.op === "put");
  const admitted = entry.steps.find((step) => step.op === "admit");
  const graph = {};
  const resolver = { rotations: () => file.context.rotationSets.genesis, ctx: contextOf(file.context) };
  assert.equal(putObject(graph, placed.record, resolver).ok, true);
  assert.equal(admitRow(graph, admitted.row, resolver).ok, true);
  const object = admitted.row.object;
  const accessor = admitted.row.accessor;
  assert.equal(checkPost(graph, object, accessor, 10).reason, "missing");
  const key = ids.postSoul(placed.record.owner, object, accessor);
  const rows = postRows(graph);
  rows.set(key, { grant: { stated: 1, from: 0, until: 1e12 } });
  assert.equal(checkPost(graph, object, accessor, 10).reason, "missing");
  const copy = postRows(graph).get(key);
  if (copy) copy.grant.stated = 0;
  assert.equal(checkPost(graph, object, accessor, 10).reason, "missing");
});
