import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import * as ids from "../ids/src/index.js";
import * as gunApi from "../src/gun.js";
import { admitPost, checkPost, postRows, runPostCase } from "../src/post.js";
import * as seeApi from "../src/see.js";
import { admitRow, putObject } from "../src/see.js";

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

test("no public path seals an unverified post row", () => {
  const file = JSON.parse(readFileSync(new URL("../../vectors/mesh/v2/post.json", import.meta.url), "utf8"));
  const entry = file.accept.find((row) => row.name === "delegate-post-cancel-denies");
  const graph = {};
  const resolver = { rotations: () => file.context.rotationSets.genesis, ctx: contextOf(file.context) };
  for (const step of entry.steps) {
    if (step.op === "put") assert.equal(putObject(graph, step.record, resolver).ok, true);
    if (step.op === "admit") assert.equal(admitRow(graph, step.row, resolver).ok, true);
    if (step.op === "admit-post") {
      const admitted = admitPost(graph, step.row, resolver);
      assert.equal(admitted.ok, true);
      assert.equal(Object.hasOwn(admitted.value, "reseal"), false);
      assert.equal(typeof admitted.value.reseal, "undefined");
    }
  }
  const object = entry.steps.find((step) => step.op === "check-post").object;
  const accessor = entry.steps.find((step) => step.op === "check-post").accessor;
  assert.equal(checkPost(graph, object, accessor, 10).reason, "cancelled");
  assert.equal(seeApi.postTable, undefined);
  assert.equal(gunApi.postTable, undefined);
  const key = ids.postSoul(entry.steps.find((step) => step.op === "put").record.owner, object, accessor);
  const forged = {
    mode: "present",
    grant: { stated: 1, from: 0, until: 1e12 },
    reseal() {
      return this;
    },
  };
  postRows(graph).set(key, forged);
  const copy = postRows(graph).get(key);
  if (copy) copy.grant.stated = 1;
  assert.equal(checkPost(graph, object, accessor, 10).allowed, false);
  assert.equal(checkPost(graph, object, accessor, 10).reason, "cancelled");
});
