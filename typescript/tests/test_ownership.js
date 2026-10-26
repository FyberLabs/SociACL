import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { Plane } from "sociacl";
import { acceptHint, checkSee, putObject } from "sociacl/gun";
import { MemoryGroupGraph } from "sociacl/group";
import { historyState } from "../ids/src/index.js";

test("the unsigned IR adapter is not an exported package entry", async () => {
  await assert.rejects(import("sociacl/ir"), { code: "ERR_PACKAGE_PATH_NOT_EXPORTED" });
  await assert.rejects(import("sociacl/src/ir.js"), { code: "ERR_PACKAGE_PATH_NOT_EXPORTED" });
});

test("public Gun ownership requires a signed object record", () => {
  const fixture = JSON.parse(readFileSync(new URL("../../vectors/mesh/v2/see.json", import.meta.url)));
  const record = fixture.accept.find(row => row.name === "owner-path-needs-exact-principal").steps[0].record;
  const { object, owner } = record;
  const accessor = fixture.context.authenticatedAccounts[1];
  const core = new Plane();
  core.addPerson(owner);
  core.addObject(object, owner);
  const graph = new MemoryGroupGraph();
  const hint = acceptHint({ principal: owner, target: object, verb: "see" });
  assert.equal(checkSee(core, object, owner, 10, hint).allowed, false);
  assert.equal(checkSee(graph, object, owner, 10, hint).allowed, false);
  const raw = fixture.context;
  const resolver = {
    rotations: principal => principal === owner ? [] : undefined,
    ctx: { ...raw, links: new Map(), pinnedIss: new Set(raw.pinnedIss),
      history: (principal, at, until) => principal === owner
        ? { ok: true, value: historyState(principal, [], at, until) }
        : { ok: false, reason: "missing-history" },
    },
  };
  const { sig, ...unsigned } = record;
  assert.equal(putObject(graph, unsigned, resolver).reason, "bad-signature");
  assert.equal(putObject(graph, { ...record, issuedAt: record.issuedAt + 1 }, resolver).reason, "bad-signature");
  assert.equal(checkSee(graph, object, owner, raw.now, hint).allowed, false);
  assert.equal(putObject(graph, record, { ...resolver, rotations: () => undefined }).reason, "missing-history");
  assert.equal(putObject(graph, record, resolver).ok, true);
  assert.equal(checkSee(graph, object, owner, raw.now).allowed, true);
  assert.equal(checkSee(graph, object, accessor, raw.now).allowed, false);
  assert.equal(putObject(graph, { ...record, owner: accessor }, resolver).ok, false);
  assert.equal(checkSee(graph, object, owner, raw.now).allowed, true);
  assert.equal(checkSee(graph, object, accessor, raw.now).allowed, false);
});
