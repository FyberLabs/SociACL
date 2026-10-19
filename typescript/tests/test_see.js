import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import * as ids from "../ids/src/index.js";
import { runSeeCase, seeAccessorEdge, seeObjectEdge } from "../src/see.js";

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

test("see vectors", () => {
  const file = JSON.parse(readFileSync(new URL("../../vectors/mesh/v2/see.json", import.meta.url), "utf8"));
  const ctx = contextOf(file.context);
  const names = [];
  for (const side of ["accept", "reject"]) {
    for (const entry of file[side]) {
      runSeeCase(entry.steps, { ctx, rotations: (name) => file.context.rotationSets[name] });
      names.push(`see/${side}/${entry.name}`);
    }
  }
  names.sort();
  const report = process.env.MESH_VECTOR_REPORT;
  if (report) writeFileSync(report, names.join("\n") + "\n");
  assert.equal(new Set(names).size, names.length);
});

test("see edge matches parse for 10k strings", () => {
  const alphabet = "abcXYZ./_~:()'\\get0123456789- \u0000";
  let state = 0x5502;
  const next = () => {
    state = (state ^ (state << 13)) >>> 0;
    state = (state ^ (state >>> 17)) >>> 0;
    state = (state ^ (state << 5)) >>> 0;
    return state;
  };
  for (let i = 0; i < 10000; i += 1) {
    const len = next() % 24;
    let value = "";
    for (let j = 0; j < len; j += 1) value += alphabet[next() % alphabet.length];
    const object = seeObjectEdge(value);
    assert.deepEqual(object, ids.parseObjectId(value));
    if (object.ok) assert.equal(object.value, value);
    const accessor = seeAccessorEdge(value);
    assert.deepEqual(accessor, ids.parsePrincipalId(value));
    if (accessor.ok) assert.equal(accessor.value, value);
  }
});

test("see forbidden names are absent", () => {
  const root = new URL("../../", import.meta.url);
  const names = JSON.parse(readFileSync(new URL("vectors/mesh/forbidden-names.json", root), "utf8")).identifiers;
  assert.ok(Array.isArray(names));
  const roots = ["typescript/src", "typescript/contract", "crates/sociacl-gun/src", "crates/sociacl-encdisc/src"];
  const skip = new Set(["migration.ts", "acl-migration.ts", "migration.rs", "acl_migration.rs"]);
  const files = [];
  const walk = (dir) => {
    for (const name of readdirSync(dir)) {
      const path = join(dir, name);
      if (skip.has(name)) continue;
      const info = statSync(path);
      if (info.isDirectory()) walk(path);
      else if (name.endsWith(".js") || name.endsWith(".ts") || name.endsWith(".rs")) files.push(path);
    }
  };
  for (const dir of roots) walk(join(fileURLToPath(root), dir));
  for (const name of names) {
    const needle = new RegExp(`(^|[^A-Za-z0-9_])${name}([^A-Za-z0-9_]|$)`);
    for (const path of files) {
      assert.equal(needle.test(readFileSync(path, "utf8")), false, `${name} in ${path}`);
    }
  }
});

function fileURLToPath(url) {
  return decodeURIComponent(url.pathname);
}
