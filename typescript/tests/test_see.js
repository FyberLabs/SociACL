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
  const root = fileURLToPath(new URL("../../", import.meta.url));
  const doc = JSON.parse(readFileSync(join(root, "vectors/mesh/forbidden-names.json"), "utf8"));
  assert.ok(Array.isArray(doc.identifiers));
  assert.ok(Array.isArray(doc.scopes));
  assert.ok(doc.scopes.length > 0);
  for (const glob of doc.scopes) {
    const files = filesForGlob(root, glob);
    assert.ok(files.length > 0, glob);
    for (const name of doc.identifiers) {
      const needle = new RegExp(`(^|[^A-Za-z0-9_])${name}([^A-Za-z0-9_]|$)`);
      for (const path of files) {
        assert.equal(needle.test(readFileSync(path, "utf8")), false, `${name} in ${path}`);
      }
    }
  }
});

function globMatch(glob, path) {
  const rec = (pattern, value) => {
    if (pattern.length === 0) return value.length === 0;
    if (pattern.startsWith("**")) {
      const rest = pattern[2] === "/" ? pattern.slice(3) : pattern.slice(2);
      if (rec(rest, value)) return true;
      for (let index = 0; index < value.length; index += 1) {
        if (rec(pattern, value.slice(index + 1))) return true;
      }
      return false;
    }
    if (pattern[0] === "*") {
      for (let index = 0; index <= value.length; index += 1) {
        if (index > 0 && value[index - 1] === "/") return false;
        if (rec(pattern.slice(1), value.slice(index))) return true;
        if (index === value.length) return false;
      }
      return false;
    }
    if (value.length === 0 || pattern[0] !== value[0]) return false;
    return rec(pattern.slice(1), value.slice(1));
  };
  return rec(glob, path);
}

function filesForGlob(root, glob) {
  if (!glob.includes("*")) {
    const path = join(root, glob);
    assert.equal(statSync(path).isFile(), true, glob);
    return [path];
  }
  const files = [];
  const walk = (dir) => {
    for (const name of readdirSync(dir)) {
      if (name === "node_modules" || name === "target") continue;
      const path = join(dir, name);
      const info = statSync(path);
      if (info.isDirectory()) walk(path);
      else if (name.endsWith(".js") || name.endsWith(".ts") || name.endsWith(".rs")) {
        const relative = path.slice(root.length).replaceAll("\\", "/").replace(/^\//, "");
        if (globMatch(glob, relative)) files.push(path);
      }
    }
  };
  walk(root);
  return files;
}

function fileURLToPath(url) {
  return decodeURIComponent(url.pathname);
}
