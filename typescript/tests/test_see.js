import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import * as ids from "../ids/src/index.js";
import { admitRow, checkSee, putObject, runSeeCase, seeAccessorEdge, seeObjectEdge } from "../src/see.js";

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

function xorshift(state) {
  state = (state ^ (state << 13)) >>> 0;
  state = (state ^ (state >>> 17)) >>> 0;
  state = (state ^ (state << 5)) >>> 0;
  return state;
}

function mutateId(value, roll, pick) {
  const kind = roll % 5;
  if (kind === 0) {
    const index = pick % value.length;
    const ch = value[index];
    const flipped = ch >= "a" && ch <= "z" ? ch.toUpperCase() : ch >= "A" && ch <= "Z" ? ch.toLowerCase() : ch;
    if (flipped !== ch) return value.slice(0, index) + flipped + value.slice(index + 1);
    return value + "x";
  }
  if (kind === 1) {
    if (value.includes("_")) return value.replace("_", ".");
    if (value.includes(".")) return value.replace(".", "_");
    return value + "x";
  }
  if (kind === 2) return value + " ";
  if (kind === 3) return "room.alpha";
  return "s3rch/items/" + value;
}

test("see edge mutations call checkSee", () => {
  const file = JSON.parse(readFileSync(new URL("../../vectors/mesh/v2/see.json", import.meta.url), "utf8"));
  const entry = file.accept.find((row) => row.name === "grant-on-chat_a-does-not-allow-chat_b");
  const placed = entry.steps.find((step) => step.op === "put");
  const admitted = entry.steps.find((step) => step.op === "admit");
  const graph = {};
  const resolver = { rotations: () => file.context.rotationSets.genesis, ctx: contextOf(file.context) };
  assert.equal(putObject(graph, placed.record, resolver).ok, true);
  assert.equal(admitRow(graph, admitted.row, resolver).ok, true);
  const object = admitted.row.object;
  const accessor = admitted.row.accessor;
  const owner = placed.record.owner;
  assert.equal(checkSee(graph, object, accessor, 10).allowed, true);
  assert.equal(checkSee(graph, object, owner, 10).reason, "owner");
  const bases = [object, accessor, owner];
  let state = 0x5502;
  for (let i = 0; i < 10000; i += 1) {
    state = xorshift(state);
    const roll = state;
    state = xorshift(state);
    const pick = state;
    state = xorshift(state);
    const base = bases[state % bases.length];
    const value = mutateId(base, roll, pick);
    const parsedObject = seeObjectEdge(value);
    const parsedPrincipal = seeAccessorEdge(value);
    assert.deepEqual(parsedObject, ids.parseObjectId(value));
    assert.deepEqual(parsedPrincipal, ids.parsePrincipalId(value));
    if (parsedObject.ok) assert.equal(parsedObject.value, value);
    if (parsedPrincipal.ok) assert.equal(parsedPrincipal.value, value);
    if (parsedObject.ok) {
      const got = checkSee(graph, value, accessor, 10);
      assert.equal(got.allowed, value === object);
    } else {
      assert.equal(checkSee(graph, value, accessor, 10).allowed, false);
    }
    if (parsedPrincipal.ok) {
      const got = checkSee(graph, object, value, 10);
      assert.equal(got.allowed, value === accessor || value === owner);
    } else {
      assert.equal(checkSee(graph, object, value, 10).allowed, false);
    }
  }
});

test("admitRow returns a copy of the tie-break bytes", () => {
  const file = JSON.parse(readFileSync(new URL("../../vectors/mesh/v2/see.json", import.meta.url), "utf8"));
  const entry = file.accept.find((row) => row.name === "grant-on-chat_a-does-not-allow-chat_b");
  const placed = entry.steps.find((step) => step.op === "put");
  const admitted = entry.steps.find((step) => step.op === "admit");
  const graph = {};
  const resolver = { rotations: () => file.context.rotationSets.genesis, ctx: contextOf(file.context) };
  assert.equal(putObject(graph, placed.record, resolver).ok, true);
  const got = admitRow(graph, admitted.row, resolver);
  assert.equal(got.ok, true);
  got.value.bytes.fill(255);
  const again = admitRow(graph, admitted.row, resolver);
  assert.equal(again.ok, true);
  assert.equal(again.kept, false);
});

test("putObject returns a copy of the owner admission", () => {
  const file = JSON.parse(readFileSync(new URL("../../vectors/mesh/v2/see.json", import.meta.url), "utf8"));
  const entry = file.accept.find((row) => row.name === "grant-on-chat_a-does-not-allow-chat_b");
  const placed = entry.steps.find((step) => step.op === "put");
  const graph = {};
  const resolver = { rotations: () => file.context.rotationSets.genesis, ctx: contextOf(file.context) };
  const got = putObject(graph, placed.record, resolver);
  assert.equal(got.ok, true);
  const object = placed.record.object;
  const owner = placed.record.owner;
  got.value.owner = "changed";
  got.value.frozen = true;
  got.value.issuedAt = 1;
  assert.equal(checkSee(graph, object, owner, 10).reason, "owner");
  assert.deepEqual(
    // admitted owner stays the stored record
    putObject(graph, placed.record, resolver),
    { ok: true, value: { owner, issuedAt: placed.record.issuedAt, frozen: false }, kept: false },
  );
});

test("putObject parses the record before reading owner", () => {
  const file = JSON.parse(readFileSync(new URL("../../vectors/mesh/v2/see.json", import.meta.url), "utf8"));
  const entry = file.accept.find((row) => row.name === "grant-on-chat_a-does-not-allow-chat_b");
  const placed = entry.steps.find((step) => step.op === "put");
  const graph = {};
  let reads = 0;
  const resolver = {
    rotations() {
      reads += 1;
      return file.context.rotationSets.genesis;
    },
    ctx: contextOf(file.context),
  };
  const proxy = new Proxy(placed.record, {
    getOwnPropertyDescriptor() { throw new Error("descriptor"); },
  });
  assert.deepEqual(putObject(graph, proxy, resolver), { ok: false, reason: "bad-record" });
  const throwing = {};
  for (const key of Object.keys(placed.record)) {
    Object.defineProperty(throwing, key, { enumerable: true, get() { throw new Error("getter"); } });
  }
  assert.deepEqual(putObject(graph, throwing, resolver), { ok: false, reason: "bad-record" });
  assert.equal(reads, 0);
  assert.equal(checkSee(graph, placed.record.object, placed.record.owner, 10).reason, "unknown");
});

test("checkSee on a primitive graph is bad-record", () => {
  assert.deepEqual(checkSee(1, "chat", "bob", 0), { allowed: false, reason: "bad-record" });
  assert.deepEqual(checkSee(null, "chat", "bob", 0), { allowed: false, reason: "bad-record" });
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
