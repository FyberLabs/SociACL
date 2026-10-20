import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  deriveExternalId,
  grantSoul,
  parseObjectId,
  parsePrincipalId,
  parseSourceKey,
} from "../ids/src/index.js";
import { seeAccessorEdge } from "../src/see.js";

const doc = JSON.parse(readFileSync(new URL("../../vectors/mesh/pr6.json", import.meta.url), "utf8"));

for (const row of doc.cases) {
  test(row.name, () => {
    if (row.kind === "grant-soul") {
      const owner = parsePrincipalId(row.owner);
      const object = parseObjectId(row.object);
      const accessor = parsePrincipalId(row.accessor);
      assert.equal(owner.ok && object.ok && accessor.ok, true, row.name);
      if (!owner.ok || !object.ok || !accessor.ok) return;
      assert.equal(grantSoul(owner.value, object.value, accessor.value), row.soul);
      return;
    }
    if (row.kind === "feed-item") {
      const source = parseSourceKey(row.source);
      assert.equal(source.ok, true, row.name);
      if (!source.ok) return;
      const derived = deriveExternalId(source.value, row.providerItemId);
      assert.equal(derived.ok, true, row.name);
      if (!derived.ok) return;
      assert.equal(derived.value, row.object);
      assert.notEqual(derived.value, row.notObject);
      return;
    }
    if (row.kind === "wallet-accessor") {
      const wallet = parsePrincipalId(row.wallet);
      const gunPath = parsePrincipalId(row.gunPath);
      const accessor = parsePrincipalId(row.accessor);
      assert.equal(wallet.ok, false);
      assert.equal(gunPath.ok, false);
      if (wallet.ok || gunPath.ok) return;
      assert.equal(wallet.reason, row.reason);
      assert.equal(gunPath.reason, row.reason);
      assert.equal(accessor.ok, true);
      const edge = seeAccessorEdge(row.wallet);
      assert.equal(edge.ok, false);
      if (edge.ok) return;
      assert.equal(edge.reason, row.reason);
      assert.equal(seeAccessorEdge(row.accessor).ok, true);
      assert.equal(row.allowed, false);
    }
  });
}
