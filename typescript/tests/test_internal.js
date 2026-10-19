import assert from "node:assert/strict";
import { readdirSync } from "node:fs";
import { test } from "node:test";
test("no internal module exports a seal set", async () => {
  const dir = new URL("../src/internal/", import.meta.url);
  const names = readdirSync(dir).filter((name) => name.endsWith(".js"));
  assert.ok(names.includes("see-rows.js"));
  assert.ok(names.includes("post-rows.js"));
  for (const name of names) {
    const mod = await import(new URL(name, dir).href);
    for (const [key, value] of Object.entries(mod)) {
      assert.equal(value instanceof WeakSet, false, `${name} ${key}`);
      assert.notEqual(key, "verified", name);
      assert.notEqual(key, "sealedPosts", name);
    }
  }
});
