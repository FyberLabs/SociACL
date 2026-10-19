import { test } from "node:test";
import { readFileSync } from "node:fs";
import * as ids from "../ids/src/index.js";
import { runPostCase } from "../src/post.js";

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
