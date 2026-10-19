import assert from "node:assert/strict";
import { test } from "node:test";
import { p256 } from "@noble/curves/nist.js";
import * as ids from "../ids/src/index.js";
import { admittedView, putObject } from "../src/see.js";
import { factorGrants } from "../src/post.js";
import { grantApprovedRequest } from "../src/request.js";
import { b64 } from "../ids/scripts/vector-util.mjs";

const secret = (n) => { const b = new Uint8Array(32); b[31] = n; return b; };
const principal = (n) => {
  const pub = p256.getPublicKey(secret(n), false);
  const id = ids.parsePrincipalId(b64(pub.slice(1, 33)) + "." + b64(pub.slice(33)));
  if (!id.ok) throw new Error(id.reason);
  return id.value;
};
const p = principal(1);
const p2 = principal(2);
const at = 1700000000;
const now = at + 60;
const chat = ids.mintObjectId("chat", p, () => new Uint8Array(16).fill(0x11));
if (!chat.ok) throw new Error(chat.reason);

function context() {
  const history = (principalId, issued, until) => principalId === p || principalId === p2
    ? { ok: true, value: ids.historyState(principalId, [], issued, until) }
    : { ok: false, reason: "missing-history" };
  return {
    jwks: { keys: [] },
    links: new Map(),
    revocations: [],
    now,
    policy: { allowedDomains: ["s3r.ch"], allowedUris: ["https://s3r.ch/identity/link"], allowedChainIds: ["1"] },
    pinnedIss: new Set(),
    history,
    genesisEpubBindings: [],
  };
}

test("stateful toString on the object is not-string and writes nothing", () => {
  const graph = {};
  const ctx = context();
  const resolver = { rotations: () => [], ctx };
  const record = { object: chat.value, owner: p, issuedAt: at, sig: "" };
  record.sig = ids.signWithKeyring(secret(1), ids.objectRecordBytes(record), p).value;
  const put = putObject(graph, record, resolver);
  assert.equal(put.ok, true);
  let n = 0;
  const source = {
    toString() {
      n += 1;
      return n === 1 ? "doc-a" : "doc-b";
    },
  };
  const requestId = ids.requestId(p2, chat.value);
  assert.equal(requestId.ok, true);
  const result = grantApprovedRequest(
    graph,
    p,
    {
      requestId: requestId.value,
      requester: p2,
      object: source,
      scope: "read",
      status: "pending",
      message: "",
      issuedAt: now,
      sig: "aa",
    },
    { from: 0, until: 100 },
    null,
    { scalar: secret(1), resolver },
  );
  assert.equal(result.granted, false);
  assert.equal(result.reason, "not-string");
  assert.equal(admittedView(graph, chat.value, p2), undefined);
});

test("factorGrants stays false for a request", () => {
  assert.equal(factorGrants("request"), false);
  assert.equal(factorGrants("hop"), false);
  assert.equal(factorGrants("inbox"), false);
});
