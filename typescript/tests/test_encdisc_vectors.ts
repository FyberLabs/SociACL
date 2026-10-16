import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import type { EpochManifestBody, InboxEntryBody } from "../../docs/s3rch-check.js";
import {
  accountBindingBytes,
  accountBindingSha256,
  canonicalDecimal,
  epochRevisionBytes,
  epochRevisionId,
  inboxEntryBytes,
  inboxEntryId,
  itemAuthBytes,
  itemAuthSha256,
  lengthPrefixed,
  sha256Hex,
  type ItemAuthBody,
} from "../contract/canonical.ts";

type VectorCase = {
  name: string;
  kind: string;
  sha256: string;
  encodedLen: number;
  fields?: string[];
  body?: {
    laneId?: string;
    grantCiphertext?: string;
    commitment?: { hash: string };
    wrap?: InboxEntryBody["wrap"];
    object?: string;
    epoch?: number;
    previousEpoch?: number;
    deviceId?: string;
    keyCommitment?: string;
    settleWindowMs?: number;
    aclSnapshot?: string;
    version?: number;
    plaintextDigest?: string;
    revisionId?: string;
    account?: string;
    pub?: string;
    epub?: string;
  };
};

const document = JSON.parse(
  readFileSync(new URL("../../vectors/encrypted-discovery/canonical.json", import.meta.url), "utf8"),
) as { cases: VectorCase[] };

function requireBody(row: VectorCase): NonNullable<VectorCase["body"]> {
  assert.ok(row.body, row.name);
  return row.body;
}

test("canonical vectors match the shared fixture", () => {
  assert.ok(document.cases.length >= 18);
  const hashes = new Map<string, string>();
  for (const row of document.cases) {
    let bytes: Uint8Array;
    let hash: string;
    if (row.kind === "fields") {
      assert.ok(row.fields, row.name);
      bytes = lengthPrefixed(row.fields);
      hash = sha256Hex(bytes);
    } else if (row.kind === "inboxEntryId") {
      const body = requireBody(row);
      assert.equal(typeof body.laneId, "string", row.name);
      assert.equal(typeof body.grantCiphertext, "string", row.name);
      assert.ok(body.commitment, row.name);
      const entry: InboxEntryBody = {
        laneId: body.laneId as string,
        grantCiphertext: body.grantCiphertext as string,
        commitment: body.commitment,
        ...(body.wrap ? { wrap: body.wrap } : {}),
      };
      bytes = inboxEntryBytes(entry);
      hash = inboxEntryId(entry);
    } else if (row.kind === "epochRevisionId") {
      const body = requireBody(row);
      const manifest: EpochManifestBody = {
        object: body.object as string,
        epoch: body.epoch as number,
        previousEpoch: body.previousEpoch as number,
        deviceId: body.deviceId as string,
        keyCommitment: body.keyCommitment as string,
        settleWindowMs: body.settleWindowMs as number,
        aclSnapshot: body.aclSnapshot as string,
      };
      bytes = epochRevisionBytes(manifest);
      hash = epochRevisionId(manifest);
    } else if (row.kind === "itemAuth") {
      const body = requireBody(row);
      const item: ItemAuthBody = {
        object: body.object as string,
        epoch: body.epoch as number,
        version: body.version as number,
        plaintextDigest: body.plaintextDigest as string,
        revisionId: body.revisionId as string,
      };
      bytes = itemAuthBytes(item);
      hash = itemAuthSha256(item);
    } else if (row.kind === "accountBinding") {
      const body = requireBody(row);
      const account = body.account as string;
      const seaPub = body.pub as string;
      const epub = body.epub as string;
      bytes = accountBindingBytes(account, seaPub, epub);
      hash = accountBindingSha256(account, seaPub, epub);
    } else {
      assert.fail(`unknown vector kind ${row.kind}`);
    }
    assert.equal(hash, row.sha256, row.name);
    assert.equal(bytes.length, row.encodedLen, row.name);
    assert.equal(hash.length, 64, row.name);
    assert.match(hash, /^[0-9a-f]{64}$/, row.name);
    hashes.set(row.name, hash);
  }
  assert.notEqual(hashes.get("fields-ab-c"), hashes.get("fields-a-bc"));
  assert.notEqual(hashes.get("fields-decimal-ten"), hashes.get("fields-decimal-leading-zero"));
  assert.equal(hashes.get("inbox-with-wrap"), hashes.get("inbox-group-empty"));
  assert.notEqual(hashes.get("inbox-with-wrap"), hashes.get("inbox-wrap-byte"));
  assert.notEqual(hashes.get("inbox-real-wrap"), hashes.get("inbox-with-wrap"));
  assert.notEqual(hashes.get("item-auth-hello"), hashes.get("item-auth-zero"));
  assert.equal(
    hashes.get("fields-empty"),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  );
});

test("decimal zero has no leading zero", () => {
  assert.equal(canonicalDecimal(0), "0");
  assert.equal(canonicalDecimal(10), "10");
  assert.throws(() => canonicalDecimal(-1));
  assert.throws(() => canonicalDecimal(1.5));
  assert.throws(() => canonicalDecimal(Number.NaN));
});
