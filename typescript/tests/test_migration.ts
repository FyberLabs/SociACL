import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import type {
  GrantStorage,
  GunAclEdge,
  MigrationAdmissionInput,
  SignedGrantPayload,
  WrappedKey,
} from "../../docs/s3rch-check.js";
import { sha256Hex, wrapReceiptBytes, wrapReceiptSha256 } from "../contract/canonical.ts";
import { applyProtocolMigration } from "../contract/migration.ts";

type GrantJson = {
  owner: string;
  object: string;
  accessor: string;
  from: number;
  until: number;
  stated: 0 | 1;
  hamState: number;
};

type Case = {
  name: string;
  owner: string;
  caller: string;
  now: number;
  storage: GrantStorage;
  object: string;
  fromVersion: number;
  toVersion: number;
  versionGate: number;
  soulHamState: number;
  grants: GrantJson[];
  payloads: SignedGrantPayload[];
  wraps: WrappedKey[];
  readers: MigrationAdmissionInput["migration"]["readers"][number][];
  readerVersions: MigrationAdmissionInput["readerVersions"][number][];
  receipts: MigrationAdmissionInput["receipts"][number][];
  expect: {
    ok: boolean;
    plaintextRetained?: string[];
    plaintextDropped?: string[];
    soulReplaced?: boolean;
    skippedPublic?: boolean;
    ciphertextPublished?: boolean;
    soulHamState?: number;
    cancelled?: { accessor: string; hamState: number; stated: 0 | 1; from: number; until: number }[];
  };
};

const document = JSON.parse(
  readFileSync(new URL("../../vectors/encrypted-discovery/migration.json", import.meta.url), "utf8"),
) as { cases: Case[] };

const canonical = JSON.parse(
  readFileSync(new URL("../../vectors/encrypted-discovery/canonical.json", import.meta.url), "utf8"),
) as { cases: { name: string; kind: string; sha256: string; fields?: string[] }[] };

function inputOf(row: Case): MigrationAdmissionInput {
  const grants: GunAclEdge[] = row.grants.map((grant) => ({
    soul: `s3rch/acl/${grant.owner}/${grant.object}/${grant.accessor}`,
    owner: grant.owner,
    hamState: grant.hamState,
    grant: {
      object: grant.object,
      accessor: grant.accessor,
      from: grant.from,
      until: grant.until,
      stated: grant.stated,
    },
  }));
  return {
    migration: {
      object: row.object,
      fromVersion: row.fromVersion,
      toVersion: row.toVersion,
      versionGate: row.versionGate,
      readers: row.readers,
      rewrapped: row.wraps,
    },
    owner: row.owner,
    caller: row.caller,
    now: row.now,
    storage: row.storage,
    grants,
    payloads: row.payloads,
    receipts: row.receipts,
    readerVersions: row.readerVersions,
    soulHamState: row.soulHamState,
  };
}

test("migration vectors match the shared fixture", () => {
  const names = document.cases.map((row) => row.name);
  for (const required of [
    "migration-wrap-receipt",
    "migration-per-reader",
    "migration-soul-replaces",
    "migration-no-widen",
    "migration-privilege-down",
    "migration-public-skipped",
    "migration-reader-cannot-issue",
  ]) {
    assert.ok(names.includes(required), required);
  }
  for (const row of document.cases) {
    if (!row.expect.ok) {
      assert.throws(() => applyProtocolMigration(inputOf(row)), /migration rejected/, row.name);
      continue;
    }
    const outcome = applyProtocolMigration(inputOf(row));
    assert.equal(outcome.grantsSee, false, row.name);
    assert.equal(outcome.delaysPrivilegeDown, false, row.name);
    assert.equal(outcome.widened, false, row.name);
    assert.equal(outcome.historicalReplicaRemains, true, row.name);
    assert.equal(outcome.object, row.object, row.name);
    assert.deepEqual(outcome.plaintextRetained, row.expect.plaintextRetained, row.name);
    assert.deepEqual(outcome.plaintextDropped, row.expect.plaintextDropped, row.name);
    assert.equal(outcome.soulReplaced, row.expect.soulReplaced, row.name);
    assert.equal(outcome.skippedPublic, row.expect.skippedPublic, row.name);
    assert.equal(outcome.ciphertextPublished, row.expect.ciphertextPublished, row.name);
    assert.equal(outcome.soulHamState, row.expect.soulHamState, row.name);
    const cancelled = row.expect.cancelled ?? [];
    assert.equal(outcome.cancelled.length, cancelled.length, row.name);
    for (let index = 0; index < cancelled.length; index += 1) {
      const actual = outcome.cancelled[index];
      const expected = cancelled[index];
      assert.ok(actual && expected, row.name);
      assert.equal(actual.grant.accessor, expected.accessor, row.name);
      assert.equal(actual.grant.stated, expected.stated, row.name);
      assert.equal(actual.hamState, expected.hamState, row.name);
      assert.equal(actual.grant.from, expected.from, row.name);
      assert.equal(actual.grant.until, expected.until, row.name);
      assert.equal(actual.grant.object, row.object, row.name);
    }
  }
});

test("wrap receipt bytes match the canonical vector", () => {
  const row = canonical.cases.find((item) => item.name === "wrap-receipt");
  assert.ok(row?.fields);
  const fields = row.fields;
  assert.equal(fields[0], "s3rch-wrap-receipt-v1");
  const object = fields[1] ?? "";
  const accessor = fields[2] ?? "";
  const version = Number(fields[3]);
  const revisionId = fields[4] ?? "";
  const entryId = fields[5] ?? "";
  const bytes = wrapReceiptBytes(object, accessor, version, revisionId, entryId);
  assert.equal(sha256Hex(bytes), row.sha256);
  assert.equal(wrapReceiptSha256(object, accessor, version, revisionId, entryId), row.sha256);
});
