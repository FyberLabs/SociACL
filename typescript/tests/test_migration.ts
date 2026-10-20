import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import type {
  AccessorId,
  CheckObjectId,
  GrantStorage,
  GunAclEdge,
  MigrationAdmissionInput,
  SignedGrantPayload,
  WrappedKey,
} from "../../docs/s3rch-check.js";
import { sha256Hex, wrapReceiptBytes, wrapReceiptSha256 } from "../contract/canonical.ts";
import { applyProtocolMigration, compareAccessors } from "../contract/migration.ts";
import { grantSoul, parseObjectId, parsePrincipalId } from "../ids/src/index.js";

function objectId(value: string): CheckObjectId {
  const parsed = parseObjectId(value);
  assert.equal(parsed.ok, true, value);
  if (!parsed.ok) throw new Error(parsed.reason);
  return parsed.value;
}

function principalId(value: string): AccessorId {
  const parsed = parsePrincipalId(value);
  assert.equal(parsed.ok, true, value);
  if (!parsed.ok) throw new Error(parsed.reason);
  return parsed.value;
}

type GrantJson = {
  soul?: string;
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

function rawInput(row: Case): MigrationAdmissionInput {
  return {
    migration: {
      object: row.object as CheckObjectId,
      fromVersion: row.fromVersion,
      toVersion: row.toVersion,
      versionGate: row.versionGate,
      readers: row.readers,
      rewrapped: row.wraps,
    },
    owner: row.owner as AccessorId,
    caller: row.caller as AccessorId,
    now: row.now,
    storage: row.storage,
    grants: [],
    payloads: [],
    receipts: [],
    readerVersions: [],
    soulHamState: row.soulHamState,
  };
}

function inputOf(row: Case): MigrationAdmissionInput {
  const owner = principalId(row.owner);
  const object = objectId(row.object);
  const grants: GunAclEdge[] = row.grants.map((grant) => ({
    soul:
      grant.soul ??
      grantSoul(principalId(grant.owner), objectId(grant.object), principalId(grant.accessor)),
    owner: principalId(grant.owner),
    hamState: grant.hamState,
    grant: {
      object: objectId(grant.object),
      accessor: principalId(grant.accessor),
      from: grant.from,
      until: grant.until,
      stated: grant.stated,
    },
  }));
  const payloads: SignedGrantPayload[] = row.payloads.map((payload) => ({
    ...payload,
    object: objectId(payload.object),
    accessor: principalId(payload.accessor),
    owner: principalId(payload.owner),
  }));
  return {
    migration: {
      object,
      fromVersion: row.fromVersion,
      toVersion: row.toVersion,
      versionGate: row.versionGate,
      readers: row.readers.map((reader) => ({ ...reader, accessor: principalId(reader.accessor) })),
      rewrapped: row.wraps.map((wrap) => ({
        ...wrap,
        object: wrap.object === undefined ? undefined : objectId(wrap.object),
      })),
      },
    owner,
    caller: principalId(row.caller),
    now: row.now,
    storage: row.storage,
    grants,
    payloads,
    receipts: row.receipts.map((receipt) => ({ ...receipt, accessor: principalId(receipt.accessor) })),
    readerVersions: row.readerVersions.map((version) => ({
      ...version,
      accessor: principalId(version.accessor),
    })),
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
      let input: MigrationAdmissionInput;
      try {
        input = inputOf(row);
      } catch {
        input = rawInput(row);
      }
      assert.throws(() => applyProtocolMigration(input), /migration rejected/, row.name);
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

test("accessor order is UTF-8 bytes for a, B, hyphen, and underscore", () => {
  const order = JSON.parse(
    readFileSync(new URL("../../vectors/encrypted-discovery/accessor-order.json", import.meta.url), "utf8"),
  ) as { input: string[]; utf8: string[] };
  assert.deepEqual([...order.input].sort(compareAccessors), order.utf8);
});

test("wrap receipt bytes match the canonical vector", () => {
  const row = canonical.cases.find((item) => item.name === "wrap-receipt");
  assert.ok(row?.fields);
  const fields = row.fields;
  assert.equal(fields[0], "s3rch-wrap-receipt-v1");
  const object = objectId(fields[1] ?? "");
  const accessor = principalId(fields[2] ?? "");
  const version = Number(fields[3]);
  const revisionId = fields[4] ?? "";
  const entryId = fields[5] ?? "";
  const bytes = wrapReceiptBytes(object, accessor, version, revisionId, entryId);
  assert.equal(sha256Hex(bytes), row.sha256);
  assert.equal(wrapReceiptSha256(object, accessor, version, revisionId, entryId), row.sha256);
});

