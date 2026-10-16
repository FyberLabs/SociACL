import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  inboxEntryBytes,
  inboxEntryId,
  inboxPowBytes,
  inboxPowSha256,
  inboxStampBytes,
  inboxStampSha256,
  leadingZeroBits,
  sha256Hex,
  writerAppendBytes,
  writerAppendSha256,
} from "../contract/canonical.ts";
import {
  appendGrantsSee,
  INBOX_ENTRY_MAX_BYTES,
  isUtcDay,
  lanesPerDevice,
  scanDailyShardIds,
  shardCloseWatermarkImplemented,
  shardScanUsesDeviceCursor,
} from "../contract/inbox.ts";
import { writerChannelSha256 } from "../contract/canonical.ts";
import {
  AuthenticatedWriterChannel,
  writerChannelMatches,
  writerNameForbidden,
} from "../contract/writer.ts";
import type { InboxEntryBody } from "../../docs/s3rch-check.js";

type InboxBody = {
  laneId: string;
  grantCiphertext: string;
  commitment: string;
  wrap: InboxEntryBody["wrap"] | null;
  entryId: string;
  encodedLen: number;
};

const document = JSON.parse(
  readFileSync(
    new URL("../../vectors/encrypted-discovery/inbox.json", import.meta.url),
    "utf8",
  ),
) as {
  maxEntryBytes: number;
  perDeviceCursor: boolean;
  shardCloseWatermark: boolean;
  bodies: InboxBody[];
  pow: {
    nonce: string;
    entryId: string;
    solution: string;
    weakSolution: string;
    difficulty: number;
    sha256: string;
    encodedLen: number;
  };
  stamp: { entryId: string; sha256: string; encodedLen: number };
  writerAppend: {
    entryId: string;
    sha256: string;
    encodedLen: number;
    bareSha256: string;
    concatenatedSha256: string;
  };
  shard: { day: string; seen: string[]; shard: string[]; fresh: string[] };
};

function bodyOf(row: InboxBody): InboxEntryBody {
  return {
    laneId: row.laneId,
    grantCiphertext: row.grantCiphertext,
    commitment: { hash: row.commitment },
    wrap: row.wrap ?? undefined,
  };
}

test("inbox vectors match the shared fixture", () => {
  assert.equal(document.maxEntryBytes, INBOX_ENTRY_MAX_BYTES);
  assert.equal(document.perDeviceCursor, false);
  assert.equal(document.shardCloseWatermark, false);
  assert.equal(shardScanUsesDeviceCursor(), false);
  assert.equal(shardCloseWatermarkImplemented(), false);
  assert.equal(lanesPerDevice(), false);
  assert.equal(appendGrantsSee(), false);

  const ids = new Set<string>();
  for (const row of document.bodies) {
    const body = bodyOf(row);
    const bytes = inboxEntryBytes(body);
    assert.equal(inboxEntryId(body), row.entryId, row.laneId + row.grantCiphertext);
    assert.equal(bytes.length, row.encodedLen);
    ids.add(row.entryId);
  }
  assert.equal(ids.size, document.bodies.length);

  const pow = document.pow;
  const powBytes = inboxPowBytes(pow.nonce, pow.entryId, pow.solution);
  assert.equal(inboxPowSha256(pow.nonce, pow.entryId, pow.solution), pow.sha256);
  assert.equal(powBytes.length, pow.encodedLen);
  assert.ok(leadingZeroBits(pow.sha256) >= pow.difficulty);
  const weak = inboxPowSha256(pow.nonce, pow.entryId, pow.weakSolution);
  assert.ok(leadingZeroBits(weak) < pow.difficulty);
  const powConcat = createHash("sha256")
    .update(`s3rch-inbox-pow-v1${pow.nonce}${pow.entryId}${pow.solution}`)
    .digest("hex");
  assert.notEqual(powConcat, pow.sha256);

  const stampBytes = inboxStampBytes(document.stamp.entryId);
  assert.equal(inboxStampSha256(document.stamp.entryId), document.stamp.sha256);
  assert.equal(stampBytes.length, document.stamp.encodedLen);
  assert.notEqual(
    sha256Hex(new TextEncoder().encode(`s3rch-inbox-stamp-v1${document.stamp.entryId}`)),
    document.stamp.sha256,
  );

  const writer = document.writerAppend;
  const writerBytes = writerAppendBytes(writer.entryId);
  assert.equal(writerAppendSha256(writer.entryId), writer.sha256);
  assert.equal(writerBytes.length, writer.encodedLen);
  assert.equal(sha256Hex(new TextEncoder().encode(writer.entryId)), writer.bareSha256);
  assert.notEqual(writer.bareSha256, writer.sha256);
  assert.equal(
    sha256Hex(new TextEncoder().encode(`s3rch-writer-append-v1${writer.entryId}`)),
    writer.concatenatedSha256,
  );

  assert.deepEqual(
    scanDailyShardIds(document.shard.day, document.shard.seen, document.shard.shard),
    document.shard.fresh,
  );
  const late = `${document.shard.fresh[0]}-late`;
  const rescanned = scanDailyShardIds(
    document.shard.day,
    [...document.shard.seen, ...document.shard.fresh],
    [...document.shard.shard, late],
  );
  assert.deepEqual(rescanned, [late]);
  assert.equal(isUtcDay("2024-02-29"), true);
  assert.equal(isUtcDay("2023-02-29"), false);
  assert.equal(isUtcDay("2026-02-31"), false);
  assert.throws(() => scanDailyShardIds("2026-02-31", [], []));
});

test("writer channel brand is unforgeable", () => {
  const names = JSON.parse(
    readFileSync(
      new URL("../../vectors/encrypted-discovery/forbidden-names.json", import.meta.url),
      "utf8",
    ),
  ) as {
    exact: string[];
    contains: string[];
    possession: { writer: string; writerPub: string; signature: string; sha256: string };
  };
  const pub = names.possession.writerPub;
  assert.equal(writerChannelSha256(names.possession.writer), names.possession.sha256);
  const real = AuthenticatedWriterChannel.openWithPossession(
    names.possession.writer,
    pub,
    names.possession.signature,
  );
  assert.equal(real instanceof AuthenticatedWriterChannel, true);
  assert.equal(real.hasTransportBrand(), true);
  assert.equal(Object.isFrozen(real), true);
  assert.equal(writerChannelMatches(real, names.possession.writer, pub), true);
  assert.equal(writerChannelMatches(real, "0xcarol", pub), false);
  assert.equal(writerChannelMatches(real, names.possession.writer, "other-pub"), false);
  assert.throws(() => {
    (real as { writer: string }).writer = "0xcarol";
  });

  const literal = {
    writer: names.possession.writer,
    writerPub: pub,
    hasTransportBrand() {
      return true;
    },
  };
  assert.equal(literal instanceof AuthenticatedWriterChannel, false);
  assert.equal(writerChannelMatches(literal, names.possession.writer, pub), false);

  const copy = Object.assign(Object.create(AuthenticatedWriterChannel.prototype), {
    writer: names.possession.writer,
    writerPub: pub,
  }) as AuthenticatedWriterChannel;
  assert.equal(copy instanceof AuthenticatedWriterChannel, true);
  assert.equal(copy.hasTransportBrand(), false);
  assert.equal(writerChannelMatches(copy, names.possession.writer, pub), false);
  assert.throws(() =>
    AuthenticatedWriterChannel.openWithPossession("", pub, names.possession.signature),
  );
  assert.throws(() =>
    AuthenticatedWriterChannel.openWithPossession(
      names.possession.writer,
      pub,
      "11".repeat(64),
    ),
  );
  assert.throws(() =>
    AuthenticatedWriterChannel.openWithPossession("itar", pub, names.possession.signature),
  );
  for (const name of names.exact) {
    assert.equal(writerNameForbidden(name), true, name);
    assert.throws(() => AuthenticatedWriterChannel.openWithPossession(name, pub, "00"), name);
  }
  for (const needle of names.contains) {
    const name = `zz${needle}zz`;
    assert.equal(writerNameForbidden(name), true, name);
  }
  assert.equal(writerNameForbidden("diff"), false);
  assert.equal(writerNameForbidden("field-iff-extra"), false);
  assert.equal(writerNameForbidden("0xbob"), false);
  assert.equal(writerNameForbidden(" Flash "), true);
  assert.equal(writerNameForbidden("ITAR"), true);
});
