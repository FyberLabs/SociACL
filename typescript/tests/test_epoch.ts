import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import type {
  AclSnapshotBody,
  AclSnapshotEntry,
  EpochFinalization,
  EpochReplicaView,
  EpochRotation,
  EpochStatusProof,
  ObjectId,
  PrincipalId,
} from "../../docs/s3rch-check.js";
import { lengthPrefixed, sha256Hex } from "../contract/canonical.ts";
import { parseObjectId, parsePrincipalId } from "../ids/src/index.js";
import {
  aclSnapshotBytes,
  aclSnapshotId,
  epochFinalizationId,
  epochFinalizationSigBytes,
  epochManifestSigBytes,
  groupEpochConfigBytes,
  epochStepCurrent,
  epochWinner,
  groupEpochConfigDigest,
  rotateOnRevoke,
  settledKeyOpen,
  SETTLE_WINDOW_DEFAULT_MS,
  SETTLE_WINDOW_MAX_MS,
  SETTLE_WINDOW_MIN_MS,
  settleWindowInRange,
  settleWindowOrDefault,
  statusIsFresh,
  type PriorHamState,
  type RotationReader,
} from "../contract/epoch.ts";

const REV = "ab".repeat(32);
const OTHER = "cd".repeat(32);
const FAR = 4_000_000_000_000;

function mustObject(value: string): ObjectId {
  const parsed = parseObjectId(value);
  if (!parsed.ok) throw new Error(parsed.reason);
  return parsed.value as ObjectId;
}

function mustPrincipal(value: string): PrincipalId {
  const parsed = parsePrincipalId(value);
  if (!parsed.ok) throw new Error(parsed.reason);
  return parsed.value as PrincipalId;
}

const OBJECT = mustObject("chat_" + "11".repeat(16));
const OBJECT_B = mustObject("chat_" + "22".repeat(16));
const ALICE = mustPrincipal(
  "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY.T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU",
);
const BOB = mustPrincipal(
  "fPJ7GI0DT36KUjgDBLUaw8CJaeJ38hs1pgtI_EdmmXg.B3dVENuO0EApPZrGn3Qw27p9reY86YIpngS3nSJ4c9E",
);
const CAROL = mustPrincipal(
  "Xsvk0aYzCkTI9--VHUvxZebGtyHvramF-0FmG8bn_Ww.hzRkDEmY_343SwbOGmSi7NgqsDY4T7g9mnmxJ6J9UDI",
);
const ADA = mustPrincipal(
  "4lNKNTLQj7ugLd5lnuYr0AMf4tt4VZbvUJMCRGsDCFI.4PFXWkxjPMcZ3-5f2oYtdk78lsPzDuAFXELCPxhO2MY",
);
const AMY = mustPrincipal(
  "UVkLelFRQNLXhMhWCGaP3--Mgv0fW-UkIVVKDcPQM-0.4MF9qJBKcn2K4b82v4p5Jg0BLwDU2AiI0dC7RP2hbaQ",
);

type VectorCase = {
  name: string;
  kind: string;
  sha256: string;
  encodedLen: number;
  fields?: string[];
};

const document = JSON.parse(
  readFileSync(new URL("../../vectors/encrypted-discovery/canonical.json", import.meta.url), "utf8"),
) as { cases: VectorCase[] };

function vector(name: string): VectorCase {
  const row = document.cases.find((item) => item.name === name);
  assert.ok(row, name);
  return row;
}

function assertHash(name: string, bytes: Uint8Array): void {
  const row = vector(name);
  assert.equal(sha256Hex(bytes), row.sha256, name);
  assert.equal(bytes.length, row.encodedLen, name);
}

function directEntry(
  accessor: PrincipalId,
  stated: 0 | 1,
  grantRevision = 1,
): AclSnapshotEntry {
  return {
    accessor,
    grantRevision,
    stated,
    from: 0,
    until: FAR,
    scope: "direct",
    setId: "",
    hamState: 0,
  };
}

function directSnapshot(entries: readonly AclSnapshotEntry[]): AclSnapshotBody {
  return { entries };
}

function finalization(
  revisionId: string,
  candidates: readonly string[] = [revisionId],
): EpochFinalization {
  const previousFinalizationId = "";
  return {
    object: OBJECT,
    previousEpoch: 1,
    epoch: 2,
    revisionId,
    candidateRevisionIds: candidates,
    previousFinalizationId,
    finalizationId: epochFinalizationId(
      OBJECT,
      2,
      1,
      revisionId,
      previousFinalizationId,
      candidates,
    ),
    signature: "ab".repeat(64),
  };
}

function view(seen: readonly EpochFinalization[], extras: Partial<EpochReplicaView> = {}): EpochReplicaView {
  return {
    object: OBJECT,
    epoch: 2,
    previousFinalizationId: "",
    seen,
    winnerSeenAt: 5_000,
    settleWindowMs: SETTLE_WINDOW_MIN_MS,
    settledRevisionId: OTHER,
    settledEpoch: 1,
    ...extras,
  };
}

function proof(signedAt: number): EpochStatusProof {
  return {
    object: OBJECT,
    epoch: 1,
    revisionId: REV,
    accessor: BOB,
    grantRevision: 4,
    stated: 0,
    signedAt,
    maxAgeMs: 60_000,
    signature: "ab".repeat(64),
    zookie: { object: OBJECT, objectVersion: 3, snapshotHash: OTHER },
  };
}

const READERS: readonly RotationReader[] = [
  { account: BOB, epub: "bob-epub" },
  { account: CAROL, epub: "carol-epub" },
];
const PRIOR: readonly PriorHamState[] = [{ accessor: BOB, hamState: 1 }];

function rotation(cipher: EpochRotation["cipher"], targetId = "carol-epub"): EpochRotation {
  return {
    object: OBJECT,
    revokedEpoch: 1,
    nextEpoch: 2,
    revisionId: REV,
    cancelled: [
      {
        kind: "plain",
        grant: {
          grant: { object: OBJECT, accessor: BOB, from: 0, until: FAR, stated: 0 },
          hamState: 2,
        },
      },
    ],
    rewrapped: [
      {
        scope: "item-dek",
        epoch: 2,
        target: "reader-epub",
        targetId,
        object: OBJECT,
        revisionId: REV,
        wrappedKey: "aa",
      },
    ],
    cipher,
  };
}

function accept(row: EpochRotation, prior: readonly PriorHamState[] = PRIOR): void {
  assert.equal(rotateOnRevoke(row, READERS, prior), undefined);
}

function reject(row: EpochRotation, prior: readonly PriorHamState[] = PRIOR): void {
  assert.throws(() => rotateOnRevoke(row, READERS, prior), /rotation rejected/);
}

test("epoch canonical bodies match the shared fixture", () => {
  assertHash(
    "acl-snapshot-direct",
    aclSnapshotBytes({
      entries: [
        {
          accessor: BOB,
          grantRevision: 4,
          stated: 0,
          from: 10,
          until: 20,
          scope: "direct",
          setId: "",
          hamState: 0,
        },
      ],
    }),
  );
  assert.equal(
    aclSnapshotId({
      entries: [
        {
          accessor: BOB,
          grantRevision: 4,
          stated: 0,
          from: 10,
          until: 20,
          scope: "direct",
          setId: "",
          hamState: 0,
        },
      ],
    }),
    vector("acl-snapshot-direct").sha256,
  );
  assertHash(
    "acl-snapshot-group",
    aclSnapshotBytes({
      objectSet: { predicate: "same-group", setId: "crew", stated: 1, hamState: 3 },
      entries: [
        {
          accessor: ADA,
          grantRevision: 2,
          stated: 1,
          from: 0,
          until: 99,
          scope: "same-group",
          setId: "crew",
          hamState: 5,
        },
      ],
    }),
  );
  assert.equal(
    epochFinalizationId(OBJECT, 3, 2, REV, "", [REV]),
    vector("epoch-finalization-body").sha256,
  );
  assertHash("epoch-manifest-sig", epochManifestSigBytes(REV));
  assertHash("epoch-finalization-sig", epochFinalizationSigBytes(REV));
  assertHash(
    "group-epoch-config",
    groupEpochConfigBytes(ALICE, "crew", "named-circle", 7_200_000, 2),
  );
  const tie = groupEpochConfigDigest(ALICE, "crew", "named-circle", SETTLE_WINDOW_DEFAULT_MS, 2);
  assert.equal(tie, vector("group-epoch-config-tie").sha256);
  assert.ok(vector("group-epoch-config").sha256 < tie);
  assert.throws(() =>
    aclSnapshotId({
      entries: [directEntry(BOB, 1, 1), directEntry(AMY, 1, 1)],
    }),
  );
  // U+E000 and U+10000 are not principals. The shared fields and the Rust suite lock this order.
  const low = "\uE000";
  const high = "\u{10000}";
  assert.equal(parsePrincipalId(low).ok, false);
  assert.equal(parsePrincipalId(high).ok, false);
  assert.equal(high < low, true);
  assert.equal(low < high, false);
  const utf8 = vector("acl-snapshot-utf8-order");
  const fields = utf8.fields;
  if (fields === undefined) throw new Error("acl-snapshot-utf8-order");
  assert.ok(fields.includes(low));
  assert.ok(fields.includes(high));
  assert.ok(fields.indexOf(low) < fields.indexOf(high));
  assert.equal(sha256Hex(lengthPrefixed(fields)), utf8.sha256);
  assert.equal(lengthPrefixed(fields).length, utf8.encodedLen);
});

test("settle window stays inside the signed bounds", () => {
  assert.equal(SETTLE_WINDOW_MIN_MS, 3_600_000);
  assert.equal(SETTLE_WINDOW_MAX_MS, 259_200_000);
  assert.equal(SETTLE_WINDOW_DEFAULT_MS, 86_400_000);
  assert.equal(settleWindowOrDefault(undefined), SETTLE_WINDOW_DEFAULT_MS);
  assert.equal(settleWindowOrDefault(SETTLE_WINDOW_MIN_MS), SETTLE_WINDOW_MIN_MS);
  assert.equal(settleWindowOrDefault(SETTLE_WINDOW_MAX_MS + 1), SETTLE_WINDOW_MAX_MS + 1);
  assert.equal(settleWindowInRange(SETTLE_WINDOW_MIN_MS), true);
  assert.equal(settleWindowInRange(SETTLE_WINDOW_DEFAULT_MS), true);
  assert.equal(settleWindowInRange(SETTLE_WINDOW_MAX_MS), true);
  assert.equal(settleWindowInRange(SETTLE_WINDOW_MIN_MS - 1), false);
  assert.equal(settleWindowInRange(SETTLE_WINDOW_MAX_MS + 1), false);
  assert.equal(settleWindowInRange(0), false);
  assert.throws(() => settleWindowOrDefault(1.5));
});

test("the smaller finalization id wins independent of seen order", () => {
  const left = finalization("11".repeat(32));
  const right = finalization("22".repeat(32));
  const smaller = left.finalizationId < right.finalizationId ? left : right;
  assert.equal(epochWinner(view([left, right]))?.finalizationId, smaller.finalizationId);
  assert.equal(epochWinner(view([right, left]))?.finalizationId, smaller.finalizationId);
  const unsorted = finalization("11".repeat(32), ["11".repeat(32), "00".repeat(32)]);
  assert.equal(epochWinner(view([unsorted, right]))?.finalizationId, right.finalizationId);
  const foreign = { ...left, object: OBJECT_B };
  assert.equal(epochWinner(view([foreign]))?.finalizationId, undefined);
  const forged = { ...smaller, finalizationId: "00".repeat(32) };
  assert.equal(epochWinner(view([forged, right]))?.revisionId, right.revisionId);
});

test("epoch step and settled key follow the merged acl", () => {
  const live = directSnapshot([directEntry(ADA, 1)]);
  const fin = finalization(REV);
  const pending = view([fin]);
  const open = pending.winnerSeenAt + SETTLE_WINDOW_MIN_MS;
  assert.equal(epochStepCurrent(pending, live, live, open - 1), false);
  assert.equal(epochStepCurrent(pending, live, live, open), true);
  const cancelled = directSnapshot([directEntry(ADA, 0)]);
  assert.equal(epochStepCurrent(pending, live, cancelled, open), false);
  const expired = directSnapshot([{ ...directEntry(ADA, 1), until: open }]);
  assert.equal(epochStepCurrent(pending, expired, expired, open), false);
  const elapsed = view([fin], { winnerSeenAt: 0, settleWindowMs: SETTLE_WINDOW_DEFAULT_MS });
  const settledNow = SETTLE_WINDOW_DEFAULT_MS;
  const pair = directSnapshot([
    directEntry(ADA, 1, 1),
    { ...directEntry(BOB, 0, 2), stated: 0 },
  ]);
  assert.equal(epochStepCurrent(elapsed, pair, pair, settledNow), true);
  const adaCancelled = directSnapshot([
    directEntry(ADA, 0, 10),
    directEntry(BOB, 0, 2),
  ]);
  assert.equal(epochStepCurrent(elapsed, pair, adaCancelled, settledNow), false);
  const omitsBob = directSnapshot([directEntry(ADA, 0, 10)]);
  assert.equal(epochStepCurrent(elapsed, omitsBob, adaCancelled, settledNow), false);
  const lowBob = directSnapshot([
    directEntry(ADA, 0, 10),
    directEntry(BOB, 0, 1),
  ]);
  assert.equal(epochStepCurrent(elapsed, lowBob, adaCancelled, settledNow), false);
  const setA: AclSnapshotBody = {
    objectSet: { predicate: "same-group", setId: "crew-a", stated: 1, hamState: 2 },
    entries: [
      {
        accessor: CAROL,
        grantRevision: 1,
        stated: 1,
        from: 0,
        until: FAR,
        scope: "same-group",
        setId: "crew-a",
        hamState: 2,
      },
    ],
  };
  const setB: AclSnapshotBody = {
    objectSet: { predicate: "same-group", setId: "crew-b", stated: 1, hamState: 4 },
    entries: [
      {
        accessor: CAROL,
        grantRevision: 1,
        stated: 1,
        from: 0,
        until: FAR,
        scope: "same-group",
        setId: "crew-b",
        hamState: 2,
      },
    ],
  };
  assert.equal(epochStepCurrent(elapsed, setA, setB, settledNow), false);
  const removed: AclSnapshotBody = {
    ...setA,
    entries: [{ ...setA.entries[0]!, stated: 0, hamState: 4 }],
  };
  assert.equal(epochStepCurrent(elapsed, setA, removed, settledNow), false);
  assert.equal(settledKeyOpen(elapsed, setA, removed, settledNow), false);
  const short = view([fin], { settleWindowMs: 0 });
  assert.equal(epochStepCurrent(short, live, live, open), false);

  const settled = view([], { settledRevisionId: REV });
  assert.equal(settledKeyOpen(settled, live, live, open), true);
  assert.equal(settledKeyOpen(pending, live, live, open), false);
  const same = view([finalization(REV)], { settledRevisionId: REV });
  assert.equal(settledKeyOpen(same, live, live, open - 1), false);
  assert.equal(settledKeyOpen(same, live, live, open), true);
  assert.equal(settledKeyOpen(settled, expired, expired, open), false);
  assert.equal(settledKeyOpen(view([], { settledRevisionId: "" }), live, live, open), false);
  assert.equal(settledKeyOpen(view([], { settledRevisionId: "zz" }), live, live, open), false);
});

test("status freshness uses the tighter max age and the skew allowance", () => {
  const signedAt = 1_000_000;
  const row = proof(signedAt);
  assert.equal(statusIsFresh(row, signedAt + 30_000, 5_000, 120_000), true);
  assert.equal(statusIsFresh(row, signedAt + 60_000, 5_000, 120_000), true);
  assert.equal(statusIsFresh(row, signedAt + 60_001, 5_000, 120_000), false);
  assert.equal(statusIsFresh(row, signedAt + 30_000, 5_000, 10_000), false);
  assert.equal(statusIsFresh(row, signedAt - 4_000, 5_000, 120_000), true);
  assert.equal(statusIsFresh(row, signedAt - 6_000, 5_000, 120_000), false);
  assert.equal(statusIsFresh(row, 1.5, 0, 0), false);
  assert.equal(row.signature.length, 128);
});

test("rotateOnRevoke accepts both cipher modes and fails closed", () => {
  assert.equal(rotateOnRevoke.length, 3);
  accept(rotation("forward-only"));
  accept(rotation("re-encrypt"));
  const skipped = rotation("forward-only");
  skipped.nextEpoch = 3;
  reject(skipped);
  const live = rotation("re-encrypt");
  const cancel = live.cancelled[0];
  assert.ok(cancel && cancel.kind === "plain");
  if (cancel.kind === "plain" && "object" in cancel.grant.grant) {
    cancel.grant.grant.stated = 1;
  }
  reject(live);
  const quiet = rotation("forward-only");
  const quietCancel = quiet.cancelled[0];
  assert.ok(quietCancel && quietCancel.kind === "plain");
  quietCancel.grant.hamState = 0;
  reject(quiet);
  reject(rotation("forward-only"), [{ accessor: BOB, hamState: 10 }]);
  reject(rotation("forward-only"), []);
  reject(rotation("forward-only", "bob-epub"));
  reject(rotation("re-encrypt", "bob-epub"));
  reject(rotation("forward-only", "bob"));
  const blank = rotation("forward-only");
  const wrap = blank.rewrapped[0];
  assert.ok(wrap);
  wrap.wrappedKey = "";
  reject(blank);
  const groupKey = rotation("forward-only");
  const keyWrap = groupKey.rewrapped[0];
  assert.ok(keyWrap);
  keyWrap.scope = "group-key";
  reject(groupKey);
  const doubled = rotation("forward-only");
  doubled.cancelled = [...doubled.cancelled, ...doubled.cancelled];
  reject(doubled);
  const group = rotation("re-encrypt");
  const groupWrap = {
    scope: "item-dek" as const,
    epoch: 2,
    target: "group-epoch" as const,
    targetId: "crew",
    object: OBJECT,
    group: "crew",
    revisionId: REV,
    wrappedKey: "bb",
  };
  group.rewrapped = [...group.rewrapped, groupWrap];
  accept(group);
  group.rewrapped = [...group.rewrapped, { ...groupWrap, scope: "group-key" }];
  reject(group);

  const privateRow: EpochRotation = {
    object: OBJECT,
    revokedEpoch: 1,
    nextEpoch: 2,
    revisionId: REV,
    cancelled: [
      {
        kind: "private-row",
        payload: {
          object: OBJECT,
          accessor: BOB,
          from: 0,
          until: FAR,
          stated: 0,
          epoch: 1,
          owner: ALICE,
          grantRevision: 5,
          itemCiphertextDigest: "",
        },
        signature: "cd".repeat(64),
        status: { ...proof(1_000), grantRevision: 5 },
      },
    ],
    rewrapped: [],
    cipher: "forward-only",
  };
  assert.equal(rotateOnRevoke(privateRow, READERS, PRIOR), undefined);
  const stale = structuredClone(privateRow);
  const staleCancel = stale.cancelled[0];
  assert.ok(staleCancel && staleCancel.kind === "private-row");
  staleCancel.status.epoch = 9;
  assert.throws(() => rotateOnRevoke(stale, READERS, PRIOR), /rotation rejected/);
  const badSig = structuredClone(privateRow);
  const badCancel = badSig.cancelled[0];
  assert.ok(badCancel && badCancel.kind === "private-row");
  badCancel.signature = "abcd";
  assert.throws(() => rotateOnRevoke(badSig, READERS, PRIOR), /rotation rejected/);
});
