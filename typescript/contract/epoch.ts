/**
 * Epoch admission, freshness, and rotation structure from
 * docs/s3rch-check.d.ts.
 *
 * s3r.ch copies that contract and reimplements it. It does not import
 * this file and it does not import the Rust crate. This module hashes
 * canonical bytes and fails closed on the decision functions. SEA
 * signatures stay in the Rust reference. A snapshot hash does not mint.
 * rotateOnRevoke does not grant, and it does not read a settle window.
 */
import type {
  AclSnapshotBody,
  AclSnapshotEntry,
  EpochFinalization,
  EpochReplicaView,
  EpochRotation,
  EpochStatusProof,
  MeshMembership,
  MeshSeeGrant,
  RotationCancel,
} from "../../docs/s3rch-check.js";
import { canonicalDecimal, lengthPrefixed, sha256Hex } from "./canonical.ts";

const DOMAIN_ACL_SNAPSHOT = "s3rch-acl-snapshot-v1";
const DOMAIN_EPOCH_FINALIZATION = "s3rch-epoch-finalization-v1";
const DOMAIN_EPOCH_MANIFEST_SIG = "s3rch-epoch-manifest-sig-v1";
const DOMAIN_EPOCH_FINALIZATION_SIG = "s3rch-epoch-finalization-sig-v1";
const DOMAIN_GROUP_EPOCH_CONFIG = "s3rch-group-epoch-config-v1";

export const SETTLE_WINDOW_MIN_MS = 3_600_000;
export const SETTLE_WINDOW_MAX_MS = 259_200_000;
export const SETTLE_WINDOW_DEFAULT_MS = 86_400_000;

/** Bytewise UTF-8 order. JavaScript `<` follows UTF-16 and disagrees past U+FFFF. */
function utf8Compare(left: string, right: string): number {
  const encodedLeft = new TextEncoder().encode(left);
  const encodedRight = new TextEncoder().encode(right);
  const length = Math.min(encodedLeft.length, encodedRight.length);
  for (let index = 0; index < length; index += 1) {
    const leftByte = encodedLeft[index] ?? 0;
    const rightByte = encodedRight[index] ?? 0;
    if (leftByte !== rightByte) {
      return leftByte - rightByte;
    }
  }
  return encodedLeft.length - encodedRight.length;
}

function safe(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0;
}

function isRevisionId(value: string): boolean {
  return /^[0-9a-f]{64}$/.test(value);
}

function isSignatureHex(value: string): boolean {
  return /^[0-9a-f]{128}$/.test(value);
}

export function settleWindowInRange(window: number): boolean {
  return safe(window) && window >= SETTLE_WINDOW_MIN_MS && window <= SETTLE_WINDOW_MAX_MS;
}

/** Omitted number is the default. An out-of-range number is not clamped. */
export function settleWindowOrDefault(signed: number | undefined): number {
  if (signed === undefined) {
    return SETTLE_WINDOW_DEFAULT_MS;
  }
  if (!safe(signed)) {
    throw new Error("bad decimal");
  }
  return signed;
}

function rejectEpoch(): never {
  throw new Error("epoch rejected");
}

function entryShape(entry: AclSnapshotEntry, body: AclSnapshotBody): void {
  if (entry.accessor.length === 0) {
    rejectEpoch();
  }
  if (entry.stated !== 0 && entry.stated !== 1) {
    rejectEpoch();
  }
  if (
    !safe(entry.grantRevision) ||
    !safe(entry.from) ||
    !safe(entry.until) ||
    !safe(entry.hamState)
  ) {
    rejectEpoch();
  }
  if (entry.scope === "direct") {
    if (entry.setId.length !== 0 || entry.hamState !== 0) {
      rejectEpoch();
    }
    return;
  }
  if (entry.scope !== "same-group" && entry.scope !== "named-circle") {
    rejectEpoch();
  }
  const set = body.objectSet;
  if (
    set === undefined ||
    entry.setId.length === 0 ||
    entry.scope !== set.predicate ||
    entry.setId !== set.setId
  ) {
    rejectEpoch();
  }
}

export function aclSnapshotBytes(body: AclSnapshotBody): Uint8Array {
  const set = body.objectSet;
  if (set !== undefined) {
    if (set.setId.length === 0 || (set.stated !== 0 && set.stated !== 1) || !safe(set.hamState)) {
      rejectEpoch();
    }
    if (set.predicate !== "same-group" && set.predicate !== "named-circle") {
      rejectEpoch();
    }
  }
  let previous: string | undefined;
  for (const entry of body.entries) {
    entryShape(entry, body);
    if (previous !== undefined && utf8Compare(entry.accessor, previous) <= 0) {
      rejectEpoch();
    }
    previous = entry.accessor;
  }
  const fields = [
    DOMAIN_ACL_SNAPSHOT,
    set !== undefined ? "1" : "0",
    set?.predicate ?? "",
    set?.setId ?? "",
    set !== undefined ? canonicalDecimal(set.stated) : "",
    set !== undefined ? canonicalDecimal(set.hamState) : "",
  ];
  for (const entry of body.entries) {
    fields.push(
      entry.accessor,
      canonicalDecimal(entry.grantRevision),
      canonicalDecimal(entry.stated),
      canonicalDecimal(entry.from),
      canonicalDecimal(entry.until),
      entry.scope,
      entry.setId,
      canonicalDecimal(entry.hamState),
    );
  }
  return lengthPrefixed(fields);
}

/** SHA-256 of the snapshot body. Entries stay in the given order. Does not mint. */
export function aclSnapshotId(body: AclSnapshotBody): string {
  return sha256Hex(aclSnapshotBytes(body));
}

export function epochManifestSigBytes(revisionId: string): Uint8Array {
  return lengthPrefixed([DOMAIN_EPOCH_MANIFEST_SIG, revisionId]);
}

export function epochFinalizationSigBytes(finalizationId: string): Uint8Array {
  return lengthPrefixed([DOMAIN_EPOCH_FINALIZATION_SIG, finalizationId]);
}

export function epochFinalizationId(
  object: string,
  epoch: number,
  previousEpoch: number,
  revisionId: string,
  previousFinalizationId: string,
  candidates: readonly string[],
): string {
  return sha256Hex(
    lengthPrefixed([
      DOMAIN_EPOCH_FINALIZATION,
      object,
      canonicalDecimal(epoch),
      canonicalDecimal(previousEpoch),
      revisionId,
      previousFinalizationId,
      ...candidates,
    ]),
  );
}

export function groupEpochConfigBytes(
  owner: string,
  setId: string,
  predicate: string,
  settleWindowMs: number,
  configRevision: number,
): Uint8Array {
  return lengthPrefixed([
    DOMAIN_GROUP_EPOCH_CONFIG,
    owner,
    setId,
    predicate,
    canonicalDecimal(settleWindowMs),
    canonicalDecimal(configRevision),
  ]);
}

export function groupEpochConfigDigest(
  owner: string,
  setId: string,
  predicate: string,
  settleWindowMs: number,
  configRevision: number,
): string {
  return sha256Hex(groupEpochConfigBytes(owner, setId, predicate, settleWindowMs, configRevision));
}

function normalized(entries: readonly AclSnapshotEntry[]): AclSnapshotEntry[] | undefined {
  const rows = [...entries].sort((left, right) => utf8Compare(left.accessor, right.accessor));
  for (let index = 1; index < rows.length; index += 1) {
    const prior = rows[index - 1];
    const row = rows[index];
    if (prior === undefined || row === undefined || prior.accessor === row.accessor) {
      return undefined;
    }
  }
  return rows;
}

function entryNumbers(entry: AclSnapshotEntry): boolean {
  return (
    (entry.stated === 0 || entry.stated === 1) &&
    safe(entry.grantRevision) &&
    safe(entry.from) &&
    safe(entry.until) &&
    safe(entry.hamState)
  );
}

function snapshotMatches(snapshot: AclSnapshotBody, current: AclSnapshotBody, now: number): boolean {
  if (!safe(now)) {
    return false;
  }
  const snapshotEntries = normalized(snapshot.entries);
  const currentEntries = normalized(current.entries);
  if (snapshotEntries === undefined || currentEntries === undefined) {
    return false;
  }
  for (const entry of [...snapshotEntries, ...currentEntries]) {
    if (!entryNumbers(entry)) {
      return false;
    }
  }
  const left = snapshot.objectSet;
  const right = current.objectSet;
  if (left === undefined && right === undefined) {
    // direct object
  } else if (left !== undefined && right !== undefined) {
    if (
      left.predicate !== right.predicate ||
      left.setId !== right.setId ||
      left.stated !== right.stated ||
      !safe(left.hamState) ||
      !safe(right.hamState) ||
      left.hamState < right.hamState
    ) {
      return false;
    }
  } else {
    return false;
  }
  for (const entry of snapshotEntries) {
    if (entry.stated === 1 && (entry.until <= now || entry.from > now)) {
      return false;
    }
    const held = currentEntries.find((row) => row.accessor === entry.accessor);
    if (held === undefined) {
      continue;
    }
    if (held.grantRevision > entry.grantRevision) {
      return false;
    }
    if (held.stated === 0 && entry.stated === 1) {
      return false;
    }
    if (held.until < entry.until || held.from > entry.from) {
      return false;
    }
    if (
      held.stated === 0 &&
      held.scope !== "direct" &&
      held.hamState > entry.hamState &&
      held.scope === entry.scope &&
      held.setId === entry.setId
    ) {
      return false;
    }
  }
  for (const held of currentEntries) {
    if (held.stated !== 0) {
      continue;
    }
    const entry = snapshotEntries.find((row) => row.accessor === held.accessor);
    if (entry === undefined) {
      return false;
    }
    if (entry.stated === 1 || entry.grantRevision < held.grantRevision) {
      return false;
    }
    if (
      held.scope !== "direct" &&
      (entry.scope !== held.scope || entry.setId !== held.setId || entry.hamState < held.hamState)
    ) {
      return false;
    }
  }
  return true;
}

function finalizationCounts(view: EpochReplicaView, fin: EpochFinalization): boolean {
  if (
    fin.object !== view.object ||
    fin.epoch !== view.epoch ||
    fin.previousFinalizationId !== view.previousFinalizationId
  ) {
    return false;
  }
  const first = fin.candidateRevisionIds[0];
  if (first === undefined || first !== fin.revisionId) {
    return false;
  }
  const sorted = [...fin.candidateRevisionIds].sort();
  if (sorted.length !== fin.candidateRevisionIds.length) {
    return false;
  }
  for (let index = 0; index < sorted.length; index += 1) {
    if (sorted[index] !== fin.candidateRevisionIds[index]) {
      return false;
    }
  }
  try {
    const id = epochFinalizationId(
      fin.object,
      fin.epoch,
      fin.previousEpoch,
      fin.revisionId,
      fin.previousFinalizationId,
      fin.candidateRevisionIds,
    );
    return id === fin.finalizationId;
  } catch {
    return false;
  }
}

/** Smallest finalizationId among the finalizations that count for this step. */
export function epochWinner(view: EpochReplicaView): EpochFinalization | undefined {
  let best: EpochFinalization | undefined;
  for (const fin of view.seen) {
    if (!finalizationCounts(view, fin)) {
      continue;
    }
    if (best === undefined || fin.finalizationId < best.finalizationId) {
      best = fin;
    }
  }
  return best;
}

function windowElapsed(seenAt: number, window: number, now: number): boolean {
  if (!safe(seenAt) || !safe(window) || !safe(now)) {
    return false;
  }
  return BigInt(now) >= BigInt(seenAt) + BigInt(window);
}

export function epochStepCurrent(
  view: EpochReplicaView,
  snapshot: AclSnapshotBody,
  current: AclSnapshotBody,
  now: number,
): boolean {
  if (!settleWindowInRange(view.settleWindowMs)) {
    return false;
  }
  if (!snapshotMatches(snapshot, current, now)) {
    return false;
  }
  if (epochWinner(view) === undefined) {
    return false;
  }
  return windowElapsed(view.winnerSeenAt, view.settleWindowMs, now);
}

export function settledKeyOpen(
  view: EpochReplicaView,
  settled: AclSnapshotBody,
  current: AclSnapshotBody,
  now: number,
): boolean {
  if (!settleWindowInRange(view.settleWindowMs)) {
    return false;
  }
  if (view.settledRevisionId.length === 0 || !isRevisionId(view.settledRevisionId)) {
    return false;
  }
  if (!snapshotMatches(settled, current, now)) {
    return false;
  }
  const winner = epochWinner(view);
  if (winner !== undefined) {
    if (winner.revisionId !== view.settledRevisionId) {
      return false;
    }
    if (!windowElapsed(view.winnerSeenAt, view.settleWindowMs, now)) {
      return false;
    }
  }
  return true;
}

export function statusIsFresh(
  proof: EpochStatusProof,
  now: number,
  skewAllowanceMs: number,
  policyMaxAgeMs: number,
): boolean {
  if (
    !safe(proof.signedAt) ||
    !safe(proof.maxAgeMs) ||
    !safe(now) ||
    !safe(skewAllowanceMs) ||
    !safe(policyMaxAgeMs)
  ) {
    return false;
  }
  const bound = proof.maxAgeMs < policyMaxAgeMs ? proof.maxAgeMs : policyMaxAgeMs;
  const latest = BigInt(now) + BigInt(skewAllowanceMs);
  if (BigInt(proof.signedAt) > latest) {
    return false;
  }
  if (BigInt(now) >= BigInt(proof.signedAt)) {
    return BigInt(now) - BigInt(proof.signedAt) <= BigInt(bound);
  }
  return true;
}

function rejectRotation(): never {
  throw new Error("rotation rejected");
}

function isMembership(grant: MeshSeeGrant | MeshMembership): grant is MeshMembership {
  return "predicate" in grant && "setId" in grant && !("object" in grant);
}

function isSeeGrant(grant: MeshSeeGrant | MeshMembership): grant is MeshSeeGrant {
  return "object" in grant && !("predicate" in grant);
}

export type RotationReader = {
  account: string;
  epub: string;
};

export type PriorHamState = {
  accessor: string;
  hamState: number;
};

function plainAccessor(
  rotation: EpochRotation,
  priorHam: readonly PriorHamState[],
  cancel: RotationCancel & { kind: "plain" },
): string {
  const record = cancel.grant;
  if (!safe(record.hamState) || record.hamState === 0) {
    rejectRotation();
  }
  const grant = record.grant;
  if (isSeeGrant(grant)) {
    if (
      grant.object !== rotation.object ||
      grant.accessor.length === 0 ||
      grant.stated !== 0 ||
      !safe(grant.from) ||
      !safe(grant.until)
    ) {
      rejectRotation();
    }
    return requireNewerHam(priorHam, grant.accessor, record.hamState);
  }
  if (!isMembership(grant)) {
    rejectRotation();
  }
  if (
    grant.accessor.length === 0 ||
    grant.stated !== 0 ||
    grant.hamState !== record.hamState ||
    grant.setId.length === 0 ||
    (grant.predicate !== "same-group" && grant.predicate !== "named-circle") ||
    !safe(grant.hamState)
  ) {
    rejectRotation();
  }
  return requireNewerHam(priorHam, grant.accessor, record.hamState);
}

function requireNewerHam(
  priorHam: readonly PriorHamState[],
  accessor: string,
  hamState: number,
): string {
  const prior = priorHam.find((row) => row.accessor === accessor);
  if (prior === undefined || !safe(prior.hamState) || hamState <= prior.hamState) {
    rejectRotation();
  }
  return accessor;
}

function privateAccessor(
  rotation: EpochRotation,
  cancel: RotationCancel & { kind: "private-row" },
): string {
  const payload = cancel.payload;
  if (
    !isSignatureHex(cancel.signature) ||
    payload.object !== rotation.object ||
    payload.stated !== 0 ||
    payload.epoch !== rotation.revokedEpoch ||
    payload.accessor.length === 0 ||
    payload.owner.length === 0 ||
    !safe(payload.from) ||
    !safe(payload.until) ||
    !safe(payload.grantRevision) ||
    (payload.itemCiphertextDigest !== "" && !isRevisionId(payload.itemCiphertextDigest))
  ) {
    rejectRotation();
  }
  const status = cancel.status;
  if (
    !isSignatureHex(status.signature) ||
    !isRevisionId(status.revisionId) ||
    status.object !== payload.object ||
    status.zookie.object !== payload.object ||
    status.accessor !== payload.accessor ||
    status.grantRevision !== payload.grantRevision ||
    status.stated !== 0 ||
    status.epoch !== payload.epoch ||
    !safe(status.signedAt) ||
    !safe(status.maxAgeMs) ||
    !safe(status.zookie.objectVersion) ||
    !isRevisionId(status.zookie.snapshotHash)
  ) {
    rejectRotation();
  }
  return payload.accessor;
}

function structuralCancel(
  rotation: EpochRotation,
  priorHam: readonly PriorHamState[],
  cancel: RotationCancel,
): string {
  if (cancel.kind === "plain") {
    return plainAccessor(rotation, priorHam, cancel);
  }
  if (cancel.kind === "private-row") {
    return privateAccessor(rotation, cancel);
  }
  rejectRotation();
}

function accountForEpub(readers: readonly RotationReader[], epub: string): string | undefined {
  let account: string | undefined;
  for (const reader of readers) {
    if (reader.epub !== epub) {
      continue;
    }
    if (account !== undefined) {
      return undefined;
    }
    account = reader.account;
  }
  return account;
}

function blank(value: string | undefined): boolean {
  return value === undefined || value.length === 0;
}

function structuralWraps(
  rotation: EpochRotation,
  readers: readonly RotationReader[],
  revoked: readonly string[],
): void {
  const seenReaders: string[] = [];
  let seenGroup = false;
  for (const wrap of rotation.rewrapped) {
    if (
      wrap.epoch !== rotation.nextEpoch ||
      wrap.revisionId !== rotation.revisionId ||
      !/^[0-9a-f]+$/.test(wrap.wrappedKey)
    ) {
      rejectRotation();
    }
    if (wrap.scope === "item-dek" && wrap.target === "reader-epub") {
      if (wrap.object !== rotation.object || !blank(wrap.group)) {
        rejectRotation();
      }
      const accessor = accountForEpub(readers, wrap.targetId);
      if (
        accessor === undefined ||
        accessor.length === 0 ||
        revoked.includes(accessor) ||
        seenReaders.includes(accessor)
      ) {
        rejectRotation();
      }
      seenReaders.push(accessor);
      continue;
    }
    if (wrap.scope === "item-dek" && wrap.target === "group-epoch") {
      if (
        seenGroup ||
        wrap.targetId.length === 0 ||
        wrap.object !== rotation.object ||
        wrap.group !== wrap.targetId
      ) {
        rejectRotation();
      }
      seenGroup = true;
      continue;
    }
    rejectRotation();
  }
}

/**
 * Structural privilege-down check. SEA verification stays in Rust.
 * readers maps each enrolled epub to its accessor before a revoked
 * reader is excluded. priorHam is the merged live hamState. The
 * settle window is not an argument, so this check cannot delay it.
 * Returns nothing. A wrap named here is not a grant.
 */
export function rotateOnRevoke(
  rotation: EpochRotation,
  readers: readonly RotationReader[],
  priorHam: readonly PriorHamState[],
): void {
  if (rotation.object.length === 0) {
    rejectRotation();
  }
  if (!safe(rotation.revokedEpoch) || !safe(rotation.nextEpoch)) {
    rejectRotation();
  }
  if (rotation.nextEpoch !== rotation.revokedEpoch + 1) {
    rejectRotation();
  }
  if (!isRevisionId(rotation.revisionId)) {
    rejectRotation();
  }
  if (rotation.cipher !== "forward-only" && rotation.cipher !== "re-encrypt") {
    rejectRotation();
  }
  if (readersConflict(readers) || rotation.cancelled.length === 0) {
    rejectRotation();
  }
  const revoked: string[] = [];
  for (const cancel of rotation.cancelled) {
    const accessor = structuralCancel(rotation, priorHam, cancel);
    if (revoked.includes(accessor)) {
      rejectRotation();
    }
    revoked.push(accessor);
  }
  structuralWraps(rotation, readers, revoked);
}

function readersConflict(readers: readonly RotationReader[]): boolean {
  for (let index = 0; index < readers.length; index += 1) {
    const reader = readers[index];
    if (reader === undefined || reader.account.length === 0 || reader.epub.length === 0) {
      return true;
    }
    for (let later = index + 1; later < readers.length; later += 1) {
      const other = readers[later];
      if (other !== undefined && (other.account === reader.account || other.epub === reader.epub)) {
        return true;
      }
    }
  }
  return false;
}
