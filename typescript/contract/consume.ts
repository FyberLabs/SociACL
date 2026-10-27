/**
 * Encrypted-discovery consume checks from docs/s3rch-check.d.ts.
 *
 * s3r.ch copies that contract and reimplements this file. It does not
 * import this module and it does not import the Rust crate. Ciphertext
 * is fetched from the revision soul. The grant names the manifest soul.
 * A hop, a status statement, and a chat node do not mint.
 */
import { p256 } from "@noble/curves/nist.js";
import { canonicalDecimal, lengthPrefixed, sha256Hex } from "./canonical.ts";
import { hexToBytes, uncompressedFromSea } from "./account-key-seal.ts";
import { KEYRING_HISTORY_MAX } from "./keyring-limits.ts";

/** Steps from a head at KEYRING_HISTORY_MAX down through seq 0. */
const ACCOUNT_KEY_WALK_LIMIT = KEYRING_HISTORY_MAX + 1;

/**
 * Ceiling for a provider or wallet account-key head, in milliseconds.
 * Five minutes covers an answer and ordinary clock skew. A longer window
 * would keep a retired key current for a verifier that has not stored an
 * anchor. The signed maxAgeMs and the verifier's policyMaxAgeMs can be
 * shorter. Neither can raise this ceiling.
 */
export const ACCOUNT_KEY_HEAD_MAX_AGE_MS = 300_000;

export const DOMAIN_ENV_DIGEST = "s3rch-env-digest-v1";
export const DOMAIN_REVISION_MANIFEST = "s3rch-revision-manifest-v1";
export const DOMAIN_GRANT_MANIFEST = "s3rch-grant-manifest-v1";
export const DOMAIN_STATUS_AUTHORITY = "s3rch-status-authority-v1";
export const DOMAIN_GROUP_INBOX_BODY = "s3rch-group-inbox-body-v1";
export const DOMAIN_GROUP_INBOX_SSIG = "s3rch-group-inbox-ssig-v1";
export const DOMAIN_ACCOUNT_KEY_LOG = "s3rch-account-key-log-v1";
export const DOMAIN_ACCOUNT_KEY_HEAD = "s3rch-account-key-head-v1";

const PREV_NONE = "none";

export type ConsumeDecision = { ok: true } | { ok: false; reason: string };

export type CurrentKeyDecision =
  | { ok: true; keyPub: string }
  | { ok: false; reason: string };

export type RevisionManifest = {
  itemId: string;
  e: number;
  rev: string;
  parent: string;
  keyId: string;
  envDigest: string;
  statusAuthPub?: string;
};

export type StatusAuthorityBinding = {
  account: string;
  accountPub: string;
  statusAuthPub: string;
  seq: number;
};

export type GroupInboxWriteSig = {
  tag: string;
  entryId: string;
  senderPub: string;
  bodyHash: string;
};

export type AccountKeyLogEntry = {
  account: string;
  keyPub: string;
  seq: number;
  prev: string;
};

/** Provider or wallet head. issuedAt and maxAgeMs are inside the signature. */
export type AccountKeyLogHead = {
  account: string;
  seq: number;
  entryHash: string;
  issuedAt: number;
  maxAgeMs: number;
};

/**
 * An entry already accepted. The hash is recomputed from `entry`.
 * A shortcut requires this account and seq + 1.
 */
export type AccountKeyAnchor = {
  entry: AccountKeyLogEntry;
};

function pathSegment(value: string): void {
  if (
    value.length === 0 ||
    value.length > 256 ||
    value === "." ||
    value === ".." ||
    value.includes("/") ||
    /[\s\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new Error("bad path");
  }
}

function digestHex(value: string): void {
  if (!/^[0-9a-f]{64}$/.test(value)) {
    throw new Error("bad revision");
  }
}

function refuse(reason: string): ConsumeDecision {
  return { ok: false, reason };
}

function accept(): ConsumeDecision {
  return { ok: true };
}

export function itemRevisionSoul(itemId: string, rev: string): string {
  pathSegment(itemId);
  pathSegment(rev);
  return `s3rch/items/${itemId}/r/${rev}`;
}

export function manifestSoul(itemId: string, rev: string): string {
  pathSegment(itemId);
  pathSegment(rev);
  return `s3rch/items/${itemId}/m/${rev}`;
}

export function itemRootSoul(itemId: string): string {
  pathSegment(itemId);
  return `s3rch/items/${itemId}`;
}

export function groupInboxSoul(tag: string, entryId: string): string {
  pathSegment(tag);
  pathSegment(entryId);
  return `s3rch/ginbox/${tag}/${entryId}`;
}

export function envDigest(
  itemId: string,
  e: number,
  rev: string,
  alg: string,
  iv: string,
  ct: string,
): string {
  pathSegment(itemId);
  pathSegment(rev);
  return sha256Hex(
    lengthPrefixed([
      DOMAIN_ENV_DIGEST,
      itemId,
      canonicalDecimal(e),
      rev,
      alg,
      iv,
      ct,
    ]),
  );
}

export function revisionManifestBytes(manifest: RevisionManifest): Uint8Array {
  pathSegment(manifest.itemId);
  pathSegment(manifest.rev);
  digestHex(manifest.keyId);
  digestHex(manifest.envDigest);
  const fields = [
    DOMAIN_REVISION_MANIFEST,
    manifest.itemId,
    canonicalDecimal(manifest.e),
    manifest.rev,
    manifest.parent,
    manifest.keyId,
    manifest.envDigest,
  ];
  const statusAuthPub = requireStatusAuth(manifest.statusAuthPub);
  if (statusAuthPub !== undefined) fields.push(statusAuthPub);
  return lengthPrefixed(fields);
}

export function grantManifestBytes(itemId: string, rev: string, manifest: string): Uint8Array {
  pathSegment(itemId);
  pathSegment(rev);
  return lengthPrefixed([DOMAIN_GRANT_MANIFEST, itemId, rev, manifest]);
}

export function statusAuthorityBytes(binding: StatusAuthorityBinding): Uint8Array {
  if (
    binding.account.length === 0 ||
    binding.accountPub.length === 0 ||
    binding.statusAuthPub.length === 0
  ) {
    throw new Error("bad path");
  }
  return lengthPrefixed([
    DOMAIN_STATUS_AUTHORITY,
    binding.account,
    binding.accountPub,
    binding.statusAuthPub,
    canonicalDecimal(binding.seq),
  ]);
}

export function groupInboxBodyHash(eph: string, ct: string, iv: string): string {
  return sha256Hex(lengthPrefixed([DOMAIN_GROUP_INBOX_BODY, eph, ct, iv]));
}

export function groupInboxSigBytes(sig: GroupInboxWriteSig): Uint8Array {
  pathSegment(sig.tag);
  pathSegment(sig.entryId);
  digestHex(sig.bodyHash);
  if (sig.senderPub.length === 0) {
    throw new Error("bad path");
  }
  return lengthPrefixed([
    DOMAIN_GROUP_INBOX_SSIG,
    sig.tag,
    sig.entryId,
    sig.senderPub,
    sig.bodyHash,
  ]);
}

export function accountKeyLogBytes(entry: AccountKeyLogEntry): Uint8Array {
  if (entry.account.length === 0 || entry.keyPub.length === 0) {
    throw new Error("bad path");
  }
  return lengthPrefixed([
    DOMAIN_ACCOUNT_KEY_LOG,
    entry.account,
    entry.keyPub,
    canonicalDecimal(entry.seq),
    entry.prev,
  ]);
}

export function accountKeyEntryHash(entry: AccountKeyLogEntry): string {
  return sha256Hex(accountKeyLogBytes(entry));
}

export function accountKeyHeadBytes(head: AccountKeyLogHead): Uint8Array {
  if (head.account.length === 0) {
    throw new Error("bad path");
  }
  digestHex(head.entryHash);
  return lengthPrefixed([
    DOMAIN_ACCOUNT_KEY_HEAD,
    head.account,
    canonicalDecimal(head.seq),
    head.entryHash,
    canonicalDecimal(head.issuedAt),
    canonicalDecimal(head.maxAgeMs),
  ]);
}

export function accountKeyHeadSignedBySea(): boolean {
  return false;
}

export function consumeStatementMints(_kind: string): boolean {
  return false;
}

export function acceptItemLocator(
  v: number,
  enc: number,
  first: string,
  expectedFirst: string,
  hasCiphertext: boolean,
): ConsumeDecision {
  if (hasCiphertext) return refuse("root-ciphertext");
  try {
    pathSegment(first);
  } catch {
    return refuse("bad-soul");
  }
  if (v !== 2 || enc !== 1 || first !== expectedFirst) return refuse("bad-soul");
  return accept();
}

export function acceptEnvelope(input: {
  itemId: string;
  e: number;
  rev: string;
  fetchedSoul: string;
  rootHasCiphertext: boolean;
  alg: string;
  iv: string;
  ct: string;
  envDigest: string;
}): ConsumeDecision {
  if (input.rootHasCiphertext) return refuse("root-ciphertext");
  let soul: string;
  try {
    soul = itemRevisionSoul(input.itemId, input.rev);
  } catch {
    return refuse("bad-path");
  }
  if (input.fetchedSoul !== soul) return refuse("bad-soul");
  let digest: string;
  try {
    digest = envDigest(input.itemId, input.e, input.rev, input.alg, input.iv, input.ct);
  } catch {
    return refuse("digest-mismatch");
  }
  if (digest !== input.envDigest) return refuse("digest-mismatch");
  return accept();
}

export function acceptGrantManifest(input: {
  manifest?: string;
  itemId: string;
  rev: string;
  authorLaneOnly: boolean;
}): ConsumeDecision {
  if (input.authorLaneOnly) return refuse("author-lane");
  const manifest = input.manifest;
  if (manifest === undefined || manifest.length === 0) return refuse("bad-soul");
  let soul: string;
  try {
    soul = manifestSoul(input.itemId, input.rev);
  } catch {
    return refuse("bad-path");
  }
  if (manifest !== soul) return refuse("bad-soul");
  return accept();
}

export function acceptRevisionManifest(input: {
  nodeV: number;
  manifest: RevisionManifest;
  itemId: string;
  rev: string;
  envelopeDigest: string;
  carriesAccountPub: boolean;
}): ConsumeDecision {
  if (input.carriesAccountPub) return refuse("bad-soul");
  if (
    input.nodeV !== 1 ||
    input.manifest.itemId !== input.itemId ||
    input.manifest.rev !== input.rev
  ) {
    return refuse("bad-soul");
  }
  if (input.manifest.envDigest !== input.envelopeDigest) return refuse("digest-mismatch");
  try {
    revisionManifestBytes(input.manifest);
  } catch {
    return refuse("bad-path");
  }
  return accept();
}

/**
 * bindingSignedByCurrent is the consumer's result. This check does not
 * verify the binding signature. The consumer must verify it under the
 * current account SEA pub before passing true.
 */
export function acceptStatusSigner(input: {
  signingPub: string;
  currentAccountPub: string;
  binding?: StatusAuthorityBinding;
  manifestStatusAuthPub?: string;
  logHeadAccount?: string;
  logHeadSeq?: number;
  bindingSignedByCurrent: boolean;
  purpose: string;
}): ConsumeDecision {
  if (input.signingPub.length === 0 || input.currentAccountPub.length === 0) {
    return refuse("authority-key");
  }
  if (input.purpose !== "status") {
    return input.signingPub === input.currentAccountPub ? accept() : refuse("authority-key");
  }
  if (input.signingPub === input.currentAccountPub) return accept();
  const binding = input.binding;
  const manifestPub = input.manifestStatusAuthPub;
  if (
    binding === undefined ||
    manifestPub === undefined ||
    manifestPub.length === 0 ||
    input.logHeadAccount === undefined ||
    input.logHeadAccount.length === 0 ||
    input.logHeadSeq === undefined
  ) {
    return refuse("missing-binding");
  }
  if (
    binding.account !== input.logHeadAccount ||
    binding.accountPub !== input.currentAccountPub ||
    binding.statusAuthPub !== input.signingPub ||
    manifestPub !== input.signingPub ||
    binding.seq !== input.logHeadSeq ||
    !input.bindingSignedByCurrent
  ) {
    return refuse("authority-key");
  }
  return accept();
}

/**
 * member, signatureUnderSender, and derivedFromGroupKey are the consumer's
 * results. This check does not verify ssig, membership, or a derivation
 * from the group epoch key. The consumer must do those checks before
 * passing true.
 */
export function acceptGroupInboxSender(input: {
  senderPub: string;
  currentAccountPub: string;
  member: boolean;
  signatureUnderSender: boolean;
  derivedFromGroupKey: boolean;
}): ConsumeDecision {
  if (input.derivedFromGroupKey) return refuse("group-writer-key");
  if (!input.signatureUnderSender) return refuse("authority-key");
  if (!input.member) return refuse("not-member");
  if (input.senderPub.length === 0 || input.senderPub !== input.currentAccountPub) {
    return refuse("superseded");
  }
  return accept();
}

function uniqueIndex(
  entries: readonly AccountKeyLogEntry[],
  account: string,
  seq: number,
): number | undefined {
  let found: number | undefined;
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    if (entry !== undefined && entry.account === account && entry.seq === seq) {
      if (found !== undefined) throw new Error("duplicate");
      found = index;
    }
  }
  return found;
}

function requireStatusAuth(statusAuthPub: string | undefined): string | undefined {
  if (statusAuthPub === undefined) return undefined;
  if (statusAuthPub.length === 0) throw new Error("bad revision");
  return statusAuthPub;
}

function anchorLinks(
  entry: AccountKeyLogEntry,
  entryHash: string,
  anchor: AccountKeyLogEntry,
  anchorHash: string,
): boolean {
  if (entry.account !== anchor.account) return false;
  if (entryHash === anchorHash && entry.seq === anchor.seq) return true;
  return entry.prev === anchorHash && entry.seq === anchor.seq + 1;
}

function safeTime(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0;
}

function headIsFresh(
  issuedAt: number,
  signedMaxAgeMs: number,
  now: number,
  skewAllowanceMs: number,
  policyMaxAgeMs: number,
): boolean {
  if (
    !safeTime(issuedAt) ||
    !safeTime(signedMaxAgeMs) ||
    !safeTime(now) ||
    !safeTime(skewAllowanceMs) ||
    !safeTime(policyMaxAgeMs)
  ) {
    return false;
  }
  let bound = signedMaxAgeMs < policyMaxAgeMs ? signedMaxAgeMs : policyMaxAgeMs;
  if (ACCOUNT_KEY_HEAD_MAX_AGE_MS < bound) bound = ACCOUNT_KEY_HEAD_MAX_AGE_MS;
  const latest = BigInt(now) + BigInt(skewAllowanceMs);
  if (BigInt(issuedAt) > latest) return false;
  if (BigInt(now) >= BigInt(issuedAt)) {
    return BigInt(now) - BigInt(issuedAt) <= BigInt(bound);
  }
  return true;
}

/** True when a hash-linked entry below `seq` uses the provider signing key. */
function providerKeyBelow(
  entries: readonly AccountKeyLogEntry[],
  account: string,
  seq: number,
  prev: string,
  providerPub: string,
): boolean {
  let currentSeq = seq;
  let currentPrev = prev;
  for (let step = 0; step < ACCOUNT_KEY_WALK_LIMIT; step += 1) {
    if (currentSeq === 0) return false;
    let parent: number | undefined;
    try {
      parent = uniqueIndex(entries, account, currentSeq - 1);
    } catch {
      return true;
    }
    if (parent === undefined) return false;
    const parentEntry = entries[parent];
    if (parentEntry === undefined || parentEntry.account !== account) return true;
    let parentHash: string;
    try {
      parentHash = accountKeyEntryHash(parentEntry);
    } catch {
      return false;
    }
    if (parentHash !== currentPrev) return false;
    if (parentEntry.keyPub === providerPub) return true;
    currentSeq = parentEntry.seq;
    currentPrev = parentEntry.prev;
  }
  return false;
}

function headSignatureOk(providerPub: string, head: AccountKeyLogHead, signature: string): boolean {
  if (providerPub.length === 0 || signature.length === 0) return false;
  try {
    return p256.verify(hexToBytes(signature), accountKeyHeadBytes(head), uncompressedFromSea(providerPub), {
      lowS: true,
      prehash: true,
    });
  } catch {
    return false;
  }
}

export function acceptCurrentKey(input: {
  head?: AccountKeyLogHead;
  entries: readonly AccountKeyLogEntry[];
  anchor?: AccountKeyAnchor;
  providerAnswered: boolean;
  providerPub: string;
  headSignature: string;
  expectedAccount: string;
  statementKeyPub: string;
  now: number;
  skewAllowanceMs: number;
  policyMaxAgeMs: number;
}): CurrentKeyDecision {
  if (!input.providerAnswered) return { ok: false, reason: "no-answer" };
  const head = input.head;
  if (head === undefined) return { ok: false, reason: "missing-head" };
  if (!headSignatureOk(input.providerPub, head, input.headSignature)) {
    return { ok: false, reason: "head-mismatch" };
  }
  if (
    input.expectedAccount.length === 0 ||
    head.account !== input.expectedAccount ||
    !/^[0-9a-f]{64}$/.test(head.entryHash)
  ) {
    return { ok: false, reason: "head-mismatch" };
  }
  let start: number | undefined;
  try {
    start = uniqueIndex(input.entries, input.expectedAccount, head.seq);
  } catch {
    return { ok: false, reason: "head-mismatch" };
  }
  if (start === undefined) return { ok: false, reason: "unlinked" };
  const startEntry = input.entries[start];
  if (startEntry === undefined) return { ok: false, reason: "unlinked" };
  let startHash: string;
  try {
    startHash = accountKeyEntryHash(startEntry);
  } catch {
    return { ok: false, reason: "head-mismatch" };
  }
  if (startHash !== head.entryHash || startEntry.keyPub.length === 0) {
    return { ok: false, reason: "head-mismatch" };
  }
  if (
    !headIsFresh(
      head.issuedAt,
      head.maxAgeMs,
      input.now,
      input.skewAllowanceMs,
      input.policyMaxAgeMs,
    )
  ) {
    return { ok: false, reason: "stale" };
  }
  let resolvedAnchor: { entry: AccountKeyLogEntry; hash: string } | undefined;
  const anchor = input.anchor;
  if (anchor !== undefined) {
    if (anchor.entry.account !== input.expectedAccount) return { ok: false, reason: "unlinked" };
    let hash: string;
    try {
      hash = accountKeyEntryHash(anchor.entry);
    } catch {
      return { ok: false, reason: "unlinked" };
    }
    if (head.seq < anchor.entry.seq) return { ok: false, reason: "superseded" };
    resolvedAnchor = { entry: anchor.entry, hash };
  }
  let index = start;
  let linked = false;
  let below: { seq: number; prev: string } | undefined;
  for (let step = 0; step < ACCOUNT_KEY_WALK_LIMIT; step += 1) {
    const entry = input.entries[index];
    if (entry === undefined) return { ok: false, reason: "unlinked" };
    if (entry.account !== input.expectedAccount) return { ok: false, reason: "head-mismatch" };
    if (entry.keyPub === input.providerPub) return { ok: false, reason: "head-mismatch" };
    let entryHash: string;
    try {
      entryHash = accountKeyEntryHash(entry);
    } catch {
      return { ok: false, reason: "prev-mismatch" };
    }
    if (resolvedAnchor !== undefined) {
      if (anchorLinks(entry, entryHash, resolvedAnchor.entry, resolvedAnchor.hash)) {
        if (resolvedAnchor.entry.keyPub === input.providerPub) {
          return { ok: false, reason: "head-mismatch" };
        }
        linked = true;
        below = { seq: resolvedAnchor.entry.seq, prev: resolvedAnchor.entry.prev };
        break;
      }
      if (entry.seq <= resolvedAnchor.entry.seq) return { ok: false, reason: "unlinked" };
    }
    if (entry.seq === 0) {
      if (resolvedAnchor !== undefined) return { ok: false, reason: "unlinked" };
      if (entry.prev !== PREV_NONE) return { ok: false, reason: "prev-mismatch" };
      linked = true;
      below = { seq: entry.seq, prev: entry.prev };
      break;
    }
    let parent: number | undefined;
    try {
      parent = uniqueIndex(input.entries, input.expectedAccount, entry.seq - 1);
    } catch {
      return { ok: false, reason: "head-mismatch" };
    }
    if (parent === undefined) return { ok: false, reason: "unlinked" };
    const parentEntry = input.entries[parent];
    if (parentEntry === undefined) return { ok: false, reason: "unlinked" };
    let parentHash: string;
    try {
      parentHash = accountKeyEntryHash(parentEntry);
    } catch {
      return { ok: false, reason: "prev-mismatch" };
    }
    if (parentHash !== entry.prev) return { ok: false, reason: "prev-mismatch" };
    index = parent;
  }
  if (!linked) return { ok: false, reason: "unlinked" };
  if (
    below !== undefined &&
    providerKeyBelow(input.entries, input.expectedAccount, below.seq, below.prev, input.providerPub)
  ) {
    return { ok: false, reason: "head-mismatch" };
  }
  if (input.statementKeyPub !== startEntry.keyPub) {
    return { ok: false, reason: "superseded" };
  }
  return { ok: true, keyPub: startEntry.keyPub };
}
