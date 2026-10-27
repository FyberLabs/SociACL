/**
 * Length-prefixed SHA-256 ids from docs/s3rch-check.d.ts.
 *
 * s3r.ch copies that contract and reimplements it. It does not import
 * this file and it does not import the Rust crate. This module hashes
 * the canonical bytes. It does not wrap keys and it does not run Check.
 * authorFastMatches only compares a revision id. It does not grant.
 */
import { createHash } from "node:crypto";
import type {
  EpochManifestBody,
  InboxEntryBody,
  ItemContentAuth,
} from "../../docs/s3rch-check.js";

const DOMAIN_INBOX = "s3rch-inbox-entry-v1";
const DOMAIN_EPOCH = "s3rch-epoch-revision-v1";
const DOMAIN_ITEM_AUTH = "s3rch-item-auth-v1";
const DOMAIN_ACCOUNT_BINDING = "s3rch-account-binding-v1";
const DOMAIN_GRANT_COMMITMENT = "s3rch-grant-commitment-v1";
const DOMAIN_GRANT_PAYLOAD = "s3rch-grant-payload-v1";
const DOMAIN_PRESENTER_BINDING = "s3rch-presenter-binding-v1";
const DOMAIN_EPOCH_STATUS = "s3rch-epoch-status-v1";
const DOMAIN_WRITER_APPEND = "s3rch-writer-append-v1";
const DOMAIN_WRITER_CHANNEL = "s3rch-writer-channel-v1";
const DOMAIN_INBOX_POW = "s3rch-inbox-pow-v1";
const DOMAIN_INBOX_STAMP = "s3rch-inbox-stamp-v1";
const DOMAIN_WRAP_RECEIPT = "s3rch-wrap-receipt-v1";

export function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

/** ASCII decimal, no sign, no leading zeros. Zero is "0". */
export function canonicalDecimal(value: number): string {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error("bad decimal");
  }
  return String(value);
}

export function lengthPrefixed(fields: readonly string[]): Uint8Array {
  const parts = fields.map((field) => new TextEncoder().encode(field));
  let size = 0;
  for (const part of parts) {
    if (part.length > 0xffffffff) {
      throw new Error("field is too long");
    }
    size += 4 + part.length;
  }
  const out = new Uint8Array(size);
  const view = new DataView(out.buffer);
  let offset = 0;
  for (const part of parts) {
    view.setUint32(offset, part.length, true);
    out.set(part, offset + 4);
    offset += 4 + part.length;
  }
  return out;
}

function blank(value: string | undefined): string {
  return value !== undefined && value.length > 0 ? value : "";
}

export function inboxEntryBytes(body: InboxEntryBody): Uint8Array {
  const wrap = body.wrap;
  const fields = wrap
    ? [
        DOMAIN_INBOX,
        body.laneId,
        body.grantCiphertext,
        body.commitment.hash,
        "1",
        wrap.scope,
        canonicalDecimal(wrap.epoch),
        wrap.target,
        wrap.targetId,
        blank(wrap.object),
        blank(wrap.group),
        wrap.revisionId,
        wrap.wrappedKey,
      ]
    : [DOMAIN_INBOX, body.laneId, body.grantCiphertext, body.commitment.hash, "0", "", "", "", "", "", "", "", ""];
  return lengthPrefixed(fields);
}

export function inboxEntryId(body: InboxEntryBody): string {
  return sha256Hex(inboxEntryBytes(body));
}

export function epochRevisionBytes(body: EpochManifestBody): Uint8Array {
  const fields = [
    DOMAIN_EPOCH,
    body.object,
    canonicalDecimal(body.epoch),
    canonicalDecimal(body.previousEpoch),
    body.deviceId,
    body.keyCommitment,
    canonicalDecimal(body.settleWindowMs),
    body.aclSnapshot,
  ];
  const statusAuthPub = body.statusAuthPub;
  if (statusAuthPub !== undefined) {
    if (statusAuthPub.length === 0) throw new Error("bad revision");
    fields.push(statusAuthPub);
  }
  return lengthPrefixed(fields);
}

export function epochRevisionId(body: EpochManifestBody): string {
  return sha256Hex(epochRevisionBytes(body));
}

/** Signed item-auth bytes. The signature is not a field of this encoding. */
export type ItemAuthBody = Pick<
  ItemContentAuth,
  "object" | "epoch" | "version" | "plaintextDigest" | "revisionId"
>;

export function itemAuthBytes(body: ItemAuthBody): Uint8Array {
  return lengthPrefixed([
    DOMAIN_ITEM_AUTH,
    body.object,
    canonicalDecimal(body.epoch),
    canonicalDecimal(body.version),
    body.plaintextDigest,
    body.revisionId,
  ]);
}

export function itemAuthSha256(body: ItemAuthBody): string {
  return sha256Hex(itemAuthBytes(body));
}

export function accountBindingBytes(account: string, seaPub: string, epub: string): Uint8Array {
  return lengthPrefixed([DOMAIN_ACCOUNT_BINDING, account, seaPub, epub]);
}

export function accountBindingSha256(account: string, seaPub: string, epub: string): string {
  return sha256Hex(accountBindingBytes(account, seaPub, epub));
}

/** Canonical grant fields covered by the commitment and the owner signature. */
export type GrantPayloadBody = {
  object: string;
  accessor: string;
  from: number;
  until: number;
  stated: number;
  epoch: number;
  owner: string;
  grantRevision: number;
  itemCiphertextDigest: string;
};

function grantFields(body: GrantPayloadBody): string[] {
  return [
    body.object,
    body.accessor,
    canonicalDecimal(body.from),
    canonicalDecimal(body.until),
    canonicalDecimal(body.stated),
    canonicalDecimal(body.epoch),
    body.owner,
    canonicalDecimal(body.grantRevision),
    body.itemCiphertextDigest,
  ];
}

export function grantCommitmentBytes(blinding: string, body: GrantPayloadBody): Uint8Array {
  return lengthPrefixed([DOMAIN_GRANT_COMMITMENT, blinding, ...grantFields(body)]);
}

export function grantCommitmentHash(blinding: string, body: GrantPayloadBody): string {
  return sha256Hex(grantCommitmentBytes(blinding, body));
}

export function grantPayloadBytes(body: GrantPayloadBody): Uint8Array {
  return lengthPrefixed([DOMAIN_GRANT_PAYLOAD, ...grantFields(body)]);
}

export function grantPayloadDigest(body: GrantPayloadBody): string {
  return sha256Hex(grantPayloadBytes(body));
}

export function presenterBindingBytes(
  nonce: string,
  commitmentHash: string,
  audience: string,
): Uint8Array {
  return lengthPrefixed([DOMAIN_PRESENTER_BINDING, nonce, commitmentHash, audience]);
}

export function presenterBindingSha256(
  nonce: string,
  commitmentHash: string,
  audience: string,
): string {
  return sha256Hex(presenterBindingBytes(nonce, commitmentHash, audience));
}

export type EpochStatusBody = {
  object: string;
  epoch: number;
  revisionId: string;
  accessor: string;
  grantRevision: number;
  stated: number;
  signedAt: number;
  maxAgeMs: number;
  zookieObject: string;
  zookieVersion: number;
  zookieSnapshot: string;
};

export function epochStatusBytes(body: EpochStatusBody): Uint8Array {
  return lengthPrefixed([
    DOMAIN_EPOCH_STATUS,
    body.object,
    canonicalDecimal(body.epoch),
    body.revisionId,
    body.accessor,
    canonicalDecimal(body.grantRevision),
    canonicalDecimal(body.stated),
    canonicalDecimal(body.signedAt),
    canonicalDecimal(body.maxAgeMs),
    body.zookieObject,
    canonicalDecimal(body.zookieVersion),
    body.zookieSnapshot,
  ]);
}

export function epochStatusSha256(body: EpochStatusBody): string {
  return sha256Hex(epochStatusBytes(body));
}

export function writerChannelBytes(writer: string): Uint8Array {
  return lengthPrefixed([DOMAIN_WRITER_CHANNEL, writer]);
}

export function writerChannelSha256(writer: string): string {
  return sha256Hex(writerChannelBytes(writer));
}

export function writerAppendBytes(entryId: string): Uint8Array {
  return lengthPrefixed([DOMAIN_WRITER_APPEND, entryId]);
}

export function writerAppendSha256(entryId: string): string {
  return sha256Hex(writerAppendBytes(entryId));
}

export function inboxPowBytes(nonce: string, entryId: string, solution: string): Uint8Array {
  return lengthPrefixed([DOMAIN_INBOX_POW, nonce, entryId, solution]);
}

export function inboxPowSha256(nonce: string, entryId: string, solution: string): string {
  return sha256Hex(inboxPowBytes(nonce, entryId, solution));
}

export function inboxStampBytes(entryId: string): Uint8Array {
  return lengthPrefixed([DOMAIN_INBOX_STAMP, entryId]);
}

export function inboxStampSha256(entryId: string): string {
  return sha256Hex(inboxStampBytes(entryId));
}

/** Length-prefixed wrap receipt. A concatenated string is not this encoding. */
export function wrapReceiptBytes(
  object: string,
  accessor: string,
  toVersion: number,
  revisionId: string,
  entryId: string,
): Uint8Array {
  return lengthPrefixed([
    DOMAIN_WRAP_RECEIPT,
    object,
    accessor,
    canonicalDecimal(toVersion),
    revisionId,
    entryId,
  ]);
}

export function wrapReceiptSha256(
  object: string,
  accessor: string,
  toVersion: number,
  revisionId: string,
  entryId: string,
): string {
  return sha256Hex(wrapReceiptBytes(object, accessor, toVersion, revisionId, entryId));
}

/** Leading zero bits of a lowercase hex SHA-256 digest. */
export function leadingZeroBits(hex: string): number {
  let count = 0;
  for (let index = 0; index < hex.length; index += 2) {
    const byte = Number.parseInt(hex.slice(index, index + 2), 16);
    if (byte === 0) {
      count += 8;
    } else {
      count += Math.clz32(byte) - 24;
      break;
    }
  }
  return count;
}

/** True only when the object and the manifest revision both match. */
export function authorFastMatches(
  record: { object: string; revisionId: string },
  object: string,
  revisionId: string,
): boolean {
  return record.object === object && record.revisionId === revisionId;
}
