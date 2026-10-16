/**
 * Length-prefixed SHA-256 ids from docs/s3rch-check.d.ts.
 *
 * s3r.ch copies that contract and reimplements it. It does not import
 * this file and it does not import the Rust crate. This module hashes
 * the canonical bytes. It does not wrap keys and it does not run Check.
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
  return lengthPrefixed([
    DOMAIN_EPOCH,
    body.object,
    canonicalDecimal(body.epoch),
    canonicalDecimal(body.previousEpoch),
    body.deviceId,
    body.keyCommitment,
    canonicalDecimal(body.settleWindowMs),
    body.aclSnapshot,
  ]);
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
