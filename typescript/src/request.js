/**
 * Signed access-request encoding and the owner-client approval helper.
 * A request is an untrusted hint. Accepting one does not write a grant.
 * grantApprovedRequest runs on the owner's client. Members auto-approve
 * calls checkGroupSee on that client. There is no hosted evaluator.
 * Explicit deny and the policy queue are not this module.
 * Check does not verify a signature. A hop, a hint, a wrap, a request,
 * or an inbox delivery never grants. Hopcap stays 1.
 *
 * @typedef {{
 *   requester: string,
 *   source: string,
 *   scope: string,
 *   message: string,
 *   status: string,
 * }} AccessRequestInput
 * @typedef {{
 *   requester: string,
 *   source: string,
 *   scope: "read" | "read+post",
 *   message: string,
 *   status: "pending" | "withdrawn",
 *   id: string,
 *   signingBytes: Uint8Array,
 * }} AcceptedAccessRequest
 * @typedef {{ predicate: "same-group" | "named-circle", now: number }} MembersAutoApprove
 * @typedef {{
 *   objectRecord(source: string): { id: string, owner: string } | undefined,
 *   stateSeeGrant(owner: string, grant: { object: string, accessor: string, from: number, until: number }): void,
 *   statePostGrant(owner: string, grant: { object: string, accessor: string, from: number, until: number }): void,
 *   seeGrant(object: string, accessor: string): { soul?: string, owner?: string, hamState?: number, grant?: { object?: string, accessor?: string, from?: number, until?: number, stated?: number } } | undefined,
 *   postGrant(object: string, accessor: string): { soul?: string, owner?: string, hamState?: number, grant?: { object?: string, accessor?: string, from?: number, until?: number, stated?: number } } | undefined,
 *   checkGroupSee?: (predicate: string, object: string, accessor: string, now: number) => { allowed: boolean, reason: string },
 * }} RequestGraph
 * @typedef {{
 *   granted: true,
 *   requestId: string,
 *   requestSigningBytes: Uint8Array,
 *   see: NonNullable<ReturnType<RequestGraph["seeGrant"]>>,
 *   post: NonNullable<ReturnType<RequestGraph["postGrant"]>> | null,
 *   postSigningBytes: Uint8Array | null,
 * } | {
 *   granted: false,
 *   reason: "withdrawn" | "owner" | "missing" | "not-member",
 * }} AccessApproval
 */

import { createHash } from "node:crypto";
import { canonicalAccessorId, nextPostHam, postGrantSigningBytes } from "./post.js";

export const ACCESS_REQUEST_DOMAIN = "s3rch-access-request-v1";
export const ACCESS_REQUEST_ID_DOMAIN = "s3rch-request";
export const ACCESS_SCOPE_READ = "read";
export const ACCESS_SCOPE_READ_POST = "read+post";
export const ACCESS_STATUS_PENDING = "pending";
export const ACCESS_STATUS_WITHDRAWN = "withdrawn";
export const ACCESS_MESSAGE_MAX = 280;

const FIELD = "access request field is not canonical";
const HELD_CLAIM_PREFIXES = ["ens:", "unstoppable:", "fc:", "lens:", "rss3:"];

/** @param {string} id */
function encodeKey(id) {
  return String(id).replace(/[.#$[\]]/g, "_");
}

/** @param {string} id */
function aclKey(id) {
  return encodeKey(String(id).trim()).replace(/\//g, "_");
}

/** @param {string} id */
function isItemShaped(id) {
  const parts = String(id).trim().split("/");
  return parts.length === 3 && parts[0] === "s3rch" && parts[1] === "items" && parts[2] !== "";
}

/** @param {string} id */
function mayAliasToItemSoul(id) {
  const text = String(id).trim();
  if (isItemShaped(text)) return true;
  if (!text.includes("/") && HELD_CLAIM_PREFIXES.some((prefix) => text.startsWith(prefix))) return false;
  return true;
}

/** @param {string} id */
function closedSource(id) {
  const text = String(id).trim();
  if (text.includes("://")) return true;
  if (text === "s3rch/meta") return true;
  if (text === "s3rch/acl" || text.startsWith("s3rch/acl/")) return true;
  return false;
}

/**
 * Canonical accessor id from the see/post path. Empty is rejected.
 * @param {string} requester
 */
export function canonicalRequestAccessor(requester) {
  const id = canonicalAccessorId(requester);
  if (!id) throw new Error(FIELD);
  return id;
}

/**
 * Object key for a request id. aclKey, with an aliasable item soul
 * reduced to the raw id's aclKey. A held claim does not alias.
 * @param {string} source
 */
export function canonicalRequestObject(source) {
  const id = String(source ?? "").trim();
  if (!id || closedSource(id)) throw new Error(FIELD);
  if (isItemShaped(id)) {
    const inner = id.split("/")[2] ?? "";
    if (
      inner &&
      !inner.includes("/") &&
      encodeKey(inner) === inner &&
      mayAliasToItemSoul(inner) &&
      !isItemShaped(inner)
    ) {
      const soul = `s3rch/items/${encodeKey(inner)}`;
      if (soul === id) {
        const key = aclKey(inner);
        if (!key) throw new Error(FIELD);
        return key;
      }
    }
  }
  const key = aclKey(id);
  if (!key) throw new Error(FIELD);
  return key;
}

/** @param {Uint8Array} bytes */
function sha256Hex(bytes) {
  const digest = createHash("sha256").update(bytes).digest();
  let hex = "";
  for (const byte of digest) hex += byte.toString(16).padStart(2, "0");
  return hex;
}

/** @param {readonly string[]} fields */
function lengthPrefixed(fields) {
  /** @type {Uint8Array[]} */
  const parts = [];
  const encoder = new TextEncoder();
  for (const field of fields) {
    const bytes = encoder.encode(field);
    const len = new Uint8Array(4);
    new DataView(len.buffer).setUint32(0, bytes.length, true);
    parts.push(len, bytes);
  }
  const size = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/**
 * SHA-256 lowercase hex. Scope, message, and status are not inputs.
 * @param {string} requester
 * @param {string} source
 * @returns {string}
 */
export function accessRequestId(requester, source) {
  const bytes = lengthPrefixed([
    ACCESS_REQUEST_ID_DOMAIN,
    canonicalRequestAccessor(requester),
    canonicalRequestObject(source),
  ]);
  return sha256Hex(bytes);
}

/** @param {string} scope */
function canonicalScope(scope) {
  if (scope !== ACCESS_SCOPE_READ && scope !== ACCESS_SCOPE_READ_POST) throw new Error(FIELD);
  return scope;
}

/** @param {string} status */
function canonicalStatus(status) {
  if (status !== ACCESS_STATUS_PENDING && status !== ACCESS_STATUS_WITHDRAWN) throw new Error(FIELD);
  return status;
}

/** @param {string} message */
function canonicalMessage(message) {
  if (typeof message !== "string") throw new Error(FIELD);
  if (Array.from(message).length > ACCESS_MESSAGE_MAX) throw new Error(FIELD);
  return message;
}

/**
 * Length-prefixed bytes a later signature can cover. Does not grant.
 * @param {AccessRequestInput} request
 */
export function accessRequestSigningBytes(request) {
  const id = accessRequestId(request.requester, request.source);
  return lengthPrefixed([
    ACCESS_REQUEST_DOMAIN,
    id,
    canonicalScope(request.scope),
    canonicalMessage(request.message),
    canonicalStatus(request.status),
  ]);
}

/**
 * Canonicalize a request. Does not read a graph and does not grant.
 * @param {AccessRequestInput} request
 * @returns {AcceptedAccessRequest}
 */
export function acceptAccessRequest(request) {
  const requester = canonicalRequestAccessor(request.requester);
  const source = canonicalRequestObject(request.source);
  const scope = canonicalScope(request.scope);
  const status = canonicalStatus(request.status);
  const message = canonicalMessage(request.message);
  const signingBytes = accessRequestSigningBytes(request);
  const id = accessRequestId(request.requester, request.source);
  return { requester, source, scope, message, status, id, signingBytes };
}

/**
 * @param {{ from: number, until: number }} window
 */
function canonicalWindow(window) {
  const from = window?.from;
  const until = window?.until;
  return Number.isSafeInteger(from) && Number.isSafeInteger(until) && from >= 0 && until >= 0 && from < until;
}

/**
 * Owner's client. Writes see, and post for read+post.
 * members runs checkGroupSee and writes only when that allows.
 * @param {RequestGraph} graph
 * @param {string} owner
 * @param {AccessRequestInput} request
 * @param {{ from: number, until: number }} window
 * @param {MembersAutoApprove | null | undefined} members
 * @returns {AccessApproval}
 */
export function grantApprovedRequest(graph, owner, request, window, members) {
  const accepted = acceptAccessRequest(request);
  if (accepted.status !== ACCESS_STATUS_PENDING) return { granted: false, reason: "withdrawn" };
  if (!canonicalWindow(window)) throw new Error(FIELD);
  const record = typeof graph.objectRecord === "function" ? graph.objectRecord(request.source) : undefined;
  if (!record?.id || record.owner == null || record.owner === "") return { granted: false, reason: "missing" };
  if (canonicalAccessorId(record.owner) !== canonicalAccessorId(owner)) {
    return { granted: false, reason: "owner" };
  }
  if (members) {
    if (members.predicate !== "same-group" && members.predicate !== "named-circle") throw new Error(FIELD);
    if (!Number.isSafeInteger(members.now) || members.now < 0) throw new Error(FIELD);
    if (typeof graph.checkGroupSee !== "function") return { granted: false, reason: "not-member" };
    const see = graph.checkGroupSee(members.predicate, request.source, request.requester, members.now);
    if (!see || see.allowed !== true) return { granted: false, reason: "not-member" };
  }
  const accessor = accepted.requester;
  if (accepted.scope === ACCESS_SCOPE_READ_POST) {
    const prev = graph.postGrant(record.id, accessor);
    if (nextPostHam(prev?.hamState, false) === undefined) {
      throw new Error("post grant field is not a canonical integer");
    }
  }
  graph.stateSeeGrant(record.owner, {
    object: record.id,
    accessor,
    from: window.from,
    until: window.until,
  });
  /** @type {NonNullable<ReturnType<RequestGraph["postGrant"]>> | null} */
  let postEdge = null;
  /** @type {Uint8Array | null} */
  let postSigningBytes = null;
  if (accepted.scope === ACCESS_SCOPE_READ_POST) {
    graph.statePostGrant(record.owner, {
      object: record.id,
      accessor,
      from: window.from,
      until: window.until,
    });
    const edge = graph.postGrant(record.id, accessor);
    const grant = edge?.grant;
    if (
      !edge ||
      edge.hamState == null ||
      !grant ||
      grant.object == null ||
      grant.accessor == null ||
      grant.stated == null ||
      grant.from == null ||
      grant.until == null
    ) {
      return { granted: false, reason: "missing" };
    }
    postEdge = edge;
    postSigningBytes = postGrantSigningBytes({
      hamState: edge.hamState,
      grant: {
        object: grant.object,
        accessor: grant.accessor,
        stated: grant.stated,
        from: grant.from,
        until: grant.until,
      },
    });
  }
  const see = graph.seeGrant(record.id, accessor);
  if (!see?.grant) return { granted: false, reason: "missing" };
  return {
    granted: true,
    requestId: accepted.id,
    requestSigningBytes: accepted.signingBytes,
    see,
    post: postEdge,
    postSigningBytes,
  };
}
