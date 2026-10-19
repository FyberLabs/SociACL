/**
 * Signed access-request encoding and the owner-client approval helper.
 * A request is an untrusted hint. Accepting one does not write a grant.
 * grantApprovedRequest runs on the owner's client. Members auto-approve
 * calls checkGroupSee on that client. There is no hosted evaluator.
 * Explicit deny and the policy queue are not this module.
 * The requester signs the request. The owner's client verifies that
 * signature against the enrolled key before any write. Grant rows
 * stay unsigned. A hop, a hint, a wrap, a request, or an inbox
 * delivery never grants. Hopcap stays 1.
 *
 * @typedef {{
 *   requester: string,
 *   source: string,
 *   scope: string,
 *   message: string,
 *   status: string,
 *   signature?: Uint8Array,
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
 *   seeGrant(object: string, accessor: string): { soul?: string, owner?: string, hamState?: number, grant?: { object?: string, accessor?: string, from?: number, until?: number, stated?: number } } | undefined,
 *   postGrant(object: string, accessor: string): { soul?: string, owner?: string, hamState?: number, grant?: { object?: string, accessor?: string, from?: number, until?: number, stated?: number } } | undefined,
 *   enrolledKey(principal: string): Uint8Array | undefined,
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
 *   reason: "withdrawn" | "owner" | "missing" | "not-member" | "signature",
 * }} AccessApproval
 */

import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { canonicalAccessorId, hasLabelPostWriter, nextPostHam, postGrantSigningBytes, stateLabelPost } from "./legacy/post-label.js";

const PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);
const SPKI_PREFIX = Uint8Array.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

export const ACCESS_REQUEST_DOMAIN = "s3rch-access-request-v1";
export const ACCESS_REQUEST_ID_DOMAIN = "s3rch-request";
export const ACCESS_SCOPE_READ = "read";
export const ACCESS_SCOPE_READ_POST = "read+post";
export const ACCESS_STATUS_PENDING = "pending";
export const ACCESS_STATUS_WITHDRAWN = "withdrawn";
export const ACCESS_MESSAGE_MAX = 280;

const FIELD = "access request field is not canonical";
const HELD_CLAIM_PREFIXES = ["ens:", "unstoppable:", "fc:", "lens:", "rss3:"];

/**
 * Same injective escape as post.js. `/` is escaped only by aclKey.
 * @param {string} id
 * @param {boolean} slash
 */
function escapeKey(id, slash) {
  return String(id).replace(slash ? /[~.#$[\]/]/g : /[~.#$[\]]/g, (ch) => {
    switch (ch) {
      case "~":
        return "~0";
      case ".":
        return "~1";
      case "#":
        return "~2";
      case "$":
        return "~3";
      case "[":
        return "~4";
      case "]":
        return "~5";
      case "/":
        return "~6";
      default:
        return ch;
    }
  });
}

/** @param {string} id */
function encodeKey(id) {
  return escapeKey(id, false);
}

/** @param {string} id */
function aclKey(id) {
  return escapeKey(String(id).trim(), true);
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
  if (isHttpUrlLeaf(text)) return true;
  if (text === "meta" || text === "s3rch/meta" || isMetaSoul(text)) return true;
  if (text === "acl" || text.startsWith("s3rch/acl") || isAclSoul(text)) return true;
  return false;
}

/** @param {string} text */
function isMetaSoul(text) {
  const segments = soulSegments(text);
  return segments != null && segments.length === 2 && segments[0] === "s3rch" && segments[1] === "meta";
}

/** @param {string} text */
function isAclSoul(text) {
  const segments = soulSegments(text);
  return segments != null && segments.length >= 2 && segments[0] === "s3rch" && segments[1] === "acl";
}

/**
 * Slash souls trim each segment and drop empty ones.
 * A string containing `.get(` is not a soul.
 * @param {string} text
 * @returns {string[] | null}
 */
function soulSegments(text) {
  if (text.includes(".get(")) return null;
  const segments = text
    .split("/")
    .map((part) => part.trim())
    .filter((part) => part !== "");
  return segments.length === 0 ? null : segments;
}

/** Same HTTP(S) leaf predicate as the Rust encoder. The scheme is folded first. `ipfs://` is not one. @param {string} id */
function isHttpUrlLeaf(id) {
  const hash = id.indexOf("#");
  const body = hash === -1 ? id : id.slice(0, hash);
  const mark = body.indexOf("://");
  if (mark < 0) return false;
  const scheme = body.slice(0, mark).toLowerCase();
  if (scheme !== "http" && scheme !== "https") return false;
  const rest = body.slice(mark + 3);
  if (!rest) return false;
  const slash = rest.indexOf("/");
  const hostport = slash === -1 ? rest : rest.slice(0, slash);
  return hostport.length > 0;
}

/**
 * Canonical accessor id from the see/post path. Empty is rejected.
 * The raw string must be Unicode scalar values. U+0085 and U+FEFF are
 * rejected so this trim matches Rust.
 * @param {string} requester
 */
export function canonicalRequestAccessor(requester) {
  if (typeof requester !== "string" || requester.includes(".get(")) throw new Error(FIELD);
  const raw = requester;
  requireUnicodeScalars(raw);
  rejectTrimMismatch(raw);
  const id = canonicalAccessorId(raw);
  if (!id) throw new Error(FIELD);
  return id;
}

/**
 * Object key for a request id. aclKey, with an aliasable item soul
 * reduced to the raw id's aclKey. An underscore in that raw id stays.
 * A held claim does not alias. The raw string must be Unicode scalar
 * values. U+0085 and U+FEFF are rejected so this trim matches Rust.
 * @param {string} source
 */
export function canonicalRequestObject(source) {
  if (typeof source !== "string" || source.includes(".get(")) throw new Error(FIELD);
  const raw = source;
  requireUnicodeScalars(raw);
  rejectTrimMismatch(raw);
  const id = raw.trim();
  if (!id || closedSource(id)) throw new Error(FIELD);
  const inner = reducibleItemInner(id);
  if (inner) {
    const key = aclKey(inner);
    if (!key) throw new Error(FIELD);
    return key;
  }
  const key = aclKey(id);
  if (!key) throw new Error(FIELD);
  return key;
}

/**
 * Reverse of encodeKey. A bad escape is not an item id.
 * @param {string} encoded
 * @returns {string | null}
 */
function unescapeEncodeKey(encoded) {
  let out = "";
  for (let i = 0; i < encoded.length; i += 1) {
    if (encoded[i] !== "~") {
      out += encoded[i];
      continue;
    }
    const decoded = { 0: "~", 1: ".", 2: "#", 3: "$", 4: "[", 5: "]", 6: "/" }[encoded[i + 1]];
    if (decoded == null) return null;
    out += decoded;
    i += 1;
  }
  return out;
}

/**
 * Item soul whose reconstructed form equals the trimmed source.
 * The inner segment is encodeKey(raw), decoded once before aclKey.
 * A spaced segment such as `s3rch/items/ foo` is not the raw id `foo`.
 * `s3rch/items/a_b` is the item soul of `a_b` and shares that request
 * key. It is not the request key of `a/b`.
 * @param {string} id
 * @returns {string | null}
 */
function reducibleItemInner(id) {
  const segments = soulSegments(id);
  if (!segments || segments.length !== 3 || segments[0] !== "s3rch" || segments[1] !== "items") return null;
  const encoded = segments[2] ?? "";
  if (!encoded || encoded.includes("/")) return null;
  const raw = unescapeEncodeKey(encoded);
  if (raw == null || !raw || raw.includes("/")) return null;
  if (encodeKey(raw) !== encoded) return null;
  if (!mayAliasToItemSoul(raw) || isItemShaped(raw)) return null;
  const soul = `s3rch/items/${encodeKey(raw)}`;
  if (soul !== id.trim()) return null;
  return raw;
}

/** Unpaired UTF-16 is not a Unicode scalar value. @param {string} text */
function requireUnicodeScalars(text) {
  for (let i = 0; i < text.length; i += 1) {
    const unit = text.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = text.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new Error(FIELD);
      i += 1;
      continue;
    }
    if (unit >= 0xdc00 && unit <= 0xdfff) throw new Error(FIELD);
  }
}

/**
 * Rust `trim` strips U+0085 and keeps U+FEFF. JavaScript `trim` does
 * the opposite. Either character in a requester or source is rejected.
 * @param {string} text
 */
function rejectTrimMismatch(text) {
  for (let i = 0; i < text.length; i += 1) {
    const unit = text.charCodeAt(i);
    if (unit === 0x0085 || unit === 0xfeff) throw new Error(FIELD);
  }
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
  requireUnicodeScalars(message);
  if (Array.from(message).length > ACCESS_MESSAGE_MAX) throw new Error(FIELD);
  return message;
}

/** @param {Uint8Array} raw */
function publicKeyFromRaw(raw) {
  const bytes = new Uint8Array(raw);
  const spki = new Uint8Array(SPKI_PREFIX.length + bytes.length);
  spki.set(SPKI_PREFIX, 0);
  spki.set(bytes, SPKI_PREFIX.length);
  return createPublicKey({ key: spki, format: "der", type: "spki" });
}

/**
 * Ed25519 signature over accessRequestSigningBytes. Does not grant.
 * @param {import("node:crypto").KeyObject} privateKey
 * @param {AccessRequestInput} request
 */
export function signAccessRequest(privateKey, request) {
  return new Uint8Array(sign(null, accessRequestSigningBytes(request), privateKey));
}

/**
 * @param {Uint8Array | undefined} publicKey
 * @param {Uint8Array} signingBytes
 * @param {Uint8Array | undefined} signature
 */
function requestSignatureOk(publicKey, signingBytes, signature) {
  if (!publicKey || publicKey.length !== 32 || !(signature instanceof Uint8Array) || signature.length !== 64) {
    return false;
  }
  try {
    return verify(null, signingBytes, publicKeyFromRaw(publicKey), signature);
  } catch {
    return false;
  }
}

/** @param {Uint8Array} seed */
export function requestIssuerFromSeed(seed) {
  const seedBytes = new Uint8Array(seed);
  const pkcs8 = new Uint8Array(PKCS8_PREFIX.length + seedBytes.length);
  pkcs8.set(PKCS8_PREFIX, 0);
  pkcs8.set(seedBytes, PKCS8_PREFIX.length);
  const privateKey = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const spki = new Uint8Array(createPublicKey(privateKey).export({ type: "spki", format: "der" }));
  return { privateKey, publicKey: spki.slice(spki.length - 32) };
}

/**
 * Length-prefixed bytes a later signature can cover. Does not grant.
 * @param {AccessRequestInput} request
 */
export function accessRequestSigningBytes(request) {
  const captured = captureRequest(request);
  const id = accessRequestId(captured.requester, captured.source);
  return lengthPrefixed([
    ACCESS_REQUEST_DOMAIN,
    id,
    canonicalScope(captured.scope),
    canonicalMessage(captured.message),
    canonicalStatus(captured.status),
  ]);
}

/**
 * Canonicalize a request. Does not read a graph and does not grant.
 * @param {AccessRequestInput} request
 * @returns {AcceptedAccessRequest}
 */
export function acceptAccessRequest(request) {
  const captured = captureRequest(request);
  const requester = canonicalRequestAccessor(captured.requester);
  const source = canonicalRequestObject(captured.source);
  const scope = canonicalScope(captured.scope);
  const status = canonicalStatus(captured.status);
  const message = canonicalMessage(captured.message);
  const signingBytes = accessRequestSigningBytes(captured);
  const id = accessRequestId(captured.requester, captured.source);
  return { requester, source, scope, message, status, id, signingBytes };
}

/** @param {unknown} value */
function snapshotString(value) {
  if (typeof value !== "string") throw new Error(FIELD);
  return value;
}

/**
 * One plain string copy of the request fields. A non-string is rejected,
 * so a stateful toString cannot change the source after signing.
 * @param {AccessRequestInput} request
 * @returns {AccessRequestInput}
 */
function captureRequest(request) {
  const signature = request?.signature;
  return {
    requester: snapshotString(request?.requester),
    source: snapshotString(request?.source),
    scope: snapshotString(request?.scope),
    message: snapshotString(request?.message),
    status: snapshotString(request?.status),
    signature: signature instanceof Uint8Array ? Uint8Array.from(signature) : signature,
  };
}

/** @param {{ hamState?: number } | undefined} edge */
function seeCanAdvance(edge) {
  if (!edge) return true;
  const ham = edge.hamState ?? 0;
  if (typeof ham !== "number" || !Number.isFinite(ham) || ham < 0) return false;
  const next = ham + 1;
  return next > ham && Number.isSafeInteger(next);
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
  const captured = captureRequest(request);
  const accepted = acceptAccessRequest(captured);
  const key = typeof graph.enrolledKey === "function" ? graph.enrolledKey(accepted.requester) : undefined;
  if (!requestSignatureOk(key, accepted.signingBytes, captured.signature)) return { granted: false, reason: "signature" };
  if (accepted.status !== ACCESS_STATUS_PENDING) return { granted: false, reason: "withdrawn" };
  if (!canonicalWindow(window)) throw new Error(FIELD);
  const record = typeof graph.objectRecord === "function" ? graph.objectRecord(captured.source) : undefined;
  if (!record?.id || record.owner == null || record.owner === "") return { granted: false, reason: "missing" };
  if (canonicalRequestAccessor(record.owner) !== canonicalRequestAccessor(owner)) {
    return { granted: false, reason: "owner" };
  }
  if (members) {
    if (members.predicate !== "same-group" && members.predicate !== "named-circle") throw new Error(FIELD);
    if (!Number.isSafeInteger(members.now) || members.now < 0) throw new Error(FIELD);
    if (typeof graph.checkGroupSee !== "function") return { granted: false, reason: "not-member" };
    const see = graph.checkGroupSee(members.predicate, record.id, accepted.requester, members.now);
    if (!see || see.allowed !== true) return { granted: false, reason: "not-member" };
  }
  const accessor = accepted.requester;
  const prevSee = graph.seeGrant(record.id, accessor);
  if (!seeCanAdvance(prevSee)) throw new Error("see grant cannot advance");
  if (accepted.scope === ACCESS_SCOPE_READ_POST) {
    const prev = graph.postGrant(record.id, accessor);
    if (nextPostHam(prev?.hamState, false) === undefined) {
      throw new Error("post grant field is not a canonical integer");
    }
    if (!hasLabelPostWriter(graph)) return { granted: false, reason: "missing" };
  }
  graph.stateSeeGrant(record.owner, {
    object: record.id,
    accessor,
    from: window.from,
    until: window.until,
  });
  const seeNow = graph.seeGrant(record.id, accessor);
  if (!seeNow?.grant || seeNow.grant.stated !== 1) throw new Error("see grant cannot advance");
  /** @type {NonNullable<ReturnType<RequestGraph["postGrant"]>> | null} */
  let postEdge = null;
  /** @type {Uint8Array | null} */
  let postSigningBytes = null;
  if (accepted.scope === ACCESS_SCOPE_READ_POST) {
    stateLabelPost(graph, record.owner, {
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
  const see = seeNow;
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
