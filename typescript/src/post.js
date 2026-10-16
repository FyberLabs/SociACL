/**
 * Post grant row for s3r.ch Views read+post.
 * Separate from the see grant. Same cancel rule: stated 0 and a
 * hamState bump. At an equal hamState a cancellation wins, then the
 * narrower window, then the smaller signing bytes.
 * Check does not verify a signature. A hop, a hint, a wrap, or an
 * inbox delivery never grants.
 *
 * @typedef {{
 *   object: string,
 *   accessor: string,
 *   from: number,
 *   until: number,
 *   stated: number,
 * }} PostGrantRow
 * @typedef {{
 *   soul: string,
 *   owner: string,
 *   hamState: number,
 *   grant: PostGrantRow,
 * }} PostEdge
 * @typedef {{
 *   ownerOf(object: string): string | undefined,
 *   seeGrant(object: string, accessor: string): PostEdge | undefined,
 *   postGrant(object: string, accessor: string): PostEdge | undefined,
 * }} PostGraph
 */

export const POST_GRANT_DOMAIN = "s3rch-post-grant-v1";
export const POST_GRANT_SCOPE = "post";

const JS_SAFE_INTEGER_MAX = Number.MAX_SAFE_INTEGER;

/** @param {string} id */
function encodeKey(id) {
  return String(id).replace(/[.#$[\]]/g, "_");
}

/** @param {string} id */
function aclKey(id) {
  return encodeKey(String(id).trim()).replace(/\//g, "_");
}

/** @param {string} id */
function aclPrincipalKey(id) {
  const text = String(id).trim();
  const parts = text.split("/");
  if (parts.length === 3 && parts[0] === "s3rch" && parts[1] === "users") {
    return encodeKey(parts[2] ?? "");
  }
  return aclKey(text);
}

const HELD_CLAIM_PREFIXES = ["ens:", "unstoppable:", "fc:", "lens:", "rss3:"];

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
function itemSoulOf(id) {
  return `s3rch/items/${encodeKey(String(id).trim())}`;
}

/**
 * A raw id and `s3rch/items/<encodeKey(id)>` name one object when
 * one side is an item soul. A held claim id without `/` does not.
 * @param {string} left
 * @param {string} right
 */
function itemSoulAlias(left, right) {
  const a = String(left).trim();
  const b = String(right).trim();
  if (!isItemShaped(a) && !isItemShaped(b)) return false;
  if (!mayAliasToItemSoul(a) || !mayAliasToItemSoul(b)) return false;
  return itemSoulOf(a) === b || itemSoulOf(b) === a;
}

/** @param {string} stored @param {string} query */
function objectNames(stored, query) {
  return aclKey(stored) === aclKey(query) || itemSoulAlias(stored, query);
}

/**
 * One accessor id. `s3rch/users/<wallet>` and the wallet are this key.
 * @param {string} id
 */
export function canonicalAccessorId(id) {
  return aclPrincipalKey(id);
}

/**
 * Two strings name one object when their acl keys match, or one is
 * the item soul of the other. A held claim id without `/` does not.
 * @param {string} left
 * @param {string} right
 */
export function sameObjectId(left, right) {
  const a = String(left ?? "").trim();
  const b = String(right ?? "").trim();
  if (!a || !b) return false;
  return objectNames(a, b);
}

/**
 * @param {string} owner
 * @param {string} object
 * @param {string} accessor
 */
export function postSoul(owner, object, accessor) {
  return `s3rch/acl/${aclPrincipalKey(owner)}/${POST_GRANT_SCOPE}/${aclKey(object)}/${aclPrincipalKey(accessor)}`;
}

/**
 * @param {unknown} value
 * @returns {value is number}
 */
function canonicalInteger(value) {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= JS_SAFE_INTEGER_MAX;
}

/** @param {number} value */
function canonicalDecimal(value) {
  if (!canonicalInteger(value)) {
    throw new Error("post grant field is not a canonical integer");
  }
  return String(value);
}

/**
 * Peer merge drops a row that cannot be encoded. It does not throw.
 * @param {PostEdge | null | undefined} edge
 */
export function postRowEncodable(edge) {
  if (!edge?.grant) return false;
  const grant = edge.grant;
  return (
    canonicalInteger(edge.hamState) &&
    canonicalInteger(grant.stated) &&
    canonicalInteger(grant.from) &&
    canonicalInteger(grant.until)
  );
}

/**
 * Next hamState that still fits in a canonical integer.
 * A cancellation at the maximum keeps that value so stated 0 wins.
 * @param {number | undefined} prev
 * @param {boolean} forCancel
 * @returns {number | undefined}
 */
export function nextPostHam(prev, forCancel) {
  const base = canonicalInteger(prev) ? prev : 0;
  const bumped = base + 1;
  if (canonicalInteger(bumped)) return bumped;
  if (forCancel && base > 0) return base;
  return undefined;
}

/**
 * Storage and lookup key. Same canonical ids as postSoul.
 * @param {string} owner
 * @param {string} object
 * @param {string} accessor
 */
export function postGrantKey(owner, object, accessor) {
  return `${aclPrincipalKey(owner)}\0${aclKey(object)}\0${aclPrincipalKey(accessor)}`;
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
 * Length-prefixed row encoding. Check does not verify a signature.
 * @param {{ grant: { object: string, accessor: string, stated: number, from: number, until: number }, hamState: number }} edge
 */
export function postGrantSigningBytes(edge) {
  const grant = edge.grant;
  return lengthPrefixed([
    POST_GRANT_DOMAIN,
    aclKey(grant.object),
    aclPrincipalKey(grant.accessor),
    canonicalDecimal(grant.stated),
    canonicalDecimal(grant.from),
    canonicalDecimal(grant.until),
    POST_GRANT_SCOPE,
    canonicalDecimal(edge.hamState),
  ]);
}

/** A hop, a hint, a wrap, or an inbox delivery never grants. @param {string} _kind */
export function factorGrants(_kind) {
  return false;
}

/** @param {string} object */
function closedReason(object) {
  const text = String(object).trim();
  if (text.includes("://")) return "url-leaf";
  if (text === "s3rch/meta") return "meta";
  if (text === "s3rch/acl" || text.startsWith("s3rch/acl/")) return "acl";
  return null;
}

/**
 * @param {{ from: number, until: number }} left
 * @param {{ from: number, until: number }} right
 */
function windowInside(left, right) {
  return (
    left.from >= right.from &&
    left.until <= right.until &&
    (left.from > right.from || left.until < right.until)
  );
}

/** @param {Uint8Array} left @param {Uint8Array} right */
function bytesBefore(left, right) {
  const n = Math.min(left.length, right.length);
  for (let i = 0; i < n; i += 1) {
    if (left[i] !== right[i]) return left[i] < right[i];
  }
  return left.length < right.length;
}

/**
 * @param {PostEdge} edge
 * @returns {PostEdge}
 */
export function canonicalPostEdge(edge) {
  const grant = edge.grant;
  return {
    soul: postSoul(edge.owner, grant.object, grant.accessor),
    owner: String(edge.owner).trim(),
    hamState: edge.hamState,
    grant: {
      object: String(grant.object).trim(),
      accessor: String(grant.accessor).trim(),
      from: grant.from,
      until: grant.until,
      stated: grant.stated,
    },
  };
}

/**
 * Higher hamState wins. At the same hamState a cancellation wins,
 * then the narrower window, then the smaller signing bytes.
 * @param {PostEdge} local
 * @param {PostEdge} incoming
 * @returns {PostEdge}
 */
export function preferPost(local, incoming) {
  const nextOk = postRowEncodable(incoming);
  const keptOk = postRowEncodable(local);
  if (!nextOk) return keptOk ? canonicalPostEdge(local) : local;
  if (!keptOk) return canonicalPostEdge(incoming);
  const kept = canonicalPostEdge(local);
  const next = canonicalPostEdge(incoming);
  if (next.hamState > kept.hamState) return next;
  if (next.hamState < kept.hamState) return kept;
  const nextDown = next.grant.stated !== 1;
  const keptDown = kept.grant.stated !== 1;
  if (nextDown && !keptDown) return next;
  if (keptDown && !nextDown) return kept;
  if (windowInside(kept.grant, next.grant) && !windowInside(next.grant, kept.grant)) return kept;
  if (windowInside(next.grant, kept.grant) && !windowInside(kept.grant, next.grant)) return next;
  const keptBytes = postGrantSigningBytes(kept);
  const nextBytes = postGrantSigningBytes(next);
  return bytesBefore(nextBytes, keptBytes) ? next : kept;
}

/**
 * @param {PostGraph} graph
 * @param {string} object
 * @param {string} accessor
 * @param {number} now
 */
function seeDecision(graph, object, accessor, now) {
  const closed = closedReason(object);
  if (closed) return { allowed: false, reason: closed };
  const owner = graph.ownerOf(String(object).trim());
  if (!owner) return { allowed: false, reason: "missing" };
  if (canonicalAccessorId(owner) === canonicalAccessorId(accessor)) {
    return { allowed: true, reason: "owner" };
  }
  const edge = graph.seeGrant(object, accessor);
  if (!edge) return { allowed: false, reason: "missing" };
  const grant = edge.grant;
  const names =
    sameObjectId(grant.object, object) &&
    canonicalAccessorId(grant.accessor) === canonicalAccessorId(accessor) &&
    canonicalAccessorId(edge.owner) === canonicalAccessorId(owner);
  if (!names) return { allowed: false, reason: "missing" };
  if (grant.stated !== 1) return { allowed: false, reason: "cancelled" };
  if (now >= grant.from && now < grant.until) return { allowed: true, reason: "delegate" };
  return { allowed: false, reason: "missing" };
}

/**
 * Allow-post only when see also passes.
 * The object owner may post. Any other accessor needs a live post row.
 * Hint and hop are echoed and do not set allowed.
 *
 * @param {PostGraph} graph
 * @param {string} object
 * @param {string} accessor
 * @param {number} now
 * @param {object | null | undefined} hint
 * @param {object | null | undefined} hop
 */
export function checkPost(graph, object, accessor, now, hint, hop) {
  const echoed = { hint: hint ?? null, hop: hop ?? null };
  const see = seeDecision(graph, object, accessor, now);
  if (!see.allowed || see.reason === "owner") {
    return { ...see, ...echoed };
  }
  const owner = graph.ownerOf(String(object).trim());
  const edge = graph.postGrant(object, accessor);
  if (!edge || !owner) return { allowed: false, reason: "missing", ...echoed };
  const grant = edge.grant;
  const names =
    sameObjectId(grant.object, object) &&
    canonicalAccessorId(grant.accessor) === canonicalAccessorId(accessor) &&
    canonicalAccessorId(edge.owner) === canonicalAccessorId(owner);
  if (!names) return { allowed: false, reason: "missing", ...echoed };
  if (grant.stated !== 1) return { allowed: false, reason: "cancelled", ...echoed };
  if (now >= grant.from && now < grant.until) {
    return { allowed: true, reason: "post", ...echoed };
  }
  return { allowed: false, reason: "missing", ...echoed };
}
