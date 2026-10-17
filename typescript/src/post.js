/**
 * Post grant row for s3r.ch Views read+post.
 * Separate from the see grant. Same cancel rule: stated 0 and a
 * hamState bump. At an equal hamState a cancellation wins, then the
 * narrower window, then the smaller signing bytes.
 * Check does not verify a signature. A hop, a hint, a wrap, a request,
 * or an inbox delivery never grants.
 *
 * @typedef {{
 *   object: string,
 *   accessor: string,
 *   from: number,
 *   until: number,
 *   stated: number,
 * }} PostGrantRow
 * @typedef {{
 *   soul: string | null,
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

/**
 * Injective path escape. `~` is the escape character.
 * `. # $ [ ]` each get their own form. `/` stays, so an item soul
 * does not gain a new spelling of a slash-bearing id.
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

/**
 * ASCII whitespace only: tab, LF, VT, FF, CR, space.
 * U+FEFF and U+0085 stay in the text so a principal can reject them.
 * @param {string} text
 */
function asciiTrim(text) {
  let start = 0;
  let end = text.length;
  while (start < end && isAsciiSpace(text.charCodeAt(start))) start += 1;
  while (end > start && isAsciiSpace(text.charCodeAt(end - 1))) end -= 1;
  return text.slice(start, end);
}

/** @param {number} code */
function isAsciiSpace(code) {
  return code === 0x09 || code === 0x0a || code === 0x0b || code === 0x0c || code === 0x0d || code === 0x20;
}

/**
 * A lone UTF-16 surrogate is not a Unicode scalar value.
 * Checked before a Unicode property escape, which throws on one.
 * @param {string} text
 */
function hasUnpairedSurrogate(text) {
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = text.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      i += 1;
      continue;
    }
    if (code >= 0xdc00 && code <= 0xdfff) return true;
  }
  return false;
}

/** @param {string} id */
function aclKey(id) {
  return escapeKey(asciiTrim(String(id)), true);
}

/**
 * A bare principal, or null. `.` may occur inside an id. The whole id
 * cannot be `.`, `..`, or `...`. `/ # $ [ ] ~`, an inner space, a control,
 * Unicode whitespace, a format character, `.get(`, an unpaired
 * surrogate, and more than 256 scalar values are rejected.
 * Never returns "".
 * @param {string} id
 * @returns {string | null}
 */
function barePrincipal(id) {
  if (!id || id === "." || id === ".." || id === "..." || id.includes(".get(") || id.includes(" ")) return null;
  if (hasUnpairedSurrogate(id)) return null;
  if ([...id].length > 256) return null;
  if (/[/#$[\]~]/.test(id)) return null;
  if (/\p{Z}|\p{Cf}/u.test(id)) return null;
  for (let i = 0; i < id.length; i += 1) {
    const code = id.charCodeAt(i);
    if (code <= 0x1f || (code >= 0x7f && code <= 0x9f)) return null;
  }
  return id;
}

/**
 * Owner / accessor key. An exact `s3rch/users/<wallet>` collapses to
 * that wallet. Anything else must be a bare principal. A failed parse
 * is null and is not a soul segment. Not an object escape.
 * @param {string | null | undefined} id
 * @returns {string | null}
 */
function aclPrincipalKey(id) {
  if (typeof id !== "string" || hasUnpairedSurrogate(id)) return null;
  const text = asciiTrim(id);
  if (!text || text.includes(".get(")) return null;
  const segments = text
    .split("/")
    .map((part) => asciiTrim(part))
    .filter((part) => part !== "");
  if (segments.length === 3 && segments[0] === "s3rch" && segments[1] === "users") {
    return barePrincipal(segments[2] ?? "");
  }
  if (text.includes("/")) return null;
  return barePrincipal(text);
}

/** @param {string | null | undefined} left @param {string | null | undefined} right */
function sameParsed(left, right) {
  if (left == null || right == null) return false;
  const a = aclPrincipalKey(left);
  const b = aclPrincipalKey(right);
  return a != null && a === b;
}

const HELD_CLAIM_PREFIXES = ["ens:", "unstoppable:", "fc:", "lens:", "rss3:"];

/** @param {string} id */
function isItemShaped(id) {
  const parts = asciiTrim(String(id)).split("/");
  return parts.length === 3 && parts[0] === "s3rch" && parts[1] === "items" && parts[2] !== "";
}

/** @param {string} id */
function mayAliasToItemSoul(id) {
  const text = asciiTrim(String(id));
  if (isItemShaped(text)) return true;
  if (!text.includes("/") && HELD_CLAIM_PREFIXES.some((prefix) => text.startsWith(prefix))) return false;
  return true;
}

/** @param {string} id */
function itemSoulOf(id) {
  return `s3rch/items/${encodeKey(asciiTrim(String(id)))}`;
}

/**
 * A raw id and `s3rch/items/<encodeKey(id)>` name one object when
 * one side is an item soul. A held claim id without `/` does not.
 * @param {string} left
 * @param {string} right
 */
function itemSoulAlias(left, right) {
  const a = asciiTrim(String(left));
  const b = asciiTrim(String(right));
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
 * @param {string | null | undefined} id
 * @returns {string | null}
 */
export function canonicalAccessorId(id) {
  return aclPrincipalKey(id);
}

/**
 * Leading or trailing whitespace, including U+0085, U+00A0, and U+FEFF.
 * That id is not stored and does not alias to the trimmed spelling.
 * @param {string | null | undefined} id
 */
export function objectIdRejected(id) {
  const text = String(id ?? "");
  if (!text || hasUnpairedSurrogate(text)) return true;
  return edgeSpace(text, true) || edgeSpace(text, false);
}

/** @param {string} text @param {boolean} fromStart */
function edgeSpace(text, fromStart) {
  const index = fromStart ? 0 : lastScalarIndex(text);
  const cp = text.codePointAt(index);
  if (cp == null) return true;
  if (cp === 0x09 || cp === 0x0a || cp === 0x0b || cp === 0x0c || cp === 0x0d || cp === 0x20 || cp === 0x85) {
    return true;
  }
  return /\p{Z}|\p{Cf}/u.test(String.fromCodePoint(cp));
}

/** @param {string} text */
function lastScalarIndex(text) {
  const end = text.charCodeAt(text.length - 1);
  if (end >= 0xdc00 && end <= 0xdfff && text.length > 1) {
    const prev = text.charCodeAt(text.length - 2);
    if (prev >= 0xd800 && prev <= 0xdbff) return text.length - 2;
  }
  return text.length - 1;
}

/**
 * Two strings name one object when their acl keys match, or one is
 * the item soul of the other. A held claim id without `/` does not.
 * Surrounding whitespace does not name the trimmed id.
 * @param {string} left
 * @param {string} right
 */
export function sameObjectId(left, right) {
  const a = String(left ?? "");
  const b = String(right ?? "");
  if (objectIdRejected(a) || objectIdRejected(b)) return false;
  return objectNames(a, b);
}

/**
 * @param {string} owner
 * @param {string} object
 * @param {string} accessor
 */
export function postSoul(owner, object, accessor) {
  const ownerKey = aclPrincipalKey(owner);
  const accessorKey = aclPrincipalKey(accessor);
  if (ownerKey == null || accessorKey == null) return null;
  return `s3rch/acl/${ownerKey}/${POST_GRANT_SCOPE}/${aclKey(object)}/${accessorKey}`;
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
 * A principal that does not parse has no soul, so that row is dropped
 * before the signing-byte tie-break.
 * @param {PostEdge | null | undefined} edge
 */
export function postRowEncodable(edge) {
  if (!edge?.grant) return false;
  const grant = edge.grant;
  if (
    !canonicalInteger(edge.hamState) ||
    !canonicalInteger(grant.stated) ||
    !canonicalInteger(grant.from) ||
    !canonicalInteger(grant.until)
  ) {
    return false;
  }
  return postSoul(edge.owner, grant.object, grant.accessor) != null;
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
  const ownerKey = aclPrincipalKey(owner);
  const accessorKey = aclPrincipalKey(accessor);
  if (ownerKey == null || accessorKey == null) return null;
  return `${ownerKey}\0${aclKey(object)}\0${accessorKey}`;
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
  const accessorKey = aclPrincipalKey(grant.accessor);
  if (accessorKey == null) {
    throw new Error("post grant field is not a canonical integer");
  }
  return lengthPrefixed([
    POST_GRANT_DOMAIN,
    aclKey(grant.object),
    accessorKey,
    canonicalDecimal(grant.stated),
    canonicalDecimal(grant.from),
    canonicalDecimal(grant.until),
    POST_GRANT_SCOPE,
    canonicalDecimal(edge.hamState),
  ]);
}

/** A hop, a hint, a wrap, a request, or an inbox delivery never grants. @param {string} _kind */
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
    owner: asciiTrim(String(edge.owner)),
    hamState: edge.hamState,
    grant: {
      object: asciiTrim(String(grant.object)),
      accessor: asciiTrim(String(grant.accessor)),
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
  const owner = graph.ownerOf(String(object));
  if (!owner) return { allowed: false, reason: "missing" };
  if (sameParsed(owner, accessor)) {
    return { allowed: true, reason: "owner" };
  }
  const edge = graph.seeGrant(object, accessor);
  if (!edge) return { allowed: false, reason: "missing" };
  const grant = edge.grant;
  const names =
    sameObjectId(grant.object, object) &&
    sameParsed(grant.accessor, accessor) &&
    sameParsed(edge.owner, owner);
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
  const owner = graph.ownerOf(String(object));
  const edge = graph.postGrant(object, accessor);
  if (!edge || !owner) return { allowed: false, reason: "missing", ...echoed };
  const grant = edge.grant;
  const names =
    sameObjectId(grant.object, object) &&
    sameParsed(grant.accessor, accessor) &&
    sameParsed(edge.owner, owner);
  if (!names) return { allowed: false, reason: "missing", ...echoed };
  if (grant.stated !== 1) return { allowed: false, reason: "cancelled", ...echoed };
  if (now >= grant.from && now < grant.until) {
    return { allowed: true, reason: "post", ...echoed };
  }
  return { allowed: false, reason: "missing", ...echoed };
}
