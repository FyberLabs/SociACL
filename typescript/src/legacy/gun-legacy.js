/**
 * Label-graph helpers still used by group and feed tests.
 *
 * The stored-id see, post, and request paths do not import this module.
 * Group's copy is deleted in PR 5. Feed, encrypted discovery, and the
 * contract copies are deleted in PR 6.
 */

/** @param {string | null | undefined} left @param {string | null | undefined} right */
function samePrincipal(left, right) {
  if (left == null || right == null) return false;
  const leftKey = canonicalAccessorId(left);
  const rightKey = canonicalAccessorId(right);
  return leftKey != null && leftKey === rightKey;
}

/** @param {Map<string, string>} objects @param {string} object */
function canonicalStoredObject(objects, object) {
  const text = String(object ?? "");
  if (objectIdRejected(text)) return text;
  if (objects.has(text)) return text;
  for (const id of objects.keys()) {
    if (sameObjectId(id, text)) return id;
  }
  return text;
}

/** @param {{ claimId?: string, object?: string }} grant @param {string} object */
function grantNamesObject(grant, object) {
  const id = String(grant.claimId ?? grant.object ?? "");
  if (objectIdRejected(id) || objectIdRejected(object)) return false;
  return sameObjectId(id, object);
}

/**
 * Injective path escape. `~` is the escape character.
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

export function encodeKey(id) {
  return escapeKey(id, false);
}

export function itemSoul(id) {
  return `s3rch/items/${encodeKey(id)}`;
}

export function userSoul(wallet) {
  return `s3rch/users/${wallet}`;
}

export function metaSoul() {
  return "s3rch/meta";
}

function asciiTrim(text) {
  const value = String(text);
  let start = 0;
  let end = value.length;
  const space = (code) =>
    code === 0x09 || code === 0x0a || code === 0x0b || code === 0x0c || code === 0x0d || code === 0x20;
  while (start < end && space(value.charCodeAt(start))) start += 1;
  while (end > start && space(value.charCodeAt(end - 1))) end -= 1;
  return value.slice(start, end);
}

export function aclKey(id) {
  return escapeKey(asciiTrim(id), true);
}

/**
 * A lone UTF-16 surrogate is not a Unicode scalar value.
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

/**
 * A bare principal, or null. `.` may occur inside an id.
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
 * Owner / accessor key. An exact `s3rch/users/<wallet>` collapses to that wallet.
 * @param {string | null | undefined} id
 * @returns {string | null}
 */
export function aclPrincipalKey(id) {
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

/** @param {string | null | undefined} id */
export function canonicalAccessorId(id) {
  return aclPrincipalKey(id);
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

/** @param {string} left @param {string} right */
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

/** @param {string | null | undefined} id */
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

/** @param {string} left @param {string} right */
export function sameObjectId(left, right) {
  const a = String(left ?? "");
  const b = String(right ?? "");
  if (objectIdRejected(a) || objectIdRejected(b)) return false;
  return objectNames(a, b);
}

/** Storage key for a label see row.
 * @param {string} owner @param {string} object @param {string} accessor */
export function postGrantKey(owner, object, accessor) {
  const ownerKey = aclPrincipalKey(owner);
  const accessorKey = aclPrincipalKey(accessor);
  if (ownerKey == null || accessorKey == null) return null;
  return `${ownerKey}\0${aclKey(object)}\0${accessorKey}`;
}

export function aclSoul(owner) {
  const ownerKey = aclPrincipalKey(owner);
  if (ownerKey == null) return null;
  return `s3rch/acl/${ownerKey}`;
}

export function grantSoul(owner, object, accessor) {
  const ownerKey = aclPrincipalKey(owner);
  const accessorKey = aclPrincipalKey(accessor);
  if (ownerKey == null || accessorKey == null) return null;
  return `s3rch/acl/${ownerKey}/${aclKey(object)}/${accessorKey}`;
}

function deny(reason) {
  return { allowed: false, reason };
}

function allow(reason) {
  return { allowed: true, reason };
}

function isMetaOrAcl(object) {
  return object === "s3rch/meta" || object === "s3rch/acl" || String(object).startsWith("s3rch/acl/");
}

function liveGrants(graph, object, now) {
  return (graph.seeGrants(object) ?? []).filter((g) => {
    if (g.stated === 0) return false;
    return now >= g.from && now < g.until;
  });
}

export function checkSeeLabel(graph, object, accessor, now, hint, hop) {
  void hint;
  void hop;
  if (!object || isMetaOrAcl(object) || String(object).includes("://")) {
    return deny("unknown");
  }
  if (!graph.hasObject(object)) return deny("unknown");
  if (samePrincipal(graph.ownerOf(object), accessor)) return allow("owner");
  const grants = liveGrants(graph, object, now);
  const ownerNow = graph.ownerOf(object);
  if (
    grants.some((g) => {
      const ownerOk = g.owner == null || samePrincipal(g.owner, ownerNow);
      return ownerOk && samePrincipal(g.accessor, accessor) && grantNamesObject(g, object);
    })
  ) {
    return allow("delegate");
  }
  return deny("delegate");
}

export function checkSeeGrant(graph, grant, object, accessor, now, hint, hop) {
  if (now < grant.from || now >= grant.until) return deny("delegate");
  const dest = checkSeeLabel(graph, object, accessor, now, hint, hop);
  if (!dest.allowed) return dest;
  if (!samePrincipal(grant.accessor, accessor)) return deny("delegate");
  const named = grant.claimId ?? grant.object;
  if (named && !sameObjectId(named, object)) return deny("delegate");
  return dest;
}

export function admitFeedNode(acl, node, owner, hint) {
  void hint;
  if (!node?.id) return { denied: true };
  acl.putObject(itemSoul(node.id), owner);
  return { object: itemSoul(node.id) };
}

export function applySeeGrant(acl, owner, grant) {
  if (acl.ownerOf(grant.claimId ?? grant.object) !== owner) return;
  acl.stateSeeGrant(owner, grant);
}

export function cancelSee(acl, owner, accessor, object) {
  if (acl.ownerOf(object) !== owner) return;
  acl.unstateSeeGrant(owner, accessor, object);
}

/** In-memory dest ACL for tests and adapters. Not a Gun peer. */
export class MemorySeeAcl {
  constructor() {
    this.objects = new Map();
    this.grants = new Map();
  }

  hasObject(object) {
    const text = String(object ?? "");
    if (objectIdRejected(text)) return false;
    if (this.objects.has(text)) return true;
    for (const id of this.objects.keys()) {
      if (sameObjectId(id, text)) return true;
    }
    return false;
  }

  ownerOf(object) {
    return this.objects.get(canonicalStoredObject(this.objects, object));
  }

  seeGrants(object) {
    const text = String(object ?? "");
    if (objectIdRejected(text)) return [];
    return [...this.grants.values()].filter((g) => {
      const id = String(g.claimId ?? g.object ?? "");
      return sameObjectId(id, text) && g.stated !== 0;
    });
  }

  putObject(object, owner) {
    const id = String(object);
    if (objectIdRejected(id)) return;
    const next = asciiTrim(String(owner));
    if (this.objects.has(id)) {
      this.objects.set(id, next);
      return;
    }
    for (const stored of this.objects.keys()) {
      if (sameObjectId(stored, id)) return;
    }
    this.objects.set(id, next);
  }

  stateSeeGrant(owner, grant) {
    const query = String(grant.claimId ?? grant.object ?? "");
    if (objectIdRejected(query)) return;
    const object = canonicalStoredObject(this.objects, query);
    const key = postGrantKey(owner, object, grant.accessor);
    if (key == null) return;
    const stored = { ...grant, stated: 1, owner };
    if (stored.claimId != null) stored.claimId = object;
    if (stored.object != null || stored.claimId == null) stored.object = object;
    this.grants.set(key, stored);
  }

  unstateSeeGrant(owner, accessor, object) {
    if (objectIdRejected(object)) return;
    const id = canonicalStoredObject(this.objects, object);
    const key = postGrantKey(owner, id, accessor);
    if (key == null) return;
    let prevKey = this.grants.has(key) ? key : undefined;
    if (!prevKey) {
      for (const [rowKey, grant] of this.grants) {
        const grantId = String(grant.claimId ?? grant.object ?? "");
        if (sameObjectId(grantId, id) && samePrincipal(grant.accessor, accessor)) {
          prevKey = rowKey;
          break;
        }
      }
    }
    if (!prevKey) return;
    const prev = this.grants.get(prevKey);
    for (const [rowKey, grant] of [...this.grants]) {
      const grantId = String(grant.claimId ?? grant.object ?? "");
      if (sameObjectId(grantId, id) && samePrincipal(grant.accessor, accessor)) this.grants.delete(rowKey);
    }
    this.grants.set(key, {
      ...prev,
      object: id,
      claimId: prev.claimId != null ? id : prev.claimId,
      stated: 0,
      hamState: (prev.hamState ?? 0) + 1,
    });
  }

  seeGrant(object, accessor) {
    if (objectIdRejected(object)) return undefined;
    const id = canonicalStoredObject(this.objects, object);
    const ownerNow = this.ownerOf(id);
    if (!ownerNow) return undefined;
    const key = postGrantKey(ownerNow, id, accessor);
    if (key == null) return undefined;
    const grant = this.grants.get(key);
    const grantOwner = grant?.owner ?? "";
    if (!grant || !grantOwner) return undefined;
    const storedKey = postGrantKey(grantOwner, id, grant.accessor);
    if (storedKey == null || storedKey !== key) return undefined;
    const grantId = grant.claimId ?? grant.object ?? id;
    return {
      soul: grantSoul(grantOwner, grantId, grant.accessor),
      owner: grantOwner,
      hamState: grant.hamState ?? 1,
      grant: {
        object: grantId,
        accessor: grant.accessor,
        from: grant.from,
        until: grant.until,
        stated: grant.stated === 0 ? 0 : 1,
      },
    };
  }
}
