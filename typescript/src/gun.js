/**
 * Light Check consume implementation for s3r.ch.
 * Same names as docs/s3rch-check.d.ts. Copy or import from here.
 * Hint and hop never set allowed. A post grant is a separate row.
 * A hop, a hint, a wrap, a request, or an inbox delivery never grants.
 * Request signing lives in group.js so this module does not load node:crypto.
 */

export {
  POST_GRANT_DOMAIN,
  POST_GRANT_SCOPE,
  checkPost,
  factorGrants,
  postGrantSigningBytes,
  postSoul,
} from "./post.js";

import { canonicalAccessorId, nextPostHam, postGrantKey, postRowEncodable, postSoul, sameObjectId } from "./post.js";

/** @param {string | null | undefined} left @param {string | null | undefined} right */
function samePrincipal(left, right) {
  if (left == null || right == null) return false;
  return canonicalAccessorId(left) === canonicalAccessorId(right);
}

/** @param {Map<string, string>} objects @param {string} object */
function canonicalStoredObject(objects, object) {
  const text = String(object ?? "").trim();
  if (objects.has(text)) return text;
  for (const id of objects.keys()) {
    if (sameObjectId(id, text)) return id;
  }
  return text;
}

/** @param {{ claimId?: string, object?: string }} grant @param {string} object */
function grantNamesObject(grant, object) {
  const id = String(grant.claimId ?? grant.object ?? "").trim();
  if (!id) return false;
  return sameObjectId(id, object);
}

export function encodeKey(id) {
  return String(id).replace(/[.#$[\]]/g, "_");
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

export function aclKey(id) {
  return encodeKey(id).replace(/\//g, "_");
}

export function aclPrincipalKey(id) {
  const prefix = "s3rch/users/";
  if (String(id).startsWith(prefix)) return String(id).slice(prefix.length);
  return aclKey(id);
}

export function aclSoul(owner) {
  return `s3rch/acl/${aclPrincipalKey(owner)}`;
}

export function grantSoul(owner, object, accessor) {
  return `${aclSoul(owner)}/${aclKey(object)}/${aclPrincipalKey(accessor)}`;
}

export function toGunNode(item) {
  return {
    id: item.id,
    source: item.source,
    kind: item.kind || "activity",
    author: item.author,
    body: item.body,
    ts: item.ts,
    permalink: item.permalink,
    tags: Array.isArray(item.tags) ? item.tags.join(",") : String(item.tags ?? ""),
    provenance: item.provenance,
  };
}

export function fromGunNode(node) {
  if (!node || !node.id) return null;
  const source = node.source;
  if (source !== "rss3" && source !== "rss" && source !== "atom") return null;
  return {
    id: node.id,
    source,
    kind: node.kind || "activity",
    author: node.author ?? "",
    body: node.body ?? "",
    ts: Number(node.ts) || 0,
    permalink: node.permalink ?? "",
    tags: String(node.tags ?? "")
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean),
    provenance: node.provenance ?? "",
  };
}

export function acceptHint(hint) {
  return { ...hint };
}

export function acceptHop(hop) {
  return hop;
}

export function decodeHop(bytes) {
  return bytes;
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

export function checkSee(graph, object, accessor, now, hint, hop) {
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
  const dest = checkSee(graph, object, accessor, now, hint, hop);
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

export function applyPostGrant(acl, owner, grant) {
  if (!samePrincipal(acl.ownerOf(grant.claimId ?? grant.object), owner)) return;
  acl.statePostGrant(owner, grant);
}

export function cancelPost(acl, owner, accessor, object) {
  if (!samePrincipal(acl.ownerOf(object), owner)) return;
  acl.unstatePostGrant(owner, accessor, object);
}

/** In-memory dest ACL for tests and adapters. Not a Gun peer. */
export class MemorySeeAcl {
  constructor() {
    this.objects = new Map();
    this.grants = new Map();
    this.posts = new Map();
  }

  hasObject(object) {
    const text = String(object ?? "").trim();
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
    const text = String(object ?? "").trim();
    return [...this.grants.values()].filter((g) => {
      const id = String(g.claimId ?? g.object ?? "").trim();
      return sameObjectId(id, text) && g.stated !== 0;
    });
  }

  putObject(object, owner) {
    const id = String(object).trim();
    const next = String(owner).trim();
    if (this.objects.has(id)) {
      this.objects.set(id, next);
      return;
    }
    for (const stored of this.objects.keys()) {
      if (sameObjectId(stored, id)) {
        this.objects.set(stored, next);
        return;
      }
    }
    this.objects.set(id, next);
  }

  stateSeeGrant(owner, grant) {
    const query = String(grant.claimId ?? grant.object ?? "").trim();
    const object = canonicalStoredObject(this.objects, query);
    const key = postGrantKey(owner, object, grant.accessor);
    const stored = { ...grant, stated: 1, owner };
    if (stored.claimId != null) stored.claimId = object;
    if (stored.object != null || stored.claimId == null) stored.object = object;
    this.grants.set(key, stored);
  }

  unstateSeeGrant(owner, accessor, object) {
    const id = canonicalStoredObject(this.objects, object);
    const key = postGrantKey(owner, id, accessor);
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
    const id = canonicalStoredObject(this.objects, object);
    const ownerNow = this.ownerOf(id);
    if (!ownerNow) return undefined;
    const grant = this.grants.get(postGrantKey(ownerNow, id, accessor));
    const grantOwner = grant?.owner ?? "";
    if (!grant || !grantOwner) return undefined;
    if (postGrantKey(grantOwner, id, grant.accessor) !== postGrantKey(ownerNow, id, accessor)) {
      return undefined;
    }
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

  postGrant(object, accessor) {
    const id = canonicalStoredObject(this.objects, object);
    const owner = this.ownerOf(id) ?? "";
    return this.posts.get(postGrantKey(owner, id, accessor));
  }

  statePostGrant(owner, grant) {
    const query = String(grant.claimId ?? grant.object ?? "").trim();
    const object = canonicalStoredObject(this.objects, query);
    if (!samePrincipal(this.ownerOf(object), owner)) return;
    const key = postGrantKey(owner, object, grant.accessor);
    const prev = this.posts.get(key);
    const hamState = nextPostHam(prev?.hamState, false);
    if (hamState === undefined) return;
    const edge = {
      soul: postSoul(owner, object, grant.accessor),
      owner,
      hamState,
      grant: {
        object,
        accessor: grant.accessor,
        from: grant.from,
        until: grant.until,
        stated: 1,
      },
    };
    if (!postRowEncodable(edge)) return;
    this.posts.set(key, edge);
  }

  unstatePostGrant(owner, accessor, object) {
    const id = canonicalStoredObject(this.objects, object);
    if (!samePrincipal(this.ownerOf(id), owner)) return;
    const key = postGrantKey(owner, id, accessor);
    const prev = this.posts.get(key);
    const hamState = nextPostHam(prev?.hamState, true);
    if (hamState === undefined) return;
    const edge = {
      soul: postSoul(owner, id, accessor),
      owner,
      hamState,
      grant: {
        object: prev?.grant.object ?? id,
        accessor: prev?.grant.accessor ?? accessor,
        from: prev?.grant.from ?? 0,
        until: prev?.grant.until ?? 0,
        stated: 0,
      },
    };
    if (!postRowEncodable(edge)) return;
    this.posts.set(key, edge);
  }
}
