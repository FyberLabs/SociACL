/**
 * Light Check consume implementation for s3r.ch.
 * Same names as docs/s3rch-check.d.ts. Copy or import from here.
 * Hint and hop never set allowed. Elect is not on this surface.
 */

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
  if (graph.ownerOf(object) === accessor) return allow("owner");
  const grants = liveGrants(graph, object, now);
  if (grants.some((g) => g.accessor === accessor && g.claimId === object || g.object === object || g.claimId == null)) {
    return allow("delegate");
  }
  if (grants.some((g) => g.accessor === accessor)) return allow("delegate");
  return deny("delegate");
}

export function checkSeeGrant(graph, grant, object, accessor, now, hint, hop) {
  if (now < grant.from || now >= grant.until) return deny("delegate");
  const dest = checkSee(graph, object, accessor, now, hint, hop);
  if (!dest.allowed) return dest;
  if (grant.accessor !== accessor) return deny("delegate");
  if (grant.claimId && grant.claimId !== object) return deny("delegate");
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
    return this.objects.has(object);
  }

  ownerOf(object) {
    return this.objects.get(object);
  }

  seeGrants(object) {
    return [...this.grants.values()].filter((g) => (g.claimId ?? g.object) === object && g.stated !== 0);
  }

  putObject(object, owner) {
    this.objects.set(object, owner);
  }

  stateSeeGrant(owner, grant) {
    const key = `${owner}\0${grant.claimId ?? grant.object}\0${grant.accessor}`;
    this.grants.set(key, { ...grant, stated: 1 });
  }

  unstateSeeGrant(owner, accessor, object) {
    const key = `${owner}\0${object}\0${accessor}`;
    const prev = this.grants.get(key);
    if (prev) this.grants.set(key, { ...prev, stated: 0 });
  }
}
