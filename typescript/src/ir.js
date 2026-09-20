/**
 * Light Check consume implementation for AImmune / Brewnix IR.
 * Same names as docs/aimmune-ir-check.d.ts. Elect is not on this surface.
 */

export function mapAction(action) {
  return action === "see" ? "read" : action;
}

export function isSiteObjectId(id) {
  if (typeof id !== "string") return false;
  if (id.includes(":host") || id.includes(":incident:")) return false;
  return /^site:[^:]+(?::ir)?$/.test(id);
}

export function acceptHint(hint) {
  return { ...hint };
}

function deny(reason) {
  return { allowed: false, reason };
}

function allow(reason) {
  return { allowed: true, reason };
}

export function checkDelegate(graph, object, accessor, action, now, hint) {
  void hint;
  if (!isSiteObjectId(object)) return deny("unknown");
  if (!graph.hasObject(object)) return deny("unknown");
  const mapped = mapAction(action);
  if (graph.ownerOf(object) === accessor) return allow("owner");
  const grants = graph.delegateGrants(object) ?? [];
  for (const grant of grants) {
    if (grant.accessor !== accessor) continue;
    if (grant.object !== object) continue;
    if (grant.until != null && now >= grant.until) continue;
    if (grant.mask !== mapped) continue;
    return allow("delegate");
  }
  return deny("delegate");
}

export function applyDelegate(acl, owner, grant) {
  if (!grant.mask) return;
  if (acl.ownerOf(grant.object) !== owner) return;
  acl.stateDelegateGrant(owner, grant);
}

export function cancelDelegate(acl, owner, accessor, object) {
  if (acl.ownerOf(object) !== owner) return;
  acl.unstateDelegateGrant(owner, accessor, object);
}

export function undelegate(acl, owner, accessor, object) {
  cancelDelegate(acl, owner, accessor, object);
}

export function remintCapability(graph, object, accessor, action, now) {
  const result = checkDelegate(graph, object, accessor, action, now);
  return result.allowed ? { refreshed: true } : { denied: true };
}

export class MemoryDelegateAcl {
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

  delegateGrants(object) {
    return [...this.grants.values()].filter((g) => g.object === object);
  }

  putObject(object, owner) {
    this.objects.set(object, owner);
  }

  stateDelegateGrant(_owner, grant) {
    this.grants.set(`${grant.object}\0${grant.accessor}`, { ...grant });
  }

  unstateDelegateGrant(_owner, accessor, object) {
    this.grants.delete(`${object}\0${accessor}`);
  }
}
