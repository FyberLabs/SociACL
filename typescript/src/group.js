/**
 * Plaintext same-group and named-circle rows for the s3r.ch light Check.
 * Hopcap 1. Both edges must be stated 1. One-sided membership is stored
 * and is not a grant. A hop, a hint, or a wrap never mints.
 * A lower hamState does not hide a removal.
 *
 * @typedef {"same-group" | "named-circle"} GroupPredicate
 * @typedef {{ principal?: string, target?: string }} HandoffHint
 * @typedef {{ channel?: string }} HopFactor
 * @typedef {{ predicate: GroupPredicate, setId: string }} PresentedGroup
 * @typedef {{ stated: 0 | 1, from: number, until: number }} DecodedGroupPayload
 * @typedef {{
 *   allowed: boolean,
 *   reason: string,
 *   hint: HandoffHint | null,
 *   hop: HopFactor | null,
 *   storeCancel: boolean,
 * }} GroupPresentation
 * @typedef {{
 *   predicate: GroupPredicate,
 *   setId: string,
 *   accessor: string,
 *   stated: 0 | 1,
 *   hamState: number,
 * }} MeshMembership
 * @typedef {{
 *   object: string,
 *   predicate: GroupPredicate,
 *   setId: string,
 *   stated: 0 | 1,
 *   hamState: number,
 * }} ObjectSetName
 * @typedef {{
 *   accessor: string,
 *   predicate: GroupPredicate,
 *   setId: string,
 *   stated: 0 | 1,
 *   hamState: number,
 * }} GroupSnapshotMember
 * @typedef {{
 *   predicate: GroupPredicate,
 *   setId: string,
 *   stated: 0 | 1,
 *   hamState: number,
 * }} GroupSnapshotObjectSet
 * @typedef {{
 *   membership: MeshMembership,
 *   memberStated: boolean,
 *   setStated: boolean,
 *   removed: boolean,
 *   soul: string,
 * }} MembershipRecord
 * @typedef {{ name: ObjectSetName, soul: string }} ObjectSetRecord
 * @typedef {{ accessor: string, from: number, until: number, stated?: 0 | 1, object?: string }} SeeGrant
 */

/** @param {string} id */
export function encodeKey(id) {
  return String(id).replace(/[.#$[\]]/g, "_");
}

/** @param {string} id */
export function aclKey(id) {
  return encodeKey(String(id).trim()).replace(/\//g, "_");
}

/** @param {string} id */
export function aclPrincipalKey(id) {
  const text = String(id).trim();
  const parts = text.split("/");
  if (parts.length === 3 && parts[0] === "s3rch" && parts[1] === "users") {
    return encodeKey(parts[2] ?? "");
  }
  return aclKey(text);
}

/**
 * @param {string} setOwner
 * @param {GroupPredicate} predicate
 * @param {string} setId
 * @param {string} accessor
 */
export function membershipSoul(setOwner, predicate, setId, accessor) {
  return `s3rch/acl/${aclPrincipalKey(setOwner)}/membership/${predicate}/${aclKey(setId)}/${aclPrincipalKey(accessor)}`;
}

/**
 * @param {string} objectOwner
 * @param {string} object
 */
export function objectSetSoul(objectOwner, object) {
  return `s3rch/acl/${aclPrincipalKey(objectOwner)}/object-set/edge/${aclKey(object)}`;
}

/** @param {string} object */
function closedReason(object) {
  const text = String(object).trim();
  if (text.includes("://")) return "url-leaf";
  if (text === "s3rch/meta") return "meta";
  if (text === "s3rch/acl" || text.startsWith("s3rch/acl/")) return "acl";
  return null;
}

/** @param {DecodedGroupPayload} payload @param {number} now */
function payloadLive(payload, now) {
  return payload.stated === 1 && now >= payload.from && now < payload.until;
}

/**
 * @param {MembershipRecord} record
 * @param {readonly GroupSnapshotMember[]} members
 */
function membershipHidden(record, members) {
  const accessor = aclPrincipalKey(record.membership.accessor);
  /** @type {GroupSnapshotMember | undefined} */
  let best;
  for (const row of members) {
    if (
      row.predicate !== record.membership.predicate ||
      row.setId !== record.membership.setId ||
      aclPrincipalKey(row.accessor) !== accessor
    ) {
      continue;
    }
    if (!best) {
      best = row;
      continue;
    }
    const rowRank = row.stated === 0 ? 1 : 0;
    const bestRank = best.stated === 0 ? 1 : 0;
    if (row.hamState > best.hamState || (row.hamState === best.hamState && rowRank > bestRank)) {
      best = row;
    }
  }
  if (!best) return true;
  if (best.stated !== 0) return true;
  return best.hamState < record.membership.hamState;
}

/**
 * In-memory group graph. Not a Gun peer.
 * See grants on the same object stay on the delegate path.
 */
export class MemoryGroupGraph {
  constructor() {
    /** @type {Map<string, string>} */
    this.objects = new Map();
    /** @type {Map<string, SeeGrant>} */
    this.grants = new Map();
    /** @type {Map<string, string>} */
    this.setOwners = new Map();
    /** @type {Map<string, MembershipRecord>} */
    this.memberships = new Map();
    /** @type {Map<string, ObjectSetRecord>} */
    this.objectSets = new Map();
  }

  /** @param {string} object */
  hasObject(object) {
    return this.objects.has(String(object).trim());
  }

  /** @param {string} object */
  ownerOf(object) {
    return this.objects.get(String(object).trim());
  }

  /**
   * @param {string} object
   * @param {string} owner
   */
  putObject(object, owner) {
    this.objects.set(String(object).trim(), String(owner).trim());
  }

  /** @param {string} object */
  seeGrants(object) {
    const id = String(object).trim();
    return [...this.grants.values()].filter((grant) => (grant.object ?? id) === id && grant.stated !== 0);
  }

  /**
   * @param {string} owner
   * @param {SeeGrant} grant
   */
  stateSeeGrant(owner, grant) {
    if (aclPrincipalKey(this.ownerOf(grant.object ?? "") ?? "") !== aclPrincipalKey(owner)) return;
    const key = `${aclPrincipalKey(owner)}\0${grant.object ?? ""}\0${aclPrincipalKey(grant.accessor)}`;
    this.grants.set(key, { ...grant, stated: 1 });
  }

  /**
   * @param {string} owner
   * @param {GroupPredicate} predicate
   * @param {string} setId
   */
  recordSetOwner(owner, predicate, setId) {
    const name = String(owner).trim();
    const id = String(setId).trim();
    if (!name || !id) throw new Error("group name is empty");
    const key = `${predicate}\0${id}`;
    const existing = this.setOwners.get(key);
    if (existing && aclPrincipalKey(existing) !== aclPrincipalKey(name)) {
      throw new Error("set already has an owner");
    }
    if (!existing) this.setOwners.set(key, name);
  }

  /**
   * @param {GroupPredicate} predicate
   * @param {string} setId
   */
  ownerOfSet(predicate, setId) {
    return this.setOwners.get(`${predicate}\0${String(setId).trim()}`);
  }

  /**
   * @param {string} speaker
   * @param {GroupPredicate} predicate
   * @param {string} setId
   * @param {string} accessor
   * @returns {[boolean, boolean]}
   */
  #speaker(speaker, predicate, setId, accessor) {
    const owner = this.ownerOfSet(predicate, setId);
    if (!owner) throw new Error("set owner is unknown");
    const speakerKey = aclPrincipalKey(speaker);
    const speaksMember = speakerKey === aclPrincipalKey(accessor);
    const speaksSet = speakerKey === aclPrincipalKey(owner);
    if (!speaksMember && !speaksSet) throw new Error("membership speaker is not the member or the set owner");
    return [speaksMember, speaksSet];
  }

  /**
   * @param {string} speaker
   * @param {GroupPredicate} predicate
   * @param {string} setId
   * @param {string} accessor
   */
  stateMembership(speaker, predicate, setId, accessor) {
    const id = String(setId).trim();
    const who = String(accessor).trim();
    if (!id || !who) throw new Error("group name is empty");
    const [speaksMember, speaksSet] = this.#speaker(speaker, predicate, id, who);
    const key = `${predicate}\0${id}\0${aclPrincipalKey(who)}`;
    const owner = this.ownerOfSet(predicate, id);
    if (!owner) throw new Error("set owner is unknown");
    const current = this.memberships.get(key);
    const record = current ?? {
      membership: { predicate, setId: id, accessor: who, stated: 0, hamState: 0 },
      memberStated: false,
      setStated: false,
      removed: false,
      soul: "",
    };
    record.soul = membershipSoul(owner, predicate, id, who);
    record.membership.hamState += 1;
    if (speaksMember) record.memberStated = true;
    if (speaksSet) record.setStated = true;
    if (record.memberStated && record.setStated) {
      record.membership.stated = 1;
      record.removed = false;
    } else {
      record.membership.stated = 0;
    }
    this.memberships.set(key, record);
  }

  /**
   * @param {string} speaker
   * @param {GroupPredicate} predicate
   * @param {string} setId
   * @param {string} accessor
   */
  cancelMembership(speaker, predicate, setId, accessor) {
    const id = String(setId).trim();
    const who = String(accessor).trim();
    if (!id || !who) throw new Error("group name is empty");
    this.#speaker(speaker, predicate, id, who);
    const key = `${predicate}\0${id}\0${aclPrincipalKey(who)}`;
    const owner = this.ownerOfSet(predicate, id);
    if (!owner) throw new Error("set owner is unknown");
    const current = this.memberships.get(key);
    const record = current ?? {
      membership: { predicate, setId: id, accessor: who, stated: 0, hamState: 0 },
      memberStated: false,
      setStated: false,
      removed: false,
      soul: "",
    };
    record.soul = membershipSoul(owner, predicate, id, who);
    record.memberStated = false;
    record.setStated = false;
    record.removed = true;
    record.membership.stated = 0;
    record.membership.hamState += 1;
    this.memberships.set(key, record);
  }

  /**
   * @param {GroupPredicate} predicate
   * @param {string} setId
   * @param {string} accessor
   * @returns {MeshMembership | undefined}
   */
  membership(predicate, setId, accessor) {
    const key = `${predicate}\0${String(setId).trim()}\0${aclPrincipalKey(accessor)}`;
    return this.memberships.get(key)?.membership;
  }

  /**
   * @param {string} owner
   * @param {string} object
   * @param {GroupPredicate} predicate
   * @param {string} setId
   */
  nameObjectSet(owner, object, predicate, setId) {
    const id = String(setId).trim();
    if (!id) throw new Error("group name is empty");
    const objectId = String(object).trim();
    const objectOwner = this.ownerOf(objectId);
    if (!objectOwner) throw new Error("mesh object is not in-graph");
    if (aclPrincipalKey(objectOwner) !== aclPrincipalKey(owner)) throw new Error("dest ACL write is owner-only");
    this.#writeObjectSet(objectId, objectOwner, predicate, id, 1);
  }

  /**
   * @param {string} owner
   * @param {string} object
   */
  clearObjectSet(owner, object) {
    const objectId = String(object).trim();
    const objectOwner = this.ownerOf(objectId);
    if (!objectOwner) throw new Error("mesh object is not in-graph");
    if (aclPrincipalKey(objectOwner) !== aclPrincipalKey(owner)) throw new Error("dest ACL write is owner-only");
    const existing = this.objectSets.get(aclKey(objectId));
    if (!existing) return;
    this.#writeObjectSet(objectId, objectOwner, existing.name.predicate, existing.name.setId, 0);
  }

  /**
   * @param {string} object
   * @returns {ObjectSetName | undefined}
   */
  objectSet(object) {
    return this.objectSets.get(aclKey(String(object).trim()))?.name;
  }

  /** @param {MemoryGroupGraph} other */
  mergeFrom(other) {
    for (const [key, incoming] of other.memberships) {
      const local = this.memberships.get(key);
      if (!local || incoming.membership.hamState > local.membership.hamState) {
        this.memberships.set(key, structuredClone(incoming));
      }
    }
    for (const [key, incoming] of other.objectSets) {
      const local = this.objectSets.get(key);
      if (!local || incoming.name.hamState > local.name.hamState) {
        this.objectSets.set(key, structuredClone(incoming));
      }
    }
    for (const [key, owner] of other.setOwners) {
      if (!this.setOwners.has(key)) this.setOwners.set(key, owner);
    }
  }

  /**
   * @param {string} objectId
   * @param {string} objectOwner
   * @param {GroupPredicate} predicate
   * @param {string} setId
   * @param {0 | 1} stated
   */
  #writeObjectSet(objectId, objectOwner, predicate, setId, stated) {
    const key = aclKey(objectId);
    const prev = this.objectSets.get(key);
    this.objectSets.set(key, {
      name: {
        object: objectId,
        predicate,
        setId,
        stated,
        hamState: (prev?.name.hamState ?? 0) + 1,
      },
      soul: objectSetSoul(objectOwner, objectId),
    });
  }
}

/**
 * @param {MemoryGroupGraph} graph
 * @param {string} object
 * @param {string} accessor
 * @param {number} now
 */
function checkSee(graph, object, accessor, now) {
  const closed = closedReason(object);
  if (closed) return { allowed: false, reason: closed };
  const owner = graph.ownerOf(object);
  if (!owner) return { allowed: false, reason: "missing" };
  if (aclPrincipalKey(owner) === aclPrincipalKey(accessor)) return { allowed: true, reason: "owner" };
  const live = graph.seeGrants(object).some((grant) => {
    return aclPrincipalKey(grant.accessor) === aclPrincipalKey(accessor) && now >= grant.from && now < grant.until;
  });
  if (live) return { allowed: true, reason: "delegate" };
  return { allowed: false, reason: "missing" };
}

/**
 * CHECK(see) for same-group or named-circle.
 * Hop missing does not fail. Hop alone never allows.
 * `now` is the Check instant. Membership has no window here.
 *
 * @param {MemoryGroupGraph} graph
 * @param {GroupPredicate} predicate
 * @param {string} object
 * @param {string} accessor
 * @param {number} now
 * @param {HandoffHint | null | undefined} hint
 * @param {HopFactor | null | undefined} hop
 */
export function checkGroupSee(graph, predicate, object, accessor, now, hint, hop) {
  void now;
  const echoed = { hint: hint ?? null, hop: hop ?? null };
  const deny = (/** @type {string} */ reason) => ({ allowed: false, reason, ...echoed });
  const closed = closedReason(object);
  if (closed) return deny(closed);
  const owner = graph.ownerOf(object);
  if (!owner) return deny("missing");
  if (aclPrincipalKey(owner) === aclPrincipalKey(accessor)) {
    return { allowed: true, reason: "owner", ...echoed };
  }
  const edge = graph.objectSet(object);
  if (!edge) return deny("missing");
  if (edge.predicate !== predicate || edge.stated !== 1) {
    return deny(edge.predicate === predicate && edge.stated !== 1 ? "cancelled" : "missing");
  }
  const row = graph.memberships.get(`${predicate}\0${edge.setId}\0${aclPrincipalKey(accessor)}`);
  if (!row) return deny("missing");
  if (row.membership.stated === 1) return { allowed: true, reason: predicate, ...echoed };
  return deny(row.removed ? "cancelled" : "missing");
}

/**
 * Group tail of a presentation. Binding and key unwrap stay outside.
 * Allowed only when checkGroupSee allows and the payload is stated 1
 * with now in [from, until). A live edge does not override a cancel.
 *
 * @param {MemoryGroupGraph} graph
 * @param {PresentedGroup | null | undefined} group
 * @param {string} object
 * @param {string} accessor
 * @param {DecodedGroupPayload} payload
 * @param {number} now
 * @param {HandoffHint | null | undefined} hint
 * @param {HopFactor | null | undefined} hop
 * @returns {GroupPresentation}
 */
export function checkGroupPresentation(graph, group, object, accessor, payload, now, hint, hop) {
  const storeCancel = payload.stated === 0;
  const echoed = { hint: hint ?? null, hop: hop ?? null, storeCancel };
  const named = graph.objectSet(object) != null;
  if (!group) {
    if (named) return { allowed: false, reason: "missing", ...echoed };
    const dest = checkSee(graph, object, accessor, now);
    if (dest.allowed && payloadLive(payload, now)) {
      return { allowed: true, reason: dest.reason, ...echoed };
    }
    return {
      allowed: false,
      reason: payloadLive(payload, now) ? dest.reason : "cancelled",
      ...echoed,
    };
  }
  const edge = graph.objectSet(object);
  if (!edge || edge.predicate !== group.predicate || edge.setId !== group.setId) {
    return { allowed: false, reason: "missing", ...echoed };
  }
  const see = checkGroupSee(graph, group.predicate, object, accessor, now, hint, hop);
  if (see.allowed && payloadLive(payload, now)) {
    return { allowed: true, reason: see.reason, ...echoed };
  }
  return {
    allowed: false,
    reason: payloadLive(payload, now) ? see.reason : "cancelled",
    ...echoed,
  };
}

/**
 * True when the snapshot hides a removal or a newer object-set edge.
 * Member hamState does not stand in for the object-set edge.
 *
 * @param {MemoryGroupGraph} graph
 * @param {string} object
 * @param {readonly GroupSnapshotMember[]} members
 * @param {GroupSnapshotObjectSet | null | undefined} objectSet
 */
export function snapshotUnderstatesGroup(graph, object, members, objectSet) {
  const current = graph.objectSet(object);
  if (!current) return objectSet != null;
  if (!objectSet) return true;
  if (
    objectSet.hamState < current.hamState ||
    objectSet.predicate !== current.predicate ||
    objectSet.setId !== current.setId ||
    objectSet.stated !== current.stated
  ) {
    return true;
  }
  for (const record of graph.memberships.values()) {
    if (
      record.removed &&
      record.membership.predicate === current.predicate &&
      record.membership.setId === current.setId &&
      membershipHidden(record, members)
    ) {
      return true;
    }
  }
  return false;
}
