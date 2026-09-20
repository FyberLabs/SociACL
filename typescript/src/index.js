/**
 * Portable SociACL light plane. Same named predicates and verbs as
 * sociacl-core. Not WASM. s3r.ch still copies docs/s3rch-check.d.ts
 * and does not npm-install this folder.
 */

export const HOPCAP = 1;
export const DEFAULT_PRIVILEGE_UP_DELAY = 1;
export const DEFAULT_ELECT_WAIT = 10;

export const RELATIONS = [
  "owns",
  "member-of",
  "in-circle",
  "object-group",
  "object-circle",
  "friend",
  "trustee",
  "delegate",
  "in-network",
];

export const PREDICATES = [
  "owner",
  "same-group",
  "named-circle",
  "posix-mode",
  "trustee",
  "delegate",
  "same-network",
];

export const CENSURE_REASONS = [
  "self-leave",
  "unintentional-failure",
  "policy-violation",
  "active-sabotage",
];

function parseRelation(s) {
  if (s === "follow") return "friend";
  return RELATIONS.includes(s) ? s : null;
}

function parseMask(s) {
  if (!s || !String(s).trim()) return null;
  const raw = String(s).trim();
  const mask = { read: false, write: false, execute: false };
  const add = (token) => {
    if (token === "read" || token === "r") mask.read = true;
    else if (token === "write" || token === "w") mask.write = true;
    else if (token === "execute" || token === "exec" || token === "x") mask.execute = true;
    else return false;
    return true;
  };
  if (/[,+\s]/.test(raw)) {
    for (const part of raw.split(/[,+\s]+/)) {
      if (!part) continue;
      if (!add(part)) return null;
    }
  } else if (raw === "read" || raw === "write" || raw === "execute" || raw === "exec") {
    if (!add(raw)) return null;
  } else {
    for (const c of raw) {
      if (!add(c)) return null;
    }
  }
  if (!mask.read && !mask.write && !mask.execute) return null;
  return mask;
}

function maskAllows(mask, action) {
  if (action === "read" || action === "r" || action === "see") return mask.read;
  if (action === "write" || action === "w") return mask.write;
  if (action === "execute" || action === "exec" || action === "x") return mask.execute;
  return false;
}

function parsePosix(s) {
  if (s == null) return null;
  const raw = String(s).trim().replace(/^0o/, "");
  const n = Number.parseInt(raw, 8);
  if (!Number.isFinite(n) || n > 0o777) return null;
  const bits = (d) => ({
    read: (d & 4) !== 0,
    write: (d & 2) !== 0,
    execute: (d & 1) !== 0,
  });
  return {
    owner: bits((n >> 6) & 7),
    group: bits((n >> 3) & 7),
    other: bits(n & 7),
  };
}

function bitsAllow(bits, action) {
  return maskAllows(bits, action);
}

export class SociaclError extends Error {
  constructor(message) {
    super(message);
    this.name = "SociaclError";
  }
}

export class Plane {
  constructor() {
    this.nodes = new Map();
    this.objects = new Map();
    this.edges = [];
    this.authn = new Map();
    this.wills = new Map();
    this.pendingElects = new Map();
    this.auditLog = [];
    this.nowTick = 0;
    this.privilegeUpDelay = DEFAULT_PRIVILEGE_UP_DELAY;
    this.electWait = DEFAULT_ELECT_WAIT;
  }

  now() {
    return this.nowTick;
  }

  setNow(tick) {
    this.nowTick = Number(tick);
  }

  addPerson(id) {
    this.#addPrincipal(id, "person");
  }

  addAgent(id) {
    this.#addPrincipal(id, "agent");
  }

  addDevice(id) {
    this.nodes.set(id, "device");
    if (!this.authn.has(id)) this.authn.set(id, "live");
  }

  addGroup(id) {
    this.nodes.set(id, "group");
  }

  addCircle(id) {
    this.nodes.set(id, "circle");
  }

  addNetwork(id) {
    this.nodes.set(id, "network");
  }

  addObject(id, owner) {
    const kind =
      this.nodes.get(id) === "device"
        ? "device"
        : this.nodes.get(id) === "network"
          ? "network"
          : "data";
    this.objects.set(id, {
      id,
      kind,
      owner,
      version: 1,
      destroyed: false,
      properties: { predicate: "owner" },
    });
    this.edges.push({
      from: owner,
      to: id,
      relation: "owns",
      fromStated: true,
      toStated: true,
      jointAt: this.nowTick,
      effectiveAt: this.nowTick,
      actions: { read: false, write: false, execute: false },
      until: null,
    });
  }

  setObjectProperty(object, key, value) {
    const obj = this.#requireObject(object);
    obj.properties[key] = String(value);
    obj.version += 1;
  }

  setAuthn(id, state) {
    if (state !== "live" && state !== "gone") {
      throw new SociaclError(`unnamed authn ${state}`);
    }
    this.authn.set(id, state);
  }

  authnOf(id) {
    return this.authn.get(id) ?? "gone";
  }

  stateEdge(speaker, from, to, relation) {
    const rel = parseRelation(relation);
    if (!rel) return;
    const speaksFrom = this.#maySpeak(speaker, from);
    const speaksTo = this.#maySpeak(speaker, to);
    if (!speaksFrom && !speaksTo) return;
    const existing = this.#findEdge(from, to, rel);
    if (existing) {
      if (speaksFrom) existing.fromStated = true;
      if (speaksTo) existing.toStated = true;
      if (existing.fromStated && existing.toStated && existing.jointAt == null) {
        existing.jointAt = this.nowTick;
        existing.effectiveAt = this.nowTick + this.privilegeUpDelay;
      }
      return;
    }
    const joint = speaksFrom && speaksTo;
    this.edges.push({
      from,
      to,
      relation: rel,
      fromStated: speaksFrom,
      toStated: speaksTo,
      jointAt: joint ? this.nowTick : null,
      effectiveAt: joint ? this.nowTick + this.privilegeUpDelay : null,
      actions: { read: false, write: false, execute: false },
      until: null,
    });
  }

  jointlyState(from, to, relation) {
    this.stateEdge(from, from, to, relation);
    this.stateEdge(to, from, to, relation);
    this.nowTick += this.privilegeUpDelay;
  }

  unstateEdge(speaker, from, to, relation) {
    const rel = parseRelation(relation);
    if (!rel) return;
    const speaksFrom = this.#maySpeak(speaker, from);
    const speaksTo = this.#maySpeak(speaker, to);
    if (!speaksFrom && !speaksTo) return;
    const edge = this.#findEdge(from, to, rel);
    if (!edge) return;
    if (speaksFrom) edge.fromStated = false;
    if (speaksTo) edge.toStated = false;
    if (!(edge.fromStated && edge.toStated)) {
      edge.jointAt = null;
      edge.effectiveAt = null;
    }
    this.edges = this.edges.filter(
      (e) => e.fromStated || e.toStated || e.from !== from || e.to !== to || e.relation !== rel,
    );
    const obj = this.objects.get(to) || this.objects.get(from);
    if (obj) obj.version += 1;
  }

  delegate(owner, principal, object, actions, until = null) {
    const mask = parseMask(actions);
    if (!mask) throw new SociaclError("delegate grant must name at least one of read, write, execute");
    const obj = this.#requireObject(object);
    if (obj.owner !== owner) throw new SociaclError(`principal ${owner} is not the live owner; cannot delegate`);
    if (this.authnOf(owner) !== "live") throw new SociaclError(`principal ${owner} authn is not live`);
    if (!this.nodes.has(principal)) throw new SociaclError(`principal ${principal} not found`);
    this.stateEdge(owner, principal, object, "delegate");
    const edge = this.#findEdge(principal, object, "delegate");
    if (edge) {
      edge.actions = mask;
      edge.until = until == null ? null : Number(until);
    }
  }

  jointlyDelegate(owner, principal, object, actions, until = null) {
    this.delegate(owner, principal, object, actions, until);
    this.stateEdge(principal, principal, object, "delegate");
    this.nowTick += this.privilegeUpDelay;
  }

  undelegate(owner, principal, object) {
    const obj = this.#requireObject(object);
    if (obj.owner !== owner) throw new SociaclError(`principal ${owner} is not the live owner; cannot delegate`);
    if (this.authnOf(owner) !== "live") throw new SociaclError(`principal ${owner} authn is not live`);
    this.unstateEdge(owner, principal, object, "delegate");
  }

  admitMember(member, network) {
    if (this.nodes.get(network) !== "network") {
      throw new SociaclError(`object ${network} not found`);
    }
    if (!this.nodes.has(member)) throw new SociaclError(`principal ${member} not found`);
    this.jointlyState(member, network, "in-network");
  }

  censure(speaker, network, member, reason) {
    if (!CENSURE_REASONS.includes(reason)) {
      throw new SociaclError(`unnamed censure reason ${reason}; fail closed`);
    }
    if (this.nodes.get(network) !== "network") {
      throw new SociaclError(`object ${network} not found`);
    }
    if (!this.nodes.has(member)) throw new SociaclError(`principal ${member} not found`);
    if (this.authnOf(speaker) !== "live") {
      throw new SociaclError(`principal ${speaker} authn is not live`);
    }
    const owner = this.objects.get(network)?.owner;
    const isSelf = speaker === member;
    const isOwner = owner === speaker;
    if (isSelf) {
      if (reason !== "self-leave") throw new SociaclError(`principal ${speaker} may not censure this member`);
    } else if (isOwner) {
      if (reason === "self-leave") throw new SociaclError(`principal ${speaker} may not censure this member`);
    } else {
      throw new SociaclError(`principal ${speaker} may not censure this member`);
    }
    this.unstateEdge(speaker, member, network, "in-network");
    const record = { network, member, speaker, reason, at: this.nowTick };
    this.auditLog.push(record);
    return `${member} ${speaker} ${reason} ${this.nowTick}`;
  }

  isMember(member, network) {
    return this.#hasLive(member, network, "in-network");
  }

  audit(network) {
    return this.auditLog
      .filter((r) => r.network === network)
      .map((r) => `${r.member} ${r.speaker} ${r.reason} ${r.at}`);
  }

  writeWill(src) {
    const will = parseWill(src);
    const obj = this.objects.get(will.object);
    if (!obj) throw new SociaclError(`object ${will.object} not found`);
    if (obj.destroyed) throw new SociaclError(`object ${will.object} destroyed`);
    if (obj.owner !== will.testator) {
      throw new SociaclError(`testator ${will.testator} must be the live owner to write a will`);
    }
    if (this.authnOf(will.testator) !== "live") {
      throw new SociaclError("will must be written while testator authn is live");
    }
    this.wills.set(will.object, will);
  }

  check(action, object, accessor, predicate) {
    if (!this.nodes.has(accessor)) {
      throw new SociaclError(`accessor ${accessor} not found`);
    }
    const obj = this.objects.get(object);
    if (!obj) throw new SociaclError(`object ${object} not found`);
    if (obj.destroyed) throw new SociaclError(`object ${object} destroyed`);
    const named = obj.properties.predicate;
    if (!named || !PREDICATES.includes(named)) {
      throw new SociaclError(`unknown predicate ${named ?? "missing"}; fail closed`);
    }
    if (predicate != null && predicate !== named) {
      throw new SociaclError(
        `requested predicate ${predicate} does not match object predicate ${named}; fail closed`,
      );
    }
    const allowed = this.#eval(named, object, accessor, action);
    return { allowed, reason: named };
  }

  remint(object, principal) {
    this.#requireObject(object);
    if (!this.nodes.has(principal)) throw new SociaclError(`principal ${principal} not found`);
    if (this.authnOf(principal) !== "live") {
      throw new SociaclError(`principal ${principal} authn is not live`);
    }
    if (!this.#aclNames(object, principal)) {
      throw new SociaclError(`ACL does not name principal ${principal} on ${object}`);
    }
    return "remint";
  }

  discover(object) {
    const will = this.#liveWill(object);
    if (will.heir) return `heir ${will.heir}`;
    if (will.successors?.length) return `heir ${will.successors[0]}`;
    if (will.circle) return `elect-among ${will.circle}`;
    if (will.destroy) return "stay-secret";
    throw new SociaclError(`will for ${object} has no elect path`);
  }

  elect(object) {
    this.#refuseIfKeepOperating(object);
    const will = this.#liveWill(object);
    if (will.destroy && !will.heir && !will.successors && !will.circle) {
      throw new SociaclError(`will for ${object} prescribes destroy, not elect`);
    }
    if (!will.heir && !will.successors && !will.circle) {
      throw new SociaclError(`will for ${object} has no elect path`);
    }
    if (this.pendingElects.has(object)) {
      throw new SociaclError(`elect on ${object} is already pending`);
    }
    const candidate = will.heir ?? will.successors?.find((id) => this.nodes.has(id));
    if (!candidate && !will.circle) {
      throw new SociaclError(`will for ${object} has no elect path`);
    }
    const readyAt = this.nowTick + this.electWait;
    const heir = candidate ?? will.circle;
    this.pendingElects.set(object, { candidate: heir, readyAt });
    return `pending ${heir}`;
  }

  commitElect(object) {
    this.#refuseIfKeepOperating(object);
    this.#liveWill(object);
    const pending = this.pendingElects.get(object);
    if (!pending) throw new SociaclError(`no pending elect on ${object}`);
    if (this.nowTick < pending.readyAt) {
      throw new SociaclError(`elect wait has not elapsed on ${object}`);
    }
    const obj = this.#requireObject(object);
    obj.owner = pending.candidate;
    obj.version += 1;
    this.edges = this.edges.filter((e) => !(e.relation === "owns" && e.to === object));
    this.edges.push({
      from: pending.candidate,
      to: object,
      relation: "owns",
      fromStated: true,
      toStated: true,
      jointAt: this.nowTick,
      effectiveAt: this.nowTick,
      actions: { read: false, write: false, execute: false },
      until: null,
    });
    this.pendingElects.delete(object);
    return `installed ${pending.candidate}`;
  }

  cancelWill(object, by) {
    const will = this.wills.get(object);
    if (!will) throw new SociaclError(`no will written while alive for ${object}`);
    const may = will.cancelableBy.includes(by) || will.testator === by;
    if (!may) throw new SociaclError(`principal ${by} may not cancel this will`);
    if (this.authnOf(by) !== "live") throw new SociaclError(`principal ${by} authn is not live`);
    will.canceled = true;
    this.pendingElects.delete(object);
    return "canceled";
  }

  destroy(object) {
    const will = this.#liveWill(object);
    if (will.heir || will.successors?.some((id) => this.nodes.has(id))) {
      throw new SociaclError(`will for ${object} names an heir; destroy refused`);
    }
    if (!will.destroy && !will.circle) {
      throw new SociaclError(`will for ${object} has no destroy path`);
    }
    const obj = this.#requireObject(object);
    obj.destroyed = true;
    obj.version += 1;
    return "destroy";
  }

  #addPrincipal(id, kind) {
    this.nodes.set(id, kind);
    if (!this.authn.has(id)) this.authn.set(id, "live");
  }

  #requireObject(id) {
    const obj = this.objects.get(id);
    if (!obj) throw new SociaclError(`object ${id} not found`);
    if (obj.destroyed) throw new SociaclError(`object ${id} destroyed`);
    return obj;
  }

  #maySpeak(speaker, endpoint) {
    if (speaker === endpoint) return true;
    const obj = this.objects.get(endpoint);
    return obj?.owner === speaker;
  }

  #findEdge(from, to, relation) {
    return this.edges.find((e) => e.from === from && e.to === to && e.relation === relation);
  }

  #effective() {
    return this.edges.filter((e) => {
      if (!(e.fromStated && e.toStated)) return false;
      if (e.effectiveAt == null || this.nowTick < e.effectiveAt) return false;
      return true;
    });
  }

  #hasLive(from, to, relation) {
    return this.#effective().some((e) => e.from === from && e.to === to && e.relation === relation);
  }

  #namedGroup(object) {
    return this.objects.get(object)?.properties.group ?? null;
  }

  #namedCircle(object) {
    return this.objects.get(object)?.properties.circle ?? null;
  }

  #namedNetwork(object) {
    const obj = this.objects.get(object);
    if (obj?.properties.network) return obj.properties.network;
    if (this.nodes.get(object) === "network") return object;
    if (obj?.kind === "network") return object;
    return null;
  }

  #aclNames(object, principal) {
    if (this.#hasLive(principal, object, "owns")) return true;
    if (this.#hasLive(principal, object, "trustee")) return true;
    if (this.#liveDelegate(principal, object)) return true;
    const group = this.#namedGroup(object);
    if (group && this.#hasLive(principal, group, "member-of")) return true;
    const circle = this.#namedCircle(object);
    if (circle && this.#hasLive(principal, circle, "in-circle")) return true;
    const network = this.#namedNetwork(object);
    if (network && this.#hasLive(principal, network, "in-network")) return true;
    return false;
  }

  #liveDelegate(principal, object, action) {
    const edge = this.#effective().find(
      (e) => e.from === principal && e.to === object && e.relation === "delegate",
    );
    if (!edge) return false;
    if (!edge.actions.read && !edge.actions.write && !edge.actions.execute) return false;
    if (edge.until != null && this.nowTick >= edge.until) return false;
    if (action) return maskAllows(edge.actions, action);
    return true;
  }

  #eval(predicate, object, accessor, action) {
    const obj = this.objects.get(object);
    switch (predicate) {
      case "owner":
        return this.#hasLive(accessor, object, "owns");
      case "same-group": {
        const group = this.#namedGroup(object);
        return Boolean(group && this.#hasLive(accessor, group, "member-of"));
      }
      case "named-circle": {
        const circle = this.#namedCircle(object);
        return Boolean(circle && this.#hasLive(accessor, circle, "in-circle"));
      }
      case "trustee":
        return this.#hasLive(accessor, object, "trustee");
      case "delegate":
        return this.#liveDelegate(accessor, object, action);
      case "same-network": {
        const network = this.#namedNetwork(object);
        return Boolean(network && this.#hasLive(accessor, network, "in-network"));
      }
      case "posix-mode": {
        const mode = parsePosix(obj.properties.mode);
        if (!mode) return false;
        if (accessor === obj.owner || this.#hasLive(accessor, object, "owns")) {
          return bitsAllow(mode.owner, action);
        }
        const group = this.#namedGroup(object);
        if (group && this.#hasLive(accessor, group, "member-of")) {
          return bitsAllow(mode.group, action);
        }
        return bitsAllow(mode.other, action);
      }
      default:
        return false;
    }
  }

  #liveWill(object) {
    this.#requireObject(object);
    const will = this.wills.get(object);
    if (!will) throw new SociaclError(`no will written while alive for ${object}`);
    if (will.canceled) throw new SociaclError(`will for ${object} was canceled`);
    return will;
  }

  #refuseIfKeepOperating(object) {
    const obj = this.#requireObject(object);
    if (this.authnOf(obj.owner) === "live") {
      throw new SociaclError(`keep-operating would suffice for ${object}; elect refused`);
    }
  }
}

function parseWill(src) {
  const lines = String(src)
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"));
  if (!lines.length) throw new SociaclError("will has no clauses");
  const head = lines[0].match(/^will\s+(\S+)\s+for\s+(object|group|network|device-class)\s+(\S+)$/);
  if (!head) throw new SociaclError("will parse failed");
  const will = {
    name: head[1],
    object: head[3],
    testator: "",
    cancelableBy: [],
    heir: null,
    successors: null,
    circle: null,
    destroy: false,
    canceled: false,
  };
  for (const line of lines.slice(1)) {
    if (line.startsWith("written-by ")) will.testator = line.slice(11).trim();
    else if (line.startsWith("cancelable-by ")) {
      will.cancelableBy = line.slice(14).trim().split(/\s+/).filter(Boolean);
    } else if (line.startsWith("discover heir ")) will.heir = line.slice(14).trim();
    else if (line.startsWith("named-successor-list ")) {
      will.successors = line.slice(21).trim().split(/\s+/).filter(Boolean);
    } else if (line.startsWith("elect circle ")) {
      will.circle = line.slice(13).trim().split(/\s+/)[0];
    } else if (line.startsWith("destroy ")) will.destroy = true;
    else if (
      line.includes("if-silent-for") ||
      line.includes("dead-hand") ||
      line.includes("vacancy")
    ) {
      throw new SociaclError(`dead-hand shape ${line}; fail closed`);
    }
  }
  if (!will.testator) throw new SociaclError("will parse failed");
  return will;
}

export { parseMask, parseRelation };
