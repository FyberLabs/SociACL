/**
 * Direct same-group and named-circle rows.
 * Hopcap is 1. Both assents must be stated 1 under each party's present
 * key, or a witnessed cancel applies. A hop, a hint, a wrap, a request,
 * or an inbox delivery never grants.
 * A set id is a minted ObjectId of kind `set`. The set owner is the
 * signed principal, and it is the principal embedded in that id.
 * @typedef {import('../ids/src/types.js').ObjectId} ObjectId
 * @typedef {import('../ids/src/types.js').PrincipalId} PrincipalId
 * @typedef {import('../ids/src/types.js').ResolutionContext} ResolutionContext
 * @typedef {import('./see.js').SeeResolver} SeeResolver
 * @typedef {'same-group' | 'named-circle'} GroupPredicate
 * @typedef {{ principal?: string, target?: string }} HandoffHint
 * @typedef {{ channel?: string }} HopFactor
 * @typedef {{ stated: 0 | 1, from: number, until: number }} DecodedGroupPayload
 * @typedef {{
 *   allowed: boolean,
 *   reason: string,
 *   hint: HandoffHint | null,
 *   hop: HopFactor | null,
 *   storeCancel: boolean,
 * }} GroupPresentation
 * @typedef {{
 *   role: 'member' | 'set',
 *   predicate: GroupPredicate,
 *   set: ObjectId,
 *   member: PrincipalId,
 *   setOwner: PrincipalId,
 *   stated: 0 | 1,
 *   hamState: number,
 *   issuedAt: number,
 *   cancels: readonly string[],
 *   sig: string,
 *   attest?: string,
 * }} MembershipAssent
 * @typedef {{
 *   owner: PrincipalId,
 *   object: ObjectId,
 *   predicate: GroupPredicate,
 *   set: ObjectId,
 *   stated: 0 | 1,
 *   hamState: number,
 *   issuedAt: number,
 *   cancels: readonly string[],
 *   sig: string,
 *   attest?: string,
 * }} ObjectSetRow
 * @typedef {{
 *   kind: 'membership' | 'object-set',
 *   rowSoul: string,
 *   cancelId: string,
 *   prior: readonly string[],
 *   signer: PrincipalId,
 *   predicate: GroupPredicate,
 *   set: ObjectId,
 *   member: PrincipalId,
 *   setOwner: PrincipalId,
 *   object?: ObjectId,
 *   issuedAt: number,
 *   sig: string,
 *   attest?: string,
 * }} GroupCancel
 */

import {
  historyState,
  membershipSoul,
  objectPrincipal,
  objectSetSoul,
  parseObjectId,
  parsePrincipalId,
  resolveCurrentKey,
  verifyAclAttestation,
  verifyKeySignature,
  verifySignedAt,
} from '../ids/src/index.js';
import { integer, lp } from '../ids/src/util.js';
import { admittedOwner, checkSee } from './see.js';

export { checkPost, factorGrants } from './post.js';
export { membershipSoul, objectSetSoul };
export {
  REQUEST_DOMAIN,
  REQUEST_ID_DOMAIN,
  accessRequestBytes,
  grantApprovedRequest,
  parseAccessRequest,
  requestId,
  verifyAccessRequest,
} from './request.js';

const MEMBER_DOMAIN = 'sociacl-membership-assent-v2';
const OBJECT_SET_DOMAIN = 'sociacl-object-set-v2';
const CANCEL_DOMAIN = 'sociacl-cancel-v2';

/**
 * @typedef {{
 *   stated: 0 | 1,
 *   hamState: number,
 *   issuedAt: number,
 *   bytes: Uint8Array,
 *   sig: string,
 *   attest?: string,
 *   observed: readonly string[],
 *   mode: 'present' | 'witnessed',
 * }} StoredAssent
 * @typedef {{
 *   id: string,
 *   prior: readonly string[],
 *   signer: PrincipalId,
 *   issuedAt: number,
 *   bytes: Uint8Array,
 *   sig: string,
 *   attest?: string,
 *   mode: 'present' | 'witnessed',
 * }} StoredCancel
 * @typedef {{
 *   predicate: GroupPredicate,
 *   set: ObjectId,
 *   member: PrincipalId,
 *   setOwner: PrincipalId,
 *   memberAssent: StoredAssent | null,
 *   setAssent: StoredAssent | null,
 *   cancels: Map<string, StoredCancel>,
 * }} StoredMembership
 * @typedef {{
 *   owner: PrincipalId,
 *   object: ObjectId,
 *   predicate: GroupPredicate,
 *   set: ObjectId,
 *   assent: StoredAssent | null,
 *   cancels: Map<string, StoredCancel>,
 * }} StoredObjectSet
 */

/** @type {WeakMap<object, Map<string, StoredMembership>>} */
const membershipTables = new WeakMap();
/** @type {WeakMap<object, Map<string, StoredObjectSet>>} */
const objectSetTables = new WeakMap();

/** @param {object} graph */
function membershipTable(graph) {
  let table = membershipTables.get(graph);
  if (!table) {
    table = new Map();
    membershipTables.set(graph, table);
  }
  return table;
}

/** @param {object} graph */
function objectSetTable(graph) {
  let table = objectSetTables.get(graph);
  if (!table) {
    table = new Map();
    objectSetTables.set(graph, table);
  }
  return table;
}

/** @param {unknown} graph */
function graphObject(graph) {
  return typeof graph === 'object' && graph !== null;
}

/** @param {unknown} row @returns {Record<string, unknown> | null} */
function snapshot(row) {
  if (row === null || typeof row !== 'object' || Array.isArray(row)) return null;
  try {
    /** @type {Record<string, unknown>} */
    const copy = {};
    for (const key of Object.keys(row)) copy[key] = /** @type {Record<string, unknown>} */ (row)[key];
    return copy;
  } catch {
    return null;
  }
}

/** @param {unknown} value @returns {value is GroupPredicate} */
function predicateOf(value) {
  return value === 'same-group' || value === 'named-circle';
}

/** @param {unknown} value @returns {readonly string[] | null} */
function cancelList(value) {
  if (!Array.isArray(value)) return null;
  /** @type {string[]} */
  const ids = [];
  for (const id of value) {
    if (typeof id !== 'string' || !/^[0-9a-f]{64}$/.test(id) || ids.includes(id)) return null;
    ids.push(id);
  }
  const sorted = [...ids].sort();
  for (let i = 0; i < ids.length; i += 1) if (ids[i] !== sorted[i]) return null;
  return ids;
}

/** @param {unknown} value @returns {{ ok: true, id: ObjectId, owner: PrincipalId } | { ok: false, reason: string }} */
function parseSetId(value) {
  const id = parseObjectId(value);
  if (!id.ok) return id;
  if (!id.value.startsWith('set_')) return { ok: false, reason: 'bad-alphabet' };
  const owner = objectPrincipal(id.value);
  if (!owner.ok) return owner;
  return { ok: true, id: id.value, owner: owner.value };
}

/**
 * @param {PrincipalId} principal
 * @param {readonly unknown[]} rotations
 * @param {ResolutionContext} ctx
 * @param {Uint8Array} bytes
 * @param {string} sig
 * @param {number} issuedAt
 * @param {0 | 1 | null} stated
 * @param {string | undefined} attest
 * @returns {{ ok: true, mode: 'present' | 'witnessed' } | { ok: false, reason: string }}
 */
function verifyParty(principal, rotations, ctx, bytes, sig, issuedAt, stated, attest) {
  const signed = verifySignedAt(principal, rotations, ctx, bytes, sig, issuedAt);
  if (signed.ok) return { ok: true, mode: 'present' };
  if (signed.reason !== 'unwitnessed-retired-key') return signed;
  if (stated !== 0 && stated !== null) {
    if (attest !== undefined) {
      const seen = verifyAclAttestation(attest, ctx.jwks, issuedAt, bytes);
      if (!seen.ok) return seen;
    }
    return { ok: false, reason: 'unwitnessed-retired-key' };
  }
  if (attest === undefined) return { ok: false, reason: 'unwitnessed-retired-key' };
  const account = resolveCurrentKey(principal, rotations, ctx);
  if (!account.ok) return account;
  const seen = verifyAclAttestation(attest, ctx.jwks, issuedAt, bytes);
  if (!seen.ok) return seen;
  if (seen.value.principal !== principal) return { ok: false, reason: 'bad-attestation' };
  const state = historyState(principal, account.value.rotations, issuedAt, ctx.now);
  const key = verifyKeySignature(state.key, sig, bytes);
  if (!key.ok) return { ok: false, reason: 'bad-signature' };
  return { ok: true, mode: 'witnessed' };
}

/** @param {MembershipAssent} row */
export function membershipAssentBytes(row) {
  return lp([
    MEMBER_DOMAIN,
    row.role,
    row.predicate,
    row.set,
    row.member,
    row.setOwner,
    String(row.stated),
    String(row.hamState),
    String(row.issuedAt),
    String(row.cancels.length),
    ...row.cancels,
  ]);
}

/** @param {ObjectSetRow} row */
export function objectSetBytes(row) {
  return lp([
    OBJECT_SET_DOMAIN,
    row.owner,
    row.object,
    row.predicate,
    row.set,
    String(row.stated),
    String(row.hamState),
    String(row.issuedAt),
    String(row.cancels.length),
    ...row.cancels,
  ]);
}

/** @param {GroupCancel} row */
export function groupCancelBytes(row) {
  return lp([
    CANCEL_DOMAIN,
    row.kind,
    row.rowSoul,
    row.cancelId,
    String(row.issuedAt),
    String(row.prior.length),
    ...row.prior,
  ]);
}

/** @param {unknown} row @returns {{ ok: true, value: MembershipAssent, bytes: Uint8Array } | { ok: false, reason: string }} */
export function parseMembershipAssent(row) {
  const copy = snapshot(row);
  if (!copy) return { ok: false, reason: 'bad-record' };
  if (copy.domain !== undefined && copy.domain !== MEMBER_DOMAIN) return { ok: false, reason: 'legacy-row' };
  if (!Object.hasOwn(copy, 'sig')) return { ok: false, reason: 'legacy-row' };
  if (copy.role !== 'member' && copy.role !== 'set') return { ok: false, reason: 'bad-record' };
  if (!predicateOf(copy.predicate)) return { ok: false, reason: 'bad-record' };
  const set = parseSetId(copy.set);
  if (!set.ok) return set;
  const member = parsePrincipalId(copy.member);
  if (!member.ok) return member;
  const setOwner = parsePrincipalId(copy.setOwner);
  if (!setOwner.ok) return setOwner;
  if (setOwner.value !== set.owner) return { ok: false, reason: 'bad-record' };
  if (!Object.is(copy.stated, 0) && !Object.is(copy.stated, 1)) return { ok: false, reason: 'bad-record' };
  if (!integer(copy.hamState) || !integer(copy.issuedAt)) return { ok: false, reason: 'bad-record' };
  const cancels = cancelList(copy.cancels);
  if (!cancels) return { ok: false, reason: 'bad-record' };
  if (typeof copy.sig !== 'string') return { ok: false, reason: 'bad-record' };
  if (Object.hasOwn(copy, 'attest') && typeof copy.attest !== 'string') return { ok: false, reason: 'bad-record' };
  /** @type {MembershipAssent} */
  const value = {
    role: copy.role,
    predicate: copy.predicate,
    set: set.id,
    member: member.value,
    setOwner: setOwner.value,
    stated: /** @type {0 | 1} */ (copy.stated),
    hamState: /** @type {number} */ (copy.hamState),
    issuedAt: /** @type {number} */ (copy.issuedAt),
    cancels,
    sig: copy.sig,
    ...(typeof copy.attest === 'string' ? { attest: copy.attest } : {}),
  };
  return { ok: true, value, bytes: membershipAssentBytes(value) };
}

/** @param {unknown} row @returns {{ ok: true, value: ObjectSetRow, bytes: Uint8Array } | { ok: false, reason: string }} */
export function parseObjectSet(row) {
  const copy = snapshot(row);
  if (!copy) return { ok: false, reason: 'bad-record' };
  if (copy.domain !== undefined && copy.domain !== OBJECT_SET_DOMAIN) return { ok: false, reason: 'legacy-row' };
  if (!Object.hasOwn(copy, 'sig')) return { ok: false, reason: 'legacy-row' };
  const owner = parsePrincipalId(copy.owner);
  if (!owner.ok) return owner;
  const object = parseObjectId(copy.object);
  if (!object.ok) return object;
  const embedded = objectPrincipal(object.value);
  if (!embedded.ok) return embedded;
  if (embedded.value !== owner.value) return { ok: false, reason: 'bad-record' };
  if (!predicateOf(copy.predicate)) return { ok: false, reason: 'bad-record' };
  const set = parseSetId(copy.set);
  if (!set.ok) return set;
  if (!Object.is(copy.stated, 0) && !Object.is(copy.stated, 1)) return { ok: false, reason: 'bad-record' };
  if (!integer(copy.hamState) || !integer(copy.issuedAt)) return { ok: false, reason: 'bad-record' };
  const cancels = cancelList(copy.cancels);
  if (!cancels) return { ok: false, reason: 'bad-record' };
  if (typeof copy.sig !== 'string') return { ok: false, reason: 'bad-record' };
  if (Object.hasOwn(copy, 'attest') && typeof copy.attest !== 'string') return { ok: false, reason: 'bad-record' };
  /** @type {ObjectSetRow} */
  const value = {
    owner: owner.value,
    object: object.value,
    predicate: copy.predicate,
    set: set.id,
    stated: /** @type {0 | 1} */ (copy.stated),
    hamState: /** @type {number} */ (copy.hamState),
    issuedAt: /** @type {number} */ (copy.issuedAt),
    cancels,
    sig: copy.sig,
    ...(typeof copy.attest === 'string' ? { attest: copy.attest } : {}),
  };
  return { ok: true, value, bytes: objectSetBytes(value) };
}

/** @param {unknown} row @returns {{ ok: true, value: GroupCancel, bytes: Uint8Array } | { ok: false, reason: string }} */
export function parseGroupCancel(row) {
  const copy = snapshot(row);
  if (!copy) return { ok: false, reason: 'bad-record' };
  if (copy.domain !== undefined && copy.domain !== CANCEL_DOMAIN) return { ok: false, reason: 'legacy-row' };
  if (!Object.hasOwn(copy, 'sig')) return { ok: false, reason: 'legacy-row' };
  if (copy.kind !== 'membership' && copy.kind !== 'object-set') return { ok: false, reason: 'bad-record' };
  if (!predicateOf(copy.predicate)) return { ok: false, reason: 'bad-record' };
  const set = parseSetId(copy.set);
  if (!set.ok) return set;
  const member = parsePrincipalId(copy.member);
  if (!member.ok) return member;
  const setOwner = parsePrincipalId(copy.setOwner);
  if (!setOwner.ok) return setOwner;
  if (setOwner.value !== set.owner) return { ok: false, reason: 'bad-record' };
  const signer = parsePrincipalId(copy.signer);
  if (!signer.ok) return signer;
  const prior = cancelList(copy.prior);
  if (!prior || typeof copy.cancelId !== 'string' || !/^[0-9a-f]{64}$/.test(copy.cancelId)) return { ok: false, reason: 'bad-record' };
  if (prior.includes(copy.cancelId)) return { ok: false, reason: 'bad-record' };
  if (!integer(copy.issuedAt) || typeof copy.sig !== 'string' || typeof copy.rowSoul !== 'string') return { ok: false, reason: 'bad-record' };
  /** @type {ObjectId | undefined} */
  let object;
  /** @type {string} */
  let expected;
  if (copy.kind === 'membership') {
    expected = membershipSoul(setOwner.value, copy.predicate, set.id, member.value);
    if (signer.value !== member.value && signer.value !== setOwner.value) return { ok: false, reason: 'bad-record' };
  } else {
    const id = parseObjectId(copy.object);
    if (!id.ok) return id;
    const embedded = objectPrincipal(id.value);
    if (!embedded.ok) return embedded;
    object = id.value;
    expected = objectSetSoul(embedded.value, id.value, copy.predicate, set.id);
    if (signer.value !== embedded.value) return { ok: false, reason: 'bad-record' };
  }
  if (copy.rowSoul !== expected) return { ok: false, reason: 'bad-record' };
  /** @type {GroupCancel} */
  const value = {
    kind: copy.kind,
    rowSoul: copy.rowSoul,
    cancelId: copy.cancelId,
    prior,
    signer: signer.value,
    predicate: copy.predicate,
    set: set.id,
    member: member.value,
    setOwner: setOwner.value,
    ...(object ? { object } : {}),
    issuedAt: /** @type {number} */ (copy.issuedAt),
    sig: copy.sig,
    ...(typeof copy.attest === 'string' ? { attest: copy.attest } : {}),
  };
  return { ok: true, value, bytes: groupCancelBytes(value) };
}

/** @param {SeeResolver | null | undefined} resolver @returns {resolver is SeeResolver} */
function resolverReady(resolver) {
  return !!resolver && typeof resolver === 'object' && typeof resolver.rotations === 'function' && !!resolver.ctx;
}

/**
 * Copy the signature that verified. Later reads do not touch the caller's row.
 * @param {{ stated: 0 | 1, hamState: number, issuedAt: number, cancels: readonly string[], sig: string, attest?: string }} assent
 * @param {Uint8Array} bytes
 * @param {'present' | 'witnessed'} mode
 * @returns {StoredAssent}
 */
function storedAssent(assent, bytes, mode) {
  return {
    stated: assent.stated,
    hamState: assent.hamState,
    issuedAt: assent.issuedAt,
    bytes,
    sig: assent.sig,
    ...(assent.attest !== undefined ? { attest: assent.attest } : {}),
    observed: assent.cancels,
    mode,
  };
}

/**
 * @param {GroupCancel} cancel
 * @param {Uint8Array} bytes
 * @param {'present' | 'witnessed'} mode
 * @returns {StoredCancel}
 */
function storedCancel(cancel, bytes, mode) {
  return {
    id: cancel.cancelId,
    prior: cancel.prior,
    signer: cancel.signer,
    issuedAt: cancel.issuedAt,
    bytes,
    sig: cancel.sig,
    ...(cancel.attest !== undefined ? { attest: cancel.attest } : {}),
    mode,
  };
}

/**
 * A witnessed copy replaces a bare one. A bare copy does not replace a witnessed one.
 * @param {Map<string, StoredCancel>} cancels
 * @param {StoredCancel} incoming
 * @returns {boolean}
 */
function keepCancel(cancels, incoming) {
  const held = cancels.get(incoming.id);
  if (!held || (held.mode !== 'witnessed' && incoming.mode === 'witnessed')) {
    cancels.set(incoming.id, incoming);
    return true;
  }
  return false;
}

/**
 * The mode is the one this history just verified, not the mode stored
 * when the row was admitted.
 * @param {PrincipalId} principal
 * @param {Uint8Array} bytes
 * @param {string} sig
 * @param {number} issuedAt
 * @param {0 | 1 | null} stated
 * @param {string | undefined} attest
 * @param {SeeResolver} resolver
 * @returns {'present' | 'witnessed' | null}
 */
function partyOk(principal, bytes, sig, issuedAt, stated, attest, resolver) {
  const rotations = resolver.rotations(principal);
  if (!rotations) return null;
  const seen = verifyParty(principal, rotations, resolver.ctx, bytes, sig, issuedAt, stated, attest);
  return seen.ok ? seen.mode : null;
}

/** @param {PrincipalId} principal @param {StoredAssent | null} assent @param {SeeResolver} resolver */
function freshAssent(principal, assent, resolver) {
  if (!assent) return null;
  const mode = partyOk(principal, assent.bytes, assent.sig, assent.issuedAt, assent.stated, assent.attest, resolver);
  return mode ? { ...assent, mode } : null;
}

/** @param {Map<string, StoredCancel>} cancels @param {SeeResolver} resolver */
function freshCancels(cancels, resolver) {
  /** @type {Map<string, StoredCancel>} */
  const next = new Map();
  for (const [id, cancel] of cancels) {
    const mode = partyOk(cancel.signer, cancel.bytes, cancel.sig, cancel.issuedAt, null, cancel.attest, resolver);
    if (mode) next.set(id, { ...cancel, mode });
  }
  return next;
}

/** @param {StoredAssent | null | undefined} prev @param {StoredAssent} next */
function replaces(prev, next) {
  if (!prev) return true;
  if (next.hamState !== prev.hamState) return next.hamState > prev.hamState;
  if (next.stated !== prev.stated) return next.stated === 0;
  const n = Math.min(prev.bytes.length, next.bytes.length);
  for (let i = 0; i < n; i += 1) {
    if (prev.bytes[i] !== next.bytes[i]) return next.bytes[i] < prev.bytes[i];
  }
  return next.bytes.length < prev.bytes.length;
}

/** @param {readonly string[]} observed @param {readonly string[]} ids */
function covers(observed, ids) {
  const have = new Set(observed);
  return ids.every((id) => have.has(id));
}

/** @param {StoredMembership} row */
function membershipLive(row) {
  if (!row.memberAssent || !row.setAssent) return false;
  if (row.memberAssent.stated !== 1 || row.setAssent.stated !== 1) return false;
  const ids = [...row.cancels.keys()].sort();
  return covers(row.memberAssent.observed, ids) && covers(row.setAssent.observed, ids);
}

/** @param {StoredObjectSet} row */
function objectSetLive(row) {
  if (!row.assent) return false;
  const ids = [...row.cancels.keys()].sort();
  return row.assent.stated === 1 && covers(row.assent.observed, ids);
}

/** A stated-0 assent or an uncovered cancel is a removal. A one-sided stated-1 join is not.
 * @param {StoredMembership} row */
function membershipRemoved(row) {
  if (row.memberAssent?.stated === 0 || row.setAssent?.stated === 0) return true;
  const ids = [...row.cancels.keys()];
  if (ids.length === 0) return false;
  const stated = [row.memberAssent, row.setAssent].filter((assent) => assent && assent.stated === 1);
  if (stated.length === 0) return true;
  return stated.some((assent) => !covers(/** @type {StoredAssent} */ (assent).observed, ids));
}

/**
 * @param {object} graph
 * @param {unknown} row
 * @param {SeeResolver} resolver
 * @returns {{ ok: true, kept: boolean } | { ok: false, reason: string }}
 */
export function admitMembership(graph, row, resolver) {
  if (!graphObject(graph) || !resolverReady(resolver)) return { ok: false, reason: 'missing-history' };
  const parsed = parseMembershipAssent(row);
  if (!parsed.ok) return parsed;
  const assent = parsed.value;
  const signer = assent.role === 'member' ? assent.member : assent.setOwner;
  const rotations = resolver.rotations(signer);
  if (!Array.isArray(rotations)) return { ok: false, reason: 'missing-history' };
  const verified = verifyParty(signer, rotations, resolver.ctx, parsed.bytes, assent.sig, assent.issuedAt, assent.stated, assent.attest);
  if (!verified.ok) return verified;
  const soul = membershipSoul(assent.setOwner, assent.predicate, assent.set, assent.member);
  const table = membershipTable(graph);
  const held = table.get(soul) ?? {
    predicate: assent.predicate,
    set: assent.set,
    member: assent.member,
    setOwner: assent.setOwner,
    memberAssent: null,
    setAssent: null,
    cancels: new Map(),
  };
  const next = storedAssent(assent, parsed.bytes, verified.mode);
  const prev = assent.role === 'member' ? held.memberAssent : held.setAssent;
  if (!replaces(prev, next)) return { ok: true, kept: false };
  if (assent.role === 'member') held.memberAssent = next;
  else held.setAssent = next;
  table.set(soul, held);
  return { ok: true, kept: true };
}

/**
 * @param {object} graph
 * @param {unknown} row
 * @param {SeeResolver} resolver
 * @returns {{ ok: true, kept: boolean } | { ok: false, reason: string }}
 */
export function admitObjectSet(graph, row, resolver) {
  if (!graphObject(graph) || !resolverReady(resolver)) return { ok: false, reason: 'missing-history' };
  const parsed = parseObjectSet(row);
  if (!parsed.ok) return parsed;
  const edge = parsed.value;
  const rotations = resolver.rotations(edge.owner);
  if (!Array.isArray(rotations)) return { ok: false, reason: 'missing-history' };
  const verified = verifyParty(edge.owner, rotations, resolver.ctx, parsed.bytes, edge.sig, edge.issuedAt, edge.stated, edge.attest);
  if (!verified.ok) return verified;
  const table = objectSetTable(graph);
  const prev = table.get(edge.object);
  const next = storedAssent(edge, parsed.bytes, verified.mode);
  if (prev?.assent && !replaces(prev.assent, next)) return { ok: true, kept: false };
  // A different set or predicate starts empty. The previous edge's cancels do not follow.
  const cancels = prev && prev.set === edge.set && prev.predicate === edge.predicate ? prev.cancels : new Map();
  table.set(edge.object, {
    owner: edge.owner,
    object: edge.object,
    predicate: edge.predicate,
    set: edge.set,
    assent: next,
    cancels,
  });
  return { ok: true, kept: true };
}

/**
 * @param {object} graph
 * @param {unknown} row
 * @param {SeeResolver} resolver
 * @returns {{ ok: true, kept: boolean } | { ok: false, reason: string }}
 */
export function admitGroupCancel(graph, row, resolver) {
  if (!graphObject(graph) || !resolverReady(resolver)) return { ok: false, reason: 'missing-history' };
  const parsed = parseGroupCancel(row);
  if (!parsed.ok) return parsed;
  const cancel = parsed.value;
  const rotations = resolver.rotations(cancel.signer);
  if (!Array.isArray(rotations)) return { ok: false, reason: 'missing-history' };
  const verified = verifyParty(cancel.signer, rotations, resolver.ctx, parsed.bytes, cancel.sig, cancel.issuedAt, null, cancel.attest);
  if (!verified.ok) return verified;
  if (cancel.kind === 'membership') {
    const soul = membershipSoul(cancel.setOwner, cancel.predicate, cancel.set, cancel.member);
    const held = membershipTable(graph).get(soul);
    if (!held) return { ok: false, reason: 'unknown' };
    const next = storedCancel(cancel, parsed.bytes, verified.mode);
    if (held.cancels.has(cancel.cancelId)) return { ok: true, kept: keepCancel(held.cancels, next) };
    for (const id of cancel.prior) if (!held.cancels.has(id)) return { ok: false, reason: 'bad-record' };
    held.cancels.set(cancel.cancelId, next);
    return { ok: true, kept: true };
  }
  const held = objectSetTable(graph).get(/** @type {ObjectId} */ (cancel.object));
  if (!held || held.set !== cancel.set || held.predicate !== cancel.predicate) return { ok: false, reason: 'unknown' };
  const next = storedCancel(cancel, parsed.bytes, verified.mode);
  if (held.cancels.has(cancel.cancelId)) return { ok: true, kept: keepCancel(held.cancels, next) };
  for (const id of cancel.prior) if (!held.cancels.has(id)) return { ok: false, reason: 'bad-record' };
  held.cancels.set(cancel.cancelId, next);
  return { ok: true, kept: true };
}

/**
 * Drop this principal's group rows that the new checkpoint rejects.
 * A stated-1 assent signed by a retired key is dropped. A witnessed cancel
 * on that object-set record stays, so the next edge for the same set and
 * predicate still sees it. An unwitnessed retired-key cancel is dropped.
 * Only a witnessed cancel survives.
 * @param {object} graph
 * @param {PrincipalId} principal
 * @param {SeeResolver} resolver
 * @returns {{ ok: true, value: { dropped: number } } | { ok: false, reason: string }}
 */
export function reverifyGroup(graph, principal, resolver) {
  const who = parsePrincipalId(principal);
  if (!who.ok) return who;
  if (!graphObject(graph) || !resolverReady(resolver)) return { ok: false, reason: 'missing-history' };
  const rotations = resolver.rotations(who.value);
  if (!Array.isArray(rotations)) return { ok: false, reason: 'missing-history' };
  let dropped = 0;
  for (const [soul, row] of [...membershipTable(graph)]) {
    for (const role of /** @type {const} */ (['member', 'set'])) {
      const assent = role === 'member' ? row.memberAssent : row.setAssent;
      const signer = role === 'member' ? row.member : row.setOwner;
      if (!assent || signer !== who.value) continue;
      const again = verifyParty(signer, rotations, resolver.ctx, assent.bytes, assent.sig, assent.issuedAt, assent.stated, assent.attest);
      if (!again.ok) {
        if (role === 'member') row.memberAssent = null;
        else row.setAssent = null;
        dropped += 1;
      }
    }
    for (const [id, cancel] of [...row.cancels]) {
      if (cancel.signer !== who.value) continue;
      const again = verifyParty(cancel.signer, rotations, resolver.ctx, cancel.bytes, cancel.sig, cancel.issuedAt, null, cancel.attest);
      if (!again.ok) {
        row.cancels.delete(id);
        dropped += 1;
      }
    }
    if (!row.memberAssent && !row.setAssent && row.cancels.size === 0) membershipTable(graph).delete(soul);
  }
  for (const [id, row] of [...objectSetTable(graph)]) {
    if (row.owner !== who.value) continue;
    if (row.assent) {
      const again = verifyParty(row.owner, rotations, resolver.ctx, row.assent.bytes, row.assent.sig, row.assent.issuedAt, row.assent.stated, row.assent.attest);
      if (!again.ok) {
        row.assent = null;
        dropped += 1;
      }
    }
    for (const [cancelId, cancel] of [...row.cancels]) {
      if (cancel.signer !== who.value) continue;
      const cancelAgain = verifyParty(cancel.signer, rotations, resolver.ctx, cancel.bytes, cancel.sig, cancel.issuedAt, null, cancel.attest);
      if (!cancelAgain.ok) {
        row.cancels.delete(cancelId);
        dropped += 1;
      }
    }
    if (!row.assent && row.cancels.size === 0) objectSetTable(graph).delete(id);
  }
  return { ok: true, value: { dropped } };
}

/**
 * @param {object} graph
 * @param {GroupPredicate} predicate
 * @param {ObjectId} object
 * @param {PrincipalId} accessor
 * @param {number} now
 * @param {HandoffHint | null | undefined} hint
 * @param {HopFactor | null | undefined} hop
 */
export function checkGroupSee(graph, predicate, object, accessor, now, hint, hop) {
  void now;
  const echoed = { hint: hint ?? null, hop: hop ?? null };
  const deny = (/** @type {string} */ reason) => ({ allowed: false, reason, ...echoed });
  if (!graphObject(graph)) return deny('missing');
  if (!predicateOf(predicate)) return deny('bad-record');
  const id = parseObjectId(object);
  if (!id.ok) return deny(id.reason);
  const who = parsePrincipalId(accessor);
  if (!who.ok) return deny(who.reason);
  const embedded = objectPrincipal(id.value);
  if (!embedded.ok) return deny('missing');
  const admitted = admittedOwner(graph, id.value);
  if (!admitted || admitted.owner !== embedded.value) return deny('missing');
  if (embedded.value === who.value) return { allowed: true, reason: 'owner', ...echoed };
  const edge = objectSetTable(graph).get(id.value);
  if (!edge || !objectSetLive(edge) || edge.predicate !== predicate || edge.owner !== embedded.value) return deny('missing');
  const setOwner = objectPrincipal(edge.set);
  if (!setOwner.ok) return deny('missing');
  const membership = membershipTable(graph).get(membershipSoul(setOwner.value, predicate, edge.set, who.value));
  if (!membership || !membershipLive(membership) || membership.member !== who.value || membership.setOwner !== setOwner.value) {
    return deny('missing');
  }
  return { allowed: true, reason: predicate, ...echoed };
}

/**
 * @param {object} graph
 * @param {ObjectId | null | undefined} set
 * @param {ObjectId} object
 * @param {PrincipalId} accessor
 * @param {DecodedGroupPayload | null | undefined} payload
 * @param {number} now
 * @param {HandoffHint | null | undefined} hint
 * @param {HopFactor | null | undefined} hop
 * @returns {GroupPresentation}
 */
export function checkGroupPresentation(graph, set, object, accessor, payload, now, hint, hop) {
  const storeCancel = payload?.stated === 0;
  const echoed = { hint: hint ?? null, hop: hop ?? null, storeCancel };
  if (!graphObject(graph)) return { allowed: false, reason: 'missing', ...echoed };
  const live = !!payload && payload.stated === 1 && integer(payload.from) && integer(payload.until) && now >= payload.from && now < payload.until;
  const id = parseObjectId(object);
  const edge = id.ok ? objectSetTable(graph).get(id.value) : undefined;
  if (set == null) {
    if (edge && objectSetLive(edge)) return { allowed: false, reason: 'missing', ...echoed };
    const dest = id.ok ? checkSee(graph, id.value, accessor, now, hint ?? undefined, hop ?? undefined) : { allowed: false, reason: 'missing' };
    if (dest.allowed && live) return { allowed: true, reason: dest.reason, ...echoed };
    return { allowed: false, reason: live ? dest.reason : 'cancelled', ...echoed };
  }
  const presented = parseSetId(set);
  if (!presented.ok || !edge || !objectSetLive(edge) || edge.set !== presented.id) return { allowed: false, reason: 'missing', ...echoed };
  const see = checkGroupSee(graph, edge.predicate, object, accessor, now, hint, hop);
  if (see.allowed && live) return { allowed: true, reason: see.reason, ...echoed };
  return { allowed: false, reason: live ? see.reason : 'cancelled', ...echoed };
}

/**
 * True when the snapshot hides a removal or a newer object-set edge.
 * An edge that is not live is a removal unless the snapshot is stated 0
 * at a hamState at least as high as the stored assent.
 * A one-sided stated-1 membership is not a removal. A stated-0 assent
 * or an uncovered cancel is.
 * Member ham does not stand in for the object-set edge.
 * @param {object} graph
 * @param {string} object
 * @param {readonly { accessor: string, predicate: GroupPredicate, setId: string, stated: number, hamState: number }[]} members
 * @param {{ predicate: GroupPredicate, setId: string, stated: number, hamState: number } | null | undefined} objectSet
 */
export function snapshotUnderstatesGroup(graph, object, members, objectSet) {
  if (!graphObject(graph)) return objectSet != null;
  const id = parseObjectId(object);
  const current = id.ok ? objectSetTable(graph).get(id.value) : undefined;
  if (!current) return objectSet != null;
  if (!objectSet) return true;
  const assent = current.assent;
  const ham = assent?.hamState ?? 0;
  if (!assent || !objectSetLive(current)) {
    if (
      objectSet.stated !== 0
      || objectSet.hamState < ham
      || objectSet.predicate !== current.predicate
      || objectSet.setId !== current.set
    ) return true;
  } else if (
    objectSet.hamState < assent.hamState
    || objectSet.predicate !== current.predicate
    || objectSet.setId !== current.set
    || objectSet.stated !== assent.stated
  ) return true;
  const setOwner = objectPrincipal(current.set);
  if (!setOwner.ok) return true;
  for (const [soul, row] of membershipTable(graph)) {
    void soul;
    if (row.predicate !== current.predicate || row.set !== current.set) continue;
    if (!membershipRemoved(row)) continue;
    const snap = members.find((member) => member.accessor === row.member && member.predicate === row.predicate && member.setId === row.set);
    const ham = Math.max(row.memberAssent?.hamState ?? 0, row.setAssent?.hamState ?? 0);
    if (!snap || snap.stated !== 0 || snap.hamState < ham) return true;
  }
  void setOwner;
  return false;
}

export class MemoryGroupGraph {
  /**
   * @param {string} object
   * @returns {{ id: string, owner: string } | undefined}
   */
  objectRecord(object) {
    const id = parseObjectId(object);
    if (!id.ok) return undefined;
    const admitted = admittedOwner(this, id.value);
    if (!admitted) return undefined;
    return { id: id.value, owner: admitted.owner };
  }

  /** @param {string} object */
  hasObject(object) {
    return this.objectRecord(object) !== undefined;
  }

  /**
   * The admitted signed owner. An unsigned label is not this owner.
   * @param {string} object
   */
  ownerOf(object) {
    const id = parseObjectId(object);
    if (!id.ok) return undefined;
    return admittedOwner(this, id.value)?.owner;
  }

  /** @param {string} object */
  canonicalObjectId(object) {
    return this.objectRecord(object)?.id ?? (typeof object === 'string' ? object : '');
  }

  /**
   * @param {GroupPredicate} predicate
   * @param {string} object
   * @param {string} accessor
   * @param {number} now
   */
  checkGroupSee(predicate, object, accessor, now) {
    return checkGroupSee(this, predicate, /** @type {ObjectId} */ (object), /** @type {PrincipalId} */ (accessor), now, null, null);
  }

  /**
   * Union memberships and object-set rows. An object-set row is copied only
   * when this graph already holds the admitted signed object record and that
   * owner is the row's owner. A row that arrives before that record is
   * dropped, and a later record does not revive it. Object-set cancels are
   * unioned only when both edges name the same set and predicate. Otherwise
   * only the winning edge's cancels are kept. Each incoming assent and
   * cancel is checked against this graph's rotation history. A copy signed
   * by a retired key is not stored.
   * @param {MemoryGroupGraph} other
   * @param {SeeResolver} resolver
   */
  mergeFrom(other, resolver) {
    if (!resolverReady(resolver)) return;
    for (const [soul, incoming] of membershipTable(other)) {
      const memberAssent = freshAssent(incoming.member, incoming.memberAssent, resolver);
      const setAssent = freshAssent(incoming.setOwner, incoming.setAssent, resolver);
      const cancels = freshCancels(incoming.cancels, resolver);
      const local = membershipTable(this).get(soul);
      if (!local) {
        if (!memberAssent && !setAssent && cancels.size === 0) continue;
        membershipTable(this).set(soul, {
          predicate: incoming.predicate,
          set: incoming.set,
          member: incoming.member,
          setOwner: incoming.setOwner,
          memberAssent,
          setAssent,
          cancels,
        });
        continue;
      }
      if (memberAssent && replaces(local.memberAssent, memberAssent)) local.memberAssent = memberAssent;
      if (setAssent && replaces(local.setAssent, setAssent)) local.setAssent = setAssent;
      for (const [, cancel] of cancels) keepCancel(local.cancels, cancel);
    }
    for (const [id, incoming] of objectSetTable(other)) {
      const admitted = admittedOwner(this, /** @type {ObjectId} */ (id));
      if (!admitted || admitted.owner !== incoming.owner) continue;
      const assent = freshAssent(incoming.owner, incoming.assent, resolver);
      const cancels = freshCancels(incoming.cancels, resolver);
      const local = objectSetTable(this).get(id);
      if (!local) {
        if (!assent && cancels.size === 0) continue;
        objectSetTable(this).set(id, { ...incoming, assent, cancels });
        continue;
      }
      const sameEdge = local.set === incoming.set && local.predicate === incoming.predicate;
      if (assent && replaces(local.assent, assent)) {
        const kept = new Map(sameEdge ? local.cancels : cancels);
        if (sameEdge) for (const [, cancel] of cancels) keepCancel(kept, cancel);
        objectSetTable(this).set(id, { ...incoming, assent, cancels: kept });
      } else if (sameEdge) {
        for (const [, cancel] of cancels) keepCancel(local.cancels, cancel);
      }
    }
  }
}
