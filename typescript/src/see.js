/**
 * Stored-id see path. One parse produces the signing bytes and the cancel bit.
 * Check reads only rows admitted through that parse. Hint and hop never grant.
 * The object owner is a signed `sociacl-object-v2` record, not a caller argument.
 * The object id embeds that owner's genesis principal. A mismatch is `bad-record`.
 * @typedef {import('../ids/src/types.js').ObjectId} ObjectId
 * @typedef {import('../ids/src/types.js').PrincipalId} PrincipalId
 * @typedef {import('../ids/src/types.js').SeeGrant} SeeGrant
 * @typedef {import('../ids/src/types.js').ObjectRecord} ObjectRecord
 * @typedef {import('../ids/src/types.js').ResolutionContext} ResolutionContext
 * @typedef {{ allowed: boolean, reason: string }} SeeCheck
 * @typedef {{ owner: PrincipalId, issuedAt: number, frozen: boolean }} ObjectAdmission
 * @typedef {ObjectAdmission & { record: ObjectRecord }} StoredOwner
 * @typedef {{
 *   owners: Map<string, StoredOwner>,
 *   rows: Map<string, SealedRow>,
 * }} SeeStore
 * @typedef {{
 *   key: PrincipalId,
 *   mode: 'present' | 'witnessed',
 *   grant: SeeGrant,
 *   bytes: Uint8Array,
 *   source: SeeGrant,
 *   witness: boolean,
 * }} SealedRow
 * @typedef {{
 *   rotations: (principal: PrincipalId) => readonly unknown[] | undefined,
 *   ctx: ResolutionContext,
 * }} SeeResolver
 */

import {
  grantSoul,
  parseObjectId,
  parsePrincipalId,
  parseObjectRecord,
  parseSeeGrant,
  verifyAclAttestation,
  verifyObjectRecord,
  verifySeeGrant,
} from '../ids/src/index.js';

const verified = new WeakSet();
/** @type {WeakMap<object, SeeStore>} */
const stores = new WeakMap();

/** @param {object} graph @returns {SeeStore} */
function store(graph) {
  let held = stores.get(graph);
  if (!held) {
    held = { owners: new Map(), rows: new Map() };
    stores.set(graph, held);
  }
  return held;
}

/** @param {unknown} graph */
function graphObject(graph) {
  return typeof graph === 'object' && graph !== null;
}

/** @param {unknown} now */
function safeNow(now) {
  return typeof now === 'number' && Number.isSafeInteger(now) && now >= 0 && !Object.is(now, -0);
}

/** @param {unknown} resolver @returns {resolver is SeeResolver} */
function resolverReady(resolver) {
  return !!resolver && typeof resolver === 'object' && typeof /** @type {SeeResolver} */ (resolver).rotations === 'function' && !!/** @type {SeeResolver} */ (resolver).ctx;
}

/** @param {Uint8Array} left @param {Uint8Array} right */
function smallerBytes(left, right) {
  const n = Math.min(left.length, right.length);
  for (let i = 0; i < n; i += 1) {
    if (left[i] !== right[i]) return left[i] < right[i];
  }
  return left.length < right.length;
}

/** @param {Uint8Array} left @param {Uint8Array} right */
function sameBytes(left, right) {
  if (left.length !== right.length) return false;
  for (let i = 0; i < left.length; i += 1) if (left[i] !== right[i]) return false;
  return true;
}

/** Strict containment. Equal windows are not narrower.
 * @param {{ from: number, until: number }} inner
 * @param {{ from: number, until: number }} outer
 */
function inside(inner, outer) {
  return inner.from >= outer.from && inner.until <= outer.until && (inner.from > outer.from || inner.until < outer.until);
}

/** Higher HAM, then a cancel, then a strictly contained window, then the
 * smaller signed bytes. Equal bytes keep the copy whose witness validates.
 * That copy only adds the witness. It does not re-open a row.
 * @param {SealedRow} prev @param {SealedRow} next
 */
function replaces(prev, next) {
  if (next.grant.hamState !== prev.grant.hamState) return next.grant.hamState > prev.grant.hamState;
  if ((next.grant.stated === 0) !== (prev.grant.stated === 0)) return next.grant.stated === 0;
  const nextInside = inside(next.grant, prev.grant);
  const prevInside = inside(prev.grant, next.grant);
  if (nextInside !== prevInside) return nextInside;
  if (!sameBytes(next.bytes, prev.bytes)) return smallerBytes(next.bytes, prev.bytes);
  return next.witness && !prev.witness;
}
/** A witness that validates under the retired-cancel rule, even on a present key.
 * @param {SeeGrant} grant @param {Uint8Array} bytes @param {ResolutionContext} ctx */
function witnessOk(grant, bytes, ctx) {
  if (grant.attest === undefined || !ctx) return false;
  const attest = verifyAclAttestation(grant.attest, ctx.jwks, grant.issuedAt, bytes);
  return attest.ok && attest.value.principal === grant.owner;
}

/** @param {SeeGrant} grant @returns {SeeGrant} */
function sourceOf(grant) {
  return Object.freeze({
    owner: grant.owner,
    object: grant.object,
    accessor: grant.accessor,
    stated: grant.stated,
    from: grant.from,
    until: grant.until,
    hamState: grant.hamState,
    issuedAt: grant.issuedAt,
    sig: grant.sig,
    ...(grant.attest !== undefined ? { attest: grant.attest } : {}),
  });
}

/**
 * @param {{ key: PrincipalId, mode: 'present' | 'witnessed', grant: SeeGrant, bytes: Uint8Array }} verifiedRow
 * @param {ResolutionContext} ctx
 * @returns {SealedRow}
 */
function seal(verifiedRow, ctx) {
  const bytes = new Uint8Array(verifiedRow.bytes);
  const row = {
    key: verifiedRow.key,
    mode: verifiedRow.mode,
    grant: Object.freeze({ ...verifiedRow.grant }),
    bytes,
    source: sourceOf(verifiedRow.grant),
    witness: witnessOk(verifiedRow.grant, bytes, ctx),
  };
  Object.freeze(row);
  verified.add(row);
  return row;
}

/** A caller-facing row. Its tie-break bytes are a copy of the stored buffer.
 * @param {SealedRow} row @returns {SealedRow}
 */
function present(row) {
  const copy = {
    key: row.key,
    mode: row.mode,
    grant: row.grant,
    bytes: new Uint8Array(row.bytes),
    source: row.source,
    witness: row.witness,
  };
  Object.freeze(copy);
  verified.add(copy);
  return copy;
}

/** @param {unknown} row */
export function isVerifiedRow(row) {
  return typeof row === 'object' && row !== null && verified.has(row);
}

/**
 * The edge Check uses. A hit is the id `parse` returned, never a second spelling.
 * @param {unknown} value
 * @returns {import('../ids/src/types.js').Result<ObjectId>}
 */
export function seeObjectEdge(value) {
  const parsed = parseObjectId(value);
  if (!parsed.ok) return parsed;
  if (parsed.value !== value) return { ok: false, reason: 'bad-record' };
  return parsed;
}

/**
 * @param {unknown} value
 * @returns {import('../ids/src/types.js').Result<PrincipalId>}
 */
export function seeAccessorEdge(value) {
  const parsed = parsePrincipalId(value);
  if (!parsed.ok) return parsed;
  if (parsed.value !== value) return { ok: false, reason: 'bad-record' };
  return parsed;
}

/** Caller-facing admission. Mutating it does not change the store.
 * @param {StoredOwner} row @returns {ObjectAdmission} */
function admissionCopy(row) {
  return { owner: row.owner, issuedAt: row.issuedAt, frozen: false };
}
/**
 * Admit a signed object record. The owner is the record, never an argument.
 * The object id must embed that owner. The same owner later is a no-op while
 * the stored record still verifies. A stored record the current key no longer
 * signs is replaced by the new one. A different owner is `bad-record`.
 * @param {object} graph
 * @param {unknown} record
 * @param {SeeResolver} resolver
 * @returns {{ ok: true, value: ObjectAdmission, kept: boolean } | { ok: false, reason: string }}
 */
export function putObject(graph, record, resolver) {
  if (!graphObject(graph) || !resolverReady(resolver)) return { ok: false, reason: 'missing-history' };
  const parsed = parseObjectRecord(record);
  if (!parsed.ok) return parsed;
  const history = resolver.rotations(parsed.value.record.owner);
  if (!Array.isArray(history)) return { ok: false, reason: 'missing-history' };
  const verified = verifyObjectRecord(parsed.value.record, history, resolver.ctx);
  if (!verified.ok) return verified;
  const held = store(graph);
  const id = verified.value.record.object;
  const owner = verified.value.record.owner;
  const issuedAt = verified.value.record.issuedAt;
  const existing = held.owners.get(id);
  if (!existing) {
    const admitted = { owner, issuedAt, frozen: false, record: verified.value.record };
    held.owners.set(id, admitted);
    return { ok: true, value: admissionCopy(admitted), kept: true };
  }
  if (existing.owner === owner) {
    const still = verifyObjectRecord(existing.record, history, resolver.ctx);
    if (still.ok) return { ok: true, value: admissionCopy(existing), kept: false };
    existing.issuedAt = issuedAt;
    existing.record = verified.value.record;
    existing.frozen = false;
    return { ok: true, value: admissionCopy(existing), kept: true };
  }
  return { ok: false, reason: 'bad-record' };
}

/**
 * @param {object} graph
 * @param {unknown} row
 * @param {SeeResolver} resolver
 * @returns {import('../ids/src/types.js').Result<SealedRow> & { kept?: boolean }}
 */
export function admitRow(graph, row, resolver) {
  if (!graphObject(graph) || !resolverReady(resolver)) return { ok: false, reason: 'missing-history' };
  const parsed = parseSeeGrant(row);
  if (!parsed.ok) return parsed;
  const rotations = resolver.rotations(parsed.value.grant.owner);
  if (!Array.isArray(rotations)) return { ok: false, reason: 'missing-history' };
  const verified = verifySeeGrant(parsed.value.grant, rotations, resolver.ctx);
  if (!verified.ok) return verified;
  const grant = verified.value.grant;
  const key = grantSoul(grant.owner, grant.object, grant.accessor);
  const held = store(graph);
  const sealed = seal(verified.value, resolver.ctx);
  const prev = held.rows.get(key);
  const kept = !prev || replaces(prev, sealed);
  if (kept) held.rows.set(key, sealed);
  const stored = held.rows.get(key) ?? sealed;
  return { ok: true, value: present(stored), kept };
}

/**
 * @param {object} graph
 * @param {PrincipalId} principal
 * @param {SeeResolver} resolver
 * @returns {import('../ids/src/types.js').Result<{ dropped: number }>}
 */
export function reverifyPrincipal(graph, principal, resolver) {
  const who = seeAccessorEdge(principal);
  if (!who.ok) return who;
  if (!graphObject(graph) || !resolverReady(resolver)) return { ok: false, reason: 'missing-history' };
  const held = store(graph);
  const rotations = resolver.rotations(who.value);
  if (!Array.isArray(rotations)) {
    for (const [key, row] of [...held.rows]) {
      if (row.grant.owner === who.value) held.rows.delete(key);
    }
    for (const [id, row] of [...held.owners]) {
      if (row.owner === who.value) held.owners.delete(id);
    }
    return { ok: false, reason: 'missing-history' };
  }
  let dropped = 0;
  for (const [key, row] of [...held.rows]) {
    if (row.grant.owner !== who.value) continue;
    const again = verifySeeGrant(row.source, rotations, resolver.ctx);
    if (!again.ok) {
      held.rows.delete(key);
      dropped += 1;
      continue;
    }
    held.rows.set(key, seal(again.value, resolver.ctx));
  }
  for (const [id, row] of [...held.owners]) {
    if (row.owner !== who.value) continue;
    const again = verifyObjectRecord(row.record, rotations, resolver.ctx);
    if (!again.ok) {
      held.owners.delete(id);
      dropped += 1;
    }
  }
  return { ok: true, value: { dropped } };
}

/**
 * @param {object} graph
 * @param {ObjectId} object
 * @param {PrincipalId} accessor
 */
export function admittedView(graph, object, accessor) {
  if (!graphObject(graph)) return undefined;
  const id = seeObjectEdge(object);
  const who = seeAccessorEdge(accessor);
  if (!id.ok || !who.ok) return undefined;
  const held = store(graph);
  const owner = held.owners.get(id.value);
  if (!owner) return undefined;
  const row = held.rows.get(grantSoul(owner.owner, id.value, who.value));
  if (!row) return undefined;
  return {
    stated: row.grant.stated,
    hamState: row.grant.hamState,
    mode: row.mode,
    from: row.grant.from,
    until: row.grant.until,
    issuedAt: row.grant.issuedAt,
    attest: row.grant.attest !== undefined,
  };
}

/** @param {object} graph @param {ObjectId} object */
export function admittedOwner(graph, object) {
  if (!graphObject(graph)) return undefined;
  const id = seeObjectEdge(object);
  if (!id.ok) return undefined;
  const owner = store(graph).owners.get(id.value);
  if (!owner) return undefined;
  return admissionCopy(owner);
}

/**
 * Check on an admitted row. A raw string is not a parameter.
 * A primitive graph is a bad record, not a throw.
 * @param {object} graph
 * @param {ObjectId} object
 * @param {PrincipalId} accessor
 * @param {number} now
 * @param {unknown} [hint]
 * @param {unknown} [hop]
 * @returns {SeeCheck}
 */
export function checkSee(graph, object, accessor, now, hint, hop) {
  void hint;
  void hop;
  if (!graphObject(graph)) return { allowed: false, reason: 'bad-record' };
  const id = seeObjectEdge(object);
  const who = seeAccessorEdge(accessor);
  if (!id.ok) return { allowed: false, reason: id.reason };
  if (!who.ok) return { allowed: false, reason: who.reason };
  if (!safeNow(now)) return { allowed: false, reason: 'unknown' };
  const admission = store(graph).owners.get(id.value);
  if (!admission) return { allowed: false, reason: 'unknown' };
  if (admission.owner === who.value) return { allowed: true, reason: 'owner' };
  const row = store(graph).rows.get(grantSoul(admission.owner, id.value, who.value));
  if (row && row.grant.stated === 1 && now >= row.grant.from && now < row.grant.until) {
    return { allowed: true, reason: 'delegate' };
  }
  return { allowed: false, reason: 'delegate' };
}

/**
 * Run one shared see vector. Expectations live on the steps.
 * @param {readonly Record<string, any>[]} steps
 * @param {{ ctx: ResolutionContext, rotations: (name: string) => readonly unknown[] }} options
 */
export function runSeeCase(steps, options) {
  const graph = {};
  const resolverFor = (/** @type {Record<string, any>} */ step) => ({
    rotations: () => (step.history === 'unavailable' ? undefined : options.rotations(step.rotations)),
    ctx: step.revocations ? { ...options.ctx, revocations: step.revocations } : options.ctx,
  });
  for (const step of steps) {
    const row = patchRow(step.row, step.patch);
    if (step.op === 'edge') {
      const got = step.kind === 'object' ? seeObjectEdge(step.value) : seeAccessorEdge(step.value);
      if (got.ok || got.reason !== step.reason) failStep(step, got);
      continue;
    }
    if (step.op === 'verify') {
      const got = verifySeeGrant(row, /** @type {readonly unknown[]} */ (resolverFor(step).rotations()), resolverFor(step).ctx);
      if (step.ok) {
        if (!got.ok || got.value.mode !== step.mode) failStep(step, got.ok ? got.value.mode : got.reason);
      } else if (got.ok || got.reason !== step.reason) failStep(step, got.ok ? got.value.mode : got.reason);
      continue;
    }
    if (step.op === 'put') {
      const got = putObject(graph, patchRow(step.record, step.patch), resolverFor(step));
      if (step.ok === false) {
        if (got.ok || got.reason !== step.reason) failStep(step, got.ok ? 'ok' : got.reason);
        continue;
      }
      if (!got.ok) failStep(step, got.reason);
      if (step.kept !== undefined && got.kept !== step.kept) failStep(step, got.kept);
      continue;
    }
    if (step.op === 'admit') {
      const got = admitRow(graph, row, resolverFor(step));
      if (!step.ok) {
        if (got.ok || got.reason !== step.reason) failStep(step, got.ok ? 'ok' : got.reason);
        continue;
      }
      if (!got.ok || got.kept !== step.kept) failStep(step, got.ok ? got.kept : got.reason);
      if (step.mode !== undefined && got.value.mode !== step.mode) failStep(step, got.value.mode);
      if (step.stated !== undefined && got.value.grant.stated !== step.stated) failStep(step, got.value.grant.stated);
      if (step.hamState !== undefined && got.value.grant.hamState !== step.hamState) failStep(step, got.value.grant.hamState);
      if (step.attest !== undefined && (got.value.grant.attest !== undefined) !== step.attest) failStep(step, got.value.grant.attest !== undefined);
      continue;
    }
    if (step.op === 'reverify') {
      const got = reverifyPrincipal(graph, step.principal, resolverFor(step));
      if (step.ok === false) {
        if (got.ok || got.reason !== step.reason) failStep(step, got.ok ? 'ok' : got.reason);
        continue;
      }
      if (!got.ok || got.value.dropped !== step.dropped) failStep(step, got.ok ? got.value.dropped : got.reason);
      continue;
    }
    if (step.op === 'owner') {
      const got = admittedOwner(graph, step.object);
      if (step.absent) {
        if (got) failStep(step, got);
        continue;
      }
      if (!got || got.owner !== step.owner || got.frozen !== !!step.frozen) failStep(step, got);
      if (step.issuedAt !== undefined && got.issuedAt !== step.issuedAt) failStep(step, got);
      continue;
    }
    if (step.op === 'view') {
      const got = admittedView(graph, step.object, step.accessor);
      if (step.absent) {
        if (got) failStep(step, got);
        continue;
      }
      if (!got || got.stated !== step.stated || got.hamState !== step.hamState || got.mode !== step.mode) failStep(step, got);
      if (step.issuedAt !== undefined && got.issuedAt !== step.issuedAt) failStep(step, got);
      if (step.from !== undefined && got.from !== step.from) failStep(step, got);
      if (step.until !== undefined && got.until !== step.until) failStep(step, got);
      if (step.attest !== undefined && got.attest !== step.attest) failStep(step, got);
      continue;
    }
    if (step.op === 'check') {
      const got = checkSee(graph, step.object, step.accessor, step.now, step.hint ? { principal: step.accessor } : undefined, step.hop ? { channel: 'convention-badge' } : undefined);
      if (got.allowed !== step.allowed || got.reason !== step.reason) failStep(step, got);
      continue;
    }
    throw Error('unknown see step ' + step.op);
  }
}

/** @param {Record<string, any> | undefined} row @param {Record<string, any> | undefined} patch */
function patchRow(row, patch) {
  if (!row || !patch) return row;
  const copy = { ...row };
  for (const [key, value] of Object.entries(patch)) copy[key] = value === '-0' ? -0 : value;
  return copy;
}

/**
 * @param {Record<string, unknown>} step
 * @param {unknown} got
 * @returns {never}
 */
function failStep(step, got) {
  throw Error(JSON.stringify({ step, got }));
}
