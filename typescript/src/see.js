/**
 * Stored-id see path. One parse produces the signing bytes and the cancel bit.
 * Check reads only rows admitted through that parse. Hint and hop never grant.
 * @typedef {import('../ids/src/types.js').ObjectId} ObjectId
 * @typedef {import('../ids/src/types.js').PrincipalId} PrincipalId
 * @typedef {import('../ids/src/types.js').SeeGrant} SeeGrant
 * @typedef {import('../ids/src/types.js').ResolutionContext} ResolutionContext
 * @typedef {{ allowed: boolean, reason: string }} SeeCheck
 * @typedef {{
 *   owners: Map<string, PrincipalId>,
 *   rows: Map<string, SealedRow>,
 * }} SeeStore
 * @typedef {{
 *   key: PrincipalId,
 *   mode: 'present' | 'witnessed',
 *   grant: SeeGrant,
 *   bytes: Uint8Array,
 *   source: SeeGrant,
 * }} SealedRow
 * @typedef {{
 *   rotations: (principal: PrincipalId) => readonly unknown[],
 *   ctx: ResolutionContext,
 * }} SeeResolver
 * @typedef {{
 *   hasObject: (object: ObjectId) => boolean,
 *   ownerOf: (object: ObjectId) => PrincipalId | undefined,
 * }} SeeGraph
 */

import {
  grantSoul,
  parseObjectId,
  parsePrincipalId,
  parseSeeGrant,
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

/** @param {unknown} now */
function safeNow(now) {
  return typeof now === 'number' && Number.isSafeInteger(now) && now >= 0 && !Object.is(now, -0);
}

/** @param {Uint8Array} left @param {Uint8Array} right */
function smallerBytes(left, right) {
  const n = Math.min(left.length, right.length);
  for (let i = 0; i < n; i += 1) {
    if (left[i] !== right[i]) return left[i] < right[i];
  }
  return left.length < right.length;
}

/** @param {SeeGrant} grant */
function width(grant) {
  return grant.until - grant.from;
}

/** @param {SealedRow} prev @param {SealedRow} next */
function replaces(prev, next) {
  if (next.grant.hamState !== prev.grant.hamState) return next.grant.hamState > prev.grant.hamState;
  if ((next.grant.stated === 0) !== (prev.grant.stated === 0)) return next.grant.stated === 0;
  if (width(next.grant) !== width(prev.grant)) return width(next.grant) < width(prev.grant);
  return smallerBytes(next.bytes, prev.bytes);
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
 * @returns {SealedRow}
 */
function seal(verifiedRow) {
  const row = Object.freeze({
    key: verifiedRow.key,
    mode: verifiedRow.mode,
    grant: Object.freeze({ ...verifiedRow.grant }),
    bytes: new Uint8Array(verifiedRow.bytes),
    source: sourceOf(verifiedRow.grant),
  });
  verified.add(row);
  return row;
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

/**
 * @param {object} graph
 * @param {ObjectId} object
 * @param {PrincipalId} owner
 */
export function putObject(graph, object, owner) {
  const id = seeObjectEdge(object);
  const who = seeAccessorEdge(owner);
  if (!id.ok || !who.ok) return;
  store(graph).owners.set(id.value, who.value);
}

/**
 * @param {object} graph
 * @param {unknown} row
 * @param {SeeResolver} resolver
 * @returns {import('../ids/src/types.js').Result<SealedRow> & { kept?: boolean }}
 */
export function admitRow(graph, row, resolver) {
  if (!graph || !resolver || typeof resolver.rotations !== 'function' || !resolver.ctx) {
    return { ok: false, reason: 'missing-history' };
  }
  const parsed = parseSeeGrant(row);
  if (!parsed.ok) return parsed;
  const rotations = resolver.rotations(parsed.value.grant.owner);
  const verified = verifySeeGrant(parsed.value.grant, Array.isArray(rotations) ? rotations : [], resolver.ctx);
  if (!verified.ok) return verified;
  const grant = verified.value.grant;
  const key = grantSoul(grant.owner, grant.object, grant.accessor);
  const held = store(graph);
  const sealed = seal(verified.value);
  const prev = held.rows.get(key);
  const kept = !prev || replaces(prev, sealed);
  if (kept) held.rows.set(key, sealed);
  const stored = held.rows.get(key);
  return { ok: true, value: stored ?? sealed, kept };
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
  if (!graph || !resolver || typeof resolver.rotations !== 'function' || !resolver.ctx) {
    return { ok: false, reason: 'missing-history' };
  }
  const held = store(graph);
  const rotations = resolver.rotations(who.value);
  let dropped = 0;
  for (const [key, row] of [...held.rows]) {
    if (row.grant.owner !== who.value) continue;
    const again = verifySeeGrant(row.source, Array.isArray(rotations) ? rotations : [], resolver.ctx);
    if (!again.ok) {
      held.rows.delete(key);
      dropped += 1;
      continue;
    }
    held.rows.set(key, seal(again.value));
  }
  return { ok: true, value: { dropped } };
}

/**
 * @param {object} graph
 * @param {ObjectId} object
 * @param {PrincipalId} accessor
 */
export function admittedView(graph, object, accessor) {
  const id = seeObjectEdge(object);
  const who = seeAccessorEdge(accessor);
  if (!id.ok || !who.ok) return undefined;
  const held = store(graph);
  const owner = held.owners.get(id.value);
  if (!owner) return undefined;
  const row = held.rows.get(grantSoul(owner, id.value, who.value));
  if (!row) return undefined;
  return {
    stated: row.grant.stated,
    hamState: row.grant.hamState,
    mode: row.mode,
    from: row.grant.from,
    until: row.grant.until,
    issuedAt: row.grant.issuedAt,
  };
}

/**
 * Check on an admitted row. A raw string is not a parameter.
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
  const id = seeObjectEdge(object);
  const who = seeAccessorEdge(accessor);
  if (!id.ok) return { allowed: false, reason: id.reason };
  if (!who.ok) return { allowed: false, reason: who.reason };
  if (!safeNow(now)) return { allowed: false, reason: 'unknown' };
  const text = id.value;
  if (text === 's3rch/meta' || text === 's3rch/acl' || text.startsWith('s3rch/acl/') || text.includes('://')) {
    return { allowed: false, reason: 'unknown' };
  }
  const owner = store(graph).owners.get(text);
  if (!owner) return { allowed: false, reason: 'unknown' };
  if (owner === who.value) return { allowed: true, reason: 'owner' };
  const row = store(graph).rows.get(grantSoul(owner, text, who.value));
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
  const resolverFor = (/** @type {string} */ name) => ({
    rotations: () => options.rotations(name),
    ctx: options.ctx,
  });
  for (const step of steps) {
    if (step.op === 'edge') {
      const got = step.kind === 'object' ? seeObjectEdge(step.value) : seeAccessorEdge(step.value);
      if (got.ok || got.reason !== step.reason) failStep(step, got);
      continue;
    }
    if (step.op === 'verify') {
      const got = verifySeeGrant(step.row, options.rotations(step.rotations), options.ctx);
      if (step.ok) {
        if (!got.ok || got.value.mode !== step.mode) failStep(step, got.ok ? got.value.mode : got.reason);
      } else if (got.ok || got.reason !== step.reason) failStep(step, got.ok ? got.value.mode : got.reason);
      continue;
    }
    if (step.op === 'put') {
      putObject(graph, step.object, step.owner);
      continue;
    }
    if (step.op === 'admit') {
      const got = admitRow(graph, step.row, resolverFor(step.rotations));
      if (!step.ok) {
        if (got.ok || got.reason !== step.reason) failStep(step, got.ok ? 'ok' : got.reason);
        continue;
      }
      if (!got.ok || got.kept !== step.kept) failStep(step, got.ok ? got.kept : got.reason);
      if (step.mode !== undefined && got.value.mode !== step.mode) failStep(step, got.value.mode);
      if (step.stated !== undefined && got.value.grant.stated !== step.stated) failStep(step, got.value.grant.stated);
      if (step.hamState !== undefined && got.value.grant.hamState !== step.hamState) failStep(step, got.value.grant.hamState);
      continue;
    }
    if (step.op === 'reverify') {
      const got = reverifyPrincipal(graph, step.principal, resolverFor(step.rotations));
      if (!got.ok || got.value.dropped !== step.dropped) failStep(step, got.ok ? got.value.dropped : got.reason);
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

/**
 * @param {Record<string, unknown>} step
 * @param {unknown} got
 * @returns {never}
 */
function failStep(step, got) {
  throw Error(JSON.stringify({ step, got }));
}
