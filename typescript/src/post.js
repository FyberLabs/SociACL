/**
 * Stored-id post path. One soul, domain sociacl-post-grant-v2.
 * Admission verifies. Check does not. A post allow requires the
 * admitted see graph to allow the same triple. The owner is the
 * admitted object record. Hint and hop are echoed and never grant.
 * @typedef {import('../ids/src/types.js').ObjectId} ObjectId
 * @typedef {import('../ids/src/types.js').PrincipalId} PrincipalId
 * @typedef {import('../ids/src/types.js').SeeGrant} PostGrant
 * @typedef {import('../ids/src/types.js').ResolutionContext} ResolutionContext
 * @typedef {import('./see.js').SeeResolver} SeeResolver
 * @typedef {{
 *   key: PrincipalId,
 *   mode: 'present' | 'witnessed',
 *   grant: PostGrant,
 *   bytes: Uint8Array,
 *   source: PostGrant,
 *   witness: boolean,
 * }} SealedPost
 */

import {
  postSoul,
  parsePostGrant,
  verifyAclAttestation,
  verifyPostGrant,
} from '../ids/src/index.js';
import {
  admitRow,
  admittedOwner,
  admittedView,
  checkSee,
  putObject,
  reverifyPrincipal,
  seeAccessorEdge,
  seeObjectEdge,
} from './see.js';

const sealedPosts = new WeakSet();
/** @type {WeakMap<object, Map<string, SealedPost>>} */
const postTables = new WeakMap();

/** @param {object} graph */
function postMap(graph) {
  let held = postTables.get(graph);
  if (!held) {
    held = new Map();
    postTables.set(graph, held);
  }
  return held;
}

/** A copy of the admitted post rows. Mutating it does not change Check.
 * @param {object} graph */
export function postRows(graph) {
  if (!graph || typeof graph !== 'object') return undefined;
  const live = postTables.get(graph);
  /** @type {Map<string, { mode: string, grant: object }>} */
  const copy = new Map();
  if (!live) return copy;
  for (const [key, row] of live) {
    copy.set(key, { mode: row.mode, grant: { ...row.grant } });
  }
  return copy;
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

/** @param {{ from: number, until: number }} inner @param {{ from: number, until: number }} outer */
function inside(inner, outer) {
  return inner.from >= outer.from && inner.until <= outer.until && (inner.from > outer.from || inner.until < outer.until);
}

/** Higher HAM, then a cancel, then a strictly contained window, then the
 * smaller signed bytes, then a validating witness. Same order as see.
 * @param {SealedPost} prev @param {SealedPost} next */
function replaces(prev, next) {
  if (next.grant.hamState !== prev.grant.hamState) return next.grant.hamState > prev.grant.hamState;
  if ((next.grant.stated === 0) !== (prev.grant.stated === 0)) return next.grant.stated === 0;
  const nextInside = inside(next.grant, prev.grant);
  const prevInside = inside(prev.grant, next.grant);
  if (nextInside !== prevInside) return nextInside;
  if (!sameBytes(next.bytes, prev.bytes)) return smallerBytes(next.bytes, prev.bytes);
  return next.witness && !prev.witness;
}

/** @param {PostGrant} grant @param {Uint8Array} bytes @param {ResolutionContext} ctx */
function witnessOk(grant, bytes, ctx) {
  if (grant.attest === undefined || !ctx) return false;
  const attest = verifyAclAttestation(grant.attest, ctx.jwks, grant.issuedAt, bytes);
  return attest.ok && attest.value.principal === grant.owner;
}

/** @param {PostGrant} grant @returns {PostGrant} */
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
 * @param {{ key: PrincipalId, mode: 'present' | 'witnessed', grant: PostGrant, bytes: Uint8Array }} verifiedRow
 * @param {ResolutionContext} ctx
 * @returns {SealedPost}
 */
function seal(verifiedRow, ctx) {
  const bytes = new Uint8Array(verifiedRow.bytes);
  /** @type {SealedPost} */
  const row = {
    key: verifiedRow.key,
    mode: verifiedRow.mode,
    grant: Object.freeze({ ...verifiedRow.grant }),
    bytes,
    source: sourceOf(verifiedRow.grant),
    witness: witnessOk(verifiedRow.grant, bytes, ctx),
  };
  Object.freeze(row);
  sealedPosts.add(row);
  return row;
}

/** @param {SealedPost} row */
function present(row) {
  return Object.freeze({
    key: row.key,
    mode: row.mode,
    grant: row.grant,
    bytes: new Uint8Array(row.bytes),
    source: row.source,
    witness: row.witness,
  });
}

/** @param {unknown} graph @param {unknown} resolver */
function ready(graph, resolver) {
  return !!graph && typeof graph === 'object' && !!resolver && typeof resolver === 'object'
    && typeof /** @type {SeeResolver} */ (resolver).rotations === 'function'
    && !!/** @type {SeeResolver} */ (resolver).ctx;
}

/**
 * Admit one sociacl-post-grant-v2 row. The owner is the admitted object
 * record. A missing object is `unknown`. A row owner that is not that
 * record is `bad-record`. Retired-key cancels are `stated === 0` in the
 * signed bytes.
 * @param {object} graph
 * @param {unknown} row
 * @param {SeeResolver} resolver
 * @returns {{ ok: true, value: { mode: 'present' | 'witnessed', grant: PostGrant }, kept: boolean } | { ok: false, reason: string }}
 */
export function admitPost(graph, row, resolver) {
  if (!ready(graph, resolver)) return { ok: false, reason: 'missing-history' };
  const parsed = parsePostGrant(row);
  if (!parsed.ok) return parsed;
  const rotations = resolver.rotations(parsed.value.grant.owner);
  if (!Array.isArray(rotations)) return { ok: false, reason: 'missing-history' };
  const verified = verifyPostGrant(parsed.value.grant, rotations, resolver.ctx);
  if (!verified.ok) return verified;
  const grant = verified.value.grant;
  const admission = admittedOwner(graph, grant.object);
  if (!admission) return { ok: false, reason: 'unknown' };
  if (admission.owner !== grant.owner) return { ok: false, reason: 'bad-record' };
  const held = postMap(graph);
  const key = postSoul(admission.owner, grant.object, grant.accessor);
  const sealed = seal(verified.value, resolver.ctx);
  const prev = held.get(key);
  const kept = !prev || !sealedPosts.has(prev) || replaces(prev, sealed);
  if (kept) held.set(key, sealed);
  const stored = held.get(key) ?? sealed;
  return { ok: true, value: present(stored), kept };
}

const stagedPosts = new WeakSet();

/**
 * Verify a post row against history the caller already resolved. Does not write.
 * @param {object} graph
 * @param {unknown} row
 * @param {readonly unknown[]} rotations
 * @param {ResolutionContext} ctx
 * @returns {{ ok: true, value: { sealed: SealedPost, key: string, kept: boolean }, kept: boolean } | { ok: false, reason: string }}
 */
export function stagePost(graph, row, rotations, ctx) {
  if (!graph || typeof graph !== 'object' || !ctx || typeof ctx !== 'object' || !Array.isArray(rotations)) {
    return { ok: false, reason: 'missing-history' };
  }
  const parsed = parsePostGrant(row);
  if (!parsed.ok) return parsed;
  const verifiedRow = verifyPostGrant(parsed.value.grant, rotations, ctx);
  if (!verifiedRow.ok) return verifiedRow;
  const grant = verifiedRow.value.grant;
  const admission = admittedOwner(graph, grant.object);
  if (!admission) return { ok: false, reason: 'unknown' };
  if (admission.owner !== grant.owner) return { ok: false, reason: 'bad-record' };
  const key = postSoul(admission.owner, grant.object, grant.accessor);
  const sealed = seal(verifiedRow.value, ctx);
  const prev = postTables.get(graph)?.get(key);
  const kept = !prev || !sealedPosts.has(prev) || replaces(prev, sealed);
  /** @type {{ sealed: SealedPost, key: string, kept: boolean }} */
  const ticket = { sealed, key, kept };
  Object.freeze(ticket);
  stagedPosts.add(ticket);
  return { ok: true, value: ticket, kept };
}

/**
 * Write one staged post row. Does not call a resolver.
 * @param {object} graph
 * @param {{ sealed: SealedPost, key: string, kept: boolean }} ticket
 * @returns {{ ok: true, value: { mode: 'present' | 'witnessed', grant: PostGrant } } | { ok: false, reason: string }}
 */
export function commitStagedPost(graph, ticket) {
  if (!graph || typeof graph !== 'object' || !ticket || !stagedPosts.has(ticket) || !sealedPosts.has(ticket.sealed)) {
    return { ok: false, reason: 'bad-record' };
  }
  if (!ticket.kept) return { ok: false, reason: 'not-kept' };
  postMap(graph).set(ticket.key, ticket.sealed);
  return { ok: true, value: present(ticket.sealed) };
}

/** @param {object} graph @param {ObjectId} object @param {PrincipalId} accessor */
export function admittedPost(graph, object, accessor) {
  const id = seeObjectEdge(object);
  const who = seeAccessorEdge(accessor);
  if (!id.ok || !who.ok) return undefined;
  const admission = admittedOwner(graph, id.value);
  const held = postTables.get(graph);
  if (!admission || !held) return undefined;
  const row = held.get(postSoul(admission.owner, id.value, who.value));
  if (!row || !sealedPosts.has(row)) return undefined;
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

/**
 * Allow-post only when the admitted see graph allows the same triple.
 * The object owner may post. Any other accessor needs a live post row.
 * A raw string is not a parameter. Hint and hop do not grant.
 * @param {object} graph
 * @param {ObjectId} object
 * @param {PrincipalId} accessor
 * @param {number} now
 * @param {unknown} [hint]
 * @param {unknown} [hop]
 */
export function checkPost(graph, object, accessor, now, hint, hop) {
  const echoed = { hint: hint ?? null, hop: hop ?? null };
  const see = checkSee(graph, object, accessor, now, hint, hop);
  if (!see.allowed || see.reason === 'owner') return { ...see, ...echoed };
  const id = seeObjectEdge(object);
  const who = seeAccessorEdge(accessor);
  if (!id.ok || !who.ok) return { ...see, ...echoed };
  const admission = admittedOwner(graph, id.value);
  if (!admission) return { allowed: false, reason: 'unknown', ...echoed };
  const held = postTables.get(graph);
  if (!held) return { allowed: false, reason: 'missing', ...echoed };
  const row = held.get(postSoul(admission.owner, id.value, who.value));
  if (!row || !sealedPosts.has(row)) return { allowed: false, reason: 'missing', ...echoed };
  if (row.grant.stated !== 1) return { allowed: false, reason: 'cancelled', ...echoed };
  if (now >= row.grant.from && now < row.grant.until) return { allowed: true, reason: 'post', ...echoed };
  return { allowed: false, reason: 'missing', ...echoed };
}

/**
 * Recheck post rows for one principal. see.js passes the rotations it already resolved.
 * @param {object} graph
 * @param {PrincipalId} principal
 * @param {readonly unknown[] | undefined} rotations
 * @param {ResolutionContext | undefined} ctx
 * @returns {import('../ids/src/types.js').Result<{ dropped: number }>}
 */
export function reverifyPosts(graph, principal, rotations, ctx) {
  const held = graph && typeof graph === 'object' ? postTables.get(graph) : undefined;
  if (!held) return { ok: true, value: { dropped: 0 } };
  if (!graph || typeof graph !== 'object' || !ctx) return { ok: false, reason: 'missing-history' };
  if (!Array.isArray(rotations)) {
    for (const [key, row] of [...held]) {
      if (row.grant.owner === principal) held.delete(key);
    }
    return { ok: false, reason: 'missing-history' };
  }
  let dropped = 0;
  for (const [key, row] of [...held]) {
    if (row.grant.owner !== principal) continue;
    const again = verifyPostGrant(row.source, rotations, ctx);
    if (!again.ok) {
      held.delete(key);
      dropped += 1;
      continue;
    }
    held.set(key, seal(again.value, ctx));
  }
  return { ok: true, value: { dropped } };
}

/** A hop, a hint, a wrap, a request, or an inbox delivery never grants.
 * @param {string} _kind */
export function factorGrants(_kind) {
  return false;
}

/**
 * Run one shared post vector. See steps on the same graph stay available.
 * @param {readonly Record<string, any>[]} steps
 * @param {{ ctx: ResolutionContext, rotations: (name: string) => readonly unknown[] }} options
 */
export function runPostCase(steps, options) {
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
      continue;
    }
    if (step.op === 'admit-post') {
      const got = admitPost(graph, row, resolverFor(step));
      if (!step.ok) {
        if (got.ok || got.reason !== step.reason) failStep(step, got.ok ? 'ok' : got.reason);
        continue;
      }
      if (!got.ok || got.kept !== step.kept) failStep(step, got.ok ? got.kept : got.reason);
      if (!got.ok) continue;
      if (step.mode !== undefined && got.value.mode !== step.mode) failStep(step, got.value.mode);
      if (step.stated !== undefined && got.value.grant.stated !== step.stated) failStep(step, got.value.grant.stated);
      if (step.hamState !== undefined && got.value.grant.hamState !== step.hamState) failStep(step, got.value.grant.hamState);
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
      if (!got || got.owner !== step.owner) failStep(step, got);
      if (step.issuedAt !== undefined && got.issuedAt !== step.issuedAt) failStep(step, got);
      continue;
    }
    if (step.op === 'view') {
      const got = admittedView(graph, step.object, step.accessor);
      if (step.absent) {
        if (got) failStep(step, got);
        continue;
      }
      if (!got || got.stated !== step.stated || got.hamState !== step.hamState) failStep(step, got);
      continue;
    }
    if (step.op === 'view-post') {
      const got = admittedPost(graph, step.object, step.accessor);
      if (step.absent) {
        if (got) failStep(step, got);
        continue;
      }
      if (!got || got.stated !== step.stated || got.hamState !== step.hamState || got.mode !== step.mode) failStep(step, got);
      if (step.from !== undefined && got.from !== step.from) failStep(step, got);
      if (step.until !== undefined && got.until !== step.until) failStep(step, got);
      continue;
    }
    if (step.op === 'check-post') {
      const got = checkPost(graph, step.object, step.accessor, step.now, step.hint ? { principal: step.accessor } : undefined, step.hop ? { channel: 'convention-badge' } : undefined);
      if (got.allowed !== step.allowed || got.reason !== step.reason) failStep(step, got);
      if (step.hint && got.hint == null) failStep(step, got);
      if (step.hop && got.hop == null) failStep(step, got);
      continue;
    }
    throw Error('unknown post step ' + step.op);
  }
}

/** @param {Record<string, any> | undefined} row @param {Record<string, any> | undefined} patch */
function patchRow(row, patch) {
  if (!row || !patch) return row;
  const copy = { ...row };
  for (const [key, value] of Object.entries(patch)) copy[key] = value === '-0' ? -0 : value;
  return copy;
}

/** @param {Record<string, unknown>} step @param {unknown} got @returns {never} */
function failStep(step, got) {
  throw Error(JSON.stringify({ step, got }));
}
