/**
 * Shared request-vector runner. Join steps admit v2 membership and
 * object-set rows. The runner does not enroll a signer.
 */
import { requestId } from '../ids/src/index.js';
import { admitMembership, admitObjectSet, MemoryGroupGraph } from '../src/group.js';
import { admitPost, admittedPost, checkPost, factorGrants } from '../src/post.js';
import { grantApprovedRequest } from '../src/request.js';
import { admitRow, admittedView, checkSee, putObject } from '../src/see.js';

/** @param {number} n */
function scalarOf(n) {
  const bytes = new Uint8Array(32);
  bytes[31] = n;
  return bytes;
}

/** @param {Record<string, any>} step @param {unknown} got */
function failStep(step, got) {
  throw new Error(`${step.op} ${JSON.stringify(got)}`);
}

/**
 * Run one shared request vector.
 * @param {readonly Record<string, any>[]} steps
 * @param {{ ctx: import('../ids/src/types.js').ResolutionContext, rotations: (name: string) => readonly unknown[] }} options
 */
/** @param {unknown} left @param {unknown} right */
function sameBytes(left, right) {
  if (left == null && right == null) return true;
  if (!(left instanceof Uint8Array) || !(right instanceof Uint8Array) || left.length !== right.length) return false;
  for (let i = 0; i < left.length; i += 1) if (left[i] !== right[i]) return false;
  return true;
}

export function runRequestCase(steps, options) {
  const graph = new MemoryGroupGraph();
  /** @type {Uint8Array | null} */
  let lastSee = null;
  /** @type {Uint8Array | null} */
  let lastPost = null;
  const resolverFor = (/** @type {Record<string, any>} */ step) => {
    const ctx = { ...options.ctx };
    if (step.revocations) ctx.revocations = step.revocations;
    if (step.now != null) ctx.now = step.now;
    return {
      rotations: () => (step.history === 'unavailable' ? undefined : options.rotations(step.rotations)),
      ctx,
    };
  };
  for (const step of steps) {
    if (step.op === 'request-id') {
      const got = requestId(step.requester, step.object);
      if (step.id) {
        if (!got.ok || got.value !== step.id) failStep(step, got.ok ? got.value : got.reason);
      } else if (got.ok || got.reason !== step.reason) failStep(step, got.ok ? got.value : got.reason);
      continue;
    }
    if (step.op === 'put') {
      const got = putObject(graph, step.record, resolverFor(step));
      if (step.ok === false) {
        if (got.ok || got.reason !== step.reason) failStep(step, got.ok ? 'ok' : got.reason);
      } else if (!got.ok) failStep(step, got.reason);
      continue;
    }
    if (step.op === 'admit' || step.op === 'admit-post') {
      const got = step.op === 'admit'
        ? admitRow(graph, step.row, resolverFor(step))
        : admitPost(graph, step.row, resolverFor(step));
      if (step.ok === false) {
        if (got.ok || got.reason !== step.reason) failStep(step, got.ok ? 'ok' : got.reason);
      } else if (!got.ok) failStep(step, got.reason);
      continue;
    }
    if (step.op === 'join') {
      const resolver = resolverFor(step);
      const member = admitMembership(graph, step.member, resolver);
      if (!member.ok) failStep(step, member.reason);
      const set = admitMembership(graph, step.set, resolver);
      if (!set.ok) failStep(step, set.reason);
      const edge = admitObjectSet(graph, step.edge, resolver);
      if (!edge.ok) failStep(step, edge.reason);
      continue;
    }
    if (step.op === 'grant') {
      const got = grantApprovedRequest(
        graph,
        step.owner,
        step.request,
        step.window,
        step.members ?? null,
        { scalar: scalarOf(step.signer), resolver: resolverFor(step) },
      );
      if (step.granted === true) {
        if (!got.granted) failStep(step, got);
        if (step.requestId && got.requestId !== step.requestId) failStep(step, got.requestId);
        if (step.hamState != null && got.see?.grant?.hamState !== step.hamState) failStep(step, got.see);
        if (step.post === false && got.post != null) failStep(step, got.post);
        if (step.post === true && (got.post == null || got.post.grant?.hamState !== step.postHam)) failStep(step, got.post);
        if (step.unchanged === true) {
          if (got.unchanged !== true || !sameBytes(got.see?.bytes, lastSee) || !sameBytes(got.post?.bytes ?? null, lastPost)) {
            failStep(step, got.unchanged);
          }
        } else if (got.unchanged === true) failStep(step, 'unchanged');
        if (step.seeBytesSame === true && !sameBytes(got.see?.bytes, lastSee)) failStep(step, got.see);
        if (step.bytesDiffer === true && sameBytes(got.see?.bytes, lastSee)) failStep(step, got.see);
        lastSee = got.see?.bytes ?? null;
        lastPost = got.post?.bytes ?? null;
      } else if (got.granted || got.reason !== step.reason) failStep(step, got.granted ? 'granted' : got.reason);
      continue;
    }
    if (step.op === 'factor') {
      if (factorGrants(step.kind) !== step.grants) failStep(step, factorGrants(step.kind));
      continue;
    }
    if (step.op === 'view') {
      const got = admittedView(graph, step.object, step.accessor);
      if (step.absent === true) {
        if (got) failStep(step, got);
      } else if (!got || got.hamState !== step.hamState || got.stated !== step.stated) failStep(step, got);
      else {
        if (step.from != null && got.from !== step.from) failStep(step, got);
        if (step.until != null && got.until !== step.until) failStep(step, got);
        if (step.issuedAt != null && got.issuedAt !== step.issuedAt) failStep(step, got);
      }
      continue;
    }
    if (step.op === 'view-post') {
      const got = admittedPost(graph, step.object, step.accessor);
      if (step.absent === true) {
        if (got) failStep(step, got);
      } else if (!got || got.hamState !== step.hamState || (step.stated != null && got.stated !== step.stated)) failStep(step, got);
      continue;
    }
    if (step.op === 'check') {
      const got = checkSee(graph, step.object, step.accessor, step.now, null, null);
      if (got.allowed !== step.allowed || got.reason !== step.reason) failStep(step, got);
      continue;
    }
    if (step.op === 'check-post') {
      const got = checkPost(graph, step.object, step.accessor, step.now, null, null);
      if (got.allowed !== step.allowed || got.reason !== step.reason) failStep(step, got);
      continue;
    }
    failStep(step, 'unknown');
  }
}
