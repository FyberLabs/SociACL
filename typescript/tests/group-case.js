import assert from 'node:assert/strict';
/**
 * Shared group-vector runner. Admission verifies v2 rows.
 * The runner does not enroll a signer.
 */
import { admitGroupCancel, admitMembership, admitObjectSet, checkGroupPresentation, checkGroupSee, MemoryGroupGraph, reverifyGroup, groupSnapshot, snapshotUnderstatesGroup } from '../src/group.js';
import { checkForumChildWrite } from '../src/post.js';
import { checkForumSee } from '../src/forum.js';
import { admitRow, putObject } from '../src/see.js';

/** @param {Record<string, any>} step @param {unknown} got */
function failStep(step, got) {
  throw new Error(`${step.op} ${JSON.stringify(got)}`);
}

/**
 * @param {readonly Record<string, any>[]} steps
 * @param {{ ctx: import('../ids/src/types.js').ResolutionContext, rotations: (name: string) => readonly unknown[] }} options
 */
export function runGroupCase(steps, options) {
  const graphs = { local: new MemoryGroupGraph(), side: new MemoryGroupGraph() };
  /** @type {Record<string, any> | null} */
  let lastRow = null;
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
    const graph = step.on === 'side' ? graphs.side : graphs.local;
    if (step.op === 'merge') {
      const into = step.into === 'side' ? graphs.side : graphs.local;
      const from = into === graphs.side ? graphs.local : graphs.side;
      const named = step.rotations ? step : { ...step, rotations: 'genesis' };
      into.mergeFrom(from, resolverFor(named));
      continue;
    }
    if (step.op === 'mutate-row') {
      if (!lastRow || typeof step.field !== 'string') failStep(step, 'no-row');
      if (step.value === null) delete lastRow[step.field];
      else lastRow[step.field] = step.value;
      continue;
    }
    if (step.op === 'put') {
      const got = putObject(graph, step.record, resolverFor(step));
      if (step.ok === false) {
        if (got.ok || got.reason !== step.reason) failStep(step, got.ok ? 'ok' : got.reason);
      } else if (!got.ok) failStep(step, got.reason);
      continue;
    }
    if (step.op === 'admit') {
      const got = admitRow(graph, step.row, resolverFor(step));
      if (!got.ok) failStep(step, got);
      continue;
    }
    if (step.op === 'admit-member' || step.op === 'admit-object-set' || step.op === 'admit-cancel') {
      lastRow = step.row;
      const got = step.op === 'admit-member'
        ? admitMembership(graph, step.row, resolverFor(step))
        : step.op === 'admit-object-set'
          ? admitObjectSet(graph, step.row, resolverFor(step))
          : admitGroupCancel(graph, step.row, resolverFor(step));
      if (step.ok === false) {
        if (got.ok || got.reason !== step.reason) failStep(step, got.ok ? 'ok' : got.reason);
      } else if (!got.ok || (step.kept != null && got.kept !== step.kept)) failStep(step, got.ok ? got.kept : got.reason);
      continue;
    }
    if (step.op === 'reverify-group') {
      const got = reverifyGroup(graph, step.principal, resolverFor(step));
      if (step.ok === false) {
        if (got.ok || got.reason !== step.reason) failStep(step, got.ok ? 'ok' : got.reason);
      } else if (!got.ok || (step.dropped != null && got.value.dropped !== step.dropped)) {
        failStep(step, got.ok ? got.value : got.reason);
      }
      continue;
    }
    if (step.op === 'check-drawer-write') {
      const got = checkForumChildWrite(graph, step.forum, step.agent, step.object, step.accessor, step.now);
      if (got.allowed !== step.allowed || got.reason !== step.reason) failStep(step, got);
      continue;
    }
    if (step.op === 'check-forum') {
      const got = checkForumSee(graph, step.object, step.accessor, step.now);
      if (got.allowed !== step.allowed || got.reason !== step.reason) failStep(step, got);
      continue;
    }
    if (step.op === 'check-group') {
      const got = checkGroupSee(
        graph,
        step.predicate,
        step.object,
        step.accessor,
        step.now,
        null,
        step.hop ? { channel: 'convention-badge' } : null,
      );
      if (got.allowed !== step.allowed || got.reason !== step.reason) failStep(step, got);
      if (step.hop && !got.hop) failStep(step, got);
      if (got.reason !== 'owner') {
        const current = groupSnapshot(graph, step.object);
        const member = current?.members.find(row => row.accessor === step.accessor);
        assert.equal(Boolean(current?.objectSet.stated === 1 && current.objectSet.predicate === step.predicate && member?.stated === 1), got.allowed);
      }
      continue;
    }
    if (step.op === 'check-presentation') {
      const got = checkGroupPresentation(
        graph,
        step.set ?? null,
        step.object,
        step.accessor,
        step.payload ?? null,
        step.now,
        null,
        null,
      );
      if (got.allowed !== step.allowed || got.reason !== step.reason) failStep(step, got);
      continue;
    }
    if (step.op === 'snapshot') {
      const got = snapshotUnderstatesGroup(graph, step.object, step.members, step.objectSet ?? null);
      if (got !== step.understates) failStep(step, got);
      const current = groupSnapshot(graph, step.object);
      if (current) {
        assert.equal(snapshotUnderstatesGroup(graph, step.object, current.members, current.objectSet), false);
        assert.deepEqual(current.members.map(row => row.accessor), current.members.map(row => row.accessor).sort());
        const before = structuredClone(current);
        current.members.length = 0;
        current.objectSet.hamState = -1;
        assert.deepEqual(groupSnapshot(graph, step.object), before);
      }
      continue;
    }
    failStep(step, 'unknown');
  }
}
