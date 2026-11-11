import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { historyState, parsePrincipalId } from '../ids/src/index.js';
import { acceptHint, checkForumSee, filterForumSearchCandidates, fromGunNode, toGunNode } from '../src/gun.js';
import { admittedOwner, admitRow, checkSee, putObject } from '../src/see.js';

const doc = JSON.parse(readFileSync(new URL('../../vectors/mesh/forums.json', import.meta.url)));
const see = JSON.parse(readFileSync(new URL('../../vectors/mesh/v2/see.json', import.meta.url)));

// Use the same signed admission/grant/cancel fixture as Rust's forum Hold.
function open() {
  const entry = see.accept.find(row => row.name === doc.seeCase);
  const [placed, live, cancel] = entry.steps;
  const raw = see.context;
  const resolver = {
    rotations: () => raw.rotationSets.genesis,
    ctx: {
      ...raw, links: new Map(raw.links ?? []), pinnedIss: new Set(raw.pinnedIss ?? []),
      history: (principal, at, until) => raw.authenticatedAccounts.includes(principal)
        ? { ok: true, value: historyState(principal, [], at, until) }
        : { ok: false, reason: 'missing-history' },
    },
  };
  const graph = {};
  assert.equal(putObject(graph, placed.record, resolver).ok, true);
  return { graph, resolver, live: live.row, cancel: cancel.row,
    owner: placed.record.owner, object: placed.record.object, accessor: live.row.accessor };
}

function baseline(name, fn) {
  assert.ok(doc.cases.includes(name), `missing shared case: ${name}`);
  test(`forums: ${name}`, fn);
}

baseline('check-deny-without-dest-acl', () => {
  const { graph, owner, object, accessor } = open();
  const hint = acceptHint({ principal: owner, target: object, verb: 'see', context: 'forum-status' });
  assert.equal(checkSee(graph, object, accessor, 10, hint).allowed, false);
  assert.equal(checkSee(graph, object, owner, 10, hint).reason, 'owner');
});

baseline('cancel-visible-on-next-check', () => {
  const { graph, resolver, live, cancel, object, accessor } = open();
  assert.equal(admitRow(graph, live, resolver).ok, true);
  assert.equal(checkSee(graph, object, accessor, 10).allowed, true);
  assert.equal(admitRow(graph, cancel, resolver).ok, true);
  assert.deepEqual(checkSee(graph, object, accessor, 10), { allowed: false, reason: 'delegate' });
});

baseline('sgh1-hint-alone-fails-closed', () => {
  const { graph, object, accessor } = open();
  // The shared bytes are round-tripped by Rust's actual SGH1 codec. TS Check
  // accepts neither an encoded frame nor decoded claims as authority.
  const bytes = Buffer.from(doc.hint.hex, 'hex');
  const decoded = acceptHint(doc.hint.fields);
  for (const hint of [bytes, decoded]) {
    assert.equal(checkSee(graph, object, accessor, 10, hint,
      { channel: 'convention-badge' }).allowed, false);
  }
});

baseline('resolve-need-does-not-elect', () => {
  const { graph, resolver, object, owner, accessor, live, cancel } = open();
  const before = admittedOwner(graph, object);
  assert.equal(admitRow(graph, live, resolver).ok, true);
  assert.equal(admitRow(graph, cancel, resolver).ok, true);
  for (const state of [doc.resolve.open, doc.resolve.resolved]) {
    const need = { id: doc.resolve.needId, forumId: doc.resolve.forumId,
      subject: doc.resolve.subject, severity: doc.resolve.severity, ...state };
    // A status/resolve put is data, never a signed object-owner admission.
    assert.equal(putObject(graph, need, resolver).ok, false);
    assert.equal(admittedOwner(graph, need.id), undefined);
    assert.equal(checkSee(graph, need.id, doc.seaPubkey, 10).allowed, false);
    assert.deepEqual(admittedOwner(graph, object), before);
    assert.equal(checkSee(graph, object, accessor, 10, need).allowed, false);
    assert.equal(checkSee(graph, object, owner, 10).reason, 'owner');
  }
});

baseline('chat-via-tagged-items', () => {
  const { graph, object, accessor } = open();
  assert.equal(doc.chatCollection, 's3rch/items');
  const tags = [doc.souls.chatTag, ...doc.chat.extra];
  const item = { id: doc.needId, source: 'rss', kind: 'chat', author: doc.seaPubkey,
    body: 'Forum chat', ts: 10, permalink: '', provenance: '', tags };
  const node = toGunNode(item);
  assert.equal(node.tags, doc.chat.joined);
  assert.deepEqual(fromGunNode(node), item);
  assert.equal(checkSee(graph, object, accessor, 10, node).allowed, false);
});

test('forums: SEA pubkey stays one Gun segment', () => {
  assert.equal(parsePrincipalId(doc.seaPubkey).ok, true);
  assert.equal(parsePrincipalId(doc.linkedWallet).ok, false);
  for (const key of ['agent', 'role', 'subtask', 'update', 'artifact']) {
    const segments = doc.souls[key].split('/');
    assert.ok(segments.includes(doc.seaPubkey), key);
    assert.equal(segments.filter(part => part === doc.seaPubkey).length, 1);
  }
});


test('forums: invalid Check instants fail closed even for the owner', () => {
  const { graph, object, owner } = open();
  for (const now of [NaN, Infinity, -1, 0.5, Number.MAX_SAFE_INTEGER + 1]) {
    assert.deepEqual(checkForumSee(graph, object, owner, now), { allowed: false, reason: 'unknown' });
  }
});

// Shared Business views never alter the authority inputs to destination Check.
const business = JSON.parse(readFileSync(new URL('../../vectors/mesh/business.json', import.meta.url)));
for (const mode of business.modes) {
  test(`business: ${mode.mode} destination grants, downgrade and replay`, async () => {
    const { admitPost, checkPost } = await import('../src/post.js');
    const { graph, resolver, object, owner } = open();
    assert.equal(business.target, object);
    assert.notEqual(business.forum, object);
    for (const record of business.sourceRecords) {
      assert.equal(putObject(graph, record, resolver).ok, true);
      assert.equal(checkSee(graph, record.object, record.owner, business.now).reason, 'owner');
    }
    for (const stage of mode.stages) {
      for (const name of stage.admit) {
        const admit = name.toLowerCase().includes('post') ? admitPost : admitRow;
        assert.equal(admit(graph, business.grants[name], resolver).ok, true);
      }
      assert.deepEqual(stage.expected.map(row => row.principal), mode.rows.map(row => row.principal));
      for (const expected of stage.expected) {
        const hint = acceptHint({ principal: expected.principal, target: object, verb: 'see', context: 'business-role' });
        assert.equal(checkSee(graph, object, expected.principal, business.now, hint).allowed, expected.read, stage.name);
        assert.equal(checkForumSee(graph, object, expected.principal, business.now).allowed, expected.read, stage.name);
        assert.equal(checkPost(graph, object, expected.principal, business.now, hint).allowed, expected.write, stage.name);
        // Owning the mounted view does not transfer target ownership.
        assert.equal(admittedOwner(graph, business.mount).owner, business.sourceRecords[0].owner);
      }
      assert.equal(admittedOwner(graph, object).owner, owner);
    }
  });
}

const rollups = JSON.parse(readFileSync(new URL('../../vectors/mesh/forum-rollups.json', import.meta.url)));
test('rollups: shared Squad/Fleet/Command destination isolation and resolution', () => {
  const raw = rollups.context;
  const resolver = { rotations: () => raw.rotationSets.genesis, ctx: {
    ...raw, links: new Map(raw.links ?? []), pinnedIss: new Set(raw.pinnedIss ?? []),
    history: (principal, at, until) => raw.authenticatedAccounts.includes(principal)
      ? { ok: true, value: historyState(principal, [], at, until) }
      : { ok: false, reason: 'missing-history' },
  }};
  const graph = {};
  for (const level of rollups.levels) assert.equal(putObject(graph, level.record, resolver).ok, true);
  for (const scenario of rollups.cases) {
    for (const instruction of scenario.admit) {
      const [name, kind] = instruction.split(':');
      assert.equal(admitRow(graph, rollups.levels.find(l => l.level === name)[kind], resolver).ok, true);
    }
    for (const [i, level] of rollups.levels.entries()) {
      const hint = acceptHint({principal: rollups.accessor, target: level.object, verb: 'see', context: 'emergency'});
      const projection = { id: level.object, kind: 'forum-report', destinationForum: level.forum,
        sourceForum: rollups.levels[0].forum, sourceObject: rollups.levels[0].object,
        reportType: 'emergency', stated: scenario.resolve ? 0 : 1 };
      const owner = admittedOwner(graph, level.object);
      assert.equal(putObject(graph, projection, resolver).ok, false, scenario.name);
      assert.deepEqual(admittedOwner(graph, level.object), owner, scenario.name);
      assert.equal(checkSee(graph, level.object, rollups.accessor, rollups.now, hint).allowed, scenario.expected[i], scenario.name);
      assert.equal(checkForumSee(graph, level.object, rollups.accessor, rollups.now).allowed, scenario.expected[i], scenario.name);
    }
  }
});


test('search: current destination grants, cancellation and invalid inputs', () => {
  const { graph, resolver, live, cancel, object, accessor } = open();
  const candidates = [object, object, 'not-an-object'];
  assert.deepEqual(filterForumSearchCandidates(graph, candidates, accessor, 10), []);
  assert.equal(admitRow(graph, live, resolver).ok, true);
  assert.deepEqual(filterForumSearchCandidates(graph, candidates, accessor, 10), [object]);
  for (const now of [NaN, Infinity, -1, 0.5]) {
    assert.deepEqual(filterForumSearchCandidates(graph, candidates, accessor, now), []);
  }
  assert.deepEqual(filterForumSearchCandidates(graph, Array(1001).fill(object), accessor, 10), []);
  assert.deepEqual(filterForumSearchCandidates(graph, null, accessor, 10), []);
  assert.equal(admitRow(graph, cancel, resolver).ok, true);
  assert.deepEqual(filterForumSearchCandidates(graph, candidates, accessor, 10), []);
});
