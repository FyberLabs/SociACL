/**
 * Test-only map edits. Tests are outside the published package.
 * Check still requires the signed object and accessor, and a row that
 * was not sealed never allows.
 */
import { postMap, postTables } from '../src/internal/post-rows.js';
import { seeStore } from '../src/internal/see-rows.js';

/** @param {object} graph @param {string} fromKey @param {string} toKey */
export function moveSeeRowForTest(graph, fromKey, toKey) {
  const held = seeStore(graph);
  const row = held.rows.get(fromKey);
  if (!row) return false;
  held.rows.delete(fromKey);
  held.rows.set(toKey, row);
  return true;
}

/** @param {object} graph @param {string} fromKey @param {string} toKey */
export function movePostRowForTest(graph, fromKey, toKey) {
  const held = postTables.get(graph);
  if (!held) return false;
  const row = held.get(fromKey);
  if (!row) return false;
  held.delete(fromKey);
  held.set(toKey, row);
  return true;
}

/** @param {object} graph @param {string} key @param {object} grant */
export function plantPlainSeeForTest(graph, key, grant) {
  seeStore(graph).rows.set(key, {
    grant,
    mode: 'present',
    bytes: new Uint8Array(),
    witness: false,
  });
}

/** @param {object} graph @param {string} key @param {object} grant */
export function plantPlainPostForTest(graph, key, grant) {
  postMap(graph).set(key, {
    grant,
    mode: 'present',
    bytes: new Uint8Array(),
    witness: false,
  });
}
