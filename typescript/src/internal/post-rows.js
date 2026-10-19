/**
 * Admitted post rows. post.js reads this map. The seal set stays in post.js.
 * Test-only edits live in row-test.js, which the package does not ship.
 */

/** @type {WeakMap<object, Map<string, any>>} */
export const postTables = new WeakMap();

/** @param {object} graph */
export function postMap(graph) {
  let held = postTables.get(graph);
  if (!held) {
    held = new Map();
    postTables.set(graph, held);
  }
  return held;
}
