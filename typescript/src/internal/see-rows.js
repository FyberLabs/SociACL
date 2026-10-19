/**
 * Admitted see rows. see.js reads this map. The package ships this file.
 * Test-only edits live in row-test.js, which the package does not ship.
 */

/** @type {WeakSet<object>} */
export const verified = new WeakSet();

/** @type {WeakMap<object, { owners: Map<string, any>, rows: Map<string, any> }>} */
const stores = new WeakMap();

/** @param {object} graph */
export function seeStore(graph) {
  let held = stores.get(graph);
  if (!held) {
    held = { owners: new Map(), rows: new Map() };
    stores.set(graph, held);
  }
  return held;
}
