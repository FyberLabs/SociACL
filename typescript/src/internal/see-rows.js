/**
 * Admitted see rows. see.js reads this map. The seal set stays in see.js.
 * Test-only edits live in tests/row-test.js, which the package does not ship.
 */

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
