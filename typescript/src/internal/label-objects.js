/**
 * Label object records for the in-memory group graph.
 * The map stays in this module. The package exports do not name it.
 * @typedef {{ id: string, owner: string }} LabelObject
 */

/** @type {WeakMap<object, Map<string, LabelObject>>} */
const tables = new WeakMap();

/** @param {object} graph @returns {Map<string, LabelObject>} */
export function labelObjects(graph) {
  let table = tables.get(graph);
  if (!table) {
    table = new Map();
    tables.set(graph, table);
  }
  return table;
}
