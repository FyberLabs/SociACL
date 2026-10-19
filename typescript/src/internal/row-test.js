/**
 * Test-only map edits. Not a package export. Check still requires the
 * signed object and accessor, and a row that was not sealed never allows.
 */

/**
 * @typedef {{
 *   moveSee?: (graph: object, fromKey: string, toKey: string) => boolean,
 *   movePost?: (graph: object, fromKey: string, toKey: string) => boolean,
 *   plantPlainSee?: (graph: object, key: string, grant: object) => void,
 *   plantPlainPost?: (graph: object, key: string, grant: object) => void,
 * }} RowTestHooks
 */

/** @type {RowTestHooks} */
let hooks = {};

/** @param {RowTestHooks} next */
export function bindRowTest(next) {
  hooks = { ...hooks, ...next };
}

/** @param {object} graph @param {string} fromKey @param {string} toKey */
export function moveSeeRowForTest(graph, fromKey, toKey) {
  return hooks.moveSee ? hooks.moveSee(graph, fromKey, toKey) : false;
}

/** @param {object} graph @param {string} fromKey @param {string} toKey */
export function movePostRowForTest(graph, fromKey, toKey) {
  return hooks.movePost ? hooks.movePost(graph, fromKey, toKey) : false;
}

/** @param {object} graph @param {string} key @param {object} grant */
export function plantPlainSeeForTest(graph, key, grant) {
  if (hooks.plantPlainSee) hooks.plantPlainSee(graph, key, grant);
}

/** @param {object} graph @param {string} key @param {object} grant */
export function plantPlainPostForTest(graph, key, grant) {
  if (hooks.plantPlainPost) hooks.plantPlainPost(graph, key, grant);
}
