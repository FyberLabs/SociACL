/** Forum read admission from verified destination ACLs; no role/hint authority. */
import { checkSee } from './see.js';
import { checkGroupSee } from './group.js';

/**
 * @param {object} graph
 * @param {import('../ids/src/types.js').ObjectId} object
 * @param {import('../ids/src/types.js').PrincipalId} accessor
 * @param {number} now
 * @returns {{allowed: boolean, reason: string}}
 */
export function checkForumSee(graph, object, accessor, now) {
  if (!Number.isSafeInteger(now) || now < 0) return { allowed: false, reason: 'unknown' };
  const direct = checkSee(graph, object, accessor, now);
  if (direct.allowed) return direct;
  for (const predicate of /** @type {const} */ (['same-group', 'named-circle'])) {
    const group = checkGroupSee(graph, predicate, object, accessor, now, null, null);
    if (group.allowed) return { allowed: true, reason: group.reason };
  }
  return direct;
}
