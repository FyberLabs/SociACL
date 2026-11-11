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

/**
 * Client-side candidate filtering only. Results are ids, never cached grants.
 * Re-run against current admitted state before display and before opening.
 * @param {object} graph
 * @param {import('../ids/src/types.js').ObjectId[]} candidates
 * @param {import('../ids/src/types.js').PrincipalId} accessor
 * @param {number} now
 * @returns {import('../ids/src/types.js').ObjectId[]}
 */
export function filterForumSearchCandidates(graph, candidates, accessor, now) {
  if (!Array.isArray(candidates) || candidates.length > 1000) return [];
  return [...new Set(candidates)].filter(object => {
    try { return checkForumSee(graph, object, accessor, now).allowed === true; }
    catch { return false; }
  });
}
