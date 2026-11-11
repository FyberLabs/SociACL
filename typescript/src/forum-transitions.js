/** Need/offer transitions are separate from Check and never elect an owner.
 * Callers authenticate the writer and serialize/persist the current need.
 * @typedef {import('../../docs/s3rch-check.js').ForumNeed} ForumNeed
 * @typedef {import('../../docs/s3rch-check.js').ForumOffer} ForumOffer
 */
import { objectPrincipal, parseObjectId, parsePrincipalId } from '../ids/src/index.js';
import { admittedOwner } from './see.js';
import { checkForumSee } from './forum.js';

/** Parse copied-contract brands at the native boundary.
 * @param {object} graph @param {string} id @param {string} actor @param {number} now */
function seeNow(graph, id, actor, now) {
  const object = parseObjectId(id), principal = parsePrincipalId(actor);
  return object.ok && principal.ok ? checkForumSee(graph, object.value, principal.value, now)
    : { allowed: false, reason: 'unknown' };
}
/** @param {object} graph @param {string} id */
function ownerOf(graph, id) {
  const parsed = parseObjectId(id);
  return parsed.ok ? admittedOwner(graph, parsed.value) : undefined;
}

/** @type {WeakMap<object, Map<string, ForumOffer>>} */
const offers = new WeakMap();
/** @param {number} n */
const integer = n => Number.isSafeInteger(n) && n >= 0;
/** @param {string} id @param {string} [kind] */
const minted = (id, kind) => parseObjectId(id).ok && objectPrincipal(id).ok &&
  (kind === undefined || id.startsWith(`${kind}_`));
/** @param {ForumNeed} n */
function validNeed(n) {
  return !!n && minted(n.id, 'need') && minted(n.forumId, 'forum') &&
    parsePrincipalId(n.subject).ok && ['need', 'emergency'].includes(n.severity) &&
    typeof n.body === 'string' && integer(n.hamState) && integer(n.ts) &&
    (n.spec === undefined || minted(n.spec)) &&
    ((n.stated === 1 && n.acceptedOffer === undefined) ||
      (n.stated === 0 && typeof n.acceptedOffer === 'string' && minted(n.acceptedOffer, 'offer')));
}
/** @param {ForumOffer} o */
function validOffer(o) {
  if (!o || !minted(o.id, 'offer') || !minted(o.need, 'need') || !minted(o.forumId, 'forum') ||
      !parsePrincipalId(o.helper).ok || typeof o.body !== 'string' || typeof o.artifacts !== 'string' ||
      (o.stated !== 0 && o.stated !== 1)) return false;
  const creator = objectPrincipal(o.id);
  const ids = o.artifacts === '' ? [] : o.artifacts.split(',');
  return creator.ok && String(creator.value) === o.helper && new Set(ids).size === ids.length &&
    ids.every(id => minted(id));
}
/** @param {ForumOffer | undefined} a @param {ForumOffer} b */
const sameOffer = (a, b) => !!a && a.id === b.id && a.need === b.need && a.forumId === b.forumId &&
  a.helper === b.helper && a.body === b.body && a.artifacts === b.artifacts && a.stated === b.stated;
/** @param {string} reason @returns {{ok:false, reason:string}} */
const denied = reason => ({ ok: false, reason });

/** Post once or withdraw a previously admitted offer; tombstones cannot repost.
 * The writer must be authenticated by the caller, never taken from untrusted row data.
 * @param {object} graph @param {ForumNeed} need @param {ForumOffer | undefined} current
 * @param {ForumOffer} next @param {import('../../docs/s3rch-check.js').PrincipalId} writer @param {number} now
 * @returns {import('../../docs/s3rch-check.js').ForumOfferTransitionResult}
 */
export function acceptForumOfferTransition(graph, need, current, next, writer, now) {
  if (!integer(now) || !parsePrincipalId(writer).ok || !validNeed(need) || !validOffer(next) ||
      next.need !== need.id || next.forumId !== need.forumId) return denied('bad-offer');
  const held = offers.get(graph);
  if (current === undefined) {
    if (next.stated !== 1 || need.stated !== 1 || writer !== next.helper || held?.has(next.id)) return denied('offer');
    const see = seeNow(graph, need.id, writer, now);
    if (!see.allowed) return denied(see.reason);
  } else {
    if (!validOffer(current) || current.stated !== 1 || next.stated !== 0 ||
        !sameOffer(current, { ...next, stated: 1 }) || !sameOffer(held?.get(current.id), current)) return denied('offer');
    if (need.stated === 0 && need.acceptedOffer === current.id) return denied('accepted-offer');
    if (writer !== current.helper) {
      const owner = ownerOf(graph, need.id);
      if (!owner || (writer !== String(owner.owner) && writer !== need.subject)) return denied('owner');
    }
  }
  const rows = held ?? new Map();
  rows.set(next.id, Object.freeze({ ...next }));
  offers.set(graph, rows);
  return { ok: true, offer: { ...next } };
}

/** Resolve from a stored live offer, reopen as owner, or update HAM under Check.
 * This returns a candidate; the caller atomically compares and persists current.
 * @param {object} graph @param {ForumNeed} current @param {ForumNeed} next
 * @param {ForumOffer | undefined} offer @param {import('../../docs/s3rch-check.js').PrincipalId} writer @param {number} now
 * @returns {import('../../docs/s3rch-check.js').ForumNeedTransitionResult}
 */
export function acceptForumNeedTransition(graph, current, next, offer, writer, now) {
  if (!integer(now) || !parsePrincipalId(writer).ok || !validNeed(current) || !validNeed(next)) return denied('bad-need');
  if (next.id !== current.id || next.forumId !== current.forumId || next.subject !== current.subject ||
      next.body !== current.body || next.severity !== current.severity || next.spec !== current.spec ||
      next.hamState <= current.hamState) return denied('need');
  const owner = ownerOf(graph, current.id);
  if (!owner) return denied('unknown');
  if (current.stated === 1 && next.stated === 0) {
    if (!offer || !validOffer(offer) || offer.stated !== 1 || offer.need !== current.id ||
        offer.forumId !== current.forumId || next.acceptedOffer !== offer.id ||
        !sameOffer(offers.get(graph)?.get(offer.id), offer)) return denied('offer');
    if (!seeNow(graph, current.id, offer.helper, now).allowed) return denied('helper');
    if (writer !== String(owner.owner) && writer !== current.subject) return denied('owner');
  } else if (current.stated === 0 && next.stated === 1) {
    if (offer !== undefined || writer !== String(owner.owner)) return denied('owner');
  } else {
    if (offer !== undefined || current.acceptedOffer !== next.acceptedOffer) return denied('offer');
    const see = seeNow(graph, current.id, writer, now);
    if (!see.allowed) return denied(see.reason);
  }
  return { ok: true, need: { ...next } };
}
