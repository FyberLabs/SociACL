/**
 * Access requests are hints. Approving one writes owner-signed v2 see
 * and post rows, and only after both rows have been checked.
 * A hop, a hint, a wrap, a request, or an inbox delivery never grants.
 * @typedef {import('../ids/src/types.js').ObjectId} ObjectId
 * @typedef {import('../ids/src/types.js').PrincipalId} PrincipalId
 * @typedef {import('../ids/src/types.js').SeeGrant} SeeGrant
 * @typedef {import('./see.js').SeeResolver} SeeResolver
 * @typedef {{ scalar: Uint8Array, resolver: SeeResolver }} RequestSigner
 * @typedef {{ predicate: 'same-group' | 'named-circle', now: number }} RequestMembers
 * @typedef {{ granted: true, requestId: string, see: unknown, post: unknown }} GrantedRequest
 * @typedef {{ granted: false, reason: string }} DeniedRequest
 */

import {
  accessRequestBytes,
  parseAccessRequest,
  parsePrincipalId,
  postGrantBytes,
  REQUEST_DOMAIN,
  REQUEST_ID_DOMAIN,
  requestId,
  resolveCurrentKey,
  seeGrantBytes,
  signWithKeyring,
  verifyAccessRequest,
  verifyPostGrant,
  verifySeeGrant,
  verifySignedAt,
} from '../ids/src/index.js';
import { integer } from '../ids/src/util.js';
import { admittedPost, commitStagedPost, stagePost } from './post.js';
import { admittedOwner, admittedView, commitStagedSee, stageSee } from './see.js';

export {
  REQUEST_DOMAIN,
  REQUEST_ID_DOMAIN,
  accessRequestBytes,
  parseAccessRequest,
  requestId,
  verifyAccessRequest,
};

const HAM_MAX = Number.MAX_SAFE_INTEGER;

/** @param {string} reason @returns {DeniedRequest} */
function deny(reason) {
  return { granted: false, reason };
}

/** @param {unknown} value @returns {value is number} */
function whole(value) {
  return integer(value);
}

/**
 * @param {SeeGrant} fields
 * @param {Uint8Array} scalar
 * @param {PrincipalId} key
 * @param {(grant: SeeGrant) => Uint8Array} bytesOf
 * @returns {{ ok: true, value: SeeGrant } | { ok: false, reason: string }}
 */
function signRow(fields, scalar, key, bytesOf) {
  const sig = signWithKeyring(scalar, bytesOf(fields), key);
  if (!sig.ok) return { ok: false, reason: sig.reason };
  return { ok: true, value: { ...fields, sig: sig.value } };
}

/**
 * Owner's client. The requester signature is present authority only.
 * History is resolved once. Both rows are checked against that history,
 * then both are written, or neither is. `issuedAt` is the resolver's `now`.
 * @param {object} graph
 * @param {unknown} owner
 * @param {unknown} request
 * @param {{ from?: unknown, until?: unknown } | null | undefined} window
 * @param {RequestMembers | null | undefined} members
 * @param {RequestSigner | null | undefined} signer
 * @returns {GrantedRequest | DeniedRequest}
 */
export function grantApprovedRequest(graph, owner, request, window, members, signer) {
  const parsed = parseAccessRequest(request);
  if (!parsed.ok) return deny(parsed.reason);
  const req = parsed.value.request;
  if (req.status === 'withdrawn') return deny('withdrawn');
  if (!window || typeof window !== 'object') return deny('bad-record');
  if (!whole(window.from) || !whole(window.until) || window.until <= window.from) return deny('bad-record');
  const who = parsePrincipalId(owner);
  if (!who.ok) return deny(who.reason);
  if (!signer || !(signer.scalar instanceof Uint8Array) || !signer.resolver) return deny('bad-key');
  const resolver = signer.resolver;
  if (!resolver.ctx || typeof resolver.rotations !== 'function') return deny('missing-history');
  /** @type {Map<string, readonly unknown[] | undefined>} */
  const history = new Map();
  /** @param {string} principal */
  const rotationsOf = (principal) => {
    if (history.has(principal)) return history.get(principal);
    const rows = resolver.rotations(/** @type {PrincipalId} */ (principal));
    history.set(principal, rows);
    return rows;
  };
  const ownerHistory = rotationsOf(who.value);
  const requesterHistory = rotationsOf(req.requester);
  if (!Array.isArray(ownerHistory) || !Array.isArray(requesterHistory)) return deny('missing-history');
  const signed = verifySignedAt(
    req.requester,
    requesterHistory,
    resolver.ctx,
    parsed.value.bytes,
    req.sig,
    req.issuedAt,
  );
  if (!signed.ok) return deny(signed.reason);
  const admission = admittedOwner(graph, req.object);
  if (!admission) return deny('unknown');
  if (admission.owner !== who.value) return deny('owner-mismatch');
  if (members != null) {
    if (members.predicate !== 'same-group' && members.predicate !== 'named-circle') return deny('bad-record');
    if (!integer(members.now)) return deny('bad-record');
    const group = /** @type {{ ownerOf?: (object: string) => string | undefined, checkGroupSee?: Function }} */ (graph);
    const labelOwner = typeof group.ownerOf === 'function' ? group.ownerOf(req.object) : undefined;
    if (typeof labelOwner !== 'string' || labelOwner !== admission.owner) return deny('not-member');
    const check = group.checkGroupSee;
    if (typeof check !== 'function') return deny('not-member');
    const see = check.call(graph, members.predicate, req.object, req.requester, members.now);
    if (!see || see.allowed !== true || see.reason === 'owner' || see.reason !== members.predicate) return deny('not-member');
  }
  const seeNow = admittedView(graph, req.object, req.requester);
  if (seeNow?.stated === 0) return deny('not-kept');
  const seeHam = (seeNow?.hamState ?? 0) + 1;
  if (!Number.isSafeInteger(seeHam) || seeHam > HAM_MAX) return deny('see-ceiling');
  /** @type {number} */
  let postHam = 1;
  if (req.scope === 'read+post') {
    const postNow = admittedPost(graph, req.object, req.requester);
    if (postNow?.stated === 0) return deny('not-kept');
    postHam = (postNow?.hamState ?? 0) + 1;
    if (!Number.isSafeInteger(postHam) || postHam > HAM_MAX) return deny('post-ceiling');
  }
  if (!integer(resolver.ctx.now)) return deny('bad-record');
  const current = resolveCurrentKey(who.value, ownerHistory, resolver.ctx);
  if (!current.ok) return deny(current.reason);
  /** @type {SeeGrant} */
  const seeFields = {
    owner: who.value,
    object: req.object,
    accessor: req.requester,
    stated: 1,
    from: window.from,
    until: window.until,
    hamState: seeHam,
    issuedAt: resolver.ctx.now,
    sig: '',
  };
  const seeSigned = signRow(seeFields, signer.scalar, current.value.currentKey, seeGrantBytes);
  if (!seeSigned.ok) return deny(seeSigned.reason);
  const seeOk = verifySeeGrant(seeSigned.value, ownerHistory, resolver.ctx);
  if (!seeOk.ok) return deny(seeOk.reason);
  /** @type {SeeGrant | null} */
  let postSigned = null;
  if (req.scope === 'read+post') {
    const postFields = { ...seeFields, hamState: postHam, sig: '' };
    const signedPost = signRow(postFields, signer.scalar, current.value.currentKey, postGrantBytes);
    if (!signedPost.ok) return deny(signedPost.reason);
    const postOk = verifyPostGrant(signedPost.value, ownerHistory, resolver.ctx);
    if (!postOk.ok) return deny(postOk.reason);
    postSigned = signedPost.value;
  }
  const seeStaged = stageSee(graph, seeSigned.value, ownerHistory, resolver.ctx);
  if (!seeStaged.ok) return deny(seeStaged.reason);
  const postStaged = postSigned ? stagePost(graph, postSigned, ownerHistory, resolver.ctx) : null;
  if (postStaged && !postStaged.ok) return deny(postStaged.reason);
  if (!seeStaged.kept || (postStaged && !postStaged.kept)) return deny('not-kept');
  const seeWrote = commitStagedSee(graph, seeStaged.value);
  if (!seeWrote.ok) return deny(seeWrote.reason);
  if (postStaged && postStaged.ok) {
    const postWrote = commitStagedPost(graph, postStaged.value);
    if (!postWrote.ok) return deny(postWrote.reason);
    return { granted: true, requestId: req.requestId, see: seeWrote.value, post: postWrote.value };
  }
  return { granted: true, requestId: req.requestId, see: seeWrote.value, post: null };
}
