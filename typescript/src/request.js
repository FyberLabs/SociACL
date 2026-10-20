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
 * @typedef {{ granted: true, requestId: string, see: unknown, post: unknown, unchanged?: true }} GrantedRequest
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
import { presentedPost } from './post.js';
import { admitGrantPair, admittedOwner, presentedSee, snapshotContext } from './see.js';

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

/** Stored live row with the same owner, object, accessor, and window.
 * @param {unknown} row
 * @param {string} owner
 * @param {string} object
 * @param {string} accessor
 * @param {{ from?: unknown, until?: unknown }} window
 */
function sameLive(row, owner, object, accessor, window) {
  if (!row || typeof row !== 'object' || !('grant' in row)) return false;
  const grant = /** @type {{ grant?: { owner?: string, object?: string, accessor?: string, stated?: number, from?: number, until?: number } }} */ (row).grant;
  return !!grant
    && grant.owner === owner
    && grant.object === object
    && grant.accessor === accessor
    && grant.stated === 1
    && grant.from === window.from
    && grant.until === window.until;
}

/**
 * Admit the see row and the post row. Both are checked, then both are
 * written, in this one call. A null row is left as stored. History comes
 * from the resolver. Nothing is exported for a caller to replay.
 * @param {object} graph
 * @param {import('../ids/src/types.js').SeeGrant | null} seeRow
 * @param {import('../ids/src/types.js').SeeGrant | null} postRow
 * @param {SeeResolver} resolver
 * @returns {{ ok: true, see: unknown, post: unknown } | { ok: false, reason: string }}
 */
function admitGrantRows(graph, seeRow, postRow, resolver) {
  return admitGrantPair(graph, seeRow, postRow, resolver);
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
  const from = window.from;
  const until = window.until;
  if (!whole(from) || !whole(until) || until <= from) return deny('bad-record');
  const span = { from, until };
  const who = parsePrincipalId(owner);
  if (!who.ok) return deny(who.reason);
  if (!signer || !(signer.scalar instanceof Uint8Array) || !signer.resolver) return deny('bad-key');
  const resolver = signer.resolver;
  if (!resolver.ctx || typeof resolver.ctx !== 'object' || typeof resolver.rotations !== 'function') return deny('missing-history');
  const ctx = snapshotContext(resolver.ctx);
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
    ctx,
    parsed.value.bytes,
    req.sig,
    req.issuedAt,
  );
  if (!signed.ok) return deny(signed.reason);
  const admission = admittedOwner(graph, req.object);
  if (!admission) return deny('unknown');
  if (admission.owner !== who.value) return deny('owner-mismatch');
  const seeStored = presentedSee(graph, req.object, req.requester);
  const postStored = req.scope === 'read+post' ? presentedPost(graph, req.object, req.requester) : null;
  const seeMatch = sameLive(seeStored, who.value, req.object, req.requester, span);
  const postMatch = req.scope !== 'read+post' || sameLive(postStored, who.value, req.object, req.requester, span);
  if (members != null) {
    if (members.predicate !== 'same-group' && members.predicate !== 'named-circle') return deny('bad-record');
    if (!integer(members.now)) return deny('bad-record');
    const group = /** @type {{ ownerOf?: (object: string) => string | undefined, checkGroupSee?: Function }} */ (graph);
    const signedOwner = typeof group.ownerOf === 'function' ? group.ownerOf(req.object) : undefined;
    const parsedOwner = typeof signedOwner === 'string' ? parsePrincipalId(signedOwner) : null;
    if (!parsedOwner || !parsedOwner.ok || parsedOwner.value !== admission.owner) return deny('not-member');
    const check = group.checkGroupSee;
    if (typeof check !== 'function') return deny('not-member');
    const see = check.call(graph, members.predicate, req.object, req.requester, members.now);
    if (!see || see.allowed !== true || see.reason === 'owner' || see.reason !== members.predicate) return deny('not-member');
    if (seeStored?.grant?.stated === 0) return deny('not-kept');
    if (req.scope === 'read+post' && postStored?.grant?.stated === 0) return deny('not-kept');
  }
  if (!integer(ctx.now)) return deny('bad-record');
  const current = resolveCurrentKey(who.value, ownerHistory, ctx);
  if (!current.ok) return deny(current.reason);
  const seeSame = seeMatch && seeStored?.key === current.value.currentKey;
  const postSame = req.scope !== 'read+post' || (postMatch && postStored?.key === current.value.currentKey);
  const ownsKey = () => signWithKeyring(signer.scalar, new Uint8Array([0]), current.value.currentKey);
  if (seeSame && postSame) {
    const owns = ownsKey();
    if (!owns.ok) return deny(owns.reason);
    return {
      granted: true,
      unchanged: true,
      requestId: req.requestId,
      see: seeStored,
      post: req.scope === 'read+post' ? postStored : null,
    };
  }
  const latest = current.value.rotations.reduce((max, row) => (row.issuedAt > max ? row.issuedAt : max), -1);
  if (latest === ctx.now) return deny('rotation-boundary');
  const owns = ownsKey();
  if (!owns.ok) return deny(owns.reason);
  const seeHam = (seeStored?.grant?.hamState ?? 0) + 1;
  if (!seeSame && (!Number.isSafeInteger(seeHam) || seeHam > HAM_MAX)) return deny('see-ceiling');
  const postHam = (postStored?.grant?.hamState ?? 0) + 1;
  if (req.scope === 'read+post' && !postSame && (!Number.isSafeInteger(postHam) || postHam > HAM_MAX)) return deny('post-ceiling');
  /** @type {SeeGrant | null} */
  let seeSigned = null;
  if (!seeSame) {
    /** @type {SeeGrant} */
    const seeFields = {
      owner: who.value,
      object: req.object,
      accessor: req.requester,
      stated: 1,
      from: span.from,
      until: span.until,
      hamState: seeHam,
      issuedAt: ctx.now,
      sig: '',
    };
    const signedSee = signRow(seeFields, signer.scalar, current.value.currentKey, seeGrantBytes);
    if (!signedSee.ok) return deny(signedSee.reason);
    const seeOk = verifySeeGrant(signedSee.value, ownerHistory, ctx);
    if (!seeOk.ok) return deny(seeOk.reason);
    seeSigned = signedSee.value;
  }
  /** @type {SeeGrant | null} */
  let postSigned = null;
  if (req.scope === 'read+post' && !postSame) {
    /** @type {SeeGrant} */
    const postFields = {
      owner: who.value,
      object: req.object,
      accessor: req.requester,
      stated: 1,
      from: span.from,
      until: span.until,
      hamState: postHam,
      issuedAt: ctx.now,
      sig: '',
    };
    const signedPost = signRow(postFields, signer.scalar, current.value.currentKey, postGrantBytes);
    if (!signedPost.ok) return deny(signedPost.reason);
    const postOk = verifyPostGrant(signedPost.value, ownerHistory, ctx);
    if (!postOk.ok) return deny(postOk.reason);
    postSigned = signedPost.value;
  }
  const wrote = admitGrantRows(graph, seeSigned, postSigned, { rotations: rotationsOf, ctx });
  if (!wrote.ok) return deny(wrote.reason);
  return {
    granted: true,
    requestId: req.requestId,
    see: seeSame ? seeStored : wrote.see,
    post: req.scope === 'read+post' ? (postSame ? postStored : wrote.post) : null,
  };
}
