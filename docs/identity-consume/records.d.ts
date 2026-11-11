/** @param {UnsignedRecord} r @returns {Result<Uint8Array>} */
export function signingBytes(r: UnsignedRecord): Result<Uint8Array>;
/** @param {UnsignedRecord} r @returns {Result<string>} */
export function linkId(r: UnsignedRecord): Result<string>;
/** @param {unknown} x @param {Jwks} jwks @param {SiwePolicy} policy @param {number} now @param {KeyState} keyState @returns {Result<WalletLink>} */
export function verifyWalletLink(x: unknown, jwks: Jwks, policy: SiwePolicy, now: number, keyState: KeyState): Result<WalletLink>;
/** @param {unknown} x @param {Jwks} jwks @param {ReadonlySet<string>} pinnedIss @param {number} now @param {KeyState} keyState @param {number} [clockSkewSeconds] @returns {Result<OidcLink>} */
export function verifyOidcLink(x: unknown, jwks: Jwks, pinnedIss: ReadonlySet<string>, now: number, keyState: KeyState, clockSkewSeconds?: number): Result<OidcLink>;
/** Present-time authority only: currentKey must be the final authenticated current key.
 * This does not certify an issuance time or produce historical revocation evidence.
 * @param {unknown} x @param {PrincipalId} currentKey @param {number} now @returns {Result<Revoke>} */
export function verifyRevokeNow(x: unknown, currentKey: PrincipalId, now: number): Result<Revoke>;
/** Witness required, including when the signer is the current key.
 * @param {unknown} x @param {PrincipalId} currentKey @param {Jwks} jwks @param {number} now @returns {Result<Revoke>} */
export function verifyRevoke(x: unknown, currentKey: PrincipalId, jwks: Jwks, now: number): Result<Revoke>;
/** Derive state ONLY from an authenticated successful resolution, complete through until.
 * @param {PrincipalId} genesis @param {readonly Rotate[]} history @param {number} at @param {number} until @returns {KeyState} */
export function historyState(genesis: PrincipalId, history: readonly Rotate[], at: number, until: number): KeyState;
/** @param {unknown} x @param {PrincipalId} currentKey @param {ResolutionContext} ctx @returns {Result<Rotate>} */
export function verifyRotate(x: unknown, currentKey: PrincipalId, ctx: ResolutionContext): Result<Rotate>;
/** Local pre-attestation check for one v3 rotation request.
 * Covers: v3 (`nextEpub` required; v2 is `bad-record`); no `attest` field
 * (a present attestation is `bad-record` and is not returned); `|issuedAt-now|`
 * within `policy.clockSkewSeconds` (`future-record` or `expired`); `prevKey`
 * equal to the supplied current key and `nextKey` different from it;
 * `nextEpub` different from `nextKey` and `prevKey`; the next-key signature;
 * the authorizer (wallet SIWE, or OIDC with no active wallet); every
 * authorizer and retained link historically valid at `issuedAt`; witnessed
 * revocation of those links at `issuedAt` and at `now` (`rotation-conflict`);
 * and an unwitnessed current-key revoke of those links at `now`
 * (`revoked-link`, `verifyRevokeNow`).
 * Freshness and present revocation apply only to this unattested request.
 * Present revocation honors `policy.clockSkewSeconds`: an offline revoke
 * issued at or before `now + skew` removes the link. A revoke dated further
 * ahead is ignored. The same horizon applies to the active-wallet check:
 * a wallet linked after `issuedAt` but at or before `now + skew` still makes
 * OIDC recovery `wallet-required`. Historical witnessed checks stay
 * skew-free, and `verifyRevokeNow` itself stays skew-free.
 * Does not cover chain sequence, sibling forks, or epub reuse against
 * history or the genesis-epub binding. Panopticon MUST call
 * `checkRotationPublish` for those. This is the building block that
 * function uses when the candidate has no attestation (panopticon#499).
 * `verifyRotate` still requires an attestation and does not use this window.
 * @param {unknown} x @param {PrincipalId} currentKey @param {ResolutionContext} ctx @returns {Result<Rotate>} */
export function verifyRotationRequest(x: unknown, currentKey: PrincipalId, ctx: ResolutionContext): Result<Rotate>;
/** Pre-attestation check for a genesis-epub binding. Shape, epub canonical and
 * distinct from the genesis pub, genesis-key signature, and
 * `|issuedAt - now| <= policy.clockSkewSeconds` (`future-record` or `expired`).
 * A present `attest` is `bad-record`. Does not check that no rotation exists;
 * Panopticon does that, then attests (panopticon#499).
 * @param {unknown} x @param {PrincipalId} genesis @param {number} now @param {SiwePolicy} policy @returns {Result<GenesisEpub>} */
export function verifyGenesisEpubRequest(x: unknown, genesis: PrincipalId, now: number, policy: SiwePolicy): Result<GenesisEpub>;
/** Structural draft the keyring builder checks before a signature exists.
 * Never an attestation gate: success does not authorize a witness signature.
 * Witnesses must use `checkRotationPublish` on the signed request.
 * An unsigned draft has no `nextSig`, `authorizer`, `attest`, or required
 * `issuedAt`. `retainedLinks` uses the signed-record rule. An identical
 * attested sibling of the same transition is a retry and is not a fork.
 * `checkRotationPublish` rejects this shape with `bad-record`. Only
 * `rotateKeyring` / `rotate_keyring` calls this.
 * @param {unknown} candidate @param {readonly unknown[]} siblings @param {PrincipalId} genesis @param {readonly unknown[]} priorRecords @param {ResolutionContext} ctx @returns {Result<Rotate>} */
export function checkRotationDraft(candidate: unknown, siblings: readonly unknown[], genesis: PrincipalId, priorRecords: readonly unknown[], ctx: ResolutionContext): Result<Rotate>;
/** Client publish check and Panopticon attest check. Same rules.
 * Refuses v2 and an unsigned draft (`bad-record`). Draft validation is
 * `checkRotationDraft`, and only the keyring builder calls it.
 * An authenticated sibling with a different signing-byte id at the same
 * (principal, seq) is `rotation-fork`. An identical attested sibling is a
 * retry and is not a fork. Junk and unattested siblings are skipped. Priors
 * are the records `resolveCurrentKey` accepts, not raw JSON.
 * A signed candidate with no attestation is checked by `verifyRotationRequest`
 * (its local checks only). Freshness and present revocation apply only to
 * that unattested request. An attested candidate uses the historical checks:
 * `issuedAt` is an upper bound, and revocation is the witnessed check at
 * `issuedAt`. Chain sequence, sibling forks, and epub reuse are applied
 * here, after that call. Panopticon MUST call this function before
 * attesting. It attests at most one genesis-epub binding per principal, only
 * before the first rotation, and that limit is global across instances and
 * signing keys (panopticon#499).
 * Does not replace verifyRotate. Historical v2 records still verify there.
 * @param {unknown} candidate @param {readonly unknown[]} siblings @param {PrincipalId} genesis @param {readonly unknown[]} priorRecords @param {ResolutionContext} ctx @returns {Result<Rotate>} */
export function checkRotationPublish(candidate: unknown, siblings: readonly unknown[], genesis: PrincipalId, priorRecords: readonly unknown[], ctx: ResolutionContext): Result<Rotate>;
/** Copies share signing-byte identity: any fully verified copy satisfies that rotation ID.
 * Unauthenticated junk is diagnostic; unresolved authenticated evidence fails closed.
 * @param {PrincipalId} genesis @param {readonly unknown[]} rotations @param {ResolutionContext} ctx @returns {Resolution<ResolvedAccount>} */
export function resolveCurrentKey(genesis: PrincipalId, rotations: readonly unknown[], ctx: ResolutionContext): Resolution<ResolvedAccount>;
/** Equal-time distinct links are ambiguous even for the same principal. No resurrection after revocation.
 * @param {Eip55} address @param {readonly unknown[]} links @param {readonly unknown[]} revocations @param {ResolutionContext} ctx @returns {Resolution<WalletLink>} */
export function resolveWalletLink(address: Eip55, links: readonly unknown[], revocations: readonly unknown[], ctx: ResolutionContext): Resolution<WalletLink>;
/** Present lookup using the final authenticated current key; never use for as-of queries.
 * @param {Eip55} address @param {readonly unknown[]} links @param {readonly unknown[]} revocations @param {ResolutionContext} ctx @returns {Resolution<WalletLink>} */
export function resolveWalletLinkNow(address: Eip55, links: readonly unknown[], revocations: readonly unknown[], ctx: ResolutionContext): Resolution<WalletLink>;
/** Present OIDC eligibility. Matches issuer, tenant, and subject. Same envelope as the wallet lookup.
 * @param {unknown} cred @param {readonly unknown[]} links @param {readonly unknown[]} revocations @param {ResolutionContext} ctx @returns {Resolution<OidcLink>} */
export function resolveOidcLinkNow(cred: unknown, links: readonly unknown[], revocations: readonly unknown[], ctx: ResolutionContext): Resolution<OidcLink>;
/** Authenticate candidate link ids and drop those revoked under the final current key.
 * Does not issue an attestation. Missing history fails the call.
 * @param {readonly unknown[]} candidates @param {ResolutionContext} ctx @returns {Result<string[]>} */
export function prepareRetainedLinksNow(candidates: readonly unknown[], ctx: ResolutionContext): Result<string[]>;
/** Group untrusted link copies by signing-byte id and keep one that verifies.
 * A tampered sibling does not drop that id. An id whose copies all fail closed
 * on missing history still fails the call. Other failures omit the id.
 * @param {readonly unknown[]} copies @param {ResolutionContext} ctx @returns {Result<Map<string, WalletLink|OidcLink>>} */
export function verifyingLinkMap(copies: readonly unknown[], ctx: ResolutionContext): Result<Map<string, WalletLink | OidcLink>>;
/** SEA P-256 ECDSA over SHA-256. Raw r||s, base64url. High-S and low-S both verify.
 * @param {PrincipalId} key @param {string} sig @param {Uint8Array} bytes @returns {Result<true>} */
export function verifyKeySignature(key: PrincipalId, sig: string, bytes: Uint8Array): Result<true>;
/** Sign ids bytes with a 32-byte SEA scalar. `expectedKey` is the resolver's current key.
 * The working copy of the scalar is wiped. A bad scalar or a different public key is `bad-key`.
 * The result is raw r||s, base64url, the encoding verifyKeySignature accepts.
 * @param {Uint8Array} scalar @param {Uint8Array} bytes @param {PrincipalId} expectedKey @returns {Result<string>} */
export function signWithKeyring(scalar: Uint8Array, bytes: Uint8Array, expectedKey: PrincipalId): Result<string>;
/** sociacl-acl-attest-v1. Checked like attestVerify with now = issuedAt.
 * Nothing in this package issues the claim.
 * @param {string} jws @param {Jwks} jwks @param {number} issuedAt @param {Uint8Array} bytes @returns {Result<AclAttestation>} */
export function verifyAclAttestation(jws: string, jwks: Jwks, issuedAt: number, bytes: Uint8Array): Result<AclAttestation>;
/** Signing bytes for one already-parsed see row. The domain and stated are inside the bytes.
 * @param {SeeGrant} grant */
export function seeGrantBytes(grant: SeeGrant): Uint8Array<ArrayBuffer>;
/** One snapshot of a see row. A getter or proxy is `bad-record`. `kind` is ignored.
 * @param {unknown} row @returns {Result<{ grant: SeeGrant, bytes: Uint8Array }>} */
export function parseSeeGrant(row: unknown): Result<{
    grant: SeeGrant;
    bytes: Uint8Array;
}>;
/** See-grant authority. Eligibility of a retired cancel is `stated === 0` on this parsed row.
 * There is no kind argument. A retired `stated === 1` row is refused even when witnessed.
 * @param {unknown} row @param {readonly unknown[]} rotations @param {ResolutionContext} ctx
 * @returns {Result<SignedAt & { grant: SeeGrant, bytes: Uint8Array }>} */
export function verifySeeGrant(row: unknown, rotations: readonly unknown[], ctx: ResolutionContext): Result<SignedAt & {
    grant: SeeGrant;
    bytes: Uint8Array;
}>;
/** Signing bytes for one already-parsed post row. The domain and stated are inside the bytes.
 * @param {SeeGrant} grant */
export function postGrantBytes(grant: SeeGrant): Uint8Array<ArrayBuffer>;
/** One snapshot of a post row. Same fields as a see row. A getter or proxy is `bad-record`.
 * @param {unknown} row @returns {Result<{ grant: SeeGrant, bytes: Uint8Array }>} */
export function parsePostGrant(row: unknown): Result<{
    grant: SeeGrant;
    bytes: Uint8Array;
}>;
/** Post-grant authority. A retired cancel is `stated === 0` on this parsed row.
 * A retired `stated === 1` row is refused even when witnessed.
 * @param {unknown} row @param {readonly unknown[]} rotations @param {ResolutionContext} ctx
 * @returns {Result<SignedAt & { grant: SeeGrant, bytes: Uint8Array }>} */
export function verifyPostGrant(row: unknown, rotations: readonly unknown[], ctx: ResolutionContext): Result<SignedAt & {
    grant: SeeGrant;
    bytes: Uint8Array;
}>;
/** Present authority under the resolved current key.
 * Arbitrary bytes stay fail-closed on a retired key. A see cancel is
 * `verifySeeGrant`: the signed `stated` field is `0`.
 * Kind is not a parameter, and this function does not take an attestation.
 * @param {PrincipalId} principal @param {readonly unknown[]} rotations @param {ResolutionContext} ctx
 * @param {Uint8Array} bytes @param {string} sig @param {number} issuedAt
 * @returns {Result<SignedAt>} */
export function verifySignedAt(principal: PrincipalId, rotations: readonly unknown[], ctx: ResolutionContext, bytes: Uint8Array, sig: string, issuedAt: number): Result<SignedAt>;
/** Signing bytes for a request id. Scope, message, and status are not inputs.
 * @param {PrincipalId} requester @param {import('./types.js').ObjectId} object */
export function requestIdBytes(requester: PrincipalId, object: import("./types.js").ObjectId): Uint8Array<ArrayBuffer>;
/** `hex(sha256(requestIdBytes))` after both ids parse. A non-string is `not-string`.
 * @param {unknown} requester @param {unknown} object @returns {Result<string>} */
export function requestId(requester: unknown, object: unknown): Result<string>;
/** Signing bytes for one already-parsed access request.
 * @param {{ requestId: string, requester: PrincipalId, object: import('./types.js').ObjectId, scope: string, status: string, message: string, issuedAt: number }} request */
export function accessRequestBytes(request: {
    requestId: string;
    requester: PrincipalId;
    object: import("./types.js").ObjectId;
    scope: string;
    status: string;
    message: string;
    issuedAt: number;
}): Uint8Array<ArrayBuffer>;
/** One snapshot of an access request. The request id is computed from the requester and object.
 * A wrong domain or a missing signature is `legacy-row`. An empty message is allowed.
 * @param {unknown} row @returns {Result<{ request: { requestId: string, requester: PrincipalId, object: import('./types.js').ObjectId, scope: 'read' | 'read+post', status: 'pending' | 'withdrawn', message: string, issuedAt: number, sig: string }, bytes: Uint8Array }>} */
export function parseAccessRequest(row: unknown): Result<{
    request: {
        requestId: string;
        requester: PrincipalId;
        object: import("./types.js").ObjectId;
        scope: "read" | "read+post";
        status: "pending" | "withdrawn";
        message: string;
        issuedAt: number;
        sig: string;
    };
    bytes: Uint8Array;
}>;
/** Present authority for the requester. A retired key is refused. Kind is not a parameter.
 * @param {unknown} row @param {readonly unknown[]} rotations @param {ResolutionContext} ctx
 * @returns {Result<SignedAt & { request: { requestId: string, requester: PrincipalId, object: import('./types.js').ObjectId, scope: 'read' | 'read+post', status: 'pending' | 'withdrawn', message: string, issuedAt: number, sig: string }, bytes: Uint8Array }>} */
export function verifyAccessRequest(row: unknown, rotations: readonly unknown[], ctx: ResolutionContext): Result<SignedAt & {
    request: {
        requestId: string;
        requester: PrincipalId;
        object: import("./types.js").ObjectId;
        scope: "read" | "read+post";
        status: "pending" | "withdrawn";
        message: string;
        issuedAt: number;
        sig: string;
    };
    bytes: Uint8Array;
}>;
/** Signing bytes for an object-owner record. The domain is inside the bytes.
 * @param {{ object: import('./types.js').ObjectId, owner: PrincipalId, issuedAt: number }} record */
export function objectRecordBytes(record: {
    object: import("./types.js").ObjectId;
    owner: PrincipalId;
    issuedAt: number;
}): Uint8Array<ArrayBuffer>;
/** Snapshot one object-owner record. A missing signature is unsigned.
 * @param {unknown} row @returns {Result<{ record: import('./types.js').ObjectRecord, bytes: Uint8Array }>} */
export function parseObjectRecord(row: unknown): Result<{
    record: import("./types.js").ObjectRecord;
    bytes: Uint8Array;
}>;
/** The owner signs `sociacl-object-v2`. A retired key is refused.
 * @param {unknown} row @param {readonly unknown[]} rotations @param {ResolutionContext} ctx
 * @returns {Result<SignedAt & { record: import('./types.js').ObjectRecord, bytes: Uint8Array }>} */
export function verifyObjectRecord(row: unknown, rotations: readonly unknown[], ctx: ResolutionContext): Result<SignedAt & {
    record: import("./types.js").ObjectRecord;
    bytes: Uint8Array;
}>;
/** Resolve the adapter-supplied history before recording a store head.
 * The adapter authenticates the snapshot and checks its completeness and freshness.
 * @param {PrincipalId} principal
 * @param {readonly unknown[]} rotations
 * @param {ResolutionContext} context
 * @param {Diagnostic[]} diagnostics
 * @returns {import('./types.js').StoreWriteAccount}
 */
export function resolveStoreAccount(principal: PrincipalId, rotations: readonly unknown[], context: ResolutionContext, diagnostics: Diagnostic[]): import("./types.js").StoreWriteAccount;
/** Each resolution list, link map, and revocation list stops at this length. Longer input is `too-long` and is not truncated. */
export const MAX_RESOLUTION_INPUT: 1024;
/** Length-prefixed domain for postGrantBytes. */
export const POST_DOMAIN: "sociacl-post-grant-v2";
/** Length-prefixed domain for requestId. The hash input is this domain, the requester, and the object. */
export const REQUEST_ID_DOMAIN: "sociacl-request-id-v2";
/** Length-prefixed domain for an access request. */
export const REQUEST_DOMAIN: "sociacl-access-request-v2";
import type { UnsignedRecord } from './types.js';
import type { Result } from './types.js';
import type { Jwks } from './types.js';
import type { SiwePolicy } from './types.js';
import type { KeyState } from './types.js';
import type { WalletLink } from './types.js';
import type { OidcLink } from './types.js';
import type { PrincipalId } from './types.js';
import type { Revoke } from './types.js';
import type { Rotate } from './types.js';
import type { ResolutionContext } from './types.js';
import type { GenesisEpub } from './types.js';
import type { ResolvedAccount } from './types.js';
import type { Resolution } from './types.js';
import type { Eip55 } from './types.js';
import type { AclAttestation } from './types.js';
import type { SeeGrant } from './types.js';
import type { SignedAt } from './types.js';
import type { Diagnostic } from './types.js';
