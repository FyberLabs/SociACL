/** @import {PrincipalId, PrincipalKey, Eip55, TenantId, OidcCredential, ObjectId, MintedObjectId, NetworkId, SourceKey, PathKey, Soul, Result, Collection, ParsedSoul, MembershipPredicate} from './types.js' */
/** @param {unknown} x @returns {Result<PrincipalId>} */
export function parsePrincipalId(x: unknown): Result<PrincipalId>;
/** @param {string} address */
export function checksum(address: string): string;
/** @param {unknown} x @returns {Result<Eip55>} */
export function parseEip55(x: unknown): Result<Eip55>;
/** UI edge only. @param {unknown} x @returns {Result<Eip55>} */
export function parseWalletInput(x: unknown): Result<Eip55>;
/** @param {unknown} x @returns {Result<TenantId>} */
export function parseTenantId(x: unknown): Result<TenantId>;
/** @param {unknown} x @returns {Result<OidcCredential>} */
export function parseOidcCredential(x: unknown): Result<OidcCredential>;
/** @param {unknown} x @returns {Result<ObjectId>} */
export function parseObjectId(x: unknown): Result<ObjectId>;
/** @param {unknown} x @returns {Result<NetworkId>} */
export function parseNetworkId(x: unknown): Result<NetworkId>;
/** @param {unknown} x @returns {Result<SourceKey>} */
export function parseSourceKey(x: unknown): Result<SourceKey>;
/** @param {PrincipalId} setOwner @param {MembershipPredicate} predicate @param {ObjectId} set @param {PrincipalId} member */
export function membershipSoul(setOwner: PrincipalId, predicate: MembershipPredicate, set: ObjectId, member: PrincipalId): Soul;
/** Seven-segment object-set soul. The set and the predicate are in the id, so a cancel signed over this soul cannot move to another set.
 * @param {PrincipalId} owner @param {ObjectId} object @param {MembershipPredicate} predicate @param {ObjectId} set */
export function objectSetSoul(owner: PrincipalId, object: ObjectId, predicate: MembershipPredicate, set: ObjectId): Soul;
/** @param {unknown} x @returns {Result<ParsedSoul>} */
export function parseSoul(x: unknown): Result<ParsedSoul>;
/** The genesis principal embedded in a bound object id.
 * An id with no embedded principal is `bad-template`.
 * @param {unknown} x @returns {Result<PrincipalId>} */
export function objectPrincipal(x: unknown): Result<PrincipalId>;
/** @param {string} kind @param {PrincipalId} creator @param {(n: number) => Uint8Array} [rng] @returns {Result<MintedObjectId>} */
export function mintObjectId(kind: string, creator: PrincipalId, rng?: (n: number) => Uint8Array): Result<MintedObjectId>;
/** @param {string} claimText @returns {Result<ObjectId>} */
export function deriveClaimId(claimText: string): Result<ObjectId>;
/** @param {SourceKey} source @param {string} providerItemId @returns {Result<ObjectId>} */
export function deriveExternalId(source: SourceKey, providerItemId: string): Result<ObjectId>;
/** @param {unknown} x @returns {Result<PrincipalKey>} */
export function parsePrincipalKey(x: unknown): Result<PrincipalKey>;
/** @param {unknown} x @returns {Result<PathKey>} */
export function parsePathKey(x: unknown): Result<PathKey>;
/** @param {Uint8Array} bytes @returns {Result<PrincipalId>} */
export function principalFromSec1(bytes: Uint8Array): Result<PrincipalId>;
export function pct(s: string): string;
export function formatPrincipalKey(p: PrincipalId): PrincipalKey;
export function formatWalletKey(w: Eip55): PathKey;
export function formatOidcKey(c: OidcCredential): PathKey;
export function formatNetworkKey(n: NetworkId): PathKey;
export function formatSourcePathKey(s: SourceKey): PathKey;
export function objectKey(o: ObjectId): PathKey;
export function objectSoul(c: Collection, o: ObjectId): Soul;
export function userSoul(p: PrincipalId): Soul;
export function aclSoul(p: PrincipalId): Soul;
export function grantSoul(owner: PrincipalId, object: ObjectId, accessor: PrincipalId): Soul;
export function postSoul(owner: PrincipalId, object: ObjectId, accessor: PrincipalId): Soul;
import type { PrincipalId } from './types.js';
import type { Result } from './types.js';
import type { Eip55 } from './types.js';
import type { TenantId } from './types.js';
import type { OidcCredential } from './types.js';
import type { ObjectId } from './types.js';
import type { NetworkId } from './types.js';
import type { SourceKey } from './types.js';
import type { MembershipPredicate } from './types.js';
import type { Soul } from './types.js';
import type { ParsedSoul } from './types.js';
import type { MintedObjectId } from './types.js';
import type { PrincipalKey } from './types.js';
import type { PathKey } from './types.js';
import type { Collection } from './types.js';
