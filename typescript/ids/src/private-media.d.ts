/** Private owner signatures are not proof of authorization or settlement.
 * Inputs must come from a current protected owner view. Keys remain client-side. */
export type PrivateMediaGrant = Readonly<{object:string;owner:string;accessor:string;from:number;until:number;stated:0|1;epoch:number;grantRevision:number;itemCiphertextDigest:string}>;
export type PrivateMediaSnapshot = Readonly<{entries:readonly Readonly<{accessor:string;grantRevision:number;stated:0|1;from:number;until:number;scope:'direct'|'same-group'|'named-circle';setId:string;hamState:number}>[];objectSet?:Readonly<{predicate:'same-group'|'named-circle';setId:string;stated:0|1;hamState:number}>}>;
export type PrivateMediaManifest = Readonly<{object:string;previousEpoch:number;epoch:number;deviceId:string;keyCommitment:string;settleWindowMs:number;aclSnapshot:string;revisionId:string;signature:string}>;
export type PrivateMediaFinalization = Readonly<{object:string;previousEpoch:number;epoch:number;revisionId:string;candidateRevisionIds:readonly string[];previousFinalizationId:string;finalizationId:string;signature:string}>;
export type PrivateMediaStatus = Readonly<{object:string;epoch:number;revisionId:string;accessor:string;grantRevision:number;stated:0|1;signedAt:number;maxAgeMs:number;zookie:Readonly<{object:string;objectVersion:number;snapshotHash:string}>;signature:string}>;
export function signPrivateMediaGrant(input:unknown,scalar:Uint8Array,currentKey:string):Readonly<{claims:PrivateMediaGrant;proof:Readonly<{grantBytes:string;signature:string}>}>;
export function signPrivateMediaEpoch(input:unknown,snapshot:unknown,scalar:Uint8Array,currentKey:string):Readonly<{manifest:PrivateMediaManifest;snapshot:PrivateMediaSnapshot}>;
export function signPrivateMediaFinalization(input:unknown,scalar:Uint8Array,currentKey:string):PrivateMediaFinalization;
export function signPrivateMediaStatus(input:unknown,scalar:Uint8Array,currentKey:string):PrivateMediaStatus;

export type PrivateMediaDeletion = Readonly<{tenant:string;object:string;owner:string;objectVersion:number;fence:string;issuedAt:number;expiresAt:number}>;
export function signPrivateMediaDeletion(input:unknown,scalar:Uint8Array,currentKey:string):Readonly<{claims:PrivateMediaDeletion;proof:Readonly<{deletionBytes:string;signature:string}>}>;
