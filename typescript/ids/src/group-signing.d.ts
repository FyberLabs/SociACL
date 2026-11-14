/** Current-key row producers. Callers independently resolve the enrolled signer.
 * A signed row alone does not establish joint membership or authorize delivery. */
export type GroupPredicate='same-group'|'named-circle';
export type MembershipAssent=Readonly<{role:'member'|'set';predicate:GroupPredicate;set:string;member:string;setOwner:string;stated:0|1;hamState:number;issuedAt:number;cancels:readonly string[];sig:string}>;
export type ObjectSetRow=Readonly<{owner:string;object:string;predicate:GroupPredicate;set:string;stated:0|1;hamState:number;issuedAt:number;cancels:readonly string[];sig:string}>;
export type GroupCancel=Readonly<{kind:'membership'|'object-set';rowSoul:string;cancelId:string;prior:readonly string[];signer:string;predicate:GroupPredicate;set:string;member:string;setOwner:string;object?:string;issuedAt:number;sig:string}>;
export function signMembershipAssent(input:unknown,scalar:Uint8Array,currentKey:string):MembershipAssent;
export function signObjectSet(input:unknown,scalar:Uint8Array,currentKey:string):ObjectSetRow;
export function signGroupCancel(input:unknown,scalar:Uint8Array,currentKey:string):GroupCancel;
export function membershipSoul(setOwner:string,predicate:GroupPredicate,set:string,member:string):string;
export function objectSetSoul(owner:string,object:string,predicate:GroupPredicate,set:string):string;
