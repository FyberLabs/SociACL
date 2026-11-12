import type {PrincipalId,ResolutionContext,Result} from './index.js';
export type WitnessOperator=Readonly<{id:string;keys:readonly Readonly<{key:PrincipalId;notBefore:number;notAfter:number}>[]}>;
export type IndependentWitnessPolicy=Readonly<{id:string;epoch:number;threshold:number;maxFaulty:number;operators:readonly WitnessOperator[]}>;
export type WitnessRequest=Readonly<{v:1;principal:PrincipalId;operation:'rotate'|'revoke';recordDigest:string;policyId:string;epoch:number;issuedAt:number;expiresAt:number;sig:string}>;
export type WitnessReceipt=Readonly<{operator:string;observedAt:number;sig:string}>;
export type WitnessObservation=Readonly<{requestId:string;recordDigest:string;policyId:string;epoch:number;operators:readonly string[];timestampUpperBound:number}>;
export type WitnessTransport=(request:Readonly<WitnessRequest>,signal:AbortSignal)=>Promise<unknown>;
export function independentWitnessPolicyBytes(policy:IndependentWitnessPolicy):Uint8Array;
export function independentWitnessTransitionDigest(previous:IndependentWitnessPolicy,next:IndependentWitnessPolicy):string;
export function witnessRequestBytes(request:Omit<WitnessRequest,'sig'>):Uint8Array;
export function witnessReceiptBytes(request:WitnessRequest,operatorId:string,observedAt:number):Uint8Array;
export function verifyIndependentWitnesses(request:WitnessRequest,receipts:readonly WitnessReceipt[],policy:IndependentWitnessPolicy,expectedRecordDigest:string,rotations:readonly unknown[],context:ResolutionContext):Result<WitnessObservation>;
export function advanceIndependentWitnessPolicy(previous:IndependentWitnessPolicy,next:IndependentWitnessPolicy,principal:PrincipalId,oldRequest:WitnessRequest,oldReceipts:readonly WitnessReceipt[],newRequest:WitnessRequest,newReceipts:readonly WitnessReceipt[],rotations:readonly unknown[],context:ResolutionContext):IndependentWitnessPolicy;
export function collectIndependentWitnesses(request:WitnessRequest,expectedRecordDigest:string,rotations:readonly unknown[],currentPolicy:()=>IndependentWitnessPolicy,currentContext:()=>ResolutionContext,transports:ReadonlyMap<string,WitnessTransport>,timeoutMs?:number):Promise<Readonly<{request:WitnessRequest;receipts:readonly WitnessReceipt[];observation:WitnessObservation}>>;
export interface IndependentWitnessPolicyStore {
  read(candidate:IndependentWitnessPolicy):Promise<IndependentWitnessPolicy>;
  advance(previous:IndependentWitnessPolicy,next:IndependentWitnessPolicy,oldRequest:WitnessRequest,oldReceipts:readonly WitnessReceipt[],newRequest:WitnessRequest,newReceipts:readonly WitnessReceipt[],currentState:()=>{rotations:readonly unknown[];context:ResolutionContext}):Promise<IndependentWitnessPolicy>;
  close():void;
}
export function openIndependentWitnessPolicyStore(options:{name:string;principal:PrincipalId;anchor:IndependentWitnessPolicy;now:()=>number;create?:boolean;indexedDB?:IDBFactory}):Promise<IndependentWitnessPolicyStore>;
