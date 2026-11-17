import type { PrincipalId, ResolutionContext } from './index.js';
import type { DescriptorFloor } from './first-contact-floor.js';
export const VAULT_SYNC_HEAD_DOMAIN:'sociacl-vault-sync-head-v1';
export type VaultSyncHead=Readonly<{v:1;owner:PrincipalId;vaultId:string;revision:number;previousDigest:string;keybagDigest:string;indexDigest:string;minimumProfile:1|2;issuedAt:number;sig:string}>;
export type VaultHeadIdentityState=()=>{rotations:readonly unknown[];context:ResolutionContext};
export function vaultSyncHeadSigningBytes(input:unknown):Uint8Array;
export function vaultSyncHeadFloor(input:unknown):DescriptorFloor;
export function verifyVaultSyncHead(input:unknown,owner:PrincipalId,vaultId:string,rotations:readonly unknown[],context:ResolutionContext):VaultSyncHead;
export function openVaultSyncHeadStore(options:{name:string;owner:PrincipalId;vaultId:string;anchor:DescriptorFloor;now:()=>number;create?:boolean;indexedDB?:IDBFactory}):Promise<Readonly<{
  read():Promise<DescriptorFloor>;close():void;
  verifyCurrent(input:unknown,current:VaultHeadIdentityState):Promise<VaultSyncHead>;
  advance(previous:unknown,input:unknown,current:VaultHeadIdentityState):Promise<VaultSyncHead>;
}>>;
