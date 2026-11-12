import type {PrincipalId,ResolutionContext,Result} from './index.js';
import type {FirstContactStore} from './first-contact-store.js';
export type FirstContactRequest=Readonly<{v:1;channelId:string;descriptorRevision:number;sender:PrincipalId;replyEpub:PrincipalId;nonce:string;issuedAt:number;expiresAt:number;message:string;sig:string}>;
export type FirstContactDescriptor=Readonly<{channelId:string;revision:number;expiresAt:number;maxLifetimeSeconds:number;maxMessageBytes:number}>;
export type FirstContactSealDescriptor=FirstContactDescriptor & Readonly<{encryptionEpub:string}>;
export type VerifiedFirstContact=Readonly<{request:FirstContactRequest;requestId:string;replayKey:string;replayUntil:number}>;
export type FirstContactSource=(channelId:string,signal:AbortSignal)=>Promise<unknown>;
export type FirstContactSenderState=()=>{rotations:readonly unknown[];context:ResolutionContext};
export function firstContactRequestBytes(request:Omit<FirstContactRequest,'sig'>):Uint8Array;
export function parseFirstContactRequest(input:unknown):Result<FirstContactRequest>;
export function verifyFirstContactRequest(input:unknown,rotations:readonly unknown[],context:ResolutionContext,descriptor:FirstContactDescriptor):Result<VerifiedFirstContact>;
export function sealFirstContactRequest(input:unknown,descriptor:FirstContactSealDescriptor):Promise<Uint8Array>;
export function openFirstContactRequest(envelope:Uint8Array,recipientEpriv:string,descriptor:FirstContactSealDescriptor,currentState:FirstContactSenderState):Promise<Result<VerifiedFirstContact>>;
export function pollFirstContact(store:FirstContactStore,source:FirstContactSource,epriv:string,currentState:FirstContactSenderState,timeoutMs?:number):Promise<readonly VerifiedFirstContact[]>;

import type {FirstContactFloor,DescriptorFloor} from './first-contact-floor.js';
export type SignedFirstContactDescriptor=Readonly<{v:1;owner:PrincipalId;issuedAt:number;descriptor:FirstContactSealDescriptor;sig:string}>;
export type FirstContactAppend=(channel:string,ciphertext:Uint8Array,signal:AbortSignal)=>Promise<unknown>;
export function firstContactDescriptorBytes(value:Omit<SignedFirstContactDescriptor,'sig'>):Uint8Array;
export function verifyFirstContactDescriptor(input:unknown,expectedOwner:PrincipalId,minimumRevision:number,rotations:readonly unknown[],context:ResolutionContext):Result<SignedFirstContactDescriptor>;
export function firstContactDescriptorFloor(descriptor:SignedFirstContactDescriptor):DescriptorFloor;
export function observeFirstContactDescriptor(input:unknown,owner:PrincipalId,store:FirstContactFloor,rotations:readonly unknown[],context:ResolutionContext):Promise<SignedFirstContactDescriptor>;
export function prepareFirstContactSubmission(input:unknown,advertisement:unknown,owner:PrincipalId,floor:FirstContactFloor,recipientState:FirstContactSenderState,senderState:FirstContactSenderState):Promise<Readonly<{ciphertextId:string;submit(append:FirstContactAppend,timeoutMs?:number):Promise<string>}>>;

export function restorePendingFirstContacts(store:FirstContactStore,epriv:string,currentState:FirstContactSenderState):Promise<readonly VerifiedFirstContact[]>;
