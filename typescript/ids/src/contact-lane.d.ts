import type {PrincipalId,ResolutionContext} from './index.js';
/** Delivery-only capability; never an object access grant. */
export type ContactLaneGrant=Readonly<{ciphertextHex:string}>;
export type OpenedContactLane=Readonly<{laneId:string;lookupKey:string;recipient:PrincipalId;sender:PrincipalId;rotationSeq:number}>;
/** Return current witnessed state on every invocation, including after decryption. */
export type ContactLaneRecipientState=()=>{rotations:readonly unknown[];context:ResolutionContext};
export function deriveContactLane(contactSecretHex:string,recipient:string,sender:string):string;
export function laneLookupKey(laneId:string):string;
/** Invalid input or changed authority rejects with lane-grant-rejected. */
export function openContactLaneGrant(senderPrincipal:string,senderEpriv:string,grant:ContactLaneGrant,expectedRecipient:string,currentState:ContactLaneRecipientState):Promise<OpenedContactLane>;
