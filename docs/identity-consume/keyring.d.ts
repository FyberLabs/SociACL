import type {ResolutionContext,ItemWrapContext} from './index.js';
/** Same identity fields as sea-device-link's Identity, without an SDK dependency. */
export type KeyringIdentity=Readonly<{principal:string;pub:string;epub:string;rotationSeq:number}>;
/** Public opaque handle. Copying this object does not copy or unlock its keys. */
export type ImportedKeyring=KeyringIdentity & Readonly<{genesisEpub:string;contentEpoch:number}>;
/** Already authenticated COMPLETE current history, supplied by the owner.
 * Never construct this callback from unverified transfer metadata. */
export type KeyringState=()=>{rotations:readonly unknown[];context:ResolutionContext};
/** Decode and admit canonical v2/v3 keyring bytes, preserving all historical keys.
 * Throws keyring-rejected for malformed keys, incomplete/stale history or mismatch.
 * Does not mint keys, issue sessions, grant permissions or persist any state. */
export function importKeyring(bytes:Uint8Array,expected:KeyringIdentity,currentState:KeyringState):ImportedKeyring;
/** Returns plaintext secret bytes; caller must encrypt and overwrite them. */
export function exportKeyring(handle:ImportedKeyring,currentState:KeyringState):Uint8Array;
/** SDK IdentityAdapter.validateKeyring implementation building block. */
export function validateKeyring(bytes:Uint8Array,expected:KeyringIdentity,currentState:KeyringState):void;
/** Deletes held references; JS strings cannot be guaranteed zeroized. */
export function closeKeyring(handle:ImportedKeyring):void;
/** Does not replace Check: expected scope must come from current authorization. */
export function openKeyringContent(handle:ImportedKeyring,wrap:unknown,expected:ItemWrapContext):Promise<Uint8Array>;

/** Complete owner-held fields. No missing history is inferred or generated. */
export type KeyringMaterial = {
 principal:string;genesisEpub:string;pub:string;priv:string;epub:string;epriv:string;
 retired:{epub:string;epriv:string}[];laneId:string;priorLanes:string[];
 contactLaneSecret:string;priorContactSecrets:string[];contentEpoch:number;rotationSeq:number;
};
/** Admit a snapshot of existing complete material through canonical validation. */
export function admitKeyring(material:KeyringMaterial,expected:KeyringIdentity,currentState:KeyringState):ImportedKeyring;
/** Explicit plaintext export for existing local SEA consumers. Fresh authority is
 * required. Caller owns the returned copy; never persist or log it unprotected. */
export function exportCurrentPair(handle:ImportedKeyring,currentState:KeyringState):{pub:string;priv:string;epub:string;epriv:string};
