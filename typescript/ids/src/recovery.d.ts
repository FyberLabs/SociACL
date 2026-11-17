import type {ImportedKeyring,KeyringIdentity,KeyringState,PendingKeyringRotation} from './keyring.js';
export type BrowserRecoveryEnvelope=Readonly<{principal:string;rotationSeq:number;signingPub:string;epub:string;bytes:Uint8Array}>;
/** Unicode16 NFC normalization for a newly entered textual passphrase. Byte
 * opening preserves exact bytes and never applies the new-passphrase strength gate. */
export function encodePassphrase(passphrase:string):Uint8Array;
/** Opens an existing canonical recovery copy into an opaque keyring. Current
 * identity and complete authenticated history must come from the owner. Refuses
 * stale/malformed/tampered copies; does not create, rotate, persist or sign in.
 * Cancellation refuses delivery after asynchronous work. Throws recovery-rejected.
 * Caller retains responsibility for wiping its own passphrase byte buffer. */
export function openRecoveryKeyring(passphrase:Uint8Array,envelope:BrowserRecoveryEnvelope,expected:KeyringIdentity,currentState:KeyringState,signal?:AbortSignal):Promise<ImportedKeyring>;

/** Awaitable new-passphrase gate; failure includes feedback, never the passphrase. */
export class RecoveryWeakPassphraseError extends Error {
 readonly score:number;readonly warning:string;readonly suggestions:readonly string[];
}
/** Encrypt existing complete material using fresh native salt/nonce. Requires the
 * new-passphrase gate and fresh owner history. Does not persist or rotate keys. */
export function sealRecoveryKeyring(handle:ImportedKeyring,passphrase:Uint8Array,currentState:KeyringState,signal?:AbortSignal,accountHandle?:string):Promise<BrowserRecoveryEnvelope>;

/** Authenticated API read plus owner-confirmed current head. A conflict requires
 * rereading every field and a fresh explicit signature; never replay a prior put. */
export type BrowserRecoveryCurrentView=Readonly<{generation:number;head:Readonly<{sequence:number;currentKey:string;currentEpub:string|null}>;row:BrowserRecoveryEnvelope|null}>;
export type BrowserRecoveryPut=Readonly<{action:'put';row:Readonly<{principal:string;rotationSeq:number;signingPub:string;epub:string;bytesHex:string}>;signature:string}>;
/** Signs a current-copy replacement only; no rotation, persistence or retry. */
export function signRecoveryCurrentPut(handle:ImportedKeyring,envelope:BrowserRecoveryEnvelope,view:BrowserRecoveryCurrentView,currentState:KeyringState):BrowserRecoveryPut;

/** Seal an explicitly prepared pending rotation, preserving the new-passphrase
 * gate and fresh original-key checks. Never publishes, persists or activates. */
export function sealPendingRecoveryKeyring(handle:PendingKeyringRotation,passphrase:Uint8Array,currentState:KeyringState,signal?:AbortSignal,accountHandle?:string):Promise<BrowserRecoveryEnvelope>;
