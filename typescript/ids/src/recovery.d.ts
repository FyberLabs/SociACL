import type {ImportedKeyring,KeyringIdentity,KeyringState} from './keyring.js';
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
