/** Browser opening of existing recovery copies. No new key generation, storage,
 * session issuance, passphrase strengthening, or rotation is implicit in open. */
import {data} from '../ids/src/util.js';
import {importKeyring,exportKeyring} from './keyring-browser.ts';
import {deriveKey,parseHeader,passphraseRejected,recoveryAad,writeHeader} from './recovery-wire.ts';
import {RECOVERY_ABSOLUTE_MAX,KEYRING_SERIAL_MAX,ARGON2ID_LIMITS,RECOVERY_NONCE_LEN} from './keyring-limits.ts';
import type {KeyringIdentity,KeyringState,ImportedKeyring} from '../ids/src/keyring.js';
import type {BrowserRecoveryEnvelope} from '../ids/src/recovery.js';
export {encodePassphrase} from './recovery-wire.ts';
import {checkRecoveryPassphrase,RecoveryWeakPassphraseError} from './passphrase-strength.ts';
export {RecoveryWeakPassphraseError} from './passphrase-strength.ts';
const rejected=():never=>{throw Error('recovery-rejected');};
/** Snapshot public metadata and secret bytes before asynchronous KDF. The owner
 * supplies authenticated current identity/history; envelope claims are not trust. */
export async function openRecoveryKeyring(passphrase:Uint8Array,envelope:BrowserRecoveryEnvelope,
 expected:KeyringIdentity,currentState:KeyringState,signal?:AbortSignal):Promise<ImportedKeyring>{
 let phrase:Uint8Array|undefined,key:Uint8Array|undefined,plain:Uint8Array|undefined;
 try{
  signal?.throwIfAborted();
  const parsed=data(envelope),identity=data(expected);
  if(!parsed.ok||!identity.ok||Object.keys(parsed.value).sort().join()!=='bytes,epub,principal,rotationSeq,signingPub'||
   Object.keys(identity.value).sort().join()!=='epub,principal,pub,rotationSeq')return rejected();
  const e=parsed.value,x=identity.value;
  if(!(e.bytes instanceof Uint8Array)||e.bytes.byteLength>RECOVERY_ABSOLUTE_MAX||!(passphrase instanceof Uint8Array))return rejected();
  const bytes=new Uint8Array(e.bytes),owner={principal:x.principal,pub:x.pub,epub:x.epub,rotationSeq:x.rotationSeq} as KeyringIdentity;
  if(e.principal!==owner.principal||e.signingPub!==owner.pub||e.epub!==owner.epub||!Number.isSafeInteger(e.rotationSeq)||e.rotationSeq!==owner.rotationSeq)return rejected();
  const header=parseHeader(bytes);
  if(header.rotationSeq!==owner.rotationSeq)return rejected();
  phrase=new Uint8Array(passphrase);if(passphraseRejected(phrase))return rejected();
  const aad=recoveryAad(owner.principal,header.rotationSeq,owner.pub,owner.epub,header.memoryKiB,header.iterations,header.parallelism,header.hashLength,header.version,header.salt);
  key=await deriveKey(phrase,header.salt,header.memoryKiB,header.iterations,header.parallelism,header.hashLength);
  signal?.throwIfAborted();
  const cryptoKey=await crypto.subtle.importKey('raw',new Uint8Array(key),{name:'AES-GCM'},false,['decrypt']);
  const opened=await crypto.subtle.decrypt({name:'AES-GCM',iv:new Uint8Array(header.nonce),additionalData:new Uint8Array(aad),tagLength:128},cryptoKey,new Uint8Array(header.ciphertext));
  plain=new Uint8Array(opened);signal?.throwIfAborted();
  if(plain.length>KEYRING_SERIAL_MAX)return rejected();
  // Import rechecks complete current authenticated history after async work.
  return importKeyring(plain,owner,()=>{signal?.throwIfAborted();return currentState();});
 }catch{return rejected();}
 finally{phrase?.fill(0);key?.fill(0);plain?.fill(0);}
}

/** Prepare a new ciphertext with explicit new-passphrase strength checking.
 * This does not publish, replace a stored copy, advance keys or authorize rotation. */
export async function sealRecoveryKeyring(handle:ImportedKeyring,passphrase:Uint8Array,
 currentState:KeyringState,signal?:AbortSignal):Promise<BrowserRecoveryEnvelope>{
 let phrase:Uint8Array|undefined,plain:Uint8Array|undefined,key:Uint8Array|undefined;
 const guard=()=>signal?.throwIfAborted();
 try{
  guard();if(!(passphrase instanceof Uint8Array))return rejected();
  phrase=new Uint8Array(passphrase);if(passphraseRejected(phrase))return rejected();
  plain=exportKeyring(handle,currentState);
  await checkRecoveryPassphrase(phrase,handle.principal);guard();
  // The estimator may load asynchronously. Retain neither a stale nor closed handle.
  const checked=exportKeyring(handle,currentState);checked.fill(0);
  const p=ARGON2ID_LIMITS,salt=crypto.getRandomValues(new Uint8Array(p.saltLength.floor));
  const nonce=crypto.getRandomValues(new Uint8Array(RECOVERY_NONCE_LEN));
  key=await deriveKey(phrase,salt,p.memoryKiB.floor,p.iterations.floor,p.parallelism.floor,p.hashLength.floor);guard();
  const aad=recoveryAad(handle.principal,handle.rotationSeq,handle.pub,handle.epub,p.memoryKiB.floor,p.iterations.floor,p.parallelism.floor,p.hashLength.floor,p.version.floor,salt);
  const cryptoKey=await crypto.subtle.importKey('raw',new Uint8Array(key),{name:'AES-GCM'},false,['encrypt']);
  const encrypted=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv:nonce,additionalData:new Uint8Array(aad),tagLength:128},cryptoKey,new Uint8Array(plain)));guard();
  const header=writeHeader(p.version.floor,p.memoryKiB.floor,p.iterations.floor,p.parallelism.floor,p.hashLength.floor,salt,handle.rotationSeq);
  const bytes=new Uint8Array(header.length+nonce.length+encrypted.length);bytes.set(header);bytes.set(nonce,header.length);bytes.set(encrypted,header.length+nonce.length);
  if(bytes.length>RECOVERY_ABSOLUTE_MAX)return rejected();
  const final=exportKeyring(handle,currentState);final.fill(0);guard();
  return {principal:handle.principal,signingPub:handle.pub,epub:handle.epub,rotationSeq:handle.rotationSeq,bytes};
 }catch(error){if(error instanceof RecoveryWeakPassphraseError)throw error;return rejected();}
 finally{phrase?.fill(0);plain?.fill(0);key?.fill(0);}
}
