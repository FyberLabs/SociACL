/** Browser opening of existing recovery copies. No new key generation, storage,
 * session issuance, passphrase strengthening, or rotation is implicit in open. */
import {data} from '../ids/src/util.js';
import {importKeyring} from './keyring-browser.ts';
import {deriveKey,parseHeader,passphraseRejected,recoveryAad} from './recovery-wire.ts';
import {RECOVERY_ABSOLUTE_MAX,KEYRING_SERIAL_MAX} from './keyring-limits.ts';
import type {KeyringIdentity,KeyringState,ImportedKeyring} from '../ids/src/keyring.js';
import type {BrowserRecoveryEnvelope} from '../ids/src/recovery.js';
export {encodePassphrase} from './recovery-wire.ts';
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
