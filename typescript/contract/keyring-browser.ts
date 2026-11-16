/** Browser facade over the canonical keyring codec and validators. Import never
 * generates keys, contacts an issuer, grants access or writes browser storage. */
import { decodeKeyring, encodeKeyring, type KeyringFields, type KeyringSource } from './keyring-codec.ts';
import { validateKeyringFields, confirmKeyring } from './keyring-validation.ts';
import { KEYRING_SERIAL_MAX } from './keyring-limits.ts';
import { data } from '../ids/src/util.js';
import { openItemDekReaderWrap } from '../ids/src/reader-wrap.js';
import type { KeyringIdentity, ImportedKeyring, KeyringState, KeyringMaterial } from '../ids/src/keyring.js';
import type { ItemWrapContext } from '../ids/src/types.js';

const held = new WeakMap<ImportedKeyring, KeyringFields>();
const byteLength = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), 'byteLength')!.get!;
function rejected(): never { throw Error('keyring-rejected'); }

function source(f: KeyringFields): KeyringSource {
  return { ...f, currentPriv: () => f.priv, currentEpriv: () => f.epriv,
    retired: () => f.retired, laneId: () => f.laneId, priorLanes: () => f.priorLanes,
    contactLaneSecret: () => f.contactLaneSecret, priorContactSecrets: () => f.priorContactSecrets };
}
function identity(f: KeyringFields): KeyringIdentity {
  return { principal: f.principal, pub: f.pub, epub: f.epub, rotationSeq: f.rotationSeq };
}
function assertExpected(f: KeyringFields, expected: KeyringIdentity): void {
  const parsed = data(expected);
  if (!parsed.ok || Object.keys(parsed.value).sort().join() !== 'epub,principal,pub,rotationSeq') rejected();
  const value = parsed.value;
  if (value.principal !== f.principal || value.pub !== f.pub || value.epub !== f.epub || value.rotationSeq !== f.rotationSeq) rejected();
}
function confirm(f: KeyringFields, currentState: KeyringState): void {
  const state = currentState();
  confirmKeyring(source(f), state.rotations, state.context);
}
/** Snapshot input before decoding. The returned object exposes public metadata
 * only; all secret fields remain privately held until export/open/close. */
export function importKeyring(bytes: Uint8Array, expected: KeyringIdentity, currentState: KeyringState): ImportedKeyring {
  let copy: Uint8Array | undefined;
  try {
    if (!ArrayBuffer.isView(bytes) || !(bytes instanceof Uint8Array)) rejected();
    const length = byteLength.call(bytes);
    if (!length || length > KEYRING_SERIAL_MAX) rejected();
    copy = new Uint8Array(bytes);
    const fields = validateKeyringFields(decodeKeyring(copy));
    assertExpected(fields, expected);
    confirm(fields, currentState);
    const handle = Object.freeze({ ...identity(fields), genesisEpub: fields.genesisEpub, contentEpoch: fields.contentEpoch });
    held.set(handle, fields);
    return handle;
  } catch { return rejected(); }
  finally { copy?.fill(0); }
}
/** Explicit secret export. Caller must encrypt immediately and overwrite bytes.
 * Fresh owner state is mandatory even for a previously imported handle. */
export function exportKeyring(handle: ImportedKeyring, currentState: KeyringState): Uint8Array {
  try {
    const fields = held.get(handle);
    if (!fields) rejected();
    confirm(fields, currentState);
    // A trusted state callback can synchronously close the handle.
    if (held.get(handle) !== fields) rejected();
    return encodeKeyring(source(fields));
  } catch { return rejected(); }
}
/** Borrow a full encoded keyring for an SDK validation callback without retaining
 * the unlocked handle. Owner current-key/freshness checks remain separate. */
export function validateKeyring(bytes: Uint8Array, expected: KeyringIdentity, currentState: KeyringState): void {
  closeKeyring(importKeyring(bytes, expected, currentState));
}
/** Drop secret references. JavaScript strings cannot be guaranteed zeroized. */
export function closeKeyring(handle: ImportedKeyring): void { held.delete(handle); }
/** Historical DEK opening, not permission to read content. The caller must obtain
 * expected scope from current Check/epoch policy, never the uploaded wrap. */
export async function openKeyringContent(handle: ImportedKeyring, wrap: unknown, expected: ItemWrapContext): Promise<Uint8Array> {
  let opened: Uint8Array | undefined;
  try {
    const fields = held.get(handle), parsed = data(wrap);
    if (!fields || !parsed.ok) rejected();
    const target = parsed.value.targetId;
    const epriv = target === fields.epub ? fields.epriv : fields.retired.find(row => row.epub === target)?.epriv;
    if (!epriv || typeof target !== 'string') rejected();
    const result = await openItemDekReaderWrap(parsed.value, epriv, target, expected);
    if (!result.ok) rejected();
    opened = result.value;
    if (held.get(handle) !== fields) rejected();
    return opened;
  } catch { opened?.fill(0); return rejected(); }
}


function boundedString(value:unknown,maximum=87):string {
  if(typeof value!=='string'||value.length<1||value.length>maximum)rejected();
  return value;
}
function boundedArray<T>(input:unknown,parse:(value:unknown)=>T):T[] {
  if(!Array.isArray(input)||input.length>1024)rejected();
  const out:T[]=[];
  for(let i=0;i<input.length;i++){
    const d=Object.getOwnPropertyDescriptor(input,String(i));
    if(!d||!('value' in d))rejected();
    out.push(parse(d.value));
  }
  return out;
}
/** Bridge existing owner-held fields to the canonical browser import. No codec
 * or history validator is delegated to the consuming application. */
export function admitKeyring(material:KeyringMaterial,expected:KeyringIdentity,currentState:KeyringState):ImportedKeyring {
  let bytes:Uint8Array|undefined;
  try {
    const parsed=data(material);if(!parsed.ok)rejected();const m=parsed.value;
    if(Object.keys(m).sort().join()!=='contactLaneSecret,contentEpoch,epriv,epub,genesisEpub,laneId,principal,priorContactSecrets,priorLanes,priv,pub,retired,rotationSeq')rejected();
    const f:KeyringFields={principal:boundedString(m.principal),genesisEpub:boundedString(m.genesisEpub),
      pub:boundedString(m.pub),priv:boundedString(m.priv,43),epub:boundedString(m.epub),epriv:boundedString(m.epriv,43),
      laneId:boundedString(m.laneId,64),contactLaneSecret:boundedString(m.contactLaneSecret,64),
      priorLanes:boundedArray(m.priorLanes,v=>boundedString(v,64)),
      priorContactSecrets:boundedArray(m.priorContactSecrets,v=>boundedString(v,64)),
      retired:boundedArray(m.retired,v=>{const r=data(v);if(!r.ok||Object.keys(r.value).sort().join()!=='epriv,epub')rejected();
        return {epub:boundedString(r.value.epub),epriv:boundedString(r.value.epriv,43)};}),
      contentEpoch:m.contentEpoch as number,rotationSeq:m.rotationSeq as number};
    const validated=validateKeyringFields(f);
    bytes=encodeKeyring(source(validated));
    return importKeyring(bytes,expected,currentState);
  } catch {return rejected();}
  finally {bytes?.fill(0);}
}
export function exportCurrentPair(handle:ImportedKeyring,currentState:KeyringState):{pub:string;priv:string;epub:string;epriv:string} {
  try {
    const f=held.get(handle);if(!f)rejected();confirm(f,currentState);
    if(held.get(handle)!==f)rejected();
    return {pub:f.pub,priv:f.priv,epub:f.epub,epriv:f.epriv};
  } catch {return rejected();}
}
