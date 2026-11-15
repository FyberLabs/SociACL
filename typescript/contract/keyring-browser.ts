/** Browser facade over the canonical keyring codec and validators. Import never
 * generates keys, contacts an issuer, grants access or writes browser storage. */
import { decodeKeyring, encodeKeyring, type KeyringFields, type KeyringSource } from './keyring-codec.ts';
import { validateKeyringFields, confirmKeyring } from './keyring-validation.ts';
import { KEYRING_SERIAL_MAX } from './keyring-limits.ts';
import { data } from '../ids/src/util.js';
import { openItemDekReaderWrap } from '../ids/src/reader-wrap.js';
import type { KeyringIdentity, ImportedKeyring, KeyringState } from '../ids/src/keyring.js';
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
