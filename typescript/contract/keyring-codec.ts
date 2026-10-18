/**
 * Length-prefixed account keyring. Shared by the recovery copy and device
 * delivery. Secrets stay in the plaintext only until the caller seals it.
 */
import type { AccountKeyring } from "./account-keyring.ts";
import { bytesToHex, hexToBytes, unb64 } from "./account-key-seal.ts";
import { canonicalDecimal, lengthPrefixed } from "./canonical.ts";
import { KEYRING_SERIAL_MAX } from "./keyring-limits.ts";

export const DOMAIN_KEYRING_PLAIN = "sociacl-keyring-plain-v1";

export type KeyringFields = {
  principal: string;
  genesisEpub: string;
  pub: string;
  priv: string;
  epub: string;
  epriv: string;
  retired: { epub: string; epriv: string }[];
  laneId: string;
  priorLanes: string[];
  contentEpoch: number;
  rotationSeq: number;
};

export function encodeKeyring(keyring: AccountKeyring): Uint8Array {
  const retired = keyring.retired();
  const prior = keyring.priorLanes();
  const fields = [
    DOMAIN_KEYRING_PLAIN,
    keyring.principal,
    keyring.genesisEpub,
    keyring.pub,
    keyring.currentPriv(),
    keyring.epub,
    keyring.currentEpriv(),
    canonicalDecimal(retired.length),
  ];
  for (const row of retired) fields.push(row.epub, row.epriv);
  fields.push(keyring.laneId(), canonicalDecimal(prior.length));
  for (const lane of prior) fields.push(lane);
  fields.push(canonicalDecimal(keyring.contentEpoch), canonicalDecimal(keyring.rotationSeq));
  let total = 0;
  for (const field of fields) {
    total += 4 + new TextEncoder().encode(field).length;
    if (total > KEYRING_SERIAL_MAX) throw new Error("keyring-too-large");
  }
  return lengthPrefixed(fields);
}

export function decodeKeyring(bytes: Uint8Array): KeyringFields {
  if (bytes.length > KEYRING_SERIAL_MAX) throw new Error("keyring-too-large");
  const cursor = new Cursor(bytes);
  if (cursor.nextString() !== DOMAIN_KEYRING_PLAIN) throw new Error("recovery-rejected");
  const principal = cursor.nextString();
  const genesisEpub = cursor.nextString();
  const pub = cursor.nextString();
  const priv = cursor.nextString();
  const epub = cursor.nextString();
  const epriv = cursor.nextString();
  const retiredCount = decimal(cursor.nextString());
  if (retiredCount > 1024) throw new Error("too-many-keys");
  if (retiredCount * 8 > cursor.remaining()) throw new Error("recovery-rejected");
  const retired: { epub: string; epriv: string }[] = [];
  for (let i = 0; i < retiredCount; i += 1) {
    retired.push({ epub: cursor.nextString(), epriv: cursor.nextString() });
  }
  const laneId = cursor.nextString();
  const priorCount = decimal(cursor.nextString());
  if (priorCount * 4 > cursor.remaining()) throw new Error("recovery-rejected");
  const priorLanes: string[] = [];
  for (let i = 0; i < priorCount; i += 1) priorLanes.push(cursor.nextString());
  const contentEpoch = decimal(cursor.nextString());
  const rotationSeq = decimal(cursor.nextString());
  if (cursor.remaining() !== 0) throw new Error("recovery-rejected");
  return { principal, genesisEpub, pub, priv, epub, epriv, retired, laneId, priorLanes, contentEpoch, rotationSeq };
}

/** Refuse a ciphertext that still contains a keyring scalar or lane id. */
export function assertKeyringHidden(bytes: Uint8Array, keyring: AccountKeyring): void {
  const hex = bytesToHex(bytes);
  for (const lane of [keyring.laneId(), ...keyring.priorLanes()]) {
    if (hex.includes(lane)) throw new Error("recovery-rejected");
    const raw = hexToBytes(lane);
    if (includesBytes(bytes, raw)) throw new Error("recovery-rejected");
    raw.fill(0);
  }
  for (const secret of [keyring.currentPriv(), keyring.currentEpriv(), ...keyring.retired().map((row) => row.epriv)]) {
    const raw = unb64(secret);
    if (includesBytes(bytes, raw) || hex.includes(bytesToHex(raw))) throw new Error("recovery-rejected");
    raw.fill(0);
  }
}

function includesBytes(haystack: Uint8Array, needle: Uint8Array): boolean {
  if (needle.length === 0 || haystack.length < needle.length) return false;
  for (let i = 0; i <= haystack.length - needle.length; i += 1) {
    let match = true;
    for (let j = 0; j < needle.length; j += 1) {
      if (haystack[i + j] !== needle[j]) {
        match = false;
        break;
      }
    }
    if (match) return true;
  }
  return false;
}

function decimal(text: string): number {
  if (!/^(0|[1-9][0-9]*)$/u.test(text)) throw new Error("recovery-rejected");
  const value = Number(text);
  if (!Number.isSafeInteger(value)) throw new Error("recovery-rejected");
  return value;
}

class Cursor {
  private offset = 0;
  private readonly bytes: Uint8Array;

  constructor(bytes: Uint8Array) {
    this.bytes = bytes;
  }

  remaining(): number {
    return this.bytes.length - this.offset;
  }

  nextString(): string {
    if (this.remaining() < 4) throw new Error("recovery-rejected");
    const view = new DataView(this.bytes.buffer, this.bytes.byteOffset, this.bytes.byteLength);
    const len = view.getUint32(this.offset, true);
    this.offset += 4;
    if (this.remaining() < len) throw new Error("recovery-rejected");
    const field = new TextDecoder().decode(this.bytes.subarray(this.offset, this.offset + len));
    this.offset += len;
    return field;
  }
}
