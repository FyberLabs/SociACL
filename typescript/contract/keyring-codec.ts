/**
 * Length-prefixed account keyring. Shared by the recovery copy and device
 * delivery. Secrets stay in the plaintext only until the caller seals it.
 */
import type { AccountKeyring } from "./account-keyring.ts";
import { canonicalDecimal, lengthPrefixed } from "./canonical.ts";
import { KEYRING_HISTORY_MAX, KEYRING_SERIAL_MAX } from "./keyring-limits.ts";

const DOMAIN_KEYRING_PLAIN_V1 = "sociacl-keyring-plain-v1";
export const DOMAIN_KEYRING_PLAIN = "sociacl-keyring-plain-v2";

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
  contactLaneSecret: string;
  priorContactSecrets: string[];
  contentEpoch: number;
  rotationSeq: number;
};

export function encodeKeyring(keyring: AccountKeyring): Uint8Array {
  const retired = keyring.retired();
  const prior = keyring.priorLanes();
  const priorContact = keyring.priorContactSecrets();
  if (prior.length > KEYRING_HISTORY_MAX || priorContact.length > KEYRING_HISTORY_MAX
    || keyring.rotationSeq > KEYRING_HISTORY_MAX) throw new Error("keyring-too-large");
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
  fields.push(keyring.contactLaneSecret(), canonicalDecimal(priorContact.length));
  for (const secret of priorContact) fields.push(secret);
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
  const domain = cursor.nextString();
  if (domain === DOMAIN_KEYRING_PLAIN_V1 || domain !== DOMAIN_KEYRING_PLAIN) throw new Error("recovery-rejected");
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
  if (priorCount > KEYRING_HISTORY_MAX) throw new Error("keyring-too-large");
  if (priorCount * 4 > cursor.remaining()) throw new Error("recovery-rejected");
  const priorLanes: string[] = [];
  for (let i = 0; i < priorCount; i += 1) priorLanes.push(cursor.nextString());
  const contactLaneSecret = cursor.nextString();
  const contactPriorCount = decimal(cursor.nextString());
  if (contactPriorCount > KEYRING_HISTORY_MAX) throw new Error("keyring-too-large");
  if (contactPriorCount * 4 > cursor.remaining()) throw new Error("recovery-rejected");
  const priorContactSecrets: string[] = [];
  for (let i = 0; i < contactPriorCount; i += 1) priorContactSecrets.push(cursor.nextString());
  const contentEpoch = decimal(cursor.nextString());
  const rotationSeq = decimal(cursor.nextString());
  if (rotationSeq > KEYRING_HISTORY_MAX) throw new Error("keyring-too-large");
  if (cursor.remaining() !== 0) throw new Error("recovery-rejected");
  return {
    principal,
    genesisEpub,
    pub,
    priv,
    epub,
    epriv,
    retired,
    laneId,
    priorLanes,
    contactLaneSecret,
    priorContactSecrets,
    contentEpoch,
    rotationSeq,
  };
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
