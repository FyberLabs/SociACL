/**
 * Recovery-copy cryptography. Not a package export. Caller-chosen salt and
 * nonce are wrapped for tests in typescript/tests/support/recovery-deterministic.ts.
 *
 * Argon2id runs in hash-wasm. That build has no pthreads. Lanes for p=4 are
 * the serial loop in its Argon2 implementation, which is the same module a
 * browser loads.
 */
import { createCipheriv, createDecipheriv } from "node:crypto";
import { argon2id } from "hash-wasm";
import { parsePrincipalId, resolveCurrentKey, type PrincipalId, type ResolutionContext } from "../ids/src/index.js";
import { AccountKeyring } from "./account-keyring.ts";
import { bytesToHex } from "./account-key-seal.ts";
import { canonicalDecimal, lengthPrefixed } from "./canonical.ts";
import { decodeKeyring, encodeKeyring } from "./keyring-codec.ts";
import {
  ARGON2ID_LIMITS,
  KEYRING_SERIAL_MAX,
  RECOVERY_ABSOLUTE_MAX,
  RECOVERY_HEADER_LEN,
  RECOVERY_NONCE_LEN,
  RECOVERY_TAG_LEN,
} from "./keyring-limits.ts";
import { assigned, passphraseWhitespace } from "./unicode16.ts";
import { recoveryEnvelopeHash, signStoreWrite, verifyStoreWrite } from "./store-write.ts";

export const DOMAIN_RECOVERY = "sociacl-recovery-copy-v1";

export type RecoveryEnvelope = {
  readonly principal: PrincipalId;
  readonly rotationSeq: number;
  readonly signingPub: PrincipalId;
  readonly epub: PrincipalId;
  readonly bytes: Uint8Array;
};

/** Ciphertext adapter. Not an authority, and not Gun.
 *
 * Every put, commit, and delete carries a signature by the account's current
 * chain-head key. Implementations must verify it against the resolved
 * published chain before they write. Session authentication is not this
 * check. Panopticon is a verifier and a witness, never the authority.
 *
 * A put at the resolved head replaces the current copy and drops any pending
 * copy. A put at head + 1 is the only pending copy. Any other sequence is
 * `store-rejected`.
 */
export interface RecoveryCopyStore {
  readonly isAuthority: false;
  readonly seesPlaintext: false;
  readonly seesPassphrase: false;
  put(envelope: RecoveryEnvelope, signature: string, rotations: readonly unknown[], context: ResolutionContext): void;
  get(principal: PrincipalId, rotationSeq: number): RecoveryEnvelope | undefined;
  pending(principal: PrincipalId): RecoveryEnvelope | undefined;
  commit(principal: PrincipalId, signature: string, rotations: readonly unknown[], context: ResolutionContext): void;
  delete(principal: PrincipalId, rotationSeq: number, signature: string, rotations: readonly unknown[], context: ResolutionContext): void;
}

type RecoverySlot = { current?: RecoveryEnvelope; pending?: RecoveryEnvelope };

export class MemoryRecoveryStore implements RecoveryCopyStore {
  readonly isAuthority = false as const;
  readonly seesPlaintext = false as const;
  readonly seesPassphrase = false as const;
  /** Current copy per principal, plus at most one pending copy at head + 1. */
  readonly #slots = new Map<string, RecoverySlot>();

  put(envelope: RecoveryEnvelope, signature: string, rotations: readonly unknown[], context: ResolutionContext): void {
    if (envelope.bytes.length === 0 || envelope.bytes.length > RECOVERY_ABSOLUTE_MAX) throw new Error("store-rejected");
    if (headerRotationSeq(envelope.bytes) !== envelope.rotationSeq) throw new Error("store-rejected");
    const account = verifyStoreWrite(
      envelope.principal,
      "put",
      canonicalDecimal(envelope.rotationSeq),
      recoveryEnvelopeHash(envelope),
      signature,
      rotations,
      context,
    );
    const head = account.rotations.length;
    const slot = this.#slots.get(envelope.principal);
    if (slot?.current && slot.current.rotationSeq > head) throw new Error("store-rejected");
    const copy = copyEnvelope(envelope);
    if (copy.rotationSeq === head) {
      if (copy.signingPub !== account.currentKey || (account.currentEpub !== null && copy.epub !== account.currentEpub)) {
        throw new Error("store-rejected");
      }
      this.#slots.set(envelope.principal, { current: copy });
      return;
    }
    if (copy.rotationSeq === head + 1) {
      this.#slots.set(envelope.principal, { current: slot?.current, pending: copy });
      return;
    }
    throw new Error("store-rejected");
  }

  get(principal: PrincipalId, rotationSeq: number): RecoveryEnvelope | undefined {
    const slot = this.#slots.get(principal);
    if (!slot) return undefined;
    if (slot.current?.rotationSeq === rotationSeq) return copyEnvelope(slot.current);
    if (slot.pending?.rotationSeq === rotationSeq) return copyEnvelope(slot.pending);
    return undefined;
  }

  pending(principal: PrincipalId): RecoveryEnvelope | undefined {
    const pending = this.#slots.get(principal)?.pending;
    return pending ? copyEnvelope(pending) : undefined;
  }

  commit(principal: PrincipalId, signature: string, rotations: readonly unknown[], context: ResolutionContext): void {
    const slot = this.#slots.get(principal);
    const pending = slot?.pending;
    if (!slot || !pending) throw new Error("store-rejected");
    const resolved = resolveCurrentKey(principal, rotations, context);
    if (!resolved.ok) throw new Error("store-rejected");
    const head = resolved.value.rotations.length;
    const account = verifyStoreWrite(
      principal,
      "commit",
      canonicalDecimal(head),
      recoveryEnvelopeHash(pending),
      signature,
      rotations,
      context,
    );
    if (pending.rotationSeq === head) {
      if (account.currentEpub === null) throw new Error("store-rejected");
      if (pending.signingPub === account.currentKey && pending.epub === account.currentEpub) {
        slot.current = pending;
        slot.pending = undefined;
        return;
      }
      slot.pending = undefined;
      if (!slot.current) this.#slots.delete(principal);
      throw new Error("store-rejected");
    }
    if (pending.rotationSeq === head + 1) throw new Error("store-rejected");
    slot.pending = undefined;
    if (!slot.current) this.#slots.delete(principal);
    throw new Error("store-rejected");
  }

  delete(
    principal: PrincipalId,
    rotationSeq: number,
    signature: string,
    rotations: readonly unknown[],
    context: ResolutionContext,
  ): void {
    const slot = this.#slots.get(principal);
    const stored =
      slot?.current?.rotationSeq === rotationSeq
        ? slot.current
        : slot?.pending?.rotationSeq === rotationSeq
          ? slot.pending
          : undefined;
    if (!slot || !stored) throw new Error("store-rejected");
    verifyStoreWrite(
      principal,
      "delete",
      canonicalDecimal(rotationSeq),
      recoveryEnvelopeHash(stored),
      signature,
      rotations,
      context,
    );
    if (slot.current?.rotationSeq === rotationSeq) slot.current = undefined;
    if (slot.pending?.rotationSeq === rotationSeq) slot.pending = undefined;
    if (!slot.current && !slot.pending) this.#slots.delete(principal);
  }
}

function copyEnvelope(envelope: RecoveryEnvelope): RecoveryEnvelope {
  return {
    principal: envelope.principal,
    rotationSeq: envelope.rotationSeq,
    signingPub: envelope.signingPub,
    epub: envelope.epub,
    bytes: new Uint8Array(envelope.bytes),
  };
}

/** NFC, then UTF-8, against Unicode 16.0.0.
 *
 * A code point unassigned in Unicode 16.0.0 is `recovery-params` before NFC.
 * Whitespace is the Unicode 16 White_Space set, including U+0085. U+FEFF is
 * not whitespace. Empty and whitespace-only passphrases are `recovery-params`.
 * Leading and trailing whitespace around other characters is preserved.
 * JavaScript strings cannot be wiped. The byte API does not normalize; it
 * applies the same Unicode 16 checks.
 *
 * The runtime must normalize Unicode 16.0.0. A runtime whose NFC is older
 * than Unicode 16 is `unicode-version` and does not derive a key. The probe
 * is U+11382 U+113C9, which Unicode 16 composes to U+11383. */
export function encodePassphrase(passphrase: string): Uint8Array {
  if ("\u{11382}\u{113C9}".normalize("NFC") !== "\u{11383}") throw new Error("unicode-version");
  if (passphrase.length === 0 || !unicode16Text(passphrase)) throw new Error("recovery-params");
  const nfc = passphrase.normalize("NFC");
  if ([...nfc].every((ch) => passphraseWhitespace(ch.codePointAt(0) ?? -1))) throw new Error("recovery-params");
  return new TextEncoder().encode(nfc);
}

function unicode16Text(text: string): boolean {
  for (const ch of text) {
    const cp = ch.codePointAt(0);
    if (cp === undefined || !assigned(cp)) return false;
  }
  return true;
}

function passphraseRejected(bytes: Uint8Array): boolean {
  if (bytes.length === 0) return true;
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return false;
  }
  if (!unicode16Text(text)) return true;
  return [...text].every((ch) => passphraseWhitespace(ch.codePointAt(0) ?? -1));
}

/** Caller-chosen salt and nonce. Tests use this through the support wrapper. */
export async function sealRecoveryCopyWith(
  keyring: AccountKeyring,
  passphrase: Uint8Array,
  salt: Uint8Array,
  nonce: Uint8Array,
  store: RecoveryCopyStore,
  rotations: readonly unknown[],
  context: ResolutionContext,
  signerPriv: string,
): Promise<RecoveryEnvelope> {
  if (keyring.priorLanes().length !== keyring.rotationSeq) throw new Error("bad-lane");
  if (passphraseRejected(passphrase)) throw new Error("recovery-params");
  if (
    salt.length < ARGON2ID_LIMITS.saltLength.floor ||
    salt.length > ARGON2ID_LIMITS.saltLength.ceiling ||
    nonce.length !== RECOVERY_NONCE_LEN
  ) {
    throw new Error("recovery-params");
  }
  let plain: Uint8Array | undefined;
  let key: Uint8Array | undefined;
  try {
    plain = encodeKeyring(keyring);
    key = await deriveKey(
      passphrase,
      salt,
      ARGON2ID_LIMITS.memoryKiB.floor,
      ARGON2ID_LIMITS.iterations.floor,
      ARGON2ID_LIMITS.parallelism.floor,
      ARGON2ID_LIMITS.hashLength.floor,
    );
    const aad = recoveryAad(
      keyring.principal,
      keyring.rotationSeq,
      keyring.pub,
      keyring.epub,
      ARGON2ID_LIMITS.memoryKiB.floor,
      ARGON2ID_LIMITS.iterations.floor,
      ARGON2ID_LIMITS.parallelism.floor,
      ARGON2ID_LIMITS.hashLength.floor,
      ARGON2ID_LIMITS.version.floor,
      salt,
    );
    const ciphertext = aesEncrypt(key, nonce, aad, plain);
    const header = writeHeader(
      ARGON2ID_LIMITS.version.floor,
      ARGON2ID_LIMITS.memoryKiB.floor,
      ARGON2ID_LIMITS.iterations.floor,
      ARGON2ID_LIMITS.parallelism.floor,
      ARGON2ID_LIMITS.hashLength.floor,
      salt,
      keyring.rotationSeq,
    );
    const bytes = new Uint8Array(header.length + nonce.length + ciphertext.length);
    bytes.set(header, 0);
    bytes.set(nonce, header.length);
    bytes.set(ciphertext, header.length + nonce.length);
    if (bytes.length > RECOVERY_ABSOLUTE_MAX) throw new Error("keyring-too-large");
    const envelope: RecoveryEnvelope = {
      principal: keyring.principal,
      rotationSeq: keyring.rotationSeq,
      signingPub: keyring.pub,
      epub: keyring.epub,
      bytes,
    };
    const signature = signStoreWrite(
      signerPriv,
      envelope.principal,
      "put",
      canonicalDecimal(envelope.rotationSeq),
      recoveryEnvelopeHash(envelope),
    );
    store.put(envelope, signature, rotations, context);
    return envelope;
  } finally {
    plain?.fill(0);
    key?.fill(0);
  }
}

export async function openRecoveryCopy(
  passphrase: Uint8Array,
  envelope: RecoveryEnvelope,
  expected: PrincipalId,
  expectedRotationSeq: number,
  rotations: readonly unknown[],
  context: ResolutionContext,
): Promise<AccountKeyring> {
  if (envelope.bytes.length > RECOVERY_ABSOLUTE_MAX) throw new Error("keyring-too-large");
  const header = parseHeader(envelope.bytes);
  if (passphraseRejected(passphrase)) throw new Error("recovery-params");
  if (envelope.principal !== expected || header.rotationSeq !== envelope.rotationSeq) throw new Error("recovery-rejected");
  if (!Number.isSafeInteger(header.rotationSeq)) throw new Error("recovery-rejected");
  const key = await deriveKey(passphrase, header.salt, header.memoryKiB, header.iterations, header.parallelism, header.hashLength);
  let plain: Uint8Array | undefined;
  try {
    const aad = recoveryAad(
      expected,
      header.rotationSeq,
      envelope.signingPub,
      envelope.epub,
      header.memoryKiB,
      header.iterations,
      header.parallelism,
      header.hashLength,
      header.version,
      header.salt,
    );
    try {
      plain = aesDecrypt(key, header.nonce, aad, header.ciphertext);
    } catch {
      throw new Error("recovery-rejected");
    }
    if (plain.length > KEYRING_SERIAL_MAX) throw new Error("keyring-too-large");
    const fields = decodeKeyring(plain);
    const parsed = parsePrincipalId(fields.principal);
    if (!parsed.ok || parsed.value !== fields.principal || parsed.value !== expected) throw new Error("recovery-rejected");
    if (fields.rotationSeq !== header.rotationSeq || fields.pub !== envelope.signingPub || fields.epub !== envelope.epub) {
      throw new Error("recovery-rejected");
    }
    if (fields.rotationSeq !== expectedRotationSeq) throw new Error("recovery-stale");
    return AccountKeyring.import(
      fields.principal,
      fields.genesisEpub,
      fields.pub,
      fields.priv,
      fields.epub,
      fields.epriv,
      fields.retired,
      fields.laneId,
      fields.contentEpoch,
      fields.rotationSeq,
      rotations,
      context,
      fields.priorLanes,
    );
  } finally {
    key.fill(0);
    plain?.fill(0);
    header.salt.fill(0);
  }
}

function deriveKey(
  passphrase: Uint8Array,
  salt: Uint8Array,
  memoryKiB: number,
  iterations: number,
  parallelism: number,
  hashLength: number,
): Promise<Uint8Array> {
  if (
    !inBound(ARGON2ID_LIMITS.version.floor, ARGON2ID_LIMITS.version) ||
    !inBound(memoryKiB, ARGON2ID_LIMITS.memoryKiB) ||
    !inBound(iterations, ARGON2ID_LIMITS.iterations) ||
    !inBound(parallelism, ARGON2ID_LIMITS.parallelism) ||
    !inBound(hashLength, ARGON2ID_LIMITS.hashLength) ||
    !inBound(salt.length, ARGON2ID_LIMITS.saltLength) ||
    hashLength !== 32
  ) {
    return Promise.reject(new Error("recovery-params"));
  }
  const copy = new Uint8Array(passphrase);
  return argon2id({
    password: copy,
    salt,
    parallelism,
    iterations,
    memorySize: memoryKiB,
    hashLength,
    outputType: "binary",
  }).finally(() => {
    copy.fill(0);
  });
}

function inBound(value: number, bound: { readonly floor: number; readonly ceiling: number }): boolean {
  return Number.isInteger(value) && value >= bound.floor && value <= bound.ceiling;
}

function parseHeader(bytes: Uint8Array): {
  version: number;
  memoryKiB: number;
  iterations: number;
  parallelism: number;
  hashLength: number;
  rotationSeq: number;
  salt: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
} {
  if (bytes.length < RECOVERY_HEADER_LEN || bytes[0] !== 1) throw new Error("recovery-rejected");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const version = view.getUint32(1, true);
  const memoryKiB = view.getUint32(5, true);
  const iterations = view.getUint32(9, true);
  const parallelism = view.getUint32(13, true);
  const hashLength = view.getUint32(17, true);
  const saltLen = view.getUint32(21, true);
  const rotationSeq = view.getUint32(29, true) * 0x100000000 + view.getUint32(25, true);
  if (
    !inBound(version, ARGON2ID_LIMITS.version) ||
    !inBound(memoryKiB, ARGON2ID_LIMITS.memoryKiB) ||
    !inBound(iterations, ARGON2ID_LIMITS.iterations) ||
    !inBound(parallelism, ARGON2ID_LIMITS.parallelism) ||
    !inBound(hashLength, ARGON2ID_LIMITS.hashLength) ||
    !inBound(saltLen, ARGON2ID_LIMITS.saltLength)
  ) {
    throw new Error("recovery-params");
  }
  const saltEnd = RECOVERY_HEADER_LEN + saltLen;
  const nonceEnd = saltEnd + RECOVERY_NONCE_LEN;
  if (bytes.length < nonceEnd) throw new Error("recovery-rejected");
  const ciphertext = bytes.subarray(nonceEnd);
  if (ciphertext.length > KEYRING_SERIAL_MAX + RECOVERY_TAG_LEN) throw new Error("keyring-too-large");
  if (ciphertext.length < RECOVERY_TAG_LEN) throw new Error("recovery-rejected");
  return {
    version,
    memoryKiB,
    iterations,
    parallelism,
    hashLength,
    rotationSeq,
    salt: bytes.slice(RECOVERY_HEADER_LEN, saltEnd),
    nonce: bytes.slice(saltEnd, nonceEnd),
    ciphertext: bytes.slice(nonceEnd),
  };
}

function headerRotationSeq(bytes: Uint8Array): number {
  if (bytes.length < RECOVERY_HEADER_LEN || bytes[0] !== 1) throw new Error("store-rejected");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return view.getUint32(29, true) * 0x100000000 + view.getUint32(25, true);
}

function writeHeader(
  version: number,
  memoryKiB: number,
  iterations: number,
  parallelism: number,
  hashLength: number,
  salt: Uint8Array,
  rotationSeq: number,
): Uint8Array {
  const header = new Uint8Array(RECOVERY_HEADER_LEN + salt.length);
  const view = new DataView(header.buffer);
  header[0] = 1;
  view.setUint32(1, version, true);
  view.setUint32(5, memoryKiB, true);
  view.setUint32(9, iterations, true);
  view.setUint32(13, parallelism, true);
  view.setUint32(17, hashLength, true);
  view.setUint32(21, salt.length, true);
  view.setUint32(25, rotationSeq >>> 0, true);
  view.setUint32(29, Math.floor(rotationSeq / 0x100000000), true);
  header.set(salt, RECOVERY_HEADER_LEN);
  return header;
}

function recoveryAad(
  principal: string,
  rotationSeq: number,
  signingPub: string,
  epub: string,
  memoryKiB: number,
  iterations: number,
  parallelism: number,
  hashLength: number,
  argonVersion: number,
  salt: Uint8Array,
): Uint8Array {
  const parsed = parsePrincipalId(principal);
  if (!parsed.ok || parsed.value !== principal) throw new Error("recovery-rejected");
  const signing = parsePrincipalId(signingPub);
  if (!signing.ok || signing.value !== signingPub) throw new Error("recovery-rejected");
  const encryption = parsePrincipalId(epub);
  if (!encryption.ok || encryption.value !== epub) throw new Error("recovery-rejected");
  return lengthPrefixed([
    DOMAIN_RECOVERY,
    parsed.value,
    canonicalDecimal(rotationSeq),
    signing.value,
    encryption.value,
    canonicalDecimal(memoryKiB),
    canonicalDecimal(iterations),
    canonicalDecimal(parallelism),
    canonicalDecimal(hashLength),
    canonicalDecimal(argonVersion),
    bytesToHex(salt),
  ]);
}

function aesEncrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, plain: Uint8Array): Uint8Array {
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(aad);
  return new Uint8Array(Buffer.concat([cipher.update(plain), cipher.final(), cipher.getAuthTag()]));
}

function aesDecrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, body: Uint8Array): Uint8Array {
  const tag = body.subarray(body.length - 16);
  const data = body.subarray(0, body.length - 16);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return new Uint8Array(Buffer.concat([decipher.update(data), decipher.final()]));
}
