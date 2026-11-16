/** Shared recovery wire parsing, KDF and AAD. No Node crypto or store operations. */
import {argon2id} from 'hash-wasm';
import {parsePrincipalId} from '../ids/src/index.js';
import {canonicalDecimal,lengthPrefixed} from './canonical.ts';
import {ARGON2ID_LIMITS,KEYRING_SERIAL_MAX,RECOVERY_HEADER_LEN,RECOVERY_NONCE_LEN,RECOVERY_TAG_LEN} from './keyring-limits.ts';
import {assigned,passphraseWhitespace} from './unicode16.ts';
export const DOMAIN_RECOVERY='sociacl-recovery-copy-v1';
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

export function passphraseRejected(bytes: Uint8Array): boolean {
  if (bytes.length === 0) return true;
  let text: string;
  try {
    // U+FEFF is a passphrase character. The UTF-8 BOM must stay in the text.
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return false;
  }
  if (!unicode16Text(text)) return true;
  return [...text].every((ch) => passphraseWhitespace(ch.codePointAt(0) ?? -1));
}

export function deriveKey(
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

export function parseHeader(bytes: Uint8Array): {
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

export function headerRotationSeq(bytes: Uint8Array): number {
  if (bytes.length < RECOVERY_HEADER_LEN || bytes[0] !== 1) throw new Error("store-rejected");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return view.getUint32(29, true) * 0x100000000 + view.getUint32(25, true);
}

export function writeHeader(
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

export function recoveryAad(
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
    Array.from(salt,b=>b.toString(16).padStart(2,'0')).join(''),
  ]);
}

