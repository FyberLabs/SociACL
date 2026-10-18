/**
 * Passphrase recovery copy of an account keyring.
 *
 * The sealing key is Argon2id. The passphrase is an argument and is not
 * stored. The envelope goes to a RecoveryCopyStore, which keeps ciphertext
 * only. Panopticon is that kind of adapter: an index, not the authority.
 * priv and epriv never go on Gun.
 *
 * Salt and nonce are drawn inside sealRecoveryCopy. The deterministic helper
 * is not exported from this module.
 */
import { rotateKeyring, type AccountKeyring, type KeyringRotation, type RotationMint } from "./account-keyring.ts";
import { ARGON2ID_LIMITS } from "./keyring-limits.ts";
import {
  encodePassphrase,
  MemoryRecoveryStore,
  openRecoveryCopy,
  sealRecoveryCopyWith,
  type RecoveryCopyStore,
  type RecoveryEnvelope,
} from "./recovery-seal.ts";
import type { PrincipalId, ResolutionContext } from "../ids/src/index.js";

export { ARGON2ID_LIMITS, KEYRING_SERIAL_MAX, DELIVERY_BLOB_MAX, RECOVERY_ABSOLUTE_MAX, RECOVERY_ENVELOPE_MAX } from "./keyring-limits.ts";
export { encodePassphrase, MemoryRecoveryStore, openRecoveryCopy };
export type { RecoveryCopyStore, RecoveryEnvelope };

export async function sealRecoveryCopy(
  keyring: AccountKeyring,
  passphrase: Uint8Array,
  store: RecoveryCopyStore,
): Promise<RecoveryEnvelope> {
  const salt = new Uint8Array(ARGON2ID_LIMITS.saltLength.floor);
  const nonce = new Uint8Array(12);
  crypto.getRandomValues(salt);
  crypto.getRandomValues(nonce);
  try {
    return await sealRecoveryCopyWith(keyring, passphrase, salt, nonce, store);
  } finally {
    salt.fill(0);
    nonce.fill(0);
  }
}

/** Seal with a passphrase string. The string is NFC-normalized, then UTF-8. */
export async function sealRecoveryCopyFromString(
  keyring: AccountKeyring,
  passphrase: string,
  store: RecoveryCopyStore,
): Promise<RecoveryEnvelope> {
  const bytes = encodePassphrase(passphrase);
  try {
    return await sealRecoveryCopy(keyring, bytes, store);
  } finally {
    bytes.fill(0);
  }
}

/** Open with a passphrase string. The string is NFC-normalized, then UTF-8. */
export async function openRecoveryCopyFromString(
  passphrase: string,
  envelope: RecoveryEnvelope,
  expected: PrincipalId,
  expectedRotationSeq: number,
  rotations: readonly unknown[],
  context: ResolutionContext,
): Promise<AccountKeyring> {
  const bytes = encodePassphrase(passphrase);
  try {
    return await openRecoveryCopy(bytes, envelope, expected, expectedRotationSeq, rotations, context);
  } finally {
    bytes.fill(0);
  }
}

/** Rotate, then seal a recovery copy of the new keyring version. */
export async function rotateAndReseal(
  keyring: AccountKeyring,
  trusted: readonly string[],
  lost: string,
  rotations: readonly unknown[],
  context: ResolutionContext,
  passphrase: Uint8Array,
  store: RecoveryCopyStore,
  mint: () => RotationMint,
): Promise<{ rotation: KeyringRotation; envelope: RecoveryEnvelope }> {
  const rotation = rotateKeyring(keyring, trusted, lost, rotations, context, mint);
  const envelope = await sealRecoveryCopy(rotation.keyring, passphrase, store);
  return { rotation, envelope };
}
