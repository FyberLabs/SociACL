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
import { checkRecoveryPassphrase, RecoveryWeakPassphraseError } from "./passphrase-strength.ts";
import {
  encodePassphrase,
  MemoryRecoveryStore,
  openRecoveryCopy,
  sealRecoveryCopyWith,
  signRecoveryOp,
  type RecoveryCopyStore,
  type RecoveryEnvelope,
} from "./recovery-seal.ts";
import { recoveryEnvelopeHash, REPLACED_NONE } from "./store-write.ts";
import { type PrincipalId, type ResolutionContext } from "../ids/src/index.js";

export { ARGON2ID_LIMITS, KEYRING_SERIAL_MAX, KEYRING_SERIAL_V2_MAX, DELIVERY_BLOB_MAX, RECOVERY_ABSOLUTE_MAX, RECOVERY_ENVELOPE_MAX } from "./keyring-limits.ts";
export { checkRecoveryPassphrase, RecoveryWeakPassphraseError, encodePassphrase, MemoryRecoveryStore, openRecoveryCopy };
export type { RecoveryCopyStore, RecoveryEnvelope };

export async function sealRecoveryCopy(
  keyring: AccountKeyring,
  passphrase: Uint8Array,
  store: RecoveryCopyStore,
  handle?: string,
): Promise<RecoveryEnvelope> {
  const salt = new Uint8Array(ARGON2ID_LIMITS.saltLength.floor);
  const nonce = new Uint8Array(12);
  crypto.getRandomValues(salt);
  crypto.getRandomValues(nonce);
  try {
    return await sealRecoveryCopyWith(keyring, passphrase, salt, nonce, keyring.currentPriv(), store, handle);
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
  handle?: string,
): Promise<RecoveryEnvelope> {
  const bytes = encodePassphrase(passphrase);
  try {
    return await sealRecoveryCopy(keyring, bytes, store, handle);
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

/** Promote the pending copy when its sequence and public keys equal the published chain head the store resolved for itself.
 *
 * `signerPriv` must be that head key. A chain that does not resolve, a
 * signature that does not verify, a pending copy at head + 1, and a pending
 * copy whose public keys differ are `store-rejected`. None of those outcomes
 * change the stored copies.
 */
export function commitRecoveryCopy(
  principal: PrincipalId,
  signerPriv: string,
  store: RecoveryCopyStore,
): void {
  const pending = store.pending(principal);
  if (!pending) throw new Error("store-rejected");
  const account = store.publishedAccount(principal);
  const current = store.current(principal);
  const signature = signRecoveryOp(
    store,
    signerPriv,
    principal,
    "commit",
    account.rotations.length,
    recoveryEnvelopeHash(pending),
    current ? recoveryEnvelopeHash(current) : REPLACED_NONE,
  );
  store.commit(principal, signature);
}

/** Delete the current or pending copy at `rotationSeq`. Does not promote. */
export function deleteRecoveryCopy(
  principal: PrincipalId,
  rotationSeq: number,
  signerPriv: string,
  store: RecoveryCopyStore,
): void {
  const envelope = store.get(principal, rotationSeq);
  if (!envelope) throw new Error("store-rejected");
  const hash = recoveryEnvelopeHash(envelope);
  const signature = signRecoveryOp(store, signerPriv, principal, "delete", rotationSeq, hash, hash);
  store.delete(principal, rotationSeq, signature);
}

/** Rotate, then seal a pending recovery copy of the new keyring version.
 * The pending put is signed by the key that is still the published chain head. */
export async function rotateAndReseal(
  keyring: AccountKeyring,
  trusted: readonly string[],
  lost: string,
  rotations: readonly unknown[],
  context: ResolutionContext,
  passphrase: Uint8Array,
  store: RecoveryCopyStore,
  mint: () => RotationMint,
  handle?: string,
): Promise<{ rotation: KeyringRotation; envelope: RecoveryEnvelope }> {
  const rotation = rotateKeyring(keyring, trusted, lost, rotations, context, mint);
  const salt = new Uint8Array(ARGON2ID_LIMITS.saltLength.floor);
  const nonce = new Uint8Array(12);
  crypto.getRandomValues(salt);
  crypto.getRandomValues(nonce);
  try {
    const envelope = await sealRecoveryCopyWith(
      rotation.keyring,
      passphrase,
      salt,
      nonce,
      keyring.currentPriv(),
      store,
      handle,
    );
    return { rotation, envelope };
  } finally {
    salt.fill(0);
    nonce.fill(0);
  }
}

export { resolveStoreAccount } from "./store-write.ts";
