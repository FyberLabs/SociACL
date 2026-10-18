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
import { recoveryEnvelopeHash, signStoreWrite } from "./store-write.ts";
import { canonicalDecimal } from "./canonical.ts";
import { resolveCurrentKey, type PrincipalId, type ResolutionContext } from "../ids/src/index.js";

export { ARGON2ID_LIMITS, KEYRING_SERIAL_MAX, DELIVERY_BLOB_MAX, RECOVERY_ABSOLUTE_MAX, RECOVERY_ENVELOPE_MAX } from "./keyring-limits.ts";
export { encodePassphrase, MemoryRecoveryStore, openRecoveryCopy };
export type { RecoveryCopyStore, RecoveryEnvelope };

export async function sealRecoveryCopy(
  keyring: AccountKeyring,
  passphrase: Uint8Array,
  store: RecoveryCopyStore,
  rotations: readonly unknown[],
  context: ResolutionContext,
): Promise<RecoveryEnvelope> {
  const salt = new Uint8Array(ARGON2ID_LIMITS.saltLength.floor);
  const nonce = new Uint8Array(12);
  crypto.getRandomValues(salt);
  crypto.getRandomValues(nonce);
  try {
    return await sealRecoveryCopyWith(keyring, passphrase, salt, nonce, store, rotations, context, keyring.currentPriv());
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
  rotations: readonly unknown[],
  context: ResolutionContext,
): Promise<RecoveryEnvelope> {
  const bytes = encodePassphrase(passphrase);
  try {
    return await sealRecoveryCopy(keyring, bytes, store, rotations, context);
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

/** Promote the pending copy when its sequence and public keys equal the resolved chain head.
 *
 * `signerPriv` is the current chain-head key. Commit must be given the chain
 * read back from the published source. An unsigned draft does not resolve.
 * A signed rotation that is not on that chain is not promoted: a pending copy
 * at head + 1 stays. A pending copy whose public keys differ is dropped, and
 * so is a pending copy at neither head nor head + 1. The current copy stays.
 */
export function commitRecoveryCopy(
  principal: PrincipalId,
  signerPriv: string,
  rotations: readonly unknown[],
  context: ResolutionContext,
  store: RecoveryCopyStore,
): void {
  const pending = store.pending(principal);
  if (!pending) throw new Error("store-rejected");
  const resolved = resolveCurrentKey(principal, rotations, context);
  if (!resolved.ok) throw new Error("store-rejected");
  const signature = signStoreWrite(
    signerPriv,
    principal,
    "commit",
    canonicalDecimal(resolved.value.rotations.length),
    recoveryEnvelopeHash(pending),
  );
  store.commit(principal, signature, rotations, context);
}

/** Delete the current or pending copy at `rotationSeq`. Does not promote. */
export function deleteRecoveryCopy(
  principal: PrincipalId,
  rotationSeq: number,
  signerPriv: string,
  rotations: readonly unknown[],
  context: ResolutionContext,
  store: RecoveryCopyStore,
): void {
  const envelope = store.get(principal, rotationSeq);
  if (!envelope) throw new Error("store-rejected");
  const signature = signStoreWrite(
    signerPriv,
    principal,
    "delete",
    canonicalDecimal(rotationSeq),
    recoveryEnvelopeHash(envelope),
  );
  store.delete(principal, rotationSeq, signature, rotations, context);
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
      store,
      rotations,
      context,
      keyring.currentPriv(),
    );
    return { rotation, envelope };
  } finally {
    salt.fill(0);
    nonce.fill(0);
  }
}
