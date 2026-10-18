/**
 * Deliver an account keyring to a device. The outer domains are separate from the genesis backup.
 *
 * The transport public key arrives out of band. The ciphertext goes to a
 * KeyWrapStore. The device inherits the account keypair and does not mint
 * an identity. The ephemeral key and nonce are drawn inside deliverKeyring.
 * The deterministic helper is not exported from this module.
 */
import { randomBytes } from "node:crypto";
import type { ObjectId, ResolutionContext } from "../ids/src/index.js";
import type { EncryptedAccountWrap, KeyWrapStore } from "./account-key.ts";
import { randomScalar } from "./account-key-seal.ts";
import type { AccountKeyring } from "./account-keyring.ts";
import { deliverKeyringWith, openDeliveredKeyring } from "./delivery-seal.ts";

export { openDeliveredKeyring };
export { DELIVERY_BLOB_MAX, KEYRING_SERIAL_MAX } from "./keyring-limits.ts";

export function deliverKeyring(
  keyring: AccountKeyring,
  transportPub: string,
  wrapId: ObjectId,
  rotations: readonly unknown[],
  context: ResolutionContext,
  store: KeyWrapStore,
): EncryptedAccountWrap {
  const ephemeral = randomScalar();
  const nonce = randomBytes(12);
  try {
    return deliverKeyringWith(keyring, transportPub, ephemeral, nonce, wrapId, rotations, context, store);
  } finally {
    ephemeral.fill(0);
    nonce.fill(0);
  }
}
