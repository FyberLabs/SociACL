/**
 * Argon2id floor and ceiling, and the fixed keyring byte cap.
 *
 * The floor is RFC 9106's second recommended option. Cost parameters are
 * pinned to that option, so a sealed copy cannot ask for less memory or
 * more. Salt length is the only range: 16 through 64 bytes.
 *
 * `KEYRING_SERIAL_MAX` is 256 KiB. The constant is unchanged. A retired
 * pair is 138 bytes. A prior base lane and a prior contact-lane secret
 * are 68 bytes each. 1024 of each list plus 1024 retired keys is about
 * 281237 bytes and does not fit. This cap rejects that encoding. Counting
 * prior lanes and prior contact-lane secrets is #68 and is not this cap.
 */
export const ARGON2ID_LIMITS = {
  version: { floor: 0x13, ceiling: 0x13 },
  memoryKiB: { floor: 65536, ceiling: 65536 },
  iterations: { floor: 3, ceiling: 3 },
  parallelism: { floor: 4, ceiling: 4 },
  hashLength: { floor: 32, ceiling: 32 },
  saltLength: { floor: 16, ceiling: 64 },
} as const;

/** Fixed cap on the serialized keyring plaintext. 256 KiB. Unchanged by the contact-lane secret. */
export const KEYRING_SERIAL_MAX = 262144;

/** Version byte, uncompressed P-256 point, 12-byte nonce, and the GCM tag. */
export const DELIVERY_BLOB_MAX = 1 + 65 + 12 + KEYRING_SERIAL_MAX + 16;

/** Envelope version, six u32 parameters, and the u64 keyring version. */
export const RECOVERY_HEADER_LEN = 1 + 4 * 6 + 8;

export const RECOVERY_NONCE_LEN = 12;
export const RECOVERY_TAG_LEN = 16;

/**
 * Header, nonce, plaintext cap, and tag. Salt length is not a term.
 * A 16-byte salt and a 64-byte salt allow the same plaintext.
 */
export const RECOVERY_ENVELOPE_MAX =
  RECOVERY_HEADER_LEN + RECOVERY_NONCE_LEN + KEYRING_SERIAL_MAX + RECOVERY_TAG_LEN;

/** Pre-parse ceiling: `RECOVERY_ENVELOPE_MAX` plus the salt ceiling. */
export const RECOVERY_ABSOLUTE_MAX = RECOVERY_ENVELOPE_MAX + ARGON2ID_LIMITS.saltLength.ceiling;

/** Cap on wrap rows stored for one principal, including the genesis backup. */
export const MAX_WRAPS_PER_PRINCIPAL = 64;
