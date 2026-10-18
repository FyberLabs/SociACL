//! Argon2id floor and ceiling, and the fixed keyring byte cap.
//!
//! The floor is RFC 9106's second recommended option. The ceiling for the
//! cost parameters is that same option, so a sealed copy cannot ask for
//! less memory or more. Salt length is the only range: 16 through 64 bytes.
//!
//! `KEYRING_SERIAL_MAX` is 256 KiB. It is not computed from `priorLanes`.
//! 1024 retired encryption keys, the #67 cap, encode to 1024 × 138 bytes
//! plus a fixed header under 1 KiB. 256 KiB is the power of two above that.
//! A prior-lane list that pushes the encoding over this constant is rejected.
//! Counting prior lanes is #68 F1 and is not this cap.

/// Inclusive floor and ceiling for one Argon2id parameter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Argon2Bound {
    pub floor: u32,
    pub ceiling: u32,
}

/// Floor and ceiling for the recovery KDF. One constant.
///
/// `version`, `memory_kib`, `iterations`, `parallelism`, and `hash_length`
/// are pinned to RFC 9106's second option (Argon2 version `0x13`). A value
/// outside a bound is refused on seal and on open, before the KDF runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Argon2IdLimits {
    pub version: Argon2Bound,
    pub memory_kib: Argon2Bound,
    pub iterations: Argon2Bound,
    pub parallelism: Argon2Bound,
    pub hash_length: Argon2Bound,
    pub salt_length: Argon2Bound,
}

pub const ARGON2ID_LIMITS: Argon2IdLimits = Argon2IdLimits {
    version: Argon2Bound {
        floor: 0x13,
        ceiling: 0x13,
    },
    memory_kib: Argon2Bound {
        floor: 65_536,
        ceiling: 65_536,
    },
    iterations: Argon2Bound {
        floor: 3,
        ceiling: 3,
    },
    parallelism: Argon2Bound {
        floor: 4,
        ceiling: 4,
    },
    hash_length: Argon2Bound {
        floor: 32,
        ceiling: 32,
    },
    salt_length: Argon2Bound {
        floor: 16,
        ceiling: 64,
    },
};

/// Fixed cap on the serialized keyring plaintext. Not a function of `priorLanes`.
pub const KEYRING_SERIAL_MAX: usize = 262_144;

/// Version byte, uncompressed P-256 point, 12-byte nonce, and the GCM tag.
pub const DELIVERY_BLOB_MAX: usize = 1 + 65 + 12 + KEYRING_SERIAL_MAX + 16;

/// Envelope version, six u32 parameters, and the u64 keyring version.
pub const RECOVERY_HEADER_LEN: usize = 1 + (4 * 6) + 8;

pub const RECOVERY_NONCE_LEN: usize = 12;
pub const RECOVERY_TAG_LEN: usize = 16;

/// Largest recovery envelope. A longer blob is refused before the KDF and before decrypt.
pub const RECOVERY_ENVELOPE_MAX: usize = RECOVERY_HEADER_LEN
    + ARGON2ID_LIMITS.salt_length.ceiling as usize
    + RECOVERY_NONCE_LEN
    + KEYRING_SERIAL_MAX
    + RECOVERY_TAG_LEN;

pub(crate) fn in_bound(value: u32, bound: Argon2Bound) -> bool {
    value >= bound.floor && value <= bound.ceiling
}
