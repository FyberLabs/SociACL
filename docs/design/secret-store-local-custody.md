# Local vault custody v1

The initial #155 backend is a passphrase-sealed Unix file. The approved payload
limit is 1 MiB (1,048,576 bytes), with at most 16 KiB of encrypted metadata.
`vault_local.rs` implements custody encryption; `vault_file.rs` implements a
private, atomic ciphertext snapshot store. These APIs do not implement a signed
vault version, a grant, Check, an offline authorization lease or a sync protocol.
The passphrase option is weaker than a hardware-backed device key: a stolen file
allows offline guesses. There is no implicit hardware fallback or claim of TPM,
Secure Enclave, StrongBox or WebAuthn protection.

## Exact framing

All lengths below are bytes. No optional fields or trailing bytes are permitted
by authenticated opening. Integers inside the ciphertext are little-endian u32.

| Offset | Length | Value |
| --- | --- | --- |
| 0 | 8 | ASCII `SAVFILE1` |
| 8 | 16 | Fresh random Argon2id salt |
| 24 | 24 | Fresh random key-wrap nonce |
| 48 | 24 | Fresh random content nonce |
| 72 | 32 | Opaque item ID, random on creation |
| 104 | 32 | Fresh random version ID |
| 136 | 48 | Encrypted 32-byte DEK plus 16-byte authentication tag |
| 184 | variable | Encrypted inner record plus 16-byte authentication tag |

The inner record is the canonical 87-byte SEA owner, metadata length, content
length, metadata, then content. Its fixed prefix is 95 bytes. Minimum envelope
size is 295 bytes; maximum is 1,065,255 bytes. Owner, names, labels and content are
inside authenticated encryption. Sizes, random identifiers, salts and nonces are
visible. File existence, access patterns and timing remain visible to local
observers; no padding is promised. This local format is not the network format.

The password is NFC-encoded by `encode_passphrase`, bounded to 4096 UTF-8 bytes
before and after encoding. Seal applies the existing recovery-passphrase strength
policy; open does not rescore existing passwords. Argon2id v0x13 uses 65,536 KiB,
three iterations, four lanes and a 32-byte result. Parameters are fixed, never
read from untrusted input. Input lengths and magic are checked before the KDF.

The KEK wraps a fresh random 32-byte DEK using XChaCha20-Poly1305. Its AAD is the
UTF-8 bytes `sociacl-vault-local-wrap-v1`, a zero byte, and the entire 136-byte
header. Content uses the DEK and XChaCha20-Poly1305. Its AAD is
`sociacl-vault-local-data-v1`, a zero byte, the header and the complete 48-byte
wrapped DEK. Both nonces and the salt are generated afresh on every seal. Owner
comparison happens only after successful authentication. Sensitive internal
buffers are zeroized on drop; caller-owned input/output copies remain the
caller's responsibility. No API accepts caller-supplied nonces or DEKs.

## File and head contract

The caller supplies a trusted parent directory. Explicit initialization creates
one 0700 directory and fsyncs its trusted parent before reporting success; reopening never creates or repairs missing state. The backend
checks directory identity and mode, uses no-follow file opens and admits only
0600 regular files with one hard link and matching directory ownership. Item
filenames contain only the opaque 64-character lowercase hex ID.

Writes acquire a per-item directory lock, compare the independently supplied old
head, write ciphertext to a fresh create-only 0600 temporary file, fsync it,
rename atomically and fsync the directory. `None` is create-only. The head binds
item ID, version ID and SHA-256 of the complete ciphertext. Concurrent stale
writers fail; no timestamp or arrival-order merge occurs. An exact ciphertext
retry succeeds after durability reconciliation even when the supplied old head
has already advanced to that candidate. Errors after rename are ambiguous; the
caller reconciles against its retained candidate head. A crash lock is never
automatically declared stale or broken. Operator recovery must establish that no
writer is active before removing it.

Reads require an independently retained expected head. Missing files, changed
permissions, symlinks and stale ciphertext fail. **A head read from the same
untrusted backup is not a rollback defense.** A protected, crash-consistent head
ledger and signed-version admission are still required for the complete vault.
The adapter retains one snapshot; immutable history retention, conflict graphs,
audit chains and atomic epoch/wrap/version publication are not implemented here.

Path parents and the running user are trusted. The API does not defend against
root or hostile same-user replacement of parents during an operation. It does
not support Windows yet. It never uploads data or unlocks implicitly.

## Verification and next integration

PR CI covers round trips, randomization, wrong owner/password, header/ciphertext
tampering and exact size boundaries. The ignored `vault_file` integration test is
registered by `scripts/nightly-integration.mjs` for central scheduled CI only. It
covers restart, competing writers, response-loss retry, stale head, crash lock,
permissions and symlink refusal. Registration is not execution evidence.

Before a consumer can treat this as an authorized vault, implement authenticated
version/manifests and confidential wrap routing, the independent head ledger,
Check plus fresh epoch proof (including bounded offline leases), signed encrypted
audit admission, and shared cross-client ciphertext vectors. Visor still owns
execute/use/sign permission brokering. Unlock alone must never bypass those gates.
