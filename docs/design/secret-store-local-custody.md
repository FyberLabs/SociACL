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

## Authorized local read composition

`read_authorized_local_vault` now composes custody unlock with the existing
destination verifier. The caller independently supplies an authenticated binding
from item ID to ACL object, exact version/ciphertext digest, owner and epoch
revision. A signed manifest binds the actual envelope; `sign_vault_version` emits
a compact 64-byte P-256 signature encoded as unpadded base64url, matching the
identity verifier. The manifest and its signature remain private metadata.

Admission requires current authenticated owner history and the same current
signing key used by the grant presentation. The existing Check validates the
item-bound grant, reader enrollment, presenter binding and fresh epoch proof.
The function overwrites any caller-provided fetched digest with the actual file
hash. A plain object grant cannot stand in for the item-bound grant. Wrong
versions, owners, objects, epochs, signatures or missing history fail before KDF
work. Identity timestamps are seconds; the destination clock is Unix milliseconds.

Unlocking is followed by another current-time admission/Check. Before plaintext
is returned, a required synchronous consumer callback must durably compare and
swap the nonce/revision state and independent item expectation against its
original snapshot. The caller owns that atomic transaction; this library cannot
prove a dishonest callback wrote durable storage. Expiry and clock rollback are
checked again after commit. A committed nonce may therefore be consumed with no
plaintext returned. The public custody-only open API remains for local key
custody; applications must use the authorized composition for grantee reads.

This adds a headless consumer seam, not a complete vault CLI or protected head
ledger. It does not authenticate version DAGs, provide conflict retention,
implement sharing/sync, or replace Visor's execute/use/sign broker. Tests compose
real signatures and destination proofs with an in-memory commit callback in CI;
filesystem persistence remains in the scheduled adapter.

## Signed version history and conflicts

`VaultVersionHistory` admits immutable, owner-signed version records against
current authenticated account history and independently supplied epoch/revision.
Explicit initialization requires an independent exact transcript digest and item
binding. Later records require known parents; missing history never resets to a
new root. Identical retries preserve state, but reusing a version ID for different
signed content fails. Concurrent children retain both heads. Only a signed
joining descendant resolves the conflict; timestamps never select a winner.
`read_expectation()` refuses ambiguous heads and carries the original object
binding into the authorized-read API. Sensitive epoch changes cannot reuse a
parent's ciphertext digest, although a new digest alone cannot prove fresh DEKs.

The bounded in-memory graph retains all accepted version IDs and refuses additions
at 256 entries rather than forgetting equivocation. This is an admission core,
not a durable ledger: the consumer must encrypt and atomically retain the graph,
protect its head from rollback and authenticate current epoch state. The file
backend still needs that ledger and consumer integration. Retention/pruning needs
an authenticated checkpoint design before this bound can be raised or compacted.
