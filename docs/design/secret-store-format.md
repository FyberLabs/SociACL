# Secret-store phase-one signing format

Status: phase-one contract for #155. The Rust `vault_format` module and
TypeScript `vault-format.ts` encode signing transcripts only. There is no vault
authorized read API, synchronization, hardware device-key adapter or permission
broker. Local custody encryption and a Unix snapshot backend are specified separately
in [local custody](secret-store-local-custody.md); they do not authorize reads. `vectors/vault/v1.json` defines the ordered
fields consumed by both language suites in CI.

## Identity and visibility

The owner is a canonical SEA genesis principal. Each version and audit event must
be signed by its authenticated current account key. Encoding a transcript does
not check a signature or grant access. Readers still need the destination Check,
fresh EpochStatusProof, authenticated owner history and matching epoch revision.

Item and version IDs are independent random 32-byte values, lowercase hex. They
must never be hashes of a secret, name or low-entropy payload. Randomness belongs
to the future writer; the format validator cannot prove how an ID was generated.
Only those opaque IDs, a format version and bounded ciphertext lengths belong in
the untrusted sync header. Names, types, labels, principals, device IDs, parents,
epoch state, sensitivity flags, audit statements and signatures are encrypted.

Existing `WrappedKey` values expose `target_id`, object/group and revision labels
(`crates/sociacl-encdisc/src/wrap.rs`). Reuse their cryptographic payloads inside
confidential, capability-addressed wrap manifests. Do not publish raw WrappedKey
objects in the vault transport or claim they meet the visibility requirement.
Selecting and provisioning that private routing layer remains part of phase one.

## Version transcript

All fields use the existing unsigned little-endian uint32 UTF-8 length prefix.
The sequence is:

1. `sociacl-vault-version-v1`, literal version `1`.
2. Item ID, version ID, owner SEA principal.
3. Epoch number, authenticated epoch revision ID, encrypted-content SHA-256 digest.
4. Sensitivity (`1` or `0`), issued-at UTC seconds, parent count.
5. The parent version IDs, sorted lexicographically and unique.

Numbers use canonical nonnegative decimal with no leading zeros, sign, fraction,
exponent or negative zero, and cannot exceed JavaScript's safe integer maximum.
IDs/digests are exactly 64 lowercase hex characters. There are at most 16 parents;
self-parenting, duplicate parents and unsorted parents are refused. Zero parents
represents initial creation. A merge names the parents it resolves; unresolved
heads remain conflicts. Parent syntax is not a DAG proof: the future verified
local store must check ownership, existence, cycles and authenticated head history.
It must not choose a winner by timestamp, sorting or transport arrival order.

Use a fresh random 32-byte DEK for every immutable version. The proposed encrypted
layout has a content ciphertext and a separate encrypted signed manifest. The
manifest's signature binds the content ciphertext digest, avoiding a circular
signature-over-ciphertext-containing-signature dependency. Domain-separated keys
and fresh nonces are required for both encryption operations. XChaCha20-Poly1305
is already a repository dependency in `sociacl-core/src/codec.rs`; the vault must
not substitute raw Case C holder signatures for SEA identity signatures. Exact
ciphertext framing, KDF domains, nonce layout, size/metadata limits and wrap
manifest vectors are still required before implementing a seal/open API.

## Audit transcript

The ordered fields are:

1. `sociacl-vault-audit-v1`, literal version `1`.
2. Random event ID, item ID, version ID, actor SEA principal, opaque device ID.
3. Operation, outcome, issued-at UTC seconds, predecessor ciphertext/record digest.

Operations are `put`, `share`, `revoke`, `read`, `use`, `enroll`, or `recover`.
Outcomes are `allowed`, `denied`, or `failed`; an outcome string does not authorize
an operation. All ID and decimal constraints match the version transcript.
An all-zero predecessor denotes a new audit chain and is accepted only during
explicit owner-authorized initialization, never as recovery from missing state.
The future store must reject resetting an observed chain and authenticate its
latest head independently of an untrusted sync peer. A signed predecessor chain
cannot prove every read/use was logged, nor that a peer returned the newest head.

Encrypt signed audit records to the owner and explicitly authorized auditors.
No plaintext secret, secret name, passphrase or raw credential belongs in an audit
record, exception, log line or metric label. Execute/use/sign permissions remain
Visor's broker responsibility, independently of successful vault decryption.

## Acceptance sequence

Canonical transcript parity is covered by PR CI. Still required in phase one:
exact confidential network framing and routing,
shared seal/open/tamper vectors, and conflict/rollback/audit-head admission vectors.
The [threat model](secret-store-threat-model.md) and local custody baseline are
recorded. Complete signed-version admission and durable head state, then the CLI
and headless consumer before sync and
platform device adapters. Each runtime stage belongs in the scheduled CI batch.
Hardware protection, provider activation, independent audit and GA are separate
milestones; the signing format does not claim any of them.

### Signed audit admission

`VaultAuditHistory` admits signed events against authenticated version history
and an independently selected actor. Bootstrap requires an exact trusted genesis
transcript digest; missing state cannot implicitly bootstrap. Advance retains all
IDs (up to 256), accepts exact transcript retries and rejects predecessor forks,
event-ID reuse, unknown versions, backward times and retired/forged actor keys.
`record_read` additionally binds a fresh event to the current unambiguous version,
accessor, device, decision outcome and supplied decision time. An allowed entry
records Check authorization, not successful plaintext delivery after commit.

The read consumer can call `record_read` inside `read_authorized_local_vault`'s
commit callback and atomically persist the candidate alongside nonce/revision
state and the item expectation. Signing uses `AccountSeaSecret::sign_vault_audit`.
These are in-memory admission and composition APIs. A protected confidential
atomic backing store, audit checkpoint persistence and CLI integration remain
required; a signed assertion is not proof every operation was logged.

### Combined encrypted version and audit checkpoint

`VaultJournal` binds an admitted audit history to its original owner/object/item
and complete admitted version graph. `seal_vault_journal` encrypts both into one
passphrase-sealed snapshot; `open_vault_journal` requires an independently retained
exact `VaultJournalHead`. Restore checks canonical encoding, one connected audit
chain, retained event IDs, nondecreasing times, known version references and the
expected audit head. A history from another object cannot be attached even when
its opaque item/version IDs match. The combined plaintext obeys the 1 MiB cap.

Publish through `LocalVaultFileStore` CAS and reconcile ambiguous responses by
retrying the prepared bytes. This prevents torn version/audit files; it does not
provide a protected head store, persist verifier nonces or atomically commit all
authorization state. Those integrations and the CLI remain open. Restored records
are previously admitted local state, not newly verified network assertions.
