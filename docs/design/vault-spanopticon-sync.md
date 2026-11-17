# Vault sync through Spanopticon

The signed-head continuity boundary and authenticated storage transport for #155
slice B are implemented. Container v2, shared-space enrollment and the end-user
UI remain open; the implemented transport is not an end-to-end usable vault.
The existing SAVFILE1 file and 1 MiB item limit remain supported. Spanopticon and
s3r.ch must use the same vault storage contract; login never supplies a vault key.

## Signed head and independent client floor

`sociacl-ids/vault-sync` exports the browser-safe head transcript, authentication
and IndexedDB continuity store. A head binds the SEA owner, opaque vault ID,
strictly increasing revision, previous transcript digest, exact encrypted keybag
and index digests, minimum container profile (1 or 2), and issuance time. Signature
verification requires current authenticated owner history. The transcript domain
is `sociacl-vault-sync-head-v1`; fields use the existing length-prefixed UTF-8
encoding in the order above, with wire version `1` immediately after the domain.
The signature is excluded from the transcript digest.

The full signed head is private metadata: encrypt it before remote storage.
Neither raw names nor the owner manifest should be put in a public record. The
storage receipt's ETag is transport CAS state, not this authenticated digest.
An independently authenticated exact head floor is mandatory at initialization.
Reopening missing state refuses; fetching the latest server record cannot repair
that trust boundary. A restored backup remains possibly stale until independently
authenticated recovery supplies the floor. Origin storage is trusted local state,
not protection against a compromised device or origin-wide rollback.

`verifyCurrent` checks a decrypted head against the retained floor and current
owner history. `advance` admits exactly one successor, rejects same-revision forks,
missing predecessors, revision skips and profile downgrade, and resolves only
after IndexedDB commit. An exact interrupted retry is idempotent. Concurrent
conflicting proposals yield one winner; callers retain the other prepared bytes
for explicit conflict resolution. No timestamp winner or automatic overwrite is
provided. Both methods reauthenticate inside the serialized transaction.

## Implemented Spanopticon API and consumer

[controlplane-core#103](https://github.com/hyperme-sh/controlplane-core/pull/103)
adds the opaque `vault` record namespace, dedicated read/write scopes, conditional
writes and the 8 MiB record bound. Vault deletion and direct-access suffixes are
not exposed. This is an untrusted ciphertext transport, not a private-head verifier.

[s3r.ch#620](https://github.com/FyberLabs/s3r.ch/pull/620) composes installed
SociACL head/floor verification with ciphertext publication. It checks current
owner history and predecessor continuity, uploads immutable ciphertext before
head CAS, verifies exact head and object readback, and only then advances the
independent client floor. Ambiguous responses reconcile the exact prepared bytes;
they do not reseal, overwrite a conflict, or trust a server revision as freshness.

[s3r.ch#622](https://github.com/FyberLabs/s3r.ch/pull/622) adds `POST /api/vault`
and the browser transport. The server resolves the session's current SociACL
principal through its configured complete authority source. A separate owner
signature binds the operation domain, site origin, vault, action, ciphertext
digest, expected revision and a maximum 60-second validity window. A session
alone cannot replace a head. Retired ownership history may remain non-authoritative;
forged history and retired session signing keys refuse.

The trusted deployment configuration binds each opaque vault ID to its owner.
Requests cannot select a tenant, credential or arbitrary vault enrollment.
The same shared storage space must be provisioned for both products; it is not
automatically provisioned by these changes. Missing configuration leaves the
route unavailable, and service credentials remain server-side.

Authenticated object access uses create-only records whose addresses are a
domain-separated hash of the vault ID and content digest. It never forwards a
caller-selected digest to the tenant-wide object store. This isolates vaults
even when another owner knows the ciphertext digest. Immutable retries compare
the retained bytes' digest; reads recheck that digest. The 8 MiB transport bound
does not replace the 1 MiB item or 16 KiB item-metadata caps.

The service never receives the decrypted private head. The local custody
adapter must decrypt/authenticate it before the SociACL client verifies it.
The signed operation authorizes ciphertext storage, not plaintext access.

## Remaining owner work and acceptance gates

| Work | Required boundary |
| --- | --- |
| Container v2 and custody | Durable key custody; passkey PRF or native-device daily slot plus mandatory recovery-key slot; SAVFILE1 import remains supported. |
| Initial enrollment and recovery | Independently authenticated initial floor and owner/vault binding; fetching a server head must never silently establish or restore trust. |
| Native consumer and CLI integration | Durable independent state, prepared-byte retry, and visible conflicts composed with the native head contract. |
| UI and cross-device sync | Compose custody with the implemented API/client; surface stale state and conflicts without automatic overwrite. |
| Merge/checkpoint history | Retain all parents and authenticated checkpoints; this head primitive does not lift the 256-version graph cap. |
| Shared-space operation | Provision scoped server credentials and bindings, then qualify the real TEST path through the naturally scheduled nightly. |

Item reads still require Check and fresh epoch status. A valid head or storage
ETag never grants a read, exposes plaintext to Spanopticon, or enables broker use.
Browser origin storage is not protected custody against a compromised device or
origin-wide rollback. Remote freshness remains a separate requirement.

## Validation

Automatic PR CI covers signature/ciphertext binding, parser boundaries, forged
and missing-history refusals, independent anchors, reopen and lost-state refusal,
exact retry, concurrent forks and downgrade/skip refusal with in-memory IndexedDB.
Packed-import and browser-bundle checks include the new export. Real browser and
TEST storage lifecycles belong to the natural nightly; none is dispatched here.

[s3r.ch#625](https://github.com/FyberLabs/s3r.ch/pull/625) composes the installed
SociACL client, browser API transport, authenticated service and vault-scoped
record adapter in one CI contract. It covers lost committed responses, exact
retries, successor publication, replayed-head refusal, revoked sessions and
retained state after reopening. Storage and custody are explicit in-process
doubles in #625. [s3r.ch#629](https://github.com/FyberLabs/s3r.ch/pull/629)
replaces the custody double with real General JWE head encryption using a
dedicated non-exportable AES-KW-256 key and fresh A256GCM content key. It adds
lock and current-history checks but does not provide durable key storage or slot
enrollment. Passing this contract is not real-storage, real-browser PRF or deployed
end-to-end vault acceptance. No nightly is manually dispatched for this work.

## Native signed-head contract

`sociacl-encdisc` exposes `parse_vault_sync_head`, canonical signing bytes and
`vault_sync_head_floor`, plus `verify_vault_sync_head` with the same expected
owner/namespace and current-history requirements as the browser contract.
`validate_vault_sync_successor` checks structural continuity, profile and time
monotonicity. It does not authenticate either head or commit a durable floor.
Native consumers must authenticate, compare an independently retained floor,
verify exact encrypted readback, and recheck authority at durable commit.
These functions neither decrypt custody bytes nor grant item reads.

The shared `vectors/vault/sync-head.json` fixture exercises transcript and parser
parity in existing Rust/TypeScript PR CI suites. Native durable floor storage,
key custody, enrollment and CLI wiring remain subsequent integration work.
