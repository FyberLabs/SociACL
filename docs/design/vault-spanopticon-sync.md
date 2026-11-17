# Vault sync through Spanopticon

This implements the first continuity boundary for #155 slice B. It does not yet
provide the v2 container, an HTTP vault route, a shared-space enrollment, or a UI.
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

## Spanopticon integration boundary still to wire

The current s3r.ch `createSpanopticonRecordStore` talks to
`/api/v1/storage/records/{namespace}/{name}` with tenant-scoped server credentials,
8 MiB bounded bytes, ETag reads and conditional writes. Its current namespace
allowlist is cache/recovery/fixtures/media. `createSpanopticonObjectStore` uses
`/api/v1/storage/objects/{sha256}` for immutable content-addressed bytes. Those
existing adapters are transport, not end-user vault authorization.

The next service/consumer slice must add the vault namespace with owner-signed
write authorization, store immutable encrypted versions before head CAS, verify
exact ciphertext readback, then commit the independent client floor. Ambiguous
remote results retry the exact prepared bytes or reconcile; they must not reseal
or blindly overwrite. A service session alone must not replace another owner's
head. Conflict reconciliation must retain all version parents; this head primitive
does not lift the existing 256-version graph cap or prove remote freshness.

Item reads still require Check and fresh epoch status. A valid head or storage
receipt never grants a read, exposes plaintext to Spanopticon, or enables broker
use. Rust parity, protected head custody beyond browser origin storage, vault
container v2, shared-space permissions, CLI/UI and full sync remain open.

## Validation

Automatic PR CI covers signature/ciphertext binding, parser boundaries, forged
and missing-history refusals, independent anchors, reopen and lost-state refusal,
exact retry, concurrent forks and downgrade/skip refusal with in-memory IndexedDB.
Packed-import and browser-bundle checks include the new export. Real browser and
TEST storage lifecycles belong to the natural nightly; none is dispatched here.
