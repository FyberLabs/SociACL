# Independent timestamp witnesses

Status: exploration for #62. Current verification uses the provisioned witness
policy and its administrative checkpoint trust root; see
`witness-policy-client.md`, `witness-policy-bootstrap.md`, and
`typescript/ids/src/{records,witness-policy,witness-checkpoint}.js`. A key set
with several keys is not evidence of several independent operators. Existing
wire formats and verification thresholds are unchanged by this document.

A future quorum policy must name operator identities, their independently held
verification keys, issuance windows, a policy epoch and a threshold. Count at
most one valid attestation per operator, regardless of how many keys it owns.
Each attestation must bind the identical canonical account-signed record digest,
principal, operation/domain and policy epoch. Account signatures remain
mandatory; witnesses can attest observation time, never authorize rotation or
mint an account/grant. Duplicate keys, duplicate operators, mixed record digests,
mixed epochs and out-of-window signatures must fail the quorum calculation.

A plausible pilot is two of three independently operated witnesses. That
survives one outage and prevents one operator alone fabricating quorum evidence,
but it is not yet a chosen deployment policy. Independence requires different
administrative/recovery control, custody and failure domains, not merely three
containers. Two compromised operators still defeat the timestamp assumption.

Quorum timestamping is not fork consensus. For rotation, require enough overlap
and an enforceable rule that every honest witness durably signs at most one
successor per `(principal, sequence, previous-key)` across restarts/key changes.
For a tolerated bound `f`, quorum intersections must exceed `f` (for example
`n=3f+1, q=2f+1`), or a separate serialized transparency/consensus service must
supply that property. A two-of-three pilot must not claim Byzantine fork
resistance with one faulty operator: its two quorums can intersect only there.
Historical resolution must still detect conflicting authenticated successors
and fail closed. Witness availability cannot justify choosing a fork locally.

Policies themselves need independent bootstrap/freshness and rollback-resistant
checkpoints. Changing membership or threshold is a versioned transition with
explicit continuity evidence; a compromised operator cannot lower the threshold
or remove dissenters by publishing a new key list. Historical revoked keys keep
their bounded issuance windows. Unknown history or unavailable quorum blocks
rotation; it never enables a one-witness fallback. Current-key offline revokes
retain their present-lookup behavior, without claiming durable historical
witness evidence after retirement.

Peer attestation requires a separate pre-enrolled recovery policy: trustees,
threshold, capabilities, expiry and cancel semantics fixed while the account is
healthy. Random peers or fresh friends cannot become recovery authorities.
Recovery must demonstrate the account's previously authorized policy and a
fresh challenge. Wills/Elect and ordinary timestamp attestations cannot be
silently interchanged.

Implementation prerequisites: choose operator/fault assumptions; freeze policy,
attestation and transition bytes; add duplicate/mixed-digest/mixed-epoch vectors;
model concurrent fork attempts and rollback; provision independently recoverable
witness lifecycles; prove unavailable quorum fails closed in nightly CI. #62
stays open until those mechanisms exist and are tested.

## Executable receipt experiment

`typescript/contract/independent-witness.ts` makes the proposed boundaries
executable without changing existing rotation/revocation wire formats. It is an
experimental receipt verifier, not a replacement for `verifyRotate`, `verifyRevoke`
or current witness policy installation. No service trusts its output yet.

An independently authenticated policy names an opaque policy ID, positive epoch,
threshold, tolerated faulty-operator count, and at most 16 operators with at most
four bounded-issuance keys each. Operator names and public keys must be unique;
rotating keys does not increase an operator's vote. Account signing keys cannot
also be witness keys. Administrative independence remains a deployment assertion,
not something a list of public keys proves.

The account signs length-prefixed UTF-8 fields: domain
`sociacl-independent-witness-request-v1`, version `1`, principal, operation
(`rotate` or `revoke`), exact underlying record digest, policy ID, epoch, issuedAt
and expiresAt. Decimal spellings are canonical. The request window is at most
600 seconds. Witnesses sign domain `sociacl-independent-witness-receipt-v1`, the
SHA-256 hex digest of those request bytes, their operator ID and observedAt.
Signatures use the existing compact P-256/SHA-256 identity contract. Account
signature validity and independently authenticated current-key history are checked
before any quorum result is returned. The caller independently supplies the
expected underlying record digest; witnesses cannot substitute another record.

Every included receipt must verify inside both its request window and its key's
issuance window. Duplicate operators, aliases sharing a key, mixed epochs/digests,
unknown operators and future observation times fail. The returned timestamp upper
bound is the latest included observation time, not a claim of exact creation time.
The result contains no grant, account successor, credential or authorization.
The original account-signed record still needs its full protocol verifier.

For tolerated fault count `f`, require `q > f` and `q <= n-f`. Rotation also
requires `2q-n > f`. Thus 2-of-3 with one tolerated fault can timestamp revocation
but is refused for rotation; 3-of-4 can satisfy the rotation intersection bound.
This does not manufacture fork consensus: honest witnesses must additionally
persist single-successor decisions before signing, across restarts and key
changes. That storage/service rule remains a prerequisite to activating rotation.

PR CI covers one unavailable operator, missing quorum, invalid account signatures,
duplicate votes/keys, mixed records and epochs, unsafe thresholds, key windows,
missing account history and future times. Still required before adoption:
authenticated policy transitions and durable
operator anti-equivocation; independent operator provisioning; scheduled outage,
concurrent-fork and rollback tests; and explicit integration into the existing
record verifiers. Peer recovery remains a separate pre-enrolled trustee protocol.

## Rust parity and CI exchange

`crates/sociacl-ids/src/independent_witness.rs` implements the experimental
receipt verifier with the same operator/key bounds, time windows, authenticated
account history and quorum rules. `vectors/independent-witness/v1.json` freezes
request fields and rejection cases. PR CI signs receipts independently in Rust
and TypeScript, passes each artifact to the other verifier, and compares the
returned observation. Public fixture scalars are test data only. No witness
service, policy transition or existing record verifier is activated by parity.

## Consumer collection

`independent-witness-client.ts::collectIndependentWitnesses` composes bounded
collection with the verifier. Before any transport call it authenticates the
account intent and provisioned policy. Each configured operator receives one
immutable request and contributes at most one matching observation. Invalid,
misattributed and timed-out responses count as unavailable; they never lower the
threshold or poison an otherwise sufficient quorum. Collection uses a maximum
ten-second deadline, aborts remaining work and rejects responses that complete
verification after the monotonic deadline.

The caller provides current authenticated policy/history functions, not data from
an operator's response. Policy changes, account retirement, expiry and backward
time invalidate the attempt before its result is returned. Transport adapters
are trusted configuration and receive an AbortSignal; no returned URL is followed.
s3r.ch adapters must use its configured Spanopticon interfaces. This collector
is usable with independently provisioned operators but does not provision them,
make them independent, or activate the existing single-witness record verifier.
Durable anti-equivocation and authenticated policy transitions remain required.

## Joint-quorum policy transitions

`advanceIndependentWitnessPolicy` authenticates an exact old-to-new policy
transition. Canonical policy transcripts bind every operator, key issuance window,
threshold and fault bound. The policy ID remains fixed and the epoch advances by
exactly one. Account-signed rotation requests under both policies must bind the
same domain-separated transition digest, and both independently satisfy the
rotation quorum rule. Neither the outgoing nor incoming operator set can change
membership alone. Reordering keys or operators does not change policy identity.

The old policy must come from independently trusted retained state, never from
the proposal. The returned policy is a candidate for atomic compare-and-swap;
this verifier does not bootstrap trust, persist a floor, prove latest policy,
or supply durable single-successor witness decisions. Those remain prerequisites
for runtime activation. Rust implements the same transition verifier; CI exchanges
independently signed old/new quorum bundles in both directions and compares their
canonical transition digests.

## Retained consumer membership

`openIndependentWitnessPolicyStore` retains an exact policy digest and epoch in
strict-durability IndexedDB transactions. It reuses the monotonic floor primitive
in a separate witness namespace. Bootstrap requires an independently authenticated
anchor; missing state on reopen fails. Current policy bytes must exactly match the
retained floor before use. Transitions authenticate joint quorums before work and
again inside the transaction and at completion with the trusted clock/history.
Competing same-epoch proposals cannot both install different membership.

Only the floor is stored, so policy bytes may be restored from an untrusted cache
only when their canonical digest matches. A lost successful transition response
is reconciled with `read(exactCandidate)`, not by resetting the old floor. This
consumer store does not provide operator anti-equivocation or independent service
provisioning, and does not change the existing single-witness runtime verifier.

The retained policy store's `collect` method composes transport collection with
its exact installed membership. It rejects an old candidate before any transport,
then rechecks the canonical policy floor and current account history inside a
strict transaction before returning the observation. A concurrent membership
transition invalidates the old collection. This is consumer continuity, not an
operator's durable single-successor decision or activation of legacy verifiers.
