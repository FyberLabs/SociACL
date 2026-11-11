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
