# Forum need and offer transitions

The light consume contract exposes `acceptForumOfferTransition` and
`acceptForumNeedTransition` separately from `checkForumSee`. This closes the
transition API portion of #156; delegated credentials and consumer adoption
remain separate work. The reference implementation is exported by `sociacl/gun`.
The corresponding Rust operations are `accept_offer_transition` and
`accept_need_transition` in `crates/sociacl-gun/src/forum.rs`.

The caller authenticates the writer, decodes rows, supplies the actual current
need, and serializes transitions with durable persistence. These functions do
not verify a transport signature, choose current state from untrusted deliveries,
or persist needs. A successful candidate must be committed with a compare-and-set
against the supplied current state; retry a conflict from the new current state.
Do not let a request supply the writer identity or substitute an older open need
for the stored resolved need. The browser graph is a trusted local verifier,
not a server authorization boundary for untrusted JavaScript callers.

Posting requires the helper's current destination Check. The verifier stores a
copy of the offer internally, separate from signed object ownership; a supplied
row or mutable public map cannot establish a posted offer. Withdrawal retains a
tombstone. A helper may withdraw their own offer; the need owner or subject may
cancel it. An accepted offer stays live until the owner reopens the need.

Resolving requires the owner or subject, an exact stored live offer, and a fresh
Check for that helper. Reopening requires the owner and clears acceptedOffer.
HAM updates preserve id, forum, subject, body, severity, spec and accepted offer,
and require a current Check. All operations leave the admitted owner unchanged. Invalid or non-safe JavaScript times fail closed.

The in-memory offer store has the graph's lifetime. After a restart, applications
must reconstruct it from authenticated, ordered history through the same
transitions; raw persisted rows cannot be inserted as trusted offers. This PR
does not provide a durable replay adapter or remove s3r.ch's existing copies.

Shared vectors are `vectors/mesh/forum-transitions.json`, with canonical ids in
`vectors/mesh/forums.json`. PR CI executes those vectors and signed-admission
regressions for unposted offers, cancellation, mutation, tombstones and owner-only
reopening. The consume manifest hashes the declarations and vectors. Rust has
its existing transition tests; these new JSON cases currently run in TypeScript.
No local test or fixture lifecycle is required or authorized by this document.
