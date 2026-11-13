# Settled epoch selection C bridge

`sociacl_match_settled_epoch(input, input_len)` returns 1 only when the existing
Rust `EpochChain` selects the expected latest settled winner from the supplied
history and current ACL. Otherwise it returns 0. It authenticates every manifest
and finalization and uses the reference snapshot comparison and settlement rule.
Pending successors refuse; this conservative service adapter never falls back
to an older read key.

This is a **trusted-service input**, not a client request format. The caller must
load the complete history, authenticated owner-key bindings at signing time,
current ACL, independently retained anchor and epoch floor, and trusted clock
from one protected policy/history view. Signature validity cannot prove history
completeness or that a supplied public key owns the object. This bridge must not
be exposed directly as a public authorization endpoint. Current Check, recipient
enrollment, freshness/rollback custody and a delivery fence remain required.

Input is one UTF-8 JSON object of 1 through 524,288 bytes:

- `object`: the protected object identifier.
- `manifests`: 1–64 objects with `document` and `expected`, each using the exact
  [manifest bridge](epoch-manifest-c-bridge.md) shape and 64 KiB limit. Each
  expected owner key must be resolved from authenticated history. Duplicate
  manifest revisions refuse.
- `finalizations`: 1–64 objects with `proof`, `ownerPub`, and `seenAt`. The proof
  contains the existing `object`, `previousEpoch`, `epoch`, `revisionId`,
  `candidateRevisionIds`, `previousFinalizationId`, `finalizationId`, `signature`
  fields. Candidate lists have at most 64 entries. Owner keys come from protected
  identity history. `seenAt` is the service's retained first observation time,
  never a sender timestamp, and cannot exceed `nowMs`. Duplicate finalization IDs
  refuse rather than allowing different observation times to replace one another.
- `current`: the current ACL snapshot in the manifest bridge's snapshot format.
  This comes from the current protected graph, not from a requested manifest.
- `nowMs`: trusted current time in milliseconds.
- `groupWindowMs`: absent/null for direct scopes, or the independently authorized
  signed group configuration's window. This bridge does not verify that separate
  configuration signature or choose its current revision.
- `anchorFinalizationId`: independently retained initial finalization ID. The
  selected chain must start at that anchor.
- `minimumEpoch`: independently retained epoch floor.
- `expectedEpoch` and `expectedRevisionId`: proposed read-key context to match.

Unknown/duplicate fields, positional objects, unsafe unsigned integers, malformed
signatures/digests, oversized graphs and inconsistent candidates refuse. The
original nested JSON bytes are preserved for strict parsing. No pointers are
retained; the buffer must remain readable for the supplied length during the call.

The caller must commit the matching selection and its authorization fence against
the same protected view before any wrap delivery. A concurrent cancellation,
rotation, policy change or item-head change invalidates that fence. This bridge
performs no storage, enrollment, key release or grant creation.

CI covers signed direct/group settlement, stale proposed keys, altered ACLs,
wrong anchors/floors, tampered finalizations and bounded strict parsing. Local
native execution is not part of this workflow.
