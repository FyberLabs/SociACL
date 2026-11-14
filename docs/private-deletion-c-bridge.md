# Private media deletion command

`signPrivateMediaDeletion` signs an explicit deletion command with an existing
browser-held SEA key. It never creates or retains a key. A cancellation or an
expired grant is not a deletion command. The C function
`sociacl_verify_private_deletion(proof, proof_len, expected, expected_len, now_ms)`
returns one only for an authentic signature matching every expected field within
a half-open interval of at most 60,000 milliseconds, without clock skew.

Claims are exactly `tenant`, `object`, `owner`, `objectVersion`, `fence`,
`issuedAt`, and `expiresAt`. The tenant is a nonzero canonical lowercase UUID;
the browser producer validates canonical media object and SEA principal IDs.
Integers are nonnegative JavaScript-safe integers. The fence is 64 lowercase hex
characters from the current protected owner view. `expected` adds `ownerPub`,
resolved independently from current protected owner history, including rotation.
It must never be copied from an untrusted command as an authorization decision.

The UTF-8 transcript is `SOCIACL_PRIVATE_MEDIA_DELETE_V1` followed by a newline
and the compact JSON array of the seven claims in the order above. Strings in
this contract are ASCII identifiers. The signature is the existing compact
low-S P-256 SEA signature, encoded as 128 lowercase hex characters. The proof
has exactly `deletionBytes` (lowercase transcript hex) and `signature`.
Duplicate/unknown JSON keys, malformed shapes, stale times and wrong signatures
refuse. Existing private-media transcripts and entry points remain unchanged.

A valid signature is intent only. Before committing deletion, the ACL consumer
must recheck authenticated subject, current owner key, policy, object version
and fence in its protected transaction. It must atomically mark the object
permanently deleted and invalidate pending reads/writes, preserve an independent
checkpoint, and refuse resurrection or reallocation of the same object. Retrying
the same accepted command must resume cleanup without authorizing a different
object. Provider deletion and quota release must be retryable and release quota
only once after confirmed cleanup. This primitive implements none of those
consumer state changes, routes, provider operations or activation switches.

CI compares the browser producer with the native verifier, rejects mutation of
every scoped field and use of a cancellation proof, and gates native bridge
coverage. No shared-host execution is required.
