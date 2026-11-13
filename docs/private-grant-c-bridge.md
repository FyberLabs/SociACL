# Confidential grant signature C bridge

`sociacl_verify_private_grant` matches an existing `SignedGrantPayload` signature
against independently trusted expected fields. It uses the Rust reference's
canonical decoder, transcript and SEA verifier; it introduces no signing format.
Return 1 means a signature and exact payload match, including for cancellation.
It does not establish current Check, presenter binding, enrollment, history
completeness, settlement or permission to deliver a wrap.

Both UTF-8 JSON buffers are 1–65,536 bytes, without a trailing NUL. Pointers remain
readable for the call and are never retained. Proof fields are exactly
`grantBytes` (the reference's lowercase hexadecimal canonical payload) and
`signature` (128 lowercase hexadecimal characters). Expected fields are exactly
`ownerPub`, `object`, `accessor`, `from`, `until`, `stated`, `epoch`, `owner`,
`grantRevision`, and `itemCiphertextDigest`. The last may be empty for a non-item
grant; otherwise it is a lowercase SHA-256 digest. Numeric fields use the existing
unsigned safe-integer contract and `stated` is 0 or 1. Labels are nonempty,
control-free and at most 1,024 UTF-8 bytes. Unknown/duplicate fields, positional
arrays and malformed transcripts fail closed. All refusals return 0.

The owner key and identity binding must come from protected enrollment history.
Expected current grant revisions and cancellation state must come from complete,
independently checkpointed private-grant history. A caller cannot establish those
facts by copying the proof into expected fields. An old authentic signature can
match; the service must still run the destination grant checks with current
status, selected epoch, recipient binding and an atomic delivery fence.

This is distinct from public `SeeGrant` records, which have no private grant
revision. Neither a forum grant nor a login token creates a private grant.
Keep proof and expected documents confidential; never place them in public feed
metadata or provider URLs. Signature, mutation and parser coverage run in CI.
