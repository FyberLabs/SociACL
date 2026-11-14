# Browser item-DEK group-epoch wrapping

`sociacl-ids/group-wrap` exports `wrapItemDekToGroupEpoch` and
`openGroupEpochWrap`. These implement the existing Rust version-2 wrap: the
item DEK is wrapped once to a group epoch key, with the object, minted set,
epoch and winning revision authenticated inside the ciphertext. Each call
creates a fresh nonce. Caller-held keys and context are copied before async
crypto; temporary key copies and plaintext buffers are cleared.

The caller must supply independently authorized current context. Wrapping does
not create group membership or replace Check, status or epoch settlement.
This entrypoint does not yet wrap the group key to individual member epubs;
that remains a separate browser consumer. Existing direct-reader wraps retain
their contract. CI opens actual Rust output in the browser consumer and opens
fresh browser output in Rust, with wrong-key/revision refusal checks.
