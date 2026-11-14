# Browser item-DEK group-epoch wrapping

`sociacl-ids/group-wrap` exports `wrapItemDekToGroupEpoch` and
`openGroupEpochWrap`. These implement the existing Rust version-2 wrap: the
item DEK is wrapped once to a group epoch key, with the object, minted set,
epoch and winning revision authenticated inside the ciphertext. Each call
creates a fresh nonce. Caller-held keys and context are copied before async
crypto; temporary key copies and plaintext buffers are cleared.

The caller must supply independently authorized current context. Wrapping does
not create group membership or replace Check, status or epoch settlement.
`sociacl-ids/group-reader-wrap` supplies the companion `wrapGroupKeyToMembers`
and `openGroupKeyReaderWrap` consumer. It uses the existing version-1 reader
wire with the group-key scope and group identity sealed inside. The caller supplies
current enrolled member bindings and a separately authorized member set; unknown
or duplicate members refuse the whole operation. No membership is minted. Existing direct-reader wraps retain
their contract. CI opens actual Rust output in the browser consumer and opens
fresh browser output in Rust, with wrong-key/revision refusal checks.

Member-wrap CI also opens fresh Rust output in JavaScript and browser output in
Rust. The browser suite independently decrypts the payload with Node crypto and
checks wrong identities, revision changes, malformed arrays and input changes
across async boundaries. These are protocol consumers, not authorization APIs.
