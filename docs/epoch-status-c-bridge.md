# Rust epoch-status evidence through C

`sociacl_verify_epoch_status` exposes the existing Rust `epoch_status_bytes`,
`verify_sea` and `status_is_fresh` functions to service adapters. It introduces no
signature format or alternate authorization engine. Both input buffers contain
UTF-8 JSON, are limited to 16 KiB, and need no NUL terminator. Unknown, duplicate,
missing and wrongly typed fields are rejected. Times are milliseconds; all
numbers must be nonnegative integers within JavaScript's safe integer range.

The proof uses the existing `EpochStatusProof` shape in `s3rch-check.d.ts`:

```json
{
  "object": "media-object",
  "epoch": 3,
  "revisionId": "<64 lowercase hexadecimal characters>",
  "accessor": "reader",
  "grantRevision": 7,
  "stated": 1,
  "signedAt": 10000,
  "maxAgeMs": 2000,
  "signature": "<existing SEA signature>",
  "zookie": {
    "object": "media-object",
    "objectVersion": 4,
    "snapshotHash": "<64 lowercase hexadecimal characters>"
  }
}
```

The expected document contains `ownerPub`, `object`, `epoch`, `revisionId`,
`accessor`, `grantRevision`, `stated`, and the same `zookie` shape. Every context
field must match the proof exactly. Obtain these values independently from
authenticated current owner/reader enrollment, selected epoch history, grant
revision and current graph state. Never copy expected values or `ownerPub` from
the presented proof or an untrusted request. Retain independent high-water and
rollback protection; a valid old signature cannot establish the current head.

The caller supplies its trusted clock, skew allowance and maximum age. Freshness
uses the smaller of the proof's age limit and that policy maximum, exactly as in
the Rust reference. Object/accessor strings are bounded to 1024 UTF-8 bytes and
exclude control characters. Revision and snapshot digests are lowercase SHA-256
hex strings. Cryptographic verification uses the enrolled owner's SEA public key.

Return value `1` means only that this signed evidence matches that trusted
context and freshness policy. In particular, a valid cancellation (`stated: 0`)
also returns `1` when expected. It never means Check allowed. Return value `0`
covers all parsing, binding, signature and freshness refusals without exposing
input material. Current Check, presenter authentication, grant cancellation,
epoch selection, private reader-wrap delivery and rollback custody remain with
the owning service. This bridge alone does not activate s3r.ch media or complete
[ACL #81](https://github.com/hyperme-sh/acl-service/issues/81).

The C caller must supply readable buffers of the stated lengths for the call.
The function retains no pointers or input data. Rust tests exercise the exported
function with genuine signatures and mutated evidence. The scheduled C runtime
example checks the public header and fail-closed buffer handling. All build,
signature, FFI and runtime validation runs in CI.
