# Epoch manifest C bridge

`sociacl_verify_epoch_manifest(document, document_len, expected, expected_len)`
authenticates an existing Rust `EpochManifest` and `AclSnapshotBody`. It returns
1 for a valid signature, snapshot digest, revision digest and exact expected
binding; otherwise it returns 0. There is no new signature or hashing format.

**This is not current-epoch selection or an access grant.** The caller must
independently establish the current enrolled owner key and protected epoch
history, admit finalizations through `EpochChain`, apply settlement and current
Check, and preserve independent rollback protection. An old correctly signed
manifest can pass this verifier. Passing a request's own values as expected
context does not establish authority. Snapshot entries are signed claims, not
proof that the supplied snapshot is current or complete.

Both inputs are UTF-8 JSON object buffers of 1 through 65,536 bytes. The buffers
need no trailing NUL and remain readable for the call. No pointer is retained.
Malformed JSON, duplicate or unknown fields, positional arrays in object fields,
unsafe unsigned integers and more than 128 snapshot entries are refused.

The document has exactly `manifest` and `snapshot` objects. The manifest fields
are the existing camelCase Rust contract: `object`, `previousEpoch`, `epoch`,
`deviceId`, `revisionId`, `keyCommitment`, `settleWindowMs`, `aclSnapshot`, optional
`statusAuthPub`, and `signature`. Optional `statusAuthPub` may be absent or null.
The reference verifies the 128-character lowercase-hex, low-s P-256 signature
over its canonical manifest transcript and recomputes both digests.

The snapshot contains `entries` and optional `objectSet` (absent or null for a
direct snapshot). Each entry contains `accessor`, `grantRevision`, `stated`,
`from`, `until`, `scope`, `setId`, and `hamState`. An object set contains
`predicate`, `setId`, `stated`, and `hamState`. The Rust reference enforces
snapshot ordering and scope/set consistency. String labels are bounded to 1,024
UTF-8 bytes without control characters; only a direct entry's `setId` may be
empty. `stated` is 0 or 1. Times and revisions are safe unsigned integers.

Expected context is exactly:

```json
{
  "ownerPub": "independently-resolved-current-SEA-key",
  "object": "protected-object-id",
  "epoch": 1,
  "revisionId": "64-lowercase-hex-characters"
}
```

The bridge does not publish snapshots or routing labels. Consumers must keep
private manifests and reader identifiers in protected tenant storage, not public
feed metadata. This API does not activate a storage or media endpoint.

CI runs reference-signed direct/group manifests, tampering and parser regressions
and enforces focused line coverage. Native/runtime validation runs only in CI.
