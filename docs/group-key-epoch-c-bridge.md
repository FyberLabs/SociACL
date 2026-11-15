# Independent group epoch C bridge

The additive C exports return 1 on success and 0 on refusal. Inputs are UTF-8
JSON with exact object fields; duplicate fields, arrays substituted for objects,
unknown fields and unsafe integers refuse. No pointers or keys are retained.

- `sociacl_verify_group_epoch_manifest(document, expected)` authenticates one
  `{manifest,snapshot}` against `{object,ownerPub,epoch,revisionId}`. Each input
  is bounded to 65,536 bytes. The manifest uses the existing epoch manifest
  fields without `statusAuthPub`; the snapshot is the independent group-key
  snapshot, not a media ACL snapshot.
- `sociacl_verify_group_epoch_history(input)` verifies bounded signed manifest
  and finalization history before a pending successor is retained.
- `sociacl_match_settled_group_epoch(input)` additionally matches the latest
  settled winner against the requested epoch and revision.

History input has `object`, `current`, `config`, `manifests`, `finalizations`,
`nowMs`, `anchorFinalizationId`, `minimumEpoch`, `expectedEpoch`, and
`expectedRevisionId`. The group object is a minted `set_` identifier. Each
manifest row contains `document` and `expected`. Each finalization row contains
`proof`, its independently authenticated `ownerPub`, and protected `seenAt`.
Arrays are nonempty and bounded to 64 rows; the complete input is at most 4 MiB.
`config` is the current owner-signed group settlement policy.

A snapshot has `predicate`, `setId`, `setOwner`, `ownerSigningPub`,
`ownerEncryptionPub`, `ownerIdentityHead`, and sorted `members`. Each member has
`accessor`, `stated`, `hamState`, `signingPub`, `encryptionPub`, and `identityHead`.
Retained withdrawals are included; the owner is not implicitly a member.

These are protected service inputs, not client assertions. The service must
resolve all signing keys and current encryption bindings from admitted identity
histories, supply complete retained group history, preserve the independent
checkpoint/anchor and epoch floor, and use its own observation clock. History
verification alone does not prove completeness, current settlement or access.
Current Check, membership and media object-set authorization remain separate
requirements before either group-key or item-key delivery.
