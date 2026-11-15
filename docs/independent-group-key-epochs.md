# Independent group key epochs

`GroupKeySnapshot` is a group-specific epoch input, independent of a media
object-set edge. Its canonical `s3rch-group-key-snapshot-v1` hash binds the
predicate, minted set and owner, current owner signing/encryption identities,
and every retained member's stated value, HAM state and current identity keys
and head. Members are strictly sorted, unique and bounded to 64. The owner is
not implicitly a member. Callers must obtain these inputs from admitted current
membership and checkpointed identity histories.

`EpochChain::insert_group_manifest` authenticates a group-scoped manifest using
that snapshot hash and its resolved owner signing key. It shares the existing
signed finalization chain and deterministic winner rules, but cannot mix media
ACL manifests with group manifests. Media selection cannot consume a group
snapshot. A group manifest has no independent status signer.

`settled_group_key` requires the current owner-signed group policy, retained
chain anchor and epoch floor. Only the latest winner can be returned, after its
observed settlement window. The current snapshot must match exactly, including
withdrawals, additions, signing/encryption key changes and identity heads. A
pending successor or changed authority never falls back to an older key.

These primitives select a group key; they do not grant access to a media item.
The protected service must separately verify current membership, the media
owner's object-set binding, current Check/status and the item epoch before
serving group-key or item-key wraps. The group key remains browser-held and is
wrapped to current members; item DEKs are wrapped once to that group epoch.
The C service adapter, browser producer and protected delivery integration are
subsequent consumers of this native primitive.
