# Identity consume contract v1

This directory is a dependency-free declaration snapshot of the canonical
`sociacl-ids` implementation. It is a sibling of `../s3rch-check.d.ts`, for
consumers that copy contracts and execute shared vectors instead of importing
the Rust crate. It contains no executable implementation and no npm dependency.
Do not treat successful TypeScript compilation as verification of a record.

| Surface | Canonical contract entry points | Shared vectors |
| --- | --- | --- |
| Recovery and raw history | `resolveCurrentKey`, `resolveStoreAccount`, `historyState`, `verifyGenesisEpubRequest` | `vectors/ids/*.json` rotation/recovery cases |
| Rotation and forks | `verifyRotate`, `verifyRotationRequest`, `checkRotationPublish`, `checkRotationDraft` | `vectors/ids/*.json` rotation cases |
| Witness JSON, key windows and ACL attestations | `parseJsonInput`, `verifyAclAttestation`, `verifyWitnessPolicyEnvelope`, `advanceWitnessPolicy`, `advanceWitnessCheckpoint` | `vectors/ids/witness-*.json` |
| Revocation | `verifyRevoke`, `verifyRevokeNow` | `vectors/ids/*.json` revoke cases |
| Linked wallet/OIDC credentials | `verifyWalletLink`, `resolveWalletLinkNow`, `verifyOidcLink`, `resolveOidcLinkNow`, `prepareRetainedLinksNow` | `vectors/ids/*.json` link cases |
| Forum need/offer transitions outside Check | `acceptForumNeedTransition`, `acceptForumOfferTransition` in `../s3rch-check.d.ts` | `vectors/mesh/forum-transitions.json`, `vectors/mesh/forums.json` |
| Scoped agent credentials and revocation | `parseAgentDelegation`, `verifyAgentDelegation`, `parseAgentRevocation` | `vectors/agent-delegation/v1.json` |
| Signed object and grant authority | `verifyObjectRecord`, `verifySeeGrant`, `verifyPostGrant`, `verifySignedAt` | `vectors/mesh/v2/{see,post}.json` |

The principal is always the stable SEA genesis identity. Wallet addresses and
OIDC subjects are linked credentials. Preserve exact domains, canonical bytes,
issuance windows, bounded history, fork refusal and retention semantics.
`historyState` accepts already authenticated complete history: it must never be
built from unverified transport JSON. Witnesses timestamp; they never replace
account-key signatures or confer grants. Runtime admission and Check remain the
canonical `typescript/src/{see,post,forum}.js` and Rust graph semantics.

## Pinning and drift

Consumers pin a SociACL commit plus the exact `manifest.json` digest. The
manifest hashes these declarations, the light Check contract and every shared
identity/mesh vector. Consumer CI compares its vendored bytes to the pinned
manifest and executes the relevant shared vectors. A deliberate pin update must
update all changed declarations/vectors together; a package version alone is
insufficient because the consume surface can evolve independently.

In SociACL CI, `scripts/test-all.sh` builds the declarations and runs
`python3 scripts/identity-consume-contract.py`; stale declarations or vector
hashes fail the PR. To regenerate after an intentional change, build
`typescript/ids` then run that script with `--write`. Generation performs no
network, live acceptance, fixture provisioning or release publication.

## #156 library acceptance and consumer handoff

All eight library surfaces requested by [#156](https://github.com/FyberLabs/SociACL/issues/156)
are now mapped above. [#160](https://github.com/FyberLabs/SociACL/pull/160)
exports the existing identity declarations and manifest;
[#162](https://github.com/FyberLabs/SociACL/pull/162) adds separate forum
transition APIs and Rust/TypeScript shared vectors;
[#163](https://github.com/FyberLabs/SociACL/pull/163) adds signed agent delegation
and revocation. The wallet/OIDC credential distinction and manifest drift check
apply to all of them. See [forum transitions](../forum-transitions.md) and
[delegated credentials](../agent-delegation/README.md) for caller obligations.

The two forum surfaces deliberately stay separate: Check answers permission;
transitions validate candidate data updates while preserving admitted ownership.
The owner still comes from authenticated object and key-history admission, never
from a role label, wallet address, UI state, or the contents of an offer.

[s3r.ch#281](https://github.com/FyberLabs/s3r.ch/issues/281) owns replacement of
application copies and its pinned-manifest enforcement. Session issuance, agent
possession challenges, fresh revocation sourcing, and deployed consumer acceptance
are not implemented merely by importing these declarations. The library issue's
completion does not close that application work.

PR CI rebuilds declarations, checks the manifest, and executes the shared
identity, delegation and transition unit/contract vectors. The scheduled
installed-tarball consumer additionally exercises package exports, canonical
bytes, signature acceptance, revocation, audience and scope denial. That
installed-consumer execution belongs only to nightly CI.
