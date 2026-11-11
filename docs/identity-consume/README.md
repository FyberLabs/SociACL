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

## Remaining #156 work

This closes the missing copied declaration/pinning surface for existing
canonical identity functions. It does not claim #156 complete: delegated agent
credentials and shared forum transition vectors/API outside Check still need
implementation. s3r.ch#281 owns replacing application copies and enabling its
pinned manifest check; this PR does not change that application.
