# Recovery stale consumer audit

This addresses #68 F13: whether a UI treats `recovery-stale` as proof that a
keyring delivery is genuine. At the pinned source revisions below, no such UI
consumer was found. This is a source audit of three repositories, not a deployed
application test or an assertion about other consumers, branches, or releases.

## Scope and evidence

Default-branch snapshots inspected on 2026-10-26 (America/New_York):

| Repository | Revision | Result |
| --- | --- | --- |
| SociACL | `a9e0cca7098f6789eebacb22a23cb6c64d8f31c0` | Opener implementations, exports, tests, and documentation; no application UI consumer |
| s3r.ch | `b712a14aeec3ef769683e8fa72bd9b7e10b01752` | No keyring opener or stale-result handler; local SEA wrapping uses a separate protocol |
| Panopticon | `ffe60df45386ad60b6134dba71356571d328cf98` | No keyring opener or stale-result handler; recovery-session HTTP routes are a separate workflow |

SociACL's [delivery API](https://github.com/FyberLabs/SociACL/blob/a9e0cca7098f6789eebacb22a23cb6c64d8f31c0/crates/sociacl-encdisc/src/delivery.rs#L152)
explicitly warns that a lost device's retired signing key can produce a stale
result. The [TypeScript implementation](https://github.com/FyberLabs/SociACL/blob/a9e0cca7098f6789eebacb22a23cb6c64d8f31c0/typescript/contract/delivery-seal.ts)
likewise rejects that path without returning key material. Recovery-copy openers
also compare the decoded sequence before completing keyring import; their stale
error is not a successful keyring validation result.

s3r.ch's [local wrap protocol](https://github.com/FyberLabs/s3r.ch/blob/b712a14aeec3ef769683e8fa72bd9b7e10b01752/lib/identity/wrap.ts)
uses `s3r.ch/sea-wrap/aes-gcm/v1` and the `s3rch-wrap-v1:` paper format.
[IdentityBar](https://github.com/FyberLabs/s3r.ch/blob/b712a14aeec3ef769683e8fa72bd9b7e10b01752/components/IdentityBar.tsx)
creates those wraps, and [readLocalMeshPair](https://github.com/FyberLabs/s3r.ch/blob/b712a14aeec3ef769683e8fa72bd9b7e10b01752/lib/identity/mesh.ts#L82)
opens them through `unwrapSeaPair`. These are not SociACL account-keyring openers.
The `stale` status in [views-backup.ts](https://github.com/FyberLabs/s3r.ch/blob/b712a14aeec3ef769683e8fa72bd9b7e10b01752/lib/views-backup.ts)
concerns View manifests, not account recovery.

Panopticon's [recovery-session routes](https://github.com/FyberLabs/panopticon/blob/ffe60df45386ad60b6134dba71356571d328cf98/core/acl-service/src/acl_service/interfaces/api/sociacl_routes.py#L259)
create a pending session and move proof submissions to `awaiting_proof`.
The proof route does not verify or install a keyring. Its generated SDK endpoints
are HTTP clients for that workflow, not evidence of cryptographic recovery
integration. The ACL dashboard, builder, hook, and helpers contain no recovery
stale handling in this snapshot.

## Reproducing the source search

Run this in each repository with `REV` set to its full revision above:

```sh
git grep -n -i -E \
  'recovery.?stale|open.?recovery.?copy|open.?delivered.?keyring|rotate.?and.?reseal|AccountKeyring|sociacl.encdisc|sociacl/(recovery|delivery)' \
  "$REV" -- . ':!package-lock.json' ':!pnpm-lock.yaml' ':!yarn.lock' ':!Cargo.lock'
```

A no-match search exits 1. Inspect matches as well as the local recovery paths:

```sh
git grep -n -i -E 'recovery|unwrapSeaPair|wrapSeaPair|stale' "$REV" -- \
  components lib frontend core/acl-service controlplane-edge products
```

The first search finds SociACL's library surfaces and Panopticon's recovery-session
HTTP paths; it finds no s3r.ch match. Manual tracing of the paths linked above
separates those results from actual keyring consumers. Searches cannot rule out
untracked code, dynamic external integrations, or deployed versions outside scope.

## Requirements when a consumer is added

Every opener error must leave recovery unsuccessful. In particular,
`recovery-stale` must not install keys, promote a backup as trusted, label a delivery
as genuine, lower the expected sequence, or reset the shared head floor. A retired
key holder can deliberately produce this result. UI wording may ask the user to
refresh recovery information, but must not claim that the sender or copy has been
authenticated successfully.

Accept key material only from a successful opener using the authenticated chain
resolver and trusted expected sequence. If refreshing history is appropriate,
fetch and authenticate that history through the normal trust path, then run the
full opener again without weakening rollback protections. Follow the
[store restoration requirements](recovery-store-operations.md) as well.

Before shipping a consumer, add an integration test that delivers a stale wrap
signed by a retired/lost key and asserts no key installation, backup promotion,
authentication success, or floor/sequence rollback. Cover stale recovery copies
and the other opener failures too, plus a successful current-keyring case.
Re-run this audit against the integrating revision. The missing lost-device
rotation UI and its new-passphrase choice remain #68 F19; this audit does not
implement that flow or establish F14/F16 production adapter acceptance.
