# Witness-policy consumer inventory

Source audit for [#136](https://github.com/FyberLabs/SociACL/issues/136), performed
2026-10-28 against these fetched default-branch revisions:

| Repository | Revision | Current integration boundary |
| --- | --- | --- |
| SociACL | `5ad03fd3dd7a7074e801cb2b3f40d235275253e0` | Library APIs, browser transport/store, injected record-verification contexts; no product startup consumer. |
| s3r.ch | `2c815a4aee7662abe2eb0a927b4cb1716b8c7a62` | Browser Check reimplementation; no `sociacl-ids` package import or witness-client consumer. |
| Panopticon | `96d3c3915d90b8beacd50d1e1d70875ff3aed25e` | ACL witness-policy publication/signing/storage; no SociACL checkpoint verifier or keyring-opener consumer. |

This is a scoped source inventory, not a deployed-version audit or a claim about
other repositories, branches, dynamically loaded clients or external consumers.

## Owner and application boundaries

s3r.ch's
[`lib/identity/check.ts`](https://github.com/FyberLabs/s3r.ch/blob/2c815a4aee7662abe2eb0a927b4cb1716b8c7a62/lib/identity/check.ts)
explicitly reimplements the consume contract without importing SociACL through
npm, crates, NAPI or WASM. Its package manifest has no `sociacl-ids` dependency.
Its local SEA wrapping and identity UI are distinct from SociACL account-keyring
recovery. Do not add a policy client to that Check path and call it account
identity adoption. The application owner must define the new enrollment/recovery
boundary and consume integration first; existing wallet or local SEA labels must
not become an independently trusted management identity by inference.

Panopticon's
[`witness_policy_routes.py`](https://github.com/FyberLabs/panopticon/blob/96d3c3915d90b8beacd50d1e1d70875ff3aed25e/core/acl-service/src/acl_service/interfaces/api/witness_policy_routes.py)
is a default-off publication endpoint. It authenticates installed signed policy
for delivery, not complete management continuity or a request-bound checkpoint.
The ACL owner must implement the independently provisioned checkpoint service and
its durable history/epoch/enrollment source before consumer startup can use it
(Panopticon #552). Identity attestation and authenticated storage resolver gates
remain Panopticon #499/#553.

SociACL provides `ResolutionContext`/`Jwks` injection to account and permission
verification. Native consumers within this source tree include
`crates/sociacl-encdisc/src/identity.rs` (current-key resolution and recovery) and
`crates/sociacl-gun/src/group.rs` / `request.rs` (signed authorization).
They are library surfaces with caller-supplied contexts, not a native application
with an independently provisioned endpoint or storage lifecycle. The C crate also
lists the local ids dependency; that does not create a network/storage adapter.
No production native witness-policy consumer requiring an I/O adapter was found
in these three pinned repositories. The Rust checkpoint verifier is a pure
boundary available to a future native adapter, not an implemented one.

## Recovery error re-audit

The searches below found no new account-keyring opener or `recovery-stale` UI
consumer in s3r.ch or Panopticon relative to the
[earlier opener audit](recovery-stale-consumer-audit.md). Panopticon's recovery proof
route still moves a workflow session to `awaiting_proof`; it does not authenticate
or install a SociACL keyring. The checkpoint verifier added for #136 does not open
keyrings or interpret opener errors. Any future integration must re-run the audit
and prove that stale/invalid deliveries cannot install keys, mark recovery
successful, lower floors, or promote a backup as authentic.

## Reproduce and continue

With `REV` set to the pinned revision for the repository:

```sh
git grep -n -E \
  'sociacl-ids|sociacl_ids|resolveWalletLinkNow|verifyRevokeNow|openWitnessPolicy' \
  "$REV" -- . ':!package-lock.json' ':!pnpm-lock.yaml' ':!uv.lock' ':!Cargo.lock'
git grep -n -i -E \
  'recovery.?stale|open.?recovery.?copy|open.?delivered.?keyring|rotate.?and.?reseal|AccountKeyring|sociacl.encdisc|sociacl/(recovery|delivery)' \
  "$REV" -- . ':!package-lock.json' ':!pnpm-lock.yaml' ':!uv.lock' ':!Cargo.lock'
git grep -n -E 'sociacl.ids|sociacl-encdisc' "$REV" -- '**/Cargo.toml'
```

No matches exits 1. Inspect implementation/manifest matches separately from tests,
fixtures and docs. The concrete next steps are authenticated checkpoint issuance,
checkpoint-aware durable browser storage with one-use requests and bounded leases,
explicit restore/root migration, then owner-approved application startup and
record-resolution wiring. The [checkpoint verifier](witness-checkpoint.md) supplies
the signature boundary only. Keep #136 open until those consumer acceptance cases
exist; deployed evidence remains Panopticon #552.
