# Witness policy bootstrap, freshness and recovery

This is the integration contract for [#135](https://github.com/FyberLabs/SociACL/issues/135).
The [policy APIs](witness-policy-client.md) authenticate envelopes, enforce
observed lifecycle history, and persist browser state. They do not establish
freshness or authenticate a restored history. This contract defines those missing
trust inputs and the conditions under which production consumers may operate.
The original contract introduces no cryptographic algorithm. The subsequent
[checkpoint authentication API and wire format](witness-checkpoint.md) implement
its signature boundary; durable adapters and services are still required.
Provisioning/recovery adapters must implement and test this contract before
production adoption (#136) or deployment (FyberLabs/panopticon#552) is complete.

## Independent provisioning authority

A deployment must provision a management/recovery authority independently of the
policy delivery endpoint, witness keys, and policy-signing root. Its credential
must arrive through authenticated application installation or managed enrollment,
not through a policy response, a URL parameter, or the browser database being
recovered. An account login, wallet signature or OIDC assertion does not by itself
authorize changes to deployment-wide witness trust.

That authority maintains a durable, serialized record of:

- deployment audience, administrative root and monotonically increasing root epoch;
- current policy revision and exact current registry;
- complete policy key history, including all removals and narrowest accepted windows;
- authorized client/enrollment continuity and recovery events.

It must authenticate policy installation evidence from the owner of the durable
server policy store. It cannot infer this record by scraping the public latest
policy endpoint. Its state and backup/restore procedure must resist rollback;
restoring an older management backup is not permission to lower floors. A
compromise of this authority is outside the policy-signature protection boundary
and requires independently authenticated operator recovery.

Policy signing and recovery authority must have separately provisioned credentials
and access control. Administrative private keys stay in controlled signing custody
with audited access and backed-up recovery material. Witness processes receive
neither administrative signing keys nor recovery credentials. Production operators
must document the concrete custody and recovery mechanism; test fixture scalars
are never production keys.

## Fresh checkpoint contract

Before first enrollment, recovery, and resuming freshness-sensitive operations, a
client requests a checkpoint through an authenticated management channel. Each
request uses a fresh unpredictable 32-byte challenge. The authenticated response
must bind the challenge, intended client/enrollment, deployment audience, root
epoch/root, policy revision, and the complete lifecycle state (or an exact-byte
cryptographic commitment to that state). It also binds issuance and expiry times.
A digest supplied beside an untrusted snapshot is not authentication.

The checkpoint authority takes this snapshot under the same serialization boundary
as its accepted policy history. It issues no checkpoint if its own view is stale,
rolled back or unverified. This is an independent trust requirement, not a service
that currently exists in the public delivery route.

The client must:

1. Authenticate the response using the independently provisioned management trust,
   match the outstanding challenge and client/audience, and consume that challenge
   once. Reject unexpected or replayed responses.
2. Require a trusted UTC clock with `issuedAt <= now < expiresAt`. The maximum
   checkpoint lifetime is 300 seconds; deployments may shorten it. There is no
   skew extension. A backward clock change or unavailable trusted clock requires
   a new checkpoint before freshness-sensitive use. A monotonic deadline also
   prevents wall-clock rollback from extending an already accepted lease.
3. Match the checkpoint root epoch and complete state against protected local
   continuity. Never lower the epoch, revision, or historical restrictions. A
   conflicting same-revision registry or inconsistent history stops processing
   and requires operator reconciliation; do not pick whichever copy arrived last.
4. Authenticate the full checkpoint state commitment before parsing it as
   `previousJson`. Validate its schema/scope through the shared transition. The
   state is not a root-signed policy envelope and cannot be trusted merely because
   an envelope authenticates its current registry.
5. Obtain a live envelope for the checkpoint's exact revision and registry, verify
   it with the checkpoint's independently authorized root/audience, and apply the
   shared transition against the complete checkpoint history. If the endpoint is
   ahead of the checkpoint, request a new checkpoint; if behind, refuse the stale
   response. A greater revision alone is not permission to skip history.
6. Under a durable serialized transaction, reconcile the latest local history,
   recheck both checkpoint and envelope expiry, and commit complete state and its
   checkpoint/continuity metadata before exposing trust. Races require rereading
   and retrying with fresh evidence; lost responses require exact read-back.
   Recheck lease expiry before returning after commit too. A post-commit failure
   can leave the row installed; reconcile it without granting current-trust use.

A checkpoint is fresh as of its serialized snapshot, with a bounded lease; it
cannot promise knowledge of changes committed afterward. No retry, cached read,
HTTP 304, unchanged revision, or newly issued envelope may extend that lease.
After restart, obtain a new checkpoint unless a platform can prove the saved lease
and monotonic elapsed time survived without rollback. After expiry or refresh
failure, block new logins/rotations and other freshness-sensitive decisions until
renewal. Previously installed keys may remain available for explicitly historical
verification; that does not certify present revocation or current account history.
Identity-history freshness is a separate requirement (Panopticon #499/#553).
This gate does not prevent creating or retaining a current-key offline revoke,
or applying a verified revoke to deny access. It gates positive authorization;
missing freshness never authorizes ignoring a revoke. The present-only lifetime
of an unwitnessed revoke and the historical timestamp requirement are unchanged.

The [v1 checkpoint format](witness-checkpoint.md) binds complete history and request
context with a separate management signature. Its owning service/adapter must
bind every field above and supply replay/expiry/concurrency tests; no unsigned
JSON or caller-provided boolean substitutes for that authentication.

## First installation and missing state

An empty database, new profile or changed database name is not evidence of a new
identity or authorization to bootstrap. The management authority must explicitly
authorize enrollment and supply the checkpoint. Even a first-time client joining
an established deployment needs the deployment's complete history.

`bootstrap(envelope)` can represent that checkpoint only when its history consists
exactly of the current registry, with no omitted removals or earlier narrower
windows. Otherwise the existing browser API cannot install the required history:
production enrollment stays blocked until a checkpoint-aware restore adapter is
implemented. Do not use a higher revision floor as a substitute for missing
history, directly write IndexedDB internals, or repeatedly bootstrap old envelopes.

The independent `minimumRevision` must be at least the current checkpoint revision;
never derive it from the downloaded envelope. It is a useful rollback bound, but
is insufficient to authenticate history, identify the newest policy, or detect a
conflicting policy with the same revision.

## Eviction, corruption and profile rollback

On missing, corrupt, unverifiable or inconsistent local state, stop current trust
use and enter recovery. Keep the damaged state for diagnosis without exposing its
keys as trusted. Do not catch the failure and call `bootstrap`, lower the floor,
rename the database, prune history, or change the root.

A valid-looking profile rollback may pass every local signature/schema check.
IndexedDB and storage-persistence permission cannot detect this. Before resuming
freshness-sensitive use, reconcile against the independently authenticated
checkpoint and the management continuity record; an on-device flag in the same
profile is not an external rollback anchor.

Recovery requires explicit authenticated authorization for the intended client,
a fresh checkpoint, its complete authenticated history, and a live matching
envelope. Merge constraints with any independently trusted surviving state: retain
all tombstones and narrowest windows. Do not silently discard a trusted local
entry absent from the management history; stop and reconcile the discrepancy.
Keep the existing 1,024-key and serialized-state resource bounds; exhaustion
requires an explicit migration decision, never history pruning.
Atomically install the restored state and new continuity metadata, record the
recovery event, and verify exact read-back before resuming. Concurrent normal
writers must be excluded or forced to reread the restored generation.

If no authoritative complete history survives, recovery fails closed. A latest
signed JWKS, old backup, current account password, or administrator claim without
independently authenticated recovery authorization cannot reconstruct it. Do not
relabel history loss as a fresh namespace. Any deliberate trust discontinuity
requires a separately reviewed migration and explicit treatment of old proofs.
The current IndexedDB API deliberately has no restore/reset entry point; #136
must implement this process before claiming recovery support.

## Root migration and compromise

Routine root migration requires an independently authenticated management action
that binds the old and new root epochs/keys, audience, effective cutover, complete
history commitment and policy revision. Increment the protected epoch; retain
revision floors, key tombstones and narrowest windows across the cutover. Validate
a live new-root envelope against that authorized checkpoint, then atomically
switch the active root/state/epoch. Changing a configuration string or accepting a
self-signed replacement root is never a migration. The existing lifecycle helper
rejects old-root state under a new root; an authorized migration adapter is needed.

Retain old-root evidence for audit and explicitly historical verification, scoped
to its old epoch. Do not silently accept new updates under either root after
cutover. Root rotation does not reset account identity, authorize an account-key
rotation, or erase credential revocations. Offline clients must re-enroll through
the management continuity check before using the new epoch for current decisions.

For suspected witness-key compromise, stop new attestations and publish an
administratively authorized removal/narrowing and fresh checkpoint. A valid
signature cannot distinguish a genuine historical timestamp from a forgery within
the compromised key's allowed window. Do not claim that retirement, narrowing or
transport freshness repairs affected records. Quarantine affected trust decisions
and define incident-specific re-attestation/recovery with the application owner;
key removal can make historical proofs unverifiable.

For suspected policy-root compromise, stop accepting updates under that root and
freeze freshness-sensitive decisions. An old-root cross-signature is insufficient
to authorize its replacement. Use the separately provisioned recovery authority,
a new root epoch and reconciled last-known-good history; preserve authenticated
removal evidence. Conflicting or missing evidence requires manual incident
resolution, not selecting the largest attacker-supplied revision. If recovery
credentials are also compromised or unavailable, remain stopped until a separately
reviewed out-of-band trust re-establishment procedure is authorized.

## Executable evidence and implementation gates

The existing TS/Rust lifecycle APIs are unchanged. Shared
`vectors/ids/witness-lifecycle.json` includes paired threat-model cases:

| Cases | What they establish |
| --- | --- |
| `limit-still-valid-replay-with-stale-floor` / `checkpoint-floor-refuses-still-valid-replay` | A valid old policy passes a stale floor; an independent newer floor rejects it. |
| `limit-missing-history-cannot-detect-resurrection` / `checkpoint-history-refuses-resurrection` | A current floor without history cannot detect removed-key resurrection. |
| `limit-revision-gap-cannot-see-intermediate-removal` / `complete-history-refuses-intermediate-resurrection` | Skipped revisions can hide a removal. |
| `limit-revision-gap-cannot-see-intermediate-narrowing` / `checkpoint-narrowing-refuses-reexpanded-window` | Skipped revisions can hide tighter issuance bounds. |
| `checkpoint-recovery-preserves-tombstones` / `checkpoint-recovery-still-requires-live-envelope` | Trusted restored history is retained; envelope expiry still applies. |
| `limit-new-root-empty-state-is-not-migration` / `root-replacement-does-not-rebind-old-state` | Supplying a new root and null history bypasses continuity; normal transitions reject root replacement. |

The `limit-*` cases intentionally succeed at the primitive boundary. They
illustrate inputs a production orchestration layer must not authorize, not safe
production bootstrap examples. The fabricated checkpoint states are trusted test
inputs, not examples of authenticating management responses.

`typescript/ids/test/indexeddb.js` additionally exercises eviction after removal
and valid signed profile rollback. Missing-state reads/refreshes fail without
implicit bootstrap; a rollback passes local reads until an external floor blocks
it. Existing corrupt-state and changed-root cases remain authoritative.

Run the canonical `bash scripts/test-all.sh` with Node 24+ for both language
manifests and adapter cases. These tests establish the library boundary and why
external continuity is required. They do not test a checkpoint service, production
clock, root custody or deployed restore transaction. #136 and Panopticon #552 must
supply those acceptance tests, including challenge replay, expired leases,
checkpoint/envelope races, same-revision history tampering and authorized migration.
