# Authenticated witness checkpoints

`verifyWitnessCheckpoint(checkpointJson, policyEnvelopeJson, expected)` and
Rust's `verify_witness_checkpoint` implement the cryptographic boundary needed by
[#136](https://github.com/FyberLabs/SociACL/issues/136). They authenticate a complete
management snapshot and a matching live policy using independent keys. They do
not install trust, consume requests, reconcile local continuity, or authorize
recovery/root migration. The [bootstrap contract](witness-policy-bootstrap.md)
remains the production integration gate.

## Independently trusted expectations

TypeScript accepts `WitnessCheckpointExpectations`; Rust accepts a borrowed struct
with the corresponding snake_case fields:

| Field | Source and validation |
| --- | --- |
| `managementRoot` | Independently provisioned management/recovery P-256 public key in canonical `x.y` form. |
| `root` | Independently provisioned policy root, distinct from the management key. |
| `rootEpoch` | Exact expected positive safe-integer root epoch from protected configuration/continuity. |
| `audience` | Exact deployment label, 1–1,024 UTF-8 bytes. |
| `client` | Exact intended enrollment/client label, 1–1,024 UTF-8 bytes. |
| `challenge` | Canonical unpadded base64url of 32 unpredictable bytes generated for the outstanding request. |
| `minimumRevision` | Independently trusted positive safe-integer policy floor. |
| `now` | Trusted current nonnegative safe-integer Unix seconds. No clock-skew allowance. |

Never fill expectations from the response being verified. A fresh random request
must bind its challenge to the authenticated enrollment and context before it is
sent. Labels compare exactly, without Unicode normalization or case folding.
These APIs cannot establish the provenance of configuration or unpredictability
of caller-supplied challenges.

## Wire format v1

The outer JSON text contains exactly `type`, `payload`, and `signature`:

- `type` is `sociacl-witness-checkpoint-envelope-v1`.
- `payload` is canonical unpadded base64url of strict UTF-8 JSON bytes.
- `signature` is canonical unpadded base64url of compact 64-byte low-S ES256.
  The management key signs UTF-8 `sociacl-witness-checkpoint-v1\n` followed by the
  **original payload bytes**. No JSON normalization occurs before verification.

The signed payload contains exactly:

```text
{
  type: "sociacl-witness-checkpoint-v1",
  audience, client, challenge, rootEpoch, issuedAt, expiresAt,
  state: { type: "sociacl-witness-policy-state-v1", root, audience,
           revision, jwks, history }
}
```

This is a field outline, not literal JSON or a bootstrap credential. The complete
`state` object is inside the management signature; history is not an unsigned
sidecar. There is no independent outer revision or root that can disagree with
it. All numeric fields require nonnegative JSON integer spelling and safe integer
values; epoch and revision are positive. Duplicate members (including escaped
aliases), unknown fields, malformed keys, unpaired surrogates and invalid UTF-8
are rejected. The checkpoint lifetime satisfies
`issuedAt <= now < expiresAt` and `0 < expiresAt - issuedAt <= 300` seconds.

The separate policy envelope retains the existing `sociacl-witness-policy-v1`
signature domain and policy-root signature. It must be valid **now**, name exactly
the checkpoint's revision and active registry, and pass the shared lifecycle state
validation. A newer response requires a new checkpoint; the verifier never merges
it with the older checkpoint history. Retired-key tombstones and narrowest windows
in the signed snapshot are preserved. Registry order is immaterial; returned
state is sorted using the existing UTF-8 key-ID order.

The management key must not be the policy root or any active/removed witness key
in this checkpoint history. This enforces separation for the observed state; the
operator must also prevent historical cross-role reuse outside that history.
Changing the expected policy root or epoch is an independently authorized
configuration/migration operation. This verifier does not prove its authorization.

Limits: decoded checkpoint payload 2,105,344 bytes; checkpoint envelope 3,145,728
UTF-8 bytes. Existing policy limits, 1,024-key history bound and 2,097,152-byte
serialized-state bound still apply. Limits are inclusive; there is no truncation
or history pruning. Inputs outside these limits fail before unbounded parsing.
Every verification failure returns `bad-attestation`. TypeScript returns deeply
frozen metadata/state; Rust returns owned data. No signing API or private key is
shipped by this change.

## Adapter obligations after successful verification

Success supplies authenticated candidate data, **not** a bearer authorization token.
Do not feed its JWKS directly into a production resolver. The adapter must:

1. Consume the matching outstanding challenge once, bound to the enrollment,
   context and operation. Repeated pure verifier calls can all succeed; the helper
   deliberately maintains no replay cache. Lost responses need explicit request
   reconciliation, not indefinite reuse of old checkpoints.
2. Reconcile against independently protected local epoch/revision/history and the
   management continuity record. A correctly signed checkpoint from a rolled-back
   management store can still be wrong. Conflicting same-revision registries,
   missing tombstones, broadened windows or lowered epochs require refusal and
   reconciliation. Never replace local history with this output blindly.
3. Require explicit management authorization for initial enrollment, recovery or
   migration, using their intended operation binding. This authentication format
   alone does not grant any of those operations. Normal refresh must not repair
   missing/corrupt storage implicitly.
4. Serialize complete state and continuity metadata under a durable transaction;
   recheck both signatures/time bounds after waits and before commit/return.
   Reconcile successful commits with lost responses by exact read-back. Never
   expose uncommitted JWKS or weaken the prior state after a failed refresh.
5. Track the checkpoint's original expiry using trusted UTC and a monotonic
   deadline. Do not extend its lease when caching or rereading, refreshing the
   policy envelope, or restarting. Renew before freshness-sensitive decisions.
   Preserve restrictive offline-revoke behavior as specified by #139.
6. Use only successfully installed, still-fresh policy in record verification,
   alongside separately authenticated fresh account history and present-revocation
   checks. Historical verification is a separate operation.

The existing `openWitnessPolicyClient`/IndexedDB v1 APIs do not perform these steps
and cannot restore a complete checkpoint history. There is intentionally no
`verified: true` callback or direct-write escape hatch. Recovery/migration storage, management service and application startup integration remain #136 and
Panopticon #552. Root migration needs its own authenticated action and atomic
transition; this API requires an exact already-trusted root/epoch.

## Validation

`vectors/ids/witness-checkpoint.json` is executed by both language manifests. Its
96 cases cover full removed-key history, exact-byte signatures, lease boundaries,
request/scope binding, replay against a different request, independent keys,
root epochs, live matching policy, malformed state, altered history, high-S
signatures, duplicate members, Unicode and canonical encodings. Boundary tests in
both languages check inclusive payload/envelope byte limits with valid signed
payloads. TypeScript also tests immutability, invalid runtime arguments and the
explicit absence of challenge consumption in the pure verifier. Browser bundling
and the installed-tarball consumer cover the new export and declarations.

The deterministic generator uses public test scalars and a fixed test challenge.
It is not a production issuer or a source of enrollment credentials. These tests
are cryptographic compatibility evidence, not production adapter or deployment
acceptance.

## Continuity reconciliation and browser refresh

`advanceWitnessCheckpoint(checkpointJson, policyEnvelopeJson, previousJson, expected)`
and Rust's `advance_witness_checkpoint` additionally reconcile the authenticated
snapshot against existing trusted state. They reject revision rollback, conflicting
same-revision registries, missing historical keys, changed key material, resurrected
tombstones and widened issuance windows. Additional authenticated history is allowed.
There is no null-state bootstrap. Both languages execute the same 17 reconciliation
cases in the checkpoint vector family.

The optional `sociacl-ids/checkpoint-store` export provides
`openWitnessCheckpointStore(options)` for refreshing **existing** browser continuity.
Options contain `name`, independent management/policy roots, `rootEpoch`, `audience`,
`client`, `minimumRevision`, and a trusted UTC `now()` in Unix seconds. An optional
`monotonic()` supplies milliseconds (default `performance.now()`); `indexedDB` and
`crypto` are injectable platform dependencies. Protect this configuration separately
from responses. The adapter does not implement a management transport or enrollment.

```js
import { openWitnessCheckpointStore } from 'sociacl-ids/checkpoint-store';
const store = await openWitnessCheckpointStore(trustedConfiguration);
const request = await store.beginRefresh();
// Send request through the independently authenticated management transport.
const response = await management.refresh(request);
await store.install(request, response.checkpoint, response.policy);
const state = await store.readFresh(); // At the freshness-sensitive decision boundary.
```

`beginRefresh()` invalidates this handle's previous lease and request, checks saved
continuity, and creates a random 32-byte challenge. `install()` accepts only that
exact request object, once; failure also consumes it. Requests are held in memory,
never restored after restart. Lost responses require a new request. The service must
bind the request to authenticated client identity and its authoritative continuity.

A strict IndexedDB transaction rereads the latest row, authenticates both signatures,
reconciles history, and saves complete state, exact signed evidence, challenge and
acceptance time together. Verification repeats after lock waits, before completion
and before returning. Failed writes preserve the prior row. A commit followed by
cancellation, expiry or a lost response may persist evidence without granting a
lease; `readInstalled()` inspects that historical state and a new refresh restores
freshness. Concurrent writers serialize; `readFresh()` rejects a row replaced by
another handle, including replacement with different evidence at the same revision.

Freshness is per handle, bounded by the earlier policy/checkpoint UTC expiry and a monotonic deadline anchored
to request creation, at most 300 seconds. Reads do not extend it. Backward/invalid
clocks, failed refreshes, `cancel()` and `close()` invalidate that handle's lease.
Reopening always requires a new checkpoint, even when saved evidence has not expired.
`readInstalled()` enforces the configured revision floor but makes no freshness
claim. A raised floor permits renewal from an older authentic row while blocking
reads of that row. Historical state must not be substituted after `readFresh()` fails.

Opening upgrades the existing policy database to schema 2, excluding schema-1
writers. Existing schema-1 rows are authenticated before use; conversion occurs only
on a successful checkpoint commit. Missing/corrupt rows remain blocked. There are
no bootstrap, restore, reset or root-migration methods. Changed roots, epochs or
client scope cannot silently migrate saved checkpoints. Trusted origin storage is
still required; this is not protection against XSS or complete profile rollback.
External authoritative continuity, explicit recovery/migration authorization and
product startup/verification integration remain #136 and Panopticon #552.

Validation includes 34 storage regressions and real Chromium schema upgrades,
concurrent refreshes, cross-page reads, full-process restart and monotonic expiry.
Run `npm run test:browser-store` with Playwright Chromium installed. This establishes
adapter behavior, not product adoption or deployed management-service acceptance.

The optional [authenticated HTTPS client](witness-checkpoint-client.md) connects
existing-state refresh to a provisioned management endpoint and credential provider.
