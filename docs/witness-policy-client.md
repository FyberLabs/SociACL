# Witness policy export authentication

`verifyWitnessPolicyEnvelope(envelopeJson, root, audience, now)` and Rust's
`verify_witness_policy_envelope` authenticate the export format from
[Panopticon #543](https://github.com/FyberLabs/panopticon/pull/543). This is the
client cryptographic boundary for #68 F4. It does not install a trust policy,
fetch a URL, persist a revision, or prove that a bundle is the latest policy.

The caller supplies the administrative P-256 public key as canonical `x.y`, an
exact deployment audience, and current Unix seconds from a trusted clock. The
root and audience must be provisioned independently of the envelope and delivery
channel. Public scalar keys in shared fixtures are test identities only.

The outer JSON text must contain exactly `type`, `payload`, and `signature`, with
type `sociacl-witness-policy-envelope-v1`. Payload and signature are canonical,
unpadded base64url. The signature is compact 64-byte, low-S ES256 over UTF-8
`sociacl-witness-policy-v1\n` followed by the **original payload bytes**. Parsing
never normalizes or reserializes the signed content. Duplicate members, including
escaped aliases, fail closed in both JSON layers; unknown fields are rejected.

The signed document contains exactly `type`, `audience`, `revision`, `issuedAt`,
`expiresAt`, and `jwks`. Its type is `sociacl-witness-policy-v1`; revision is a
positive safe integer. Integer fields use nonnegative JSON integer spelling
(no fractions, exponents, or negative zero). Transport validity requires
`issuedAt <= now < expiresAt` with a lifetime of at most 86,400 seconds, without
clock-skew expansion. Expiry applies to acceptance of the transport document;
it is distinct from the issuance windows of its witness keys.

Each public key requires `kid`, `kty: EC`, `crv: P-256`, `alg: ES256`, `use: sig`,
`key_ops: [verify]`, canonical on-curve `x` and `y`, and safe-integer
`notBefore < notAfter`. Key IDs contain 1–128 Unicode scalar values. Duplicate
IDs, duplicate public points, private or unknown fields, and using the
administrative root as a witness key are rejected. Retired witness windows may
remain in the registry for historical proofs; an empty key list is a valid
signed removal of all witness trust.

Limits are 262,144 decoded payload bytes and 360,448 UTF-8 envelope bytes. Larger
inputs fail before signature verification; there is no truncation. All policy
verification failures return `bad-attestation`. TypeScript returns a frozen
copy; Rust returns the validated `WitnessPolicy` document.

## Client policy lifecycle transition

`advanceWitnessPolicy(envelopeJson, previousJson, root, audience,
minimumRevision, now)` and Rust's `advance_witness_policy` calculate a complete
candidate snapshot for an adapter's atomic update. They authenticate the envelope
again and enforce the same observed-key lifecycle rules as Panopticon's policy
repository. They perform no I/O and do not install or publish trust.

`previousJson` must be the exact latest state read from the adapter's trusted,
rollback-protected storage. It is JSON text so duplicate fields remain detectable.
TypeScript `null` / Rust `None` is allowed only for independently authorized first
bootstrap; missing, corrupt or unreadable storage must never silently become a
bootstrap. The required `minimumRevision` is an independently provisioned positive
safe integer, not a value taken from the envelope. It applies on every call in
addition to the stored revision floor.

The returned `sociacl-witness-policy-state-v1` snapshot contains the pinned root,
audience, revision, current JWKS, and complete observed key history. Each history
entry contains its last accepted public JWK and a `removed` boolean. The parser
rejects wrong root/audience, unknown fields, invalid keys, duplicates, and any
mismatch between current JWKS and nonremoved history. A plausible but stale or
forged snapshot cannot be detected from its structure alone: this format is not
an authenticated transport envelope and must not be supplied by a network caller.

Transitions enforce:

- Revisions below either floor are rejected. Equal revisions require identical
  key registries, ignoring key order. A newly signed transport refresh may have
  different issue/expiry times without changing policy revision.
- An existing key's `kid` and public point cannot change, and its issuance window
  may only narrow. Time retirement alone leaves the key available for historical
  verification within its window.
- Omission marks a key permanently removed. Its ID and public point remain in
  history; neither can be reused under a later revision, even with narrower bounds.
- A new key requires both a new ID and new material. Removal of all keys is valid
  and preserves all prior history. Failures return `bad-attestation` without
  changing the supplied state.

Current keys and history entries are sorted by UTF-8 key-ID order in both
languages. The state accepts at most 1,024 historical keys and 2,097,152 UTF-8
serialized bytes. Exhaustion fails closed; history is never pruned to admit a new
key. Empty updates and idempotent refreshes remain possible at the history cap.
An authenticated namespace/root migration requires a separate operator procedure;
this API does not provide a reset or drop history when configuration changes.

The rules apply to **observed** policies. A revision jump is allowed, but a client
cannot infer an omitted key or narrower window from revisions it never received.
Initial bootstrap also cannot reconstruct pre-bootstrap key history. Server-side
permanent history, trustworthy bootstrap state, and a defined distribution and
freshness protocol remain necessary. A policy floor alone does not establish
that a current-looking signed bundle is the newest one.

### Adapter transaction requirements

Read the latest snapshot and serialize the transition, clock check, and complete
state write under one lock or an equivalent atomic compare-and-swap. Do not expose
candidate JWKS before the entire state (including history and revision) commits.
If the write loses a race, discard its candidate, reread, and rerun the transition
with the current clock. A failed or lost write response must be reconciled against
the exact saved state; it must not trigger a bootstrap or floor reset. Recheck
transport expiry immediately before commit after any asynchronous work or waits.
The function's `now` argument is only the caller's point-in-time observation.

The shared cases cover serialization/restart, conflict rechecks and expiry after
lock waits; they are not deployment persistence or concurrent-database acceptance
tests. The IndexedDB adapter below supplies browser transactions and restart tests. Native client adapters and deployment acceptance remain open.

## Before a client may use the returned JWKS

An authenticated document is not an installed policy. An adapter must still:

1. Establish a trusted bootstrap revision/freshness requirement independently of
   the bundle. A first-time client cannot discover the latest policy from a valid
   old signature alone.
2. Under one durable update transaction, reject revisions below its stored floor,
   reject conflicting same-revision registries, and enforce permanent key history:
   no widened windows, changed key material, or resurrection of removed keys.
3. Recheck the transport clock at commit after waiting for any lock, and atomically
   persist the policy, floor, and key history before exposing new trust to readers.
4. Preserve administrative root custody and define authenticated root rotation and
   compromise recovery. HTTPS delivery alone does not replace these requirements.

The pure transition above supplies the lifecycle decision in step 2. Browser adapter execution is available below; native client storage, bootstrap, delivery, root lifecycle and deployment remain open. Do not assign the verifier's result directly to a production resolver's
JWKS. The helper deliberately performs no installation or rollback-floor reset.
A compromised witness can still forge timestamps within its authorized window;
validity-window enforcement does not detect such forgeries by itself.

## Validation

`vectors/ids/witness-policy.json` is consumed by both language manifests. It has
64 cases, including exact whitespace, empty policies, retired windows, inclusive
issuance/exclusive expiry, a maximum-size payload, domain/root/audience changes,
high-S signatures, malformed UTF-8, duplicate keys/members, and resource limits.
All nine accepted exports were also checked against Panopticon's actual
`verify_policy` implementation at merged source `7b2ddda1`. The deterministic
authoring script uses public test scalars 17–20 and is not a key-provisioning tool.


`vectors/ids/witness-lifecycle.json` adds 56 shared transition cases: 15 accepted
sequences and 41 rejections. They cover matching/reordered refreshes, restart
floors, narrowing, retirement, removal, material/ID reuse, concurrent-winner
rechecks, clock expiry, malformed stored state, UTF-8 ordering, and history/byte
limits. Test fixtures use public scalars only and are never bootstrap credentials.


## IndexedDB browser adapter

The optional `sociacl-ids/indexeddb` entry point exports
`openWitnessPolicyStore`. It imports no Node modules and does not touch IndexedDB
until opened. This is a browser platform adapter for the existing TS/Rust shared
lifecycle contract; it introduces no new signature or lifecycle rules and is not
a Rust native-storage implementation.

```ts
import { openWitnessPolicyStore } from 'sociacl-ids/indexeddb';

const store = await openWitnessPolicyStore({
  name: 'application-witness-policy-v1', // dedicated, stable database name
  root: trustedConfig.administratorRoot,
  audience: trustedConfig.audience,
  minimumRevision: trustedConfig.minimumRevision,
  now: () => Math.floor(Date.now() / 1000), // must satisfy application's trusted-clock contract
});
// Only an independently authorized first-install flow may call bootstrap(bundle).
// Ordinary startup never catches a missing row and bootstraps automatically.
const installed = await store.read();
const updated = await store.refresh(signedBundleText);
// These results have committed. Pass their JWKS to the authenticated resolver
// with the separate account-history and freshness requirements still enforced.
store.close();
```

`bootstrap` refuses any existing row. `refresh` refuses missing or corrupt state.
Every write uses one strict-durability IndexedDB read/write transaction over the
latest row. The row contains the entire revision/JWKS/history snapshot, original
signed envelope and acceptance time. Independent connections serialize on the
same object store, so a losing writer evaluates the winner's history and cannot
replace it with a stale candidate. There is no in-memory fallback, reset API,
history pruning, or automatic root migration. Unsupported strict durability fails
closed.

A read reauthenticates the saved envelope at its recorded acceptance time and
requires it to match the stored revision/registry. Ordinary transport expiration
does not delete previously installed witness windows: historical attestations
still need their retired keys. A newly raised configuration floor blocks old reads
but permits an authenticated refresh above that floor using all stored history.
Root/audience changes fail until a separate trusted migration is defined.

Updates check the clock after acquiring the transaction, after the write request
succeeds (while the transaction can still abort), and again before returning the
committed result. Aborted writes never expose the candidate. If commit succeeds
but the final clock check fails, the call rejects although the row may have
committed. Reconcile with `read()`; do not bootstrap, reset or blindly assume the
old revision. The final check cannot undo an already completed transaction.

The database is **trusted origin-local storage**, not a cryptographic anti-rollback
anchor. The saved history and acceptance time are not signed by the root. XSS,
malicious same-origin code, profile modification, backup rollback or origin-data
eviction can defeat local continuity. Storage persistence permission can reduce
eviction but cannot authenticate a lost history. A missing row must require the
application's independently authenticated restoration/bootstrap procedure and
freshness floor; merely seeing an empty database is not authorization. Use a stable
database name; choosing a new name is effectively a new bootstrap namespace.
Callers must not supply the factory, clock, root, floor or database name from an
untrusted bundle. The optional `indexedDB` factory supports test/platform injection.

`npm test` includes 32 adapter tests using `fake-indexeddb`, including 15 unchanged
shared TS/Rust lifecycle cases executed through database transactions. Additional
cases cover restart, contention, abort/quota failures, corruption, floor increases,
expiry and lost-response reconciliation. A separate real-Chromium test uses a
persistent profile, closes and relaunches the browser process, and checks concurrent
conflicts, cross-page reads and rollback rejection:

```sh
cd typescript/ids
npm ci
npx playwright install --with-deps chromium
npm run test:browser-store
```

CI runs this in the separate `browser-policy-store` job. Browser-process restart
is tested; sudden power loss, browser eviction recovery, other browser engines and
production application adoption are not established by these tests. Distribution,
independent freshness, root custody/compromise recovery and deployment acceptance
remain open under #68 F4.


## Panopticon HTTP delivery integration

Merged [Panopticon PR #550](https://github.com/FyberLabs/panopticon/pull/550) adds the
server delivery path `GET /api/v1/acl/sociacl/witness-policy`, disabled until an
operator provisions its signed files and independent public root/audience. The
endpoint returns the same envelope accepted by the existing TS/Rust verifier;
there are no new signature or lifecycle rules. The edge allows only this exact
GET without login and keeps it on the anonymous client-address rate limiter.

The server verifies each response against its current installed policy under a
shared lock, rejects stale/unavailable state with 503, and sends `no-store`.
Unconfigured publication returns 404. Treat every non-200, malformed response or
verification failure as a failed refresh; never clear the local revision/history,
bootstrap automatically, or install unsigned JWKS as a fallback. An already
installed policy remains subject to the application's independent freshness rules.

A successful download is still only an input to `store.refresh`, or to an
independently authorized first `store.bootstrap`. The client must keep its root,
audience, bootstrap floor and clock independent of the response and redirect
source. The endpoint cannot establish latest-revision freshness for a new client,
repair lost local history, or revoke artifacts previously delivered. Production
role grants, signed-file mounts/renewal, TLS/edge acceptance, actual application
adoption and root custody/compromise recovery remain outstanding. PR #550 and SociACL companion #133 are merged. Their final CI passed; this records implementation and test evidence, not deployment.

Local Panopticon validation passed 157 ACL-service tests (including 27 new HTTP,
startup and restricted-role cases) and 244 edge tests (one existing skip), including
11 new route/limiter/proxy cases. Boundary and dependency checks also passed.


## Browser HTTPS client

`sociacl-ids/witness-client` exports `openWitnessPolicyClient`, combining the
existing IndexedDB store and an HTTPS download. Opening it creates no trust and
performs no fetch. It exposes `bootstrap()`, `refresh()`, `read()` and `close()`:

```ts
import { openWitnessPolicyClient } from 'sociacl-ids/witness-client';

const client = await openWitnessPolicyClient({
  name: 'application-witness-policy-v1',
  root: trustedConfig.administratorRoot,
  audience: trustedConfig.audience,
  minimumRevision: trustedConfig.minimumRevision,
  now: () => Math.floor(Date.now() / 1000),
  url: trustedConfig.policyEndpoint,
  timeoutMs: 10000,
});
// An independently authorized first-install flow calls client.bootstrap().
// Ordinary refresh must never turn missing state into automatic bootstrap.
const installed = await client.refresh({ signal: requestAbortController.signal });
// Only now has the downloaded policy authenticated and committed.
useInstalledPolicy(installed.jwks);
client.close();
```

The URL is independently trusted configuration: it must be absolute HTTPS and
contain no user information, query or fragment. Root/audience/floor/clock/name
remain independently configured too; nothing is discovered from a redirect or
response. Normal browser TLS and CORS checks remain active. GET requests use
`redirect: error`, `credentials: omit`, `cache: no-store` and `referrerPolicy:
no-referrer`, with `Accept: application/json`. The client accepts only status 200,
a non-redirected JSON response and a readable body. Non-200 responses (including
304 and partial 206 responses), network errors and invalid signatures reject.

Both advertised Content-Length (if present) and streamed **decoded body bytes**
are limited to `MAX_WITNESS_ENVELOPE_BYTES` (360,448). Missing or understated
lengths cannot bypass the streaming limit. Text decoding is strict UTF-8 and
preserves BOM bytes so malformed input cannot be repaired before verification.
The original envelope text then passes through the existing TS/Rust-compatible
verifier and lifecycle decision inside the store's serialized transaction.
No new signature, lifecycle or shared-vector rules are introduced. This browser
adapter is not a Rust native HTTP/storage implementation.

The timeout defaults to 10 seconds and must be an integer from 1 through 60,000
milliseconds. It covers response headers and the full streamed body; timeout,
caller abort or `close()` cancels an active download. Late responses cannot install
state. Waiting is bounded even when an injected test transport ignores abort or
its stream cancellation never resolves. As with browser timers generally, a
suspended or blocked JavaScript event loop can delay the timeout callback; the
elapsed monotonic deadline is rechecked before storage, and the store's trusted
clock independently rejects expired policy on resumption.

Cancellation and the timeout end **before the database transaction starts**.
Once installation starts, normal store commit/abort rules apply. `close()` drains
already-started database transactions rather than promising to roll them back.
An error after a commit still requires reconciliation using `read()`, as described
in the store contract. Concurrent downloads rerun lifecycle validation against
the latest committed row, so a delayed response cannot overwrite newer history.

A failed refresh rejects; it never returns the previously stored policy, clears
history, or retries as a bootstrap. `read()` explicitly reads installed state and
does not establish current network freshness. Callers must enforce their own
freshness policy before resuming freshness-sensitive operations after failure.
Root compromise recovery, eviction/rollback recovery, bootstrap approval and
production application adoption remain outside this adapter. The optional
`fetch` and `indexedDB` injections are trusted platform/test dependencies, never
request-supplied values.

Validation includes 42 transport/store tests using the existing shared lifecycle
fixtures, plus the real Chromium HTTPS run in `npm run test:browser-store`. That
run creates a temporary test-only TLS certificate, uses an actual HTTP server and
persistent browser profile, and checks cookie/referrer omission, redirect refusal,
timeout/error preservation, rollback rejection and browser-process restart. Only
the test browser ignores the generated certificate error; the library has no TLS
bypass option. The existing full TS/Rust shared corpus remains authoritative for
signature and lifecycle parity. No deployed endpoint or application rollout is
claimed by these tests.
