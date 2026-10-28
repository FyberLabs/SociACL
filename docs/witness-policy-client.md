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
tests. Durable browser/server adapters and those acceptance tests remain open.

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

The pure transition above supplies the lifecycle decision in step 2. Durable
adapter execution, bootstrap, delivery, root lifecycle and deployment remain open. Do not assign the verifier's result directly to a production resolver's
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
