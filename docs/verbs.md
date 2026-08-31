# Verbs

Implement against this page. Fail closed unless a named rule allows the call.

## CHECK(action, object, accessor)

Hot path. Live Check is server-evaluated. After a cut, `Client::check` evaluates the same rules against a pre-cut bundle only. Load that bundle from durable bytes or a file with the holder secret (`Client::from_bytes`, `Client::from_path`, C `sociacl_client_open`, Python `Client.from_bytes`).

**Inputs**

- `action` — caller-supplied verb on the object (`read`, `write`, `execute`, …). Used by `posix-mode` bits and by a `delegate` action mask. Otherwise cached, not interpreted. The two are not merged.
- `object` — protected object id. Check parses kind, owner, properties, version. Properties select the predicate (`predicate`, and for `posix-mode` also `mode` and `group`).
- `accessor` — person, agent, or device id.
- `predicate` — optional. If set, must equal the object's named predicate. The accessor cannot pick a richer predicate than the object names.
- `zookie` — optional freshness token from a prior Check. Bound to this object version.
- `attestation` — optional Ed25519-signed statement (`identity-live` or `device-live`) from an enrolled issuer, bound to this snapshot or object version. The signature is checked against the verify key recorded at enroll. Missing does not fail Check. A present unenrolled, unsigned, post-cut, or forbidden claim fails closed. Not a grant. Does not mint an edge, owner, or heir. Check does not read a will.

**Rules**

1. Object properties must name a predicate from `owner`, `same-group`, `named-circle`, `posix-mode`, `trustee`, `delegate`. Missing, unknown, or `heir-template` → error (fail closed).
2. Explicit predicate that does not match the object's name → error (fail closed).
3. Missing or destroyed object → deny / error, never allow.
4. Evaluate the object's predicate on edges that are **jointly stated** and past the privilege-up delay, hopcap **1**. One-sided follow/friend is not a grant.
5. Reason is the **predicate id**, not a path, person list, or hop trace.
6. Return a zookie bound to the current object version and snapshot hash.
7. If a presented zookie is bound to an older object version, do not honor a cached allow. Re-evaluate the current snapshot.
8. Privilege-down invalidates immediately. Privilege-up does not grant until the delay. The cache key is `(accessor, owner-or-anchors, edge-types, hopcap, snapshot)`; `posix-mode` and `delegate` also key by `action`.
9. A `delegate` grant is keep-operating. Owner authn stays live. Owner stays owner. No rekey, no heir. If the grant carries `until` and `now >= until`, Check denies that accessor. That is grant expiry, not dead-hand ownership. Cancel (`undelegate`) unstates immediately and bumps the object version. An attestation or Social Light hop is an optional factor on this already-named predicate. Missing hop does not fail Check. A hop alone does not mint a delegate.

**Outputs**

- `allowed: bool`
- `reason: PredicateId`
- `zookie: Zookie`
- `attestation_factor` — set only when a valid enrolled factor was consumed. Never sets `allowed` by itself.

See [ARCHITECTURE.md](../ARCHITECTURE.md) for predicate tables and new-enemy.

## REMINT(object, principal)

Authn holds, authz stale. Not election.

**Allow** only when:

- the principal's authn is live, and
- a current jointly stated ACL already names that principal for the object (`owns`, group membership for a named `object-group`, direct circle membership for a named `object-circle`, `trustee`, or a live `delegate` grant whose `until` has not elapsed).

**Deny** if the ACL no longer names them. Do not look at wills to pick a new owner.

An optional enrolled-station liveness attestation may confirm the same principal. It does not name a new one. `remint_with_attestation` refuses an unenrolled, unsigned, or forbidden claim. If a live pre-cut will names remint issuers, the factor's issuer must be one of those enrolled names. That list is a restriction, not a grant.

**Output:** a new `Capability` (fresh zookie for that principal and object).

## DISCOVER(object)

Authn gone. Report what a pre-written will says. Do not install an owner. Do not advertise a vacancy.

**Allow** only with a will written while the testator was alive and not canceled.

**Output:** `Heir(node)`, `ElectAmong { circle }`, or `StaySecret`. No will → error.

## ELECT(object)

Authn gone. Slow Elect clock. A ceremony, not an instant transfer.

**Refuse** when keep-operating would suffice (object owner authn still live). A live `delegate` grant is keep-operating. Elect from a delegate grant always fails. Owner stays owner.

**Refuse** without a pre-written, uncanceled, pre-cut will that names an elect path.

**Refuse** if the will's disposition is destroy / stay secret (call Destroy instead).

**Refuse** if a rank/circle template has nobody still-attesting. Silence is not a vote.

**Start** (`elect`): resolve the candidate heir (named heir, first existing successor, or first still-attesting enrolled circle member). Notify live principals the will lists as able to cancel. Record a pending Elect. Do not install an owner. Do not publish a vacancy.

**Wait**: the Elect clock is a delay on that record (`elect_wait`). It is not the keep-operating privilege-up delay. The plane does not sleep. The delay elapsing does not install an owner.

**Cancel**: any principal the will still treats as live may `cancel_will`. A canceled will cannot commit.

**Commit** (`commit_elect`): only after the wait, and only if the will is still live and keep-operating still would not suffice. Then the owner becomes the candidate, the object version bumps, and a jointly stated `owns` edge is written.

Elect does not fire because someone attested silence or a station was loud. `elect_from_attestation` always fails.

On the Case C client path, `elect` and `commit_elect` refuse. The C and Python bindings expose `sociacl_client_elect` / `Client.elect` so that refuse is visible; they always fail. The radio being quiet is not a reason to elect. Discover reports the bundled will (`sociacl_client_discover` / `Client.discover`). Destroy erases local key material (`sociacl_client_destroy` / `Client.destroy`) when the will allows and does not change the owner.

`Client::rejoin` continues keep-operating edges that already existed on the same pre-cut (`cut_at` and exported snapshot identity). If either side installed a post-cut Elect, or the owners or memberships differ, it refuses. It does not union two post-cut graphs. `rejoin_with_quorum` stays degraded: k-of-n is omitted. See [ARCHITECTURE.md](../ARCHITECTURE.md).

A Social Light statement is a channel, not a grant. Check, Remint, and Discover may consume a hop frame (`SLHP`, as published by FyberLabs/socialight) through the existing attestation verify path. Elect from a flash always fails. socialight delivers the bytes. See [social-light.md](social-light.md).

A Gun handoff hint is untrusted. Decode does not mint. Destination Check, including a live `delegate` grant, issues the grant. `see` maps to Check `read`. Elect from a hint fails. See [gun.md](gun.md).

No public vacancy ads. No dead-hand timer.

## DESTROY(object)

Cryptographic erasure: drop the object's content-key material, mark destroyed, bump version.

**Allow** only with an uncanceled will whose disposition is stay secret / destroy, or a will that names no heir that can be discovered.

**Fail closed** with no will.

A will that names a living heir is not a destroy grant.
