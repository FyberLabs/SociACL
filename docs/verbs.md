# Verbs

Implement against this page. Fail closed unless a named rule allows the call.

## CHECK(action, object, accessor)

Hot path. Server-evaluated in this cut.

**Inputs**

- `action` — caller-supplied verb on the object (`read`, `write`, …). Used by `posix-mode` bits. Otherwise cached, not interpreted.
- `object` — protected object id. Check parses kind, owner, properties, version. Properties select the predicate (`predicate`, and for `posix-mode` also `mode` and `group`).
- `accessor` — person, agent, or device id.
- `predicate` — optional. If set, must equal the object's named predicate. The accessor cannot pick a richer predicate than the object names.
- `zookie` — optional freshness token from a prior Check. Bound to this object version.
- `attestation` — optional signed statement (`identity-live` or `device-live`) from an enrolled issuer, bound to this snapshot or object version. Missing does not fail Check. A present unenrolled, post-cut, or forbidden claim fails closed. Not a grant. Does not mint an edge, owner, or heir. Check does not read a will.

**Rules**

1. Object properties must name a predicate from `owner`, `same-group`, `named-circle`, `posix-mode`, `trustee`. Missing, unknown, or `heir-template` → error (fail closed).
2. Explicit predicate that does not match the object's name → error (fail closed).
3. Missing or destroyed object → deny / error, never allow.
4. Evaluate the object's predicate on edges that are **jointly stated** and past the privilege-up delay, hopcap **1**. One-sided follow/friend is not a grant.
5. Reason is the **predicate id**, not a path, person list, or hop trace.
6. Return a zookie bound to the current object version and snapshot hash.
7. If a presented zookie is bound to an older object version, do not honor a cached allow. Re-evaluate the current snapshot.
8. Privilege-down invalidates immediately. Privilege-up does not grant until the delay. The cache key is `(accessor, owner-or-anchors, edge-types, hopcap, snapshot)`; `posix-mode` also keys by `action`.

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
- a current jointly stated ACL already names that principal for the object (`owns`, group membership for a named `object-group`, or direct circle membership for a named `object-circle`).

**Deny** if the ACL no longer names them. Do not look at wills. Do not pick a new owner.

An optional enrolled-station liveness attestation may confirm the same principal. It does not name a new one. `remint_with_attestation` refuses an unenrolled or forbidden claim.

**Output:** a new `Capability` (fresh zookie for that principal and object).

## DISCOVER(object)

Authn gone. Report what a pre-written will says. Do not install an owner. Do not advertise a vacancy.

**Allow** only with a will written while the testator was alive and not canceled.

**Output:** `Heir(node)`, `ElectAmong { circle }`, or `StaySecret`. No will → error.

## ELECT(object)

Authn gone. Slow Elect clock. Install the heir named by a live will.

**Refuse** when keep-operating would suffice (object owner authn still live).

**Refuse** without a pre-written, uncanceled will.

**Refuse** if the will's disposition is destroy / stay secret (call Destroy instead).

On success: owner becomes the named heir or the first still-attesting enrolled member of the named circle, object version bumps, notify the live principals listed as able to cancel. Those principals may `cancel_will` before or after; a canceled will cannot elect.

Elect does not fire because someone attested silence or a station was loud. `elect_from_attestation` always fails. If a rank/circle template has nobody still-attesting, Elect fails closed.

No public vacancy ads. No dead-hand timer.

## DESTROY(object)

Cryptographic erasure: drop the object's content-key material, mark destroyed, bump version.

**Allow** only with an uncanceled will whose disposition is stay secret / destroy, or a will that names no heir.

**Fail closed** with no will.

A will that names a living heir is not a destroy grant.
