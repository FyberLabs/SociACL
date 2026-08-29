# Verbs

Implement against this page. Fail closed unless a named rule allows the call.

## CHECK(action, object, accessor)

Hot path. Server-evaluated in this cut.

**Inputs**

- `action` — caller-supplied verb on the object (`read`, `write`, …). Cached, not interpreted.
- `object` — protected object id.
- `accessor` — person, agent, or device id.
- `predicate` — named predicate id (`owner`, `same-group`, `named-circle`).
- `zookie` — optional freshness token from a prior Check.

**Rules**

1. Unknown predicate → error (fail closed). `heir-template` and will template names are not predicates.
2. Missing or destroyed object → deny / error, never allow.
3. Evaluate the named predicate on **jointly stated** edges only, hopcap **1**.
4. Reason is the **predicate id**, not a path.
5. Return a zookie bound to the current object version and snapshot hash.
6. If a presented zookie is bound to an older object version, do not honor a cached allow. Re-evaluate the current snapshot.

**Outputs**

- `allowed: bool`
- `reason: PredicateId`
- `zookie: Zookie`

See [ARCHITECTURE.md](../ARCHITECTURE.md) for predicate tables and new-enemy.

## REMINT(object, principal)

Authn holds, authz stale. Not election.

**Allow** only when:

- the principal's authn is live, and
- a current jointly stated ACL already names that principal for the object (`owns`, group membership for a named `object-group`, or direct circle membership for a named `object-circle`).

**Deny** if the ACL no longer names them. Do not look at wills. Do not pick a new owner.

**Output:** a new `Capability` (fresh zookie for that principal and object).

## DISCOVER(object)

Authn gone. Report what a pre-written will says. Do not install an owner. Do not advertise a vacancy.

**Allow** only with a will written while the testator was alive and not canceled.

**Output:** `Heir(node)` or `StaySecret`. No will → error.

## ELECT(object)

Authn gone. Slow Elect clock. Install the heir named by a live will.

**Refuse** when keep-operating would suffice (object owner authn still live).

**Refuse** without a pre-written, uncanceled will.

**Refuse** if the will's disposition is destroy / stay secret (call Destroy instead).

On success: owner becomes the named heir, object version bumps, notify the live principals listed as able to cancel. Those principals may `cancel_will` before or after; a canceled will cannot elect.

No public vacancy ads. No dead-hand timer.

## DESTROY(object)

Cryptographic erasure: drop the object's content-key material, mark destroyed, bump version.

**Allow** only with an uncanceled will whose disposition is stay secret / destroy, or a will that names no heir.

**Fail closed** with no will.

A will that names a living heir is not a destroy grant.
