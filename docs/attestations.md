# Attestations

A signed statement. Not a grant. Light, radio, and proximity can carry one. They do not mint an owner, walk the graph, or turn nearby into friend or heir.

## Shape

- `issuer` — who said it
- `subject` — about whom or what
- `claim` — `identity-live`, `device-live`, or `station-liveness`
- `issued_at` — when
- `enrollment` — which enrolled issuer (must equal `issuer`)
- `binding` — this object version, or this snapshot hash
- `signature` — digest of those fields. Edge code may replace the digest with a real signature scheme. The plane checks that the digest matches.

Forbidden claims fail closed: `silence`, `loud`, `vacancy`, `flash`, `ping`, `death`, and any unnamed id. Silence is a bad oracle under attack. A loud station is not a grant.

## Enrollment

Oracles accept attestations from pre-enrolled principals only. `Plane::enroll(issuer, station|principal|device)` records the issuer at `now`. An unknown issuer is refused.

## What each verb may consume

| Verb | May consume | Must not |
| --- | --- | --- |
| Check | `identity-live` or `device-live` as a *factor* on the object's already-named predicate | Station loudness. A will. A missing factor (missing does not fail Check). |
| Remint | Enrolled-station liveness, or identity/device liveness, for a principal the ACL already names | Naming a new principal. Reading a will. |
| Elect | Identity/device liveness only when *choosing* among a pre-enrolled circle that a will already named | Firing because someone attested silence, or because a station was loud. `elect_from_attestation` always fails. |

An attestation never sets Check `allowed` by itself. The named predicate still has to hold. The result may record `attestation_factor` so callers can see the factor was used.

## After a cut

Only pre-cut attestations and old jointly stated edges count. An issuer enrolled after the cut cannot grant. An attestation issued after the cut is refused even if the issuer was enrolled earlier.

## Channels

Social Light and LightIFF are attestation channels. They are not implemented here. This plane stores the statement and the enrollment rule.
