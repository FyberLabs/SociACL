# Attestations

A signed statement. Not a grant. Light, radio, and proximity can carry one. They do not mint an owner, walk the graph, or turn nearby into friend or heir.

## Shape

- `issuer` — who said it
- `subject` — about whom or what
- `claim` — `identity-live`, `device-live`, or `station-liveness`
- `issued_at` — when
- `enrollment` — which enrolled issuer (must equal `issuer`)
- `binding` — this object version, or this snapshot hash
- `signature` — Ed25519 over the SHA-256 field digest. The digest is the message. It is not the signature.

Forbidden claims fail closed: `silence`, `loud`, `vacancy`, `flash`, `ping`, `death`, and any unnamed id. Silence is a bad oracle under attack. A loud station is not a grant.

## Enrollment

Oracles accept attestations from pre-enrolled principals only. `Plane::enroll(issuer, station|principal|device, verify_key)` records the issuer and their Ed25519 verify key at `now`. An unknown issuer or a missing/invalid key is refused. The plane does not store the signing key. The issuer (edge or test helper `IssuerSecret`) holds that.

Wrong key, missing enrollment, bad signature, forbidden claim, or subject mismatch fails closed. A SHA-256 digest stuffed into the signature field is not a signature.

## What each verb may consume

| Verb | May consume | Must not |
| --- | --- | --- |
| Check | `identity-live` or `device-live` as a *factor* on the object's already-named predicate | Station loudness. A will. A missing factor (missing does not fail Check). |
| Remint | Enrolled-station liveness, or identity/device liveness, for a principal the ACL already names | Naming a new principal. Reading a will. |
| Elect | Identity/device liveness only when *choosing* among a pre-enrolled circle that a will already named | Firing because someone attested silence, or because a station was loud. `elect_from_attestation` always fails. |

An attestation never sets Check `allowed` by itself. The named predicate still has to hold. The result may record `attestation_factor` so callers can see the factor was used.

## After a cut

Only pre-cut attestations and old jointly stated edges count. An issuer enrolled after the cut cannot grant. An attestation issued after the cut is refused even if the issuer was enrolled earlier. A post-cut key is not enrolled.

Durable `CutBundle` encoding is SACL v2. It carries the verify key and a length-prefixed 64-byte signature. v1 frames stored a 32-byte digest as the signature and no key; load refuses them. Bundle open also refuses a statement that does not verify against a pre-cut enrollment.

## Channels

Social Light and LightIFF are attestation channels. They are not implemented here. This plane stores the statement, the enrollment, and the verify key.
