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
| Check | `identity-live` or `device-live` as a *factor* on the object's already-named predicate, including `delegate` | Station loudness. A will. A missing factor (missing does not fail Check). Minting a delegate. |
| Remint | Enrolled-station liveness, or identity/device liveness, for a principal the ACL already names | Naming a new principal. Reading a will. |
| Elect | Identity/device liveness only when *choosing* among a pre-enrolled circle that a will already named | Firing because someone attested silence, or because a station was loud. `elect_from_attestation` always fails. |

An attestation never sets Check `allowed` by itself. The named predicate still has to hold. The result may record `attestation_factor` so callers can see the factor was used.

## After a cut

Only pre-cut attestations and old jointly stated edges count. An issuer enrolled after the cut cannot grant. An attestation issued after the cut is refused even if the issuer was enrolled earlier. A post-cut key is not enrolled.

Durable `CutBundle` encoding is SACL v4. Share keys are wrapped with XChaCha20-Poly1305. The wrapping key is derived from the holder secret. Each share gets its own nonce from object, holder, and `held_at`. Object keys stay out of the file. The frame is holder-signed with Ed25519 over the SHA-256 of the header and payload. Export and open still require the holder secret. v1 stored a 32-byte digest as an attestation signature. v2 signed attestations but left share keys in the clear and the frame unsigned. v3 XOR-wrapped share keys with SHA-256. Load refuses those. Bundle open also refuses a statement that does not verify against a pre-cut enrollment.

## Channels

Social Light is an attestation channel. SociACL is the authority plane. They compose. They do not merge names. [FyberLabs/socialight](https://github.com/FyberLabs/socialight) speaks the hop frame. This crate verifies it. See [social-light.md](social-light.md).

Named public-safe kinds only:

| Channel | Carries | Verb may |
| --- | --- | --- |
| `convention-badge` | `identity-live` of a living person, plus an optional voluntary share-token | Discover reports the badge principal. Check may use the statement as a factor on an already-named predicate. The token is not a capability. |
| `enrolled-station` | enrolled-station liveness, or identity/device liveness | Remint or Check as a factor for a principal the ACL already names. |

Presenting a Social Light statement goes through the existing attestation verify path (enrolled key, allowed claims only). Elect from a flash always fails (`elect_from_social_light`). Nearby, loud, flash, and ping are not friends, heirs, or grants.

LightIFF is not implemented here and must not be. No waveforms, frequencies, or challenge-response. This plane stores the statement, the enrollment, the verify key, and the named channel.
