# SociACL architecture

Authority plane over a social graph. Same four verbs from a POSIX user/group slider up to Circles-rich predicates.

## First-cut assumptions

These are working choices for this tree, not closed design.

- Live `CHECK` is **server-evaluated** against an in-memory graph.
- Case C evaluates **offline against a pre-cut bundle**. Export copies the last granting snapshot, the live will, pre-cut enrollments, and shares the remaining principal already had a right to hold. The durable image is sealed to a holder secret the caller keeps (`HolderSecret`, same 32-byte Ed25519 shape as `IssuerSecret`). `to_bytes` / `write_path` wrap share keys and holder-sign the frame. `Client::from_bytes` / `from_path` reconstruct only with that secret. C (`sociacl_export_bundle`, `sociacl_client_open`, Check, Remint, Discover, Destroy) and Python (`Plane.export_bundle`, `Client`) are the edge entry points. Export without the secret fails closed. Load refuses a missing, wrong, or unsigned signature, a tampered frame, or post-cut material. It is not a fetch from a dead plane.
- Check reasons are **predicate ids**, not paths.
- Hopcap is **1**. No friend-of-friend, no nested-circle walk.
- **k-of-n(circle)** is omitted (forest-fire risk).
- License is **MIT** (public edge).
- An object's current owner may write its will (jointly stated at write, owner speaks for both sides). A will is a named macro body, not a Check query. A will may name any existing node as heir, including an agent; that is a type allowance, not a policy decision.
- Privilege-up waits for a jointly stated edge **and** a configurable delay after the second statement (`DEFAULT_PRIVILEGE_UP_DELAY` in tests). Privilege-down is immediate. One TTL is not used for both.
- Co-ownership is refused: an object has one owner.
- The object names the Check predicate in its properties. An explicit predicate on the request must match that name.

## Open questions

Do not treat these as decided.

1. **Server-evaluated vs client-evaluated Check.** Live Check stays on the plane. Case C evaluates the same named predicates against a frozen bundle. Rejoin continues keep-operating edges that already existed on the same pre-cut snapshot. It refuses a union of post-cut Elects or post-cut memberships. k-of-n quorum heal is omitted.
2. **Who articulates an edge.** Both endpoints must state. For an object endpoint, the current owner speaks. The live-plane delay after the second statement is configurable; tests use `DEFAULT_PRIVILEGE_UP_DELAY`.
3. **Co-ownership:** union, intersect, or refuse. This cut refuses (single owner).
4. **k-of-n(circle) in v1.** Default is omit. Adding it later is a new predicate, not a silent walk.
5. **Who may write a will**, and whether a will may name an **agent** as heir.

## Graph

Nodes: **person**, **agent**, **device**, plus **group** and **circle** as named sets. Protected **objects** (including a device when it is the thing being authorized) carry a kind, an owner, properties, and a monotonically increasing version.

Check parses the object and reads the `predicate` property. That property must name one id from the table below. Fail closed if it is missing or unknown (`heir-template` is unknown). A caller-supplied predicate must match. The accessor cannot pick a richer predicate than the object names.

Edges store direction (`from` → `to`) and joint articulation (`from_stated`, `to_stated`, `joint_at`). A one-sided follow or friend request is stored and is not a grant. Privilege-up becomes live only after both sides have stated **and** `now >= joint_at + privilege_up_delay`. Privilege-down is immediate: one side unstating drops the edge from Check and bumps affected object versions. For an object endpoint, the current owner speaks for the object.

Relations used by named predicates:

- `owns` — accessor owns the object
- `member-of` — accessor is in a POSIX-shaped group (hop 1)
- `in-circle` — accessor is in a named circle (hop 1)
- `object-group` — the object's ACL names that group
- `object-circle` — the object's ACL names that circle
- `friend` — person-to-person; one-sided is a request, not a grant; not a walk
- `trustee` — jointly stated; Check uses it only if the object names `trustee`

`heir-template` is never a Check predicate. Wills are not consulted on the hot path.

Ambient proximity, radio, and light are **not** grants. Check may accept an optional attestation (`identity-live` or `device-live`) from a pre-enrolled issuer, bound to this snapshot or object version, as a factor on the object's already-named predicate. Missing attestation does not fail Check. A present bad statement fails closed. Attestation does not mint an edge, owner, or heir. Social Light is a named channel for those statements (`convention-badge`, `enrolled-station`). A flash is not a friend, heir, or grant. See [docs/attestations.md](docs/attestations.md).

## Named predicates

The object names the predicate. If the id is unknown, Check fails closed. If the predicate does not hold on the current snapshot, Check denies. The reason field is the predicate id. No path, person list, or hop trace.

| Predicate id | Holds when (hopcap 1) |
| --- | --- |
| `owner` | Jointly stated `owns` from accessor to object. |
| `same-group` | Object names a group; accessor is a member of that group. |
| `named-circle` | Object names a circle; accessor has a direct `in-circle` edge to that circle. |
| `posix-mode` | Object carries owner/group/other bits (`mode`) and a group. Owner bits if accessor is owner; group bits if hop-1 jointly stated `member-of`; else other bits. |
| `trustee` | Object names `trustee`; accessor has a jointly stated `trustee` edge to the object. |

No friends-of-friends. No hop 2/3. No Expand/ListUsers.

## Hash cache (new-enemy)

Like Zanzibar zookies: a Check result carries a **zookie** bound to **this object version** and a hash of the edges that currently grant (joint plus privilege-up delay elapsed).

- Cache lookup is keyed by `(accessor, owner-or-anchors, edge-types, hopcap, snapshot)`. `posix-mode` also keys by `action` so owner/group/other bits are not reused across verbs.
- Privilege-reducing graph changes bump the object version and change the snapshot immediately.
- Privilege-increasing edges do not grant until the delay. That delay is not a TTL on privilege-down.
- A zookie from version *N* cannot authorize a write at version *> N*. After unfriend then write, the revoked accessor does not see the new content as an old friend.

## Two clocks

- **Keep-operating** — fast. Authn still holds. No new owner, no rekey. Remint lives here.
- **Elect** — slow. Authn is gone. Used only when a pre-written will names a path. Live principals who can cancel are notified; there is no public vacancy listing.

There is no dead-hand timer. Inactivity is a bad death oracle and is not implemented.

Elect **refuses** if keep-operating would suffice (owner authn still live).

## Cases

**A — Remint.** Principal can still authenticate. ACL still names them. Issue a new capability from current edges. Not an election.

**B — Discover / Elect / Destroy.** Principal cannot authenticate. Look at a will written while alive. Discover reports the disposition without electing. Elect is a notify / wait / cancel ceremony on the slow clock; `commit_elect` installs the named heir only after the wait. Destroy erases if the will says stay secret or there is no heir that can be discovered. Fail closed with no will.

**C — Continuity of command.** The plane is gone or hostile. After a cut, only pre-cut wills, pre-cut enrollments, pre-cut attestations, old jointly stated edges, and shares already held work. **New edges stated after the cut do not grant.**

`export_bundle` copies that set for a remaining principal who already had a right to hold it. The durable form is a versioned length-prefixed encoding (`SACL` / version 4). Share keys are wrapped with XChaCha20-Poly1305. The wrapping key is derived from the holder secret. Each share gets its own nonce from object, holder, and `held_at`. Object `content_key` is omitted from the file. The holder signs the frame with Ed25519, same scheme as attestations. A SHA-256 trailer is integrity of the bytes, not authenticity. Open refuses a missing, wrong, or unsigned signature. v1, v2, and v3 (hash-XOR wrap) frames fail closed. The signing key stays with the caller, not in the bundle. A captured SACL file without the holder secret is not the object. Not Debug. Not a chain or IPFS adapter.

`Client::from_bytes` and `Client::from_path` unwrap held shares with the secret and evaluate Check and Remint on the frozen snapshot. Same named predicates, hopcap 1, privilege-up already elapsed, privilege-down already applied. A zookie from the bundle is bound to the exported object version.

A device talks to this through `crates/sociacl-c` and `python/sociacl`: write a will while the owner still holds the object (`sociacl_write_will` / `Plane.write_will`), export or load the sealed bundle, then Check, Remint, Discover, and Destroy. `sociacl_client_elect` exists so the refuse is visible and always fails.

Discover reports `Heir`, `ElectAmong`, or `StaySecret` without installing. Destroy erases local key material when the pre-cut will says stay secret or no heir can be discovered. It does not elect a new owner. Destroy still wipes whatever the client reconstructed locally.

Elect and `commit_elect` refuse. The radio being quiet is not a reason to elect. `elect_from_attestation` and `elect_from_social_light` still always fail. New shares are not minted after the cut. A presented post-cut edge, enrollment, or attestation is refused, including after a bytes or file load. Rejoin continues the same pre-cut snapshot. It does not union two post-cut Elects or post-cut memberships. A side that installed a post-cut Elect stays degraded. `heir-template` is still not a Check predicate.

## Devices

A device is a first-class node. It can hold a will. It can be a protected object (Check target) with an owner and a version. Same verbs as any other object.

## Wills and attestations

A will is a named macro body bound to an object (or a group, network, or device class): which verb, which circle, which threshold, which clock, what to destroy. Parse fails closed on unnamed verbs, missing enrollment, dead-hand shapes, and mixed clocks. `heir-template` is not a verb and not a Check predicate.

An attestation is an Ed25519-signed statement from a pre-enrolled issuer. Enrollment records the verify key. The plane never stores the signing key. Check may use identity or device liveness as a factor on an already-named predicate. Remint may use enrolled-station liveness for a principal the ACL already names. Elect does not start because someone attested silence or a station was loud. After a cut, only pre-cut attestations from pre-cut enrollments count.

## Public vs ITAR

This repository is the **public** authority plane: graph, verbs, clocks, hash cache, named predicates.

**ITAR** is named only. ITAR-controlled technical data, waveforms, and related implementation do not belong in this tree.

## Composition

Hypermesh, chain/IPFS object stores, and ATAK are separate. This plane does not embed them.

Social Light is an attestation channel. SociACL is the authority plane. They compose. They do not merge names. Named public-safe kinds only: `convention-badge` and `enrolled-station`. LightIFF is not implemented here and must not be.

[FyberLabs/socialight](https://github.com/FyberLabs/socialight) owns badge, station, and hop delivery. It published hop frame v1 (`SLHP`) in `socialight-hop`. This repo consumes that layout, verifies the attestation bytes, and evaluates the verbs. `crates/social-light` is a local in-process lab; it is not the product sibling and it is not a hosted service. FlexModule (2014) is ancestor badge hardware, not a friend edge. See [docs/social-light.md](docs/social-light.md).

Contracts, if any, execute already-written wills. Oracles accept attestations from pre-enrolled issuers only. See [docs/wills.md](docs/wills.md) and [docs/attestations.md](docs/attestations.md).

Slider: POSIX `same-group` and Circles `named-circle` are predicates on the same verbs. They are not different APIs.
