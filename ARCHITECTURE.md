# SociACL architecture

Authority plane over a social graph. Same four verbs from a POSIX user/group slider up to Circles-rich predicates.

## First-cut assumptions

These are working choices for this tree, not closed design.

- Live `CHECK` is **server-evaluated** against an in-memory graph.
- Case C (plane gone or hostile) is **types and comments only**. Client-held shares are not implemented.
- Check reasons are **predicate ids**, not paths.
- Hopcap is **1**. No friend-of-friend, no nested-circle walk.
- **k-of-n(circle)** is omitted (forest-fire risk).
- License is **MIT** (public edge).
- An object's current owner may write its will. A will may name any existing node as heir, including an agent; that is a type allowance, not a policy decision.
- Privilege-up waits for a jointly stated edge. There is no extra live-plane delay timer.
- Co-ownership is refused: an object has one owner.

## Open questions

Do not treat these as decided.

1. **Server-evaluated vs client-evaluated Check.** Case C requires a client path to exist. This cut evaluates on the plane only.
2. **Who articulates an edge, and the live-plane delay.** Joint statement is the privilege-up gate here. Delay after the second statement is unspecified.
3. **Co-ownership:** union, intersect, or refuse. This cut refuses (single owner).
4. **k-of-n(circle) in v1.** Default is omit. Adding it later is a new predicate, not a silent walk.
5. **Who may write a will**, and whether a will may name an **agent** as heir.

## Graph

Nodes: **person**, **agent**, **device**, plus **group** and **circle** as named sets. Protected **objects** (including a device when it is the thing being authorized) carry an owner and a monotonically increasing version.

Edges are **jointly stated**. Both endpoints must state the same relation. Privilege-up is delayed until both have stated. Privilege-down is immediate: one side unstating drops the edge from Check. For an object endpoint, the current owner speaks for the object.

Relations used by named predicates:

- `owns` — accessor owns the object
- `member-of` — accessor is in a POSIX-shaped group
- `in-circle` — accessor is in a named circle (one hop)
- `object-group` — the object's ACL names that group
- `object-circle` — the object's ACL names that circle

`heir-template` is never a Check predicate. Wills are not consulted on the hot path.

Ambient proximity, radio, and light are **not** grants. They may be used by an attestation channel to support a statement. Check reads jointly stated edges only.

## Named predicates

Check names a predicate. If the id is unknown, Check fails closed. If the predicate does not hold on the current snapshot, Check denies. The reason field is the predicate id.

| Predicate id | Holds when (hopcap 1) |
| --- | --- |
| `owner` | Jointly stated `owns` from accessor to object. |
| `same-group` | Object names a group; accessor is a member of that group. |
| `named-circle` | Object names a circle; accessor has a direct `in-circle` edge to that circle. |

## Hash cache (new-enemy)

Like Zanzibar zookies: a Check result carries a **zookie** bound to the **object version** and a hash of the jointly stated edge snapshot.

- Privilege-down and a write both bump the object version.
- Cache lookup is keyed by `(object, object_version, snapshot_hash, accessor, predicate, action)`.
- A zookie from version *N* cannot authorize a write at version *> N*. After revoke then write, the revoked accessor does not see the new content as an old friend.

## Two clocks

- **Keep-operating** — fast. Authn still holds. No new owner, no rekey. Remint lives here.
- **Elect** — slow. Authn is gone. Used only when a pre-written will names a path. Live principals who can cancel are notified; there is no public vacancy listing.

There is no dead-hand timer. Inactivity is a bad death oracle and is not implemented.

Elect **refuses** if keep-operating would suffice (owner authn still live).

## Cases

**A — Remint.** Principal can still authenticate. ACL still names them. Issue a new capability from current edges. Not an election.

**B — Discover / Elect / Destroy.** Principal cannot authenticate. Look at a will written while alive. Discover reports the disposition without electing. Elect installs a named heir on the slow clock. Destroy erases if the will says stay secret or there is no heir. Fail closed with no will.

**C — Continuity of command.** The plane is gone or hostile. After a cut, only pre-positioned wills and client-held shares work. **New edges stated after the cut do not grant.** This cut ships `CutBoundary` and `ClientHeldShare` as types plus comments. Reconstruction and offline Check are not implemented.

## Devices

A device is a first-class node. It can hold a will. It can be a protected object (Check target) with an owner and a version. Same verbs as any other object.

## Public vs ITAR

This repository is the **public** authority plane: graph, verbs, clocks, hash cache, named predicates.

**ITAR** is named only. ITAR-controlled technical data, waveforms, and related implementation do not belong in this tree.

## Composition

Hypermesh, attestation channels (Social Light, LightIFF), chain/IPFS object stores, and ATAK are separate. This plane does not embed them.

Contracts, if any, execute already-written wills. Oracles, if any, are pre-enrolled attestations. Neither is implemented here.

Slider: POSIX `same-group` and Circles `named-circle` are predicates on the same verbs. They are not different APIs.
