# Networks

SociACL proves **ownership** and **membership** of a network. It does not say how that network routes, elects a leader, runs BFT, discovers peers, scales, or recovers. Those belong to the service (Panopticon, s3r.ch Gun mesh, a leader set, a BFT quorum). The plane only answers: who owns this network object, who is a jointly stated member, and who was removed.

## What is in scope

| Name | Meaning |
| --- | --- |
| node `network` | Named membership set. Same slider as group / circle. |
| object kind `network` | The network itself is a Check target. |
| relation `in-network` | Hopcap 1. Jointly stated. Privilege-up waits; privilege-down is immediate. |
| predicate `same-network` | Object names a network (or is the network); accessor has a live `in-network` edge. |
| `admit_member` | Both sides state `in-network`, then the privilege-up delay. |
| `censure` | Owner or the member unstates immediately and records a reason. Not a grant. |
| audit | Records of removals. Not Expand / ListUsers of current members. |

A one-sided join request is stored and is not a grant. Check reasons stay predicate ids. No friend-of-friend walk.

## What is out of scope

- Transport, NAT, or peer discovery
- BFT, Raft, or any leader/quorum scheme
- Scaling, shard, or recovery state machines
- How a remaining member finds a replacement after censure

Those may exist **on** the network. SociACL does not implement them and does not mint them from a Check.

s3r.ch stays a **light** consume path on its Gun graph (`CHECK(see, …)` + optional hop factor). Panopticon and other exterior surfaces use the full plane (Rust / C / Python) or the portable TypeScript light plane. Integration is oracle + dest Check: a discovered node still has to pass `same-network` or `owner` at the destination.

## Censure reasons

Named only. Fail closed on anything else.

| Reason | Who may state it |
| --- | --- |
| `self-leave` | The member |
| `unintentional-failure` | Network object owner |
| `policy-violation` | Network object owner |
| `active-sabotage` | Network object owner |

Censure is privilege-down plus an audit record. Check does not read the record. Elect does not start because someone was censured. A member cannot censure another member.

To remove someone for sabotage or policy, the network must be a protected object (`add_network` then `add_object` on the same id) so an owner can speak for it.

## Verbs on a network object

Same four verbs as any object.

- **Check** — `owner` or `same-network` (or `delegate` / `trustee` if the object names them)
- **Remint** — ACL already names the principal (owner, member, trustee, live delegate)
- **Discover / Elect** — only from a pre-written will; refuse if keep-operating would suffice
- **Destroy** — only when the will says stay secret / no discoverable heir

## Bindings

| Language | Entry |
| --- | --- |
| Rust | `Plane::add_network`, `admit_member`, `censure`, `audit`, `check` |
| C | `sociacl_add_network`, `sociacl_admit_member`, `sociacl_censure`, `sociacl_is_member` |
| Python | `Plane.add_network`, `admit_member`, `censure`, `is_member`, `audit` |
| TypeScript | `typescript/src/index.js` (`Plane`) — portable light plane, not an s3r.ch npm dependency |
