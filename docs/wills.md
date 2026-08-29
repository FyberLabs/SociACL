# Wills

A will is a named template bound to an object, group, network, or device class. Written while the owner is alive and jointly stated, the same way an edge is. After a cut or after authn is gone, only that pre-positioned text runs.

It is not a Check query. `heir-template` is never a Check predicate. Check does not read wills.

## Macro language

Small and named. Not a general programming language. Each clause names a verb, and when it matters a circle, a threshold, a clock, and what to destroy.

```
will <name> for object|group|network|device-class <id>
written-by <testator>
cancelable-by <id>*
keep-operating circle <id>
remint issuers <id>+
discover heir <id>
elect circle <id> clock elect [threshold <n>] notify <id>* wait cancel
destroy if-no-heir keys|content
highest-still-attesting-rank circle <id>
named-successor-list <id>+
```

`military-rank` is an alias for `highest-still-attesting-rank`. `corporate-succession` is an alias for `named-successor-list`. They are named instances, not doctrine tables. Circle order is jointly stated `in-circle` time, then node id. Rank numbers are not loaded from anywhere.

A will may contain both clocks. Remint stays on keep-operating. Elect stays on Elect. That is composition, not a mix.

## Fail closed

Parse or validate rejects:

- Unnamed verbs
- Remint issuers that are not enrolled
- `elect` without `clock elect`, `wait`, and `cancel`
- `elect clock keep-operating` or `remint clock elect`
- A single `timeout` shared by both clocks
- Dead-hand shapes: `if-silent-for`, `if-inactive`, `on-silence`, `dead-hand`, `elect-on-silence`
- `heir-template`
- `vacancy` / `vacancy-ad`
- An empty body

Elect without `cancel` would be automatic seizure. It is refused.

## Discover / Elect / Destroy

| Body | Discover | Elect | Destroy |
| --- | --- | --- | --- |
| `discover heir p` | reports `p` | pending, then installs `p` after wait if keep-operating would not suffice | fail (has heir) |
| `named-successor-list` | reports the first name | pending, then installs the first existing name after wait | fail if a name remains |
| `highest-still-attesting-rank` / `elect circle` | reports `ElectAmong` | pending, then installs the first still-attesting enrolled member after wait | fail if one is still-attesting |
| `destroy if-no-heir` only | stay secret | fail (use Destroy) | erase key material |
| missing / canceled | fail closed | fail closed | fail closed |

Nobody still-attesting is not a vote. Elect does not pick a silent member. `elect_from_attestation` always fails.

No public vacancy listing. Discover and Elect do not enumerate the graph looking for volunteers.

## Who may write

This cut: the current owner may write or replace the will on that object. The write is jointly stated at `now` (the owner speaks for both sides, same as the `owns` edge at object creation). Whether others may write, and whether an agent may be named as heir, are open questions. Types accept any existing node as heir.

## After a cut (Case C)

`CutBoundary { cut_at }` seals the bundle. `export_bundle` copies the live will, pre-cut enrollments, and shares the remaining principal already had a right to hold. Reconstruction verifies the share hash over the local key. Check does not read the share.

New attestations from issuers enrolled after the cut do not grant. Post-cut wills, edges, and enrollments are omitted from the bundle and refused if presented. Discover may report the bundled will. Elect and `commit_elect` refuse on the client. Destroy may erase the local key when the will says stay secret; it does not install an owner.

## Storage note

Chains or IPFS may store objects, will text, and snapshot hashes. No chain adapter ships in this repository. Contracts, if introduced later, execute already-written wills; they do not draft them.
