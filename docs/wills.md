# Wills

A will is written **while alive**. After a cut or after authn is gone, only that pre-positioned text runs. New edges stated after a cut do not grant. Contracts, if introduced later, execute already-written wills; they do not draft them.

## Shape

- `object` — the protected object or device the will governs
- `testator` — who wrote it (this cut: current owner)
- `template` — named template for a small closed group (`military-rank`, `corporate-succession`, or a custom id)
- `disposition` — `Heir(node)` or `StaySecret`
- `written_at` — timestamp; must be while testator authn was live
- `cancelable_by` — live principals who may cancel; Elect notifies them

Templates are labels for humans and for later contract runners. **`heir-template` is never a Check predicate.** Check does not read wills.

## Who may write (open)

This cut: the current owner may write or replace the will on that object. Whether others may write, and whether an agent may be named as heir, are open questions. Types accept any existing node as heir.

## Discover / Elect / Destroy

| Disposition | Discover | Elect | Destroy |
| --- | --- | --- | --- |
| `Heir(p)` | reports `p` | installs `p` if keep-operating would not suffice | fail (has heir) |
| `StaySecret` | reports stay secret | fail (use Destroy) | erase key material |
| missing / canceled | fail closed | fail closed | fail closed |

No public vacancy listing. Discover and Elect do not enumerate the graph looking for volunteers.

## After a cut (Case C)

`CutBoundary { cut_at }` is recorded so a later client path can ignore edges stated after the cut. Client-held shares are typed (`ClientHeldShare`) and not reconstructed here.

Oracles, if any, are pre-enrolled attestations only. This tree does not enroll oracles.

## Storage note

Chains or IPFS may store objects, will text, and snapshot hashes. No chain adapter ships in this repository.
