# Clocks

Two clocks. No third. No dead-hand.

## Keep-operating

Fast. Used when the owner's authn still holds.

- No new owner.
- No rekey.
- `REMINT` is the keep-operating repair: authz is stale, ACL still names the principal, issue a fresh capability.

Inactivity on this clock is **not** death. Do not start Elect because someone went quiet.

## Elect

Slow. Used only when authn is gone **and** a will written while alive names an heir.

- `ELECT` refuses if keep-operating would suffice.
- Notify live principals who may cancel. They can cancel; Elect then fails closed.
- Do not publish a vacancy.

The slowness is a policy clock (wait, notify, allow cancel), not a countdown to automatic seizure. The plane does not sleep. `elect` records a pending Elect and notifies. `commit_elect` may install only after `elect_wait`. That wait is not shared with keep-operating. Expiry does not install an owner.

## Forbidden

- Dead-hand timers (fire Elect or Destroy because a clock expired).
- Using inactivity as a death oracle.
- Starting Elect to "refresh" a live owner (that is Remint or a no-op).
- One `timeout` for keep-operating and Elect.
- Elect on silence, or Elect because a station was loud.

## Mapping

| Situation | Clock | Verb |
| --- | --- | --- |
| Authn live, authz stale, ACL names principal | Keep-operating | Remint |
| Authn live, owner still live | Keep-operating | Check; Elect refuses |
| Authn gone, will names heir | Elect | Discover then Elect |
| Authn gone, will says stay secret / no heir | — | Destroy |
| Plane gone (Case C) | Keep-operating on the pre-cut bundle | Load the sealed bundle with the holder secret. Offline Check / Remint / Discover / Destroy. Elect refuses. Same-cut rejoin may continue. A union of post-cut Elects refuses. |
| Social Light flash | Keep-operating | Channel only. Check / Remint / Discover may consume the signed statement. Silence does not Elect. |
