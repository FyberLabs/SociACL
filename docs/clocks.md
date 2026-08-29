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

The slowness is a policy clock (wait, notify, allow cancel), not a countdown to automatic seizure. This cut does not sleep; it returns `Clock::Elect` on a successful elect so callers can apply the slow path.

## Forbidden

- Dead-hand timers (fire Elect or Destroy because a clock expired).
- Using inactivity as a death oracle.
- Starting Elect to "refresh" a live owner (that is Remint or a no-op).

## Mapping

| Situation | Clock | Verb |
| --- | --- | --- |
| Authn live, authz stale, ACL names principal | Keep-operating | Remint |
| Authn live, owner still live | Keep-operating | Check; Elect refuses |
| Authn gone, will names heir | Elect | Discover then Elect |
| Authn gone, will says stay secret / no heir | — | Destroy |
| Plane gone (Case C) | pre-positioned only | types only in this cut |
