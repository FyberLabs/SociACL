# Changelog

## sociacl-ids 0.4.0 — unreleased

- Freeze authenticated rotation/revocation contradictions with `rotation-conflict`,
  including a compromised witness backdating revokes signed by a retired key.
- After authenticating a rotation signature and attestation, fail with
  `missing-history` when authorizing or retained credential evidence is missing
  or cannot verify. Never silently discard that rotation and return an older key.
- Freeze witnessed wallet-ownership and OIDC-eligibility contradictions during
  history resolution. Preserve diagnostics-only handling of unauthenticated junk.
- Add shared rollback regressions and clarify complete-history, latest-state
  checkpoint and Panopticon availability requirements.

## sociacl-ids 0.3.0 — superseded before release

- Authenticate relevant link witnesses before requesting history; reject or skip
  unrelated, future and forged index records without fetching their history.
- Enforce pre-rotation revocations for every retained credential. Require a
  timestamp attestation on revokes to prevent retired-key rollback on replay.
- Bind the authorizing link and kind into rotation v2 signing bytes and
  attestations. OIDC recovery requires an enrolled, retained, unrevoked OIDC
  credential and no active wallet, with explicit issuer pinning in the context.
- Reject noncanonical did:web ports, encoded unreserved/control URL bytes and
  nonalphabetic final hostname labels. Add shared attack regressions and update
  the normative contract and migration prerequisites.

## sociacl-ids 0.2.0 — superseded before release

- Require Panopticon wallet timestamp attestations and sorted retained-link
  commitments in rotation signatures and attestations. Require authenticated key
  state and reject backdated retired-key revocations and unretained credentials.
- Skip malformed/forged history entries with diagnostics; freeze valid forks;
  resolve external accounts using authenticated history and make equal-time
  wallet bindings deterministic.
- Replace runtime URL parsers with a shared strict ASCII grammar and remove the
  vulnerable `url`/`idna` dependency. Pin SIWE domain/URI/chain; cap attestation
  lifetime and bound optional clock skew.
- Complete TypeScript/Rust parsing API parity, add shared review regressions,
  test packed consumers with an empty cache, and separate release write access
  from package execution. Releases require protected-master ancestry.

## sociacl-ids 0.1.0 — superseded before release

- Add browser/Node ESM `sociacl-ids`, optional Zod adapters, and the
  `sociacl-ids` Rust crate with canonical identity types, path keys and souls.
- Add domain-separated signing bytes, wallet/OIDC link proofs, ES256
  attestations, key rotation/fork detection and credential revocation checks.
- Add shared TS/Rust vectors, property/fuzz/million-mint tests, browser and
  installed-tarball checks, and an `ids-v*` GitHub Release asset workflow.
- Preserve existing callers. Track their implementation sequence in
  `docs/identity-migration-roadmap.md`.

The ids package versions independently of the existing SociACL packages.
Changes to an accept/reject vector, grammar, or signing domain bump MINOR while
below 1.0 and MAJOR from 1.0 onward. Record those changes here before publication.
