# Changelog

## sociacl-ids 0.2.0 — unreleased

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
