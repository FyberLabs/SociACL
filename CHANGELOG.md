# Changelog

## sociacl-ids 0.1.0 — unreleased

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
