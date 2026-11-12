# Nightly integration and browser E2E

The scheduled `FyberLabs/infra` nightly batch owns SociACL integration execution,
with one concurrency group and cancellation of superseded runs. The
`sociacl-browser` registry entry follows current `master`; its name is retained
for historical result comparison. SociACL has no independent cron or manual
integration dispatch. PRs run unit/contract tests, type checks, builds and package
export checks. Automatic TEST package publication continues after PR-style CI;
nightly results are advisory and are not release or merge prerequisites.

`scripts/nightly-integration.mjs` emits one native
JUnit case per executed harness:

- Rust runtime examples, six C FFI examples and six Python binding suites;
- a packed identity package installed and executed in a clean consumer, including
  delegated credentials, revocation, audience and scope boundaries;
- real Chromium policy store conflict, restart and rollback checks;
- browser witness fetch/policy validation;
- checkpoint persistence and checkpoint client validation in Chromium.

The Infra registry installs locked npm dependencies, Rust and Chromium before
running the adapter. Infra owns the disposable fixture lifecycle and process
cleanup. Existing browser harnesses use loopback servers, temporary profiles,
synthetic signed vectors and `finally` teardown. The installed consumer owns its
temporary package/cache directory. No shared TEST tenant, host or database is
used. `NIGHTLY_OUTPUT`/`TEST_EVIDENCE_DIR` are run-specific directories owned by
Infra; raw JUnit is normalized there before upload. Setup failures, missing
results and failed teardown cannot establish success.

The adapter rejects local, PR and manual-dispatch execution. Do not run it by
hand or manually start/rerun the full batch. Inspect the next scheduled run's
JUnit, revision and redacted diagnostics. The checked-in workflow and adapter
are coverage definitions, not evidence that a scheduled run has passed.

The historical README coverage snapshot remains historical; the removed PR
coverage invocation included Python FFI runtime integration. Coverage scripts
remain available for future CI-owned measurement, not a local acceptance step.

## Recorded scheduled baseline

The [November 11, 2026 SociACL job](https://github.com/FyberLabs/infra/actions/runs/43039946456/job/130588798374)
passed at owner revision `219f4c76479ff841ffbb50383b763736fa3f943c`.
Its [artifact](https://github.com/FyberLabs/infra/actions/runs/43039946456/artifacts/13865624144)
records six passing native harness cases, successful setup, and successful cleanup.
The overall infra batch failed in other suites; this is SociACL-specific evidence.
This baseline predates the added installed-delegation assertions. Their execution
must be checked in a subsequent scheduled run, not inferred from this result.
