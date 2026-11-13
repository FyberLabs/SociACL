#!/usr/bin/env bash
# PR unit/contract checks. Runtime integration belongs to the Infra nightly batch.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

python3 "${root}/scripts/check-release-versions.py"

if [[ -f "$HOME/.cargo/env" ]]; then
  # shellcheck source=/dev/null
  . "$HOME/.cargo/env"
fi
# shellcheck source=/dev/null
. "${root}/scripts/require-node.sh"

bash "${root}/scripts/release-automation.test.sh"

# The dependency audit uses the pinned TypeScript parser (tooling only).
npm ci --prefix typescript
npm ci --prefix typescript/ids
# Browser declarations do not depend on generated Rust conformance output.
npm run --prefix typescript/ids typecheck
# Declaration failures should precede the native compilation workload.
npx --prefix typescript tsc --strict --noEmit -p typescript/contract
node "${root}/scripts/audit-forbidden-names.mjs"

cargo build --workspace --locked
# Test dependencies enable `vectors`; also compile the public library without it.
cargo rustc -p sociacl-gun --lib --locked -- -D warnings
mkdir -p target/ids
mkdir -p target/mesh
WITNESS_RUST_VECTOR="${root}/target/ids/witness-rust.json" FIRST_CONTACT_RUST_VECTOR="${root}/target/ids/first-contact-rust.bin" IDS_VECTOR_REPORT="${root}/target/ids/rust-vectors.txt" MESH_VECTOR_REPORT="${root}/target/mesh/rust-vectors.txt" cargo test --workspace --locked

MESH_VECTOR_REPORT="${root}/target/mesh/ts-vectors.txt" node --test typescript/tests/*.js
WITNESS_RUST_VECTOR="${root}/target/ids/witness-rust.json" WITNESS_TS_VECTOR="${root}/target/ids/witness-ts.json" FIRST_CONTACT_RUST_VECTOR="${root}/target/ids/first-contact-rust.bin" FIRST_CONTACT_TS_VECTOR="${root}/target/ids/first-contact-ts.bin" node --experimental-strip-types --test typescript/tests/test_encdisc_vectors.ts typescript/tests/test_presentation.ts typescript/tests/test_inbox.ts typescript/tests/test_epoch.ts typescript/tests/test_migration.ts typescript/tests/test_account_key.ts typescript/tests/test_account_keyring.ts typescript/tests/test_recovery.ts typescript/tests/test_contact_lane.ts typescript/tests/test_first_contact.ts typescript/tests/test_vault_format.ts typescript/tests/test_independent_witness.ts typescript/tests/test_consume.ts
FIRST_CONTACT_TS_VECTOR="${root}/target/ids/first-contact-ts.bin" cargo test -p sociacl-encdisc --locked --test first_contact
WITNESS_TS_VECTOR="${root}/target/ids/witness-ts.json" cargo test -p sociacl-ids --locked --test independent_witness
npm run --prefix typescript typecheck

PRIVATE_MEDIA_VECTOR="${root}/target/ids/private-media.json" node --experimental-strip-types --test --experimental-test-coverage --test-coverage-include=typescript/contract/private-media.ts --test-coverage-lines=90 --test-coverage-branches=80 typescript/tests/test_private_media.ts
python3 scripts/private-media-native.py

# Independent browser package: each language reports exactly which shared vectors ran.
IDS_VECTOR_REPORT="${root}/target/ids/ts-vectors.txt" node --test typescript/ids/test/*.js
node --check typescript/ids/scripts/browser-first-contact.mjs
node --check typescript/ids/scripts/browser-independent-witness.mjs
npm run --prefix typescript/ids browser
npm run --prefix typescript/ids build
node typescript/ids/scripts/packed-browser-exports.mjs
python3 scripts/identity-consume-contract.py
node typescript/ids/scripts/compare-vectors.mjs "${root}/vectors/ids" target/ids/rust-vectors.txt target/ids/ts-vectors.txt
node typescript/ids/scripts/compare-vectors.mjs "${root}/vectors/mesh/v2" target/mesh/rust-vectors.txt target/mesh/ts-vectors.txt
