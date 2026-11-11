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
node "${root}/scripts/audit-forbidden-names.mjs"

cargo build --workspace --locked
# Test dependencies enable `vectors`; also compile the public library without it.
cargo rustc -p sociacl-gun --lib --locked -- -D warnings
mkdir -p target/ids
mkdir -p target/mesh
IDS_VECTOR_REPORT="${root}/target/ids/rust-vectors.txt" MESH_VECTOR_REPORT="${root}/target/mesh/rust-vectors.txt" cargo test --workspace --locked

npx --prefix typescript tsc --strict --noEmit -p typescript/contract
MESH_VECTOR_REPORT="${root}/target/mesh/ts-vectors.txt" node --test typescript/tests/*.js
node --experimental-strip-types --test typescript/tests/test_encdisc_vectors.ts typescript/tests/test_presentation.ts typescript/tests/test_inbox.ts typescript/tests/test_epoch.ts typescript/tests/test_migration.ts typescript/tests/test_account_key.ts typescript/tests/test_account_keyring.ts typescript/tests/test_recovery.ts typescript/tests/test_contact_lane.ts typescript/tests/test_consume.ts
npm run --prefix typescript typecheck

# Independent browser package: each language reports exactly which shared vectors ran.
npm ci --prefix typescript/ids
IDS_VECTOR_REPORT="${root}/target/ids/ts-vectors.txt" node --test typescript/ids/test/*.js
npm run --prefix typescript/ids typecheck
node scripts/check-agent-contract.mjs
npm run --prefix typescript/ids browser
node typescript/ids/scripts/compare-vectors.mjs "${root}/vectors/ids" target/ids/rust-vectors.txt target/ids/ts-vectors.txt
node typescript/ids/scripts/compare-vectors.mjs "${root}/vectors/mesh/v2" target/mesh/rust-vectors.txt target/mesh/ts-vectors.txt
