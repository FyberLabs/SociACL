#!/usr/bin/env bash
# Run every SociACL suite the same way CI does.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

if [[ -f "$HOME/.cargo/env" ]]; then
  # shellcheck source=/dev/null
  . "$HOME/.cargo/env"
fi
# shellcheck source=/dev/null
. "${root}/scripts/require-node.sh"

node "${root}/scripts/audit-forbidden-names.mjs"

cargo build --workspace --locked
mkdir -p target/ids
mkdir -p target/mesh
IDS_VECTOR_REPORT="${root}/target/ids/rust-vectors.txt" MESH_VECTOR_REPORT="${root}/target/mesh/rust-vectors.txt" cargo test --workspace --locked

cargo run --locked -p sociacl-core --example check
cargo run --locked -p sociacl-core --example wills
cargo run --locked -p sociacl-core --example network
cargo run --locked -p sociacl-core --example elect
cargo run --locked -p social-light --example lab
cargo run --locked -p sociacl-gun --example gun

run_c() {
  local name="$1"
  local src="$2"
  cc -I crates/sociacl-c/include "$src" -L target/debug -lsociacl -o "target/sociacl-${name}-c"
  LD_LIBRARY_PATH="${root}/target/debug" "target/sociacl-${name}-c"
}

run_c check examples/check.c
run_c client examples/client.c
run_c social-light examples/social_light.c
run_c gun examples/gun.c
run_c verbs examples/verbs.c
run_c elect examples/elect.c

PYTHONPATH=python python3 python/tests/test_check.py
PYTHONPATH=python python3 python/tests/test_client.py
PYTHONPATH=python python3 python/tests/test_social_light.py
PYTHONPATH=python python3 python/tests/test_gun.py
PYTHONPATH=python python3 python/tests/test_verbs.py
PYTHONPATH=python python3 python/tests/test_network.py

npm ci --prefix typescript
npx --prefix typescript tsc --strict --noEmit -p typescript/contract
MESH_VECTOR_REPORT="${root}/target/mesh/ts-vectors.txt" node --test typescript/tests/*.js
node --experimental-strip-types --test typescript/tests/test_encdisc_vectors.ts typescript/tests/test_presentation.ts typescript/tests/test_inbox.ts typescript/tests/test_epoch.ts typescript/tests/test_migration.ts typescript/tests/test_account_key.ts typescript/tests/test_account_keyring.ts typescript/tests/test_recovery.ts typescript/tests/test_contact_lane.ts
npm run --prefix typescript typecheck

# Independent browser package: each language reports exactly which shared vectors ran.
npm ci --prefix typescript/ids
IDS_VECTOR_REPORT="${root}/target/ids/ts-vectors.txt" node --test typescript/ids/test/*.js
npm run --prefix typescript/ids typecheck
npm run --prefix typescript/ids browser
npm run --prefix typescript/ids consumer
node typescript/ids/scripts/compare-vectors.mjs "${root}/vectors/ids" target/ids/rust-vectors.txt target/ids/ts-vectors.txt
node typescript/ids/scripts/compare-vectors.mjs "${root}/vectors/mesh/v2" target/mesh/rust-vectors.txt target/mesh/ts-vectors.txt
