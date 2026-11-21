#!/usr/bin/env bash
# Called only by the Infra nightly integration adapter.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
node --input-type=module -e 'const { requireInfraNightly } = await import(process.argv[1]); requireInfraNightly();' "$root/scripts/nightly-context.mjs"
cd "$root"
cargo build --workspace --locked
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
run_c epoch-status examples/epoch_status.c
run_c epoch-manifest examples/epoch_manifest.c
run_c epoch-selection examples/epoch_selection.c
run_c private-grant examples/private_grant.c

PYTHONPATH=python python3 python/tests/test_check.py
PYTHONPATH=python python3 python/tests/test_client.py
PYTHONPATH=python python3 python/tests/test_social_light.py
PYTHONPATH=python python3 python/tests/test_gun.py
PYTHONPATH=python python3 python/tests/test_verbs.py
PYTHONPATH=python python3 python/tests/test_network.py

