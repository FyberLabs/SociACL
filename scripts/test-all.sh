#!/usr/bin/env bash
# Run every SociACL suite the same way CI does.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

if [[ -f "$HOME/.cargo/env" ]]; then
  # shellcheck source=/dev/null
  . "$HOME/.cargo/env"
fi

cargo build --workspace --locked
cargo test --workspace --locked

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

node --test typescript/tests/*.js
