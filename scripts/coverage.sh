#!/usr/bin/env bash
# Measure Rust / C FFI, Python, and TypeScript coverage.
# Writes docs/coverage.md and refreshes the README snapshot.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

if [[ -f "$HOME/.cargo/env" ]]; then
  # shellcheck source=/dev/null
  . "$HOME/.cargo/env"
fi

mkdir -p target/coverage

echo "==> Rust + C FFI (cargo-llvm-cov)"
if ! command -v cargo-llvm-cov >/dev/null; then
  cargo install cargo-llvm-cov --locked
fi
rustup component add llvm-tools-preview >/dev/null
cargo test --workspace --locked -- --list > target/coverage/rust-test-list.txt
cargo llvm-cov --workspace --locked --lcov --output-path target/coverage/rust.lcov \
  > target/coverage/rust-tests.txt
cargo llvm-cov report --summary-only > target/coverage/rust-summary.txt

echo "==> Python"
# No venv: self-hosted images often lack ensurepip. Prefer coverage.py if
# already installed; otherwise scripts/run_python_coverage.py uses stdlib.
python3 scripts/run_python_coverage.py

echo "==> TypeScript (node --experimental-test-coverage)"
# Coverage reporter is extra output; a second run confirms the suite still passes.
set +e
node --test --experimental-test-coverage \
  --test-coverage-include='typescript/src/**' \
  --test-reporter=spec \
  typescript/tests/*.js \
  > target/coverage/typescript-report.txt 2>&1
ts_status=$?
set -e
if [[ "${ts_status}" -ne 0 ]]; then
  cat target/coverage/typescript-report.txt
  exit "${ts_status}"
fi
node --test typescript/tests/*.js >/dev/null

python3 scripts/write_coverage.py

echo
echo "--- rust ---"
tail -n 3 target/coverage/rust-summary.txt
echo
echo "--- python ---"
cat target/coverage/python-report.txt
echo
echo "--- typescript ---"
tail -n 20 target/coverage/typescript-report.txt
