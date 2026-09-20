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

echo "==> TypeScript"
# Node 20 has --experimental-test-coverage. --test-coverage-include is Node 22+.
# The self-hosted PATH node is older than the Actions Node 24 runtime.
run_ts_coverage() {
  node --test --experimental-test-coverage "$@" --test-reporter=spec typescript/tests/*.js \
    > target/coverage/typescript-report.txt 2>&1
}

set +e
run_ts_coverage --test-coverage-include='typescript/src/**'
ts_status=$?
if [[ "${ts_status}" -ne 0 ]] && grep -q 'bad option: --test-coverage-include' target/coverage/typescript-report.txt; then
  run_ts_coverage
  ts_status=$?
fi
if [[ "${ts_status}" -ne 0 ]] && grep -q 'bad option' target/coverage/typescript-report.txt; then
  echo "node coverage flags unsupported; tests only" | tee target/coverage/typescript-report.txt
  node --test typescript/tests/*.js
  ts_status=$?
  printf '\nall files | n/a |\n' >> target/coverage/typescript-report.txt
fi
set -e
if [[ "${ts_status}" -ne 0 ]]; then
  cat target/coverage/typescript-report.txt
  exit "${ts_status}"
fi

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
