# Coverage

Measured **2026-09-20** by `scripts/coverage.sh`.

| Surface | Result | Line coverage | Tool |
| --- | --- | ---: | --- |
| Rust workspace | 229 tests + 6 examples | 85.50% | cargo-llvm-cov |
| C FFI | 12 unit + 6 examples | 82.71% (`sociacl-c`) | same llvm-cov |
| Python | 28 tests | 77.3% | coverage.py |
| TypeScript | 20 tests | 85.8% | node --experimental-test-coverage |

C examples are smoke tests against `libsociacl`. Their line hits land in the Rust FFI crate.

## Rust files

| File | Lines | Cover |
| --- | ---: | ---: |
| `sociacl-c/src/lib.rs` | 2649 | 82.71% |
| `sociacl-core/src/attestation.rs` | 209 | 80.38% |
| `sociacl-core/src/bundle.rs` | 288 | 90.62% |
| `sociacl-core/src/cache.rs` | 49 | 91.84% |
| `sociacl-core/src/channel.rs` | 218 | 76.15% |
| `sociacl-core/src/check.rs` | 231 | 92.21% |
| `sociacl-core/src/client.rs` | 242 | 87.19% |
| `sociacl-core/src/codec.rs` | 725 | 87.31% |
| `sociacl-core/src/graph.rs` | 799 | 88.74% |
| `sociacl-core/src/hop.rs` | 253 | 92.09% |
| `sociacl-core/src/network.rs` | 69 | 92.75% |
| `sociacl-core/src/types.rs` | 343 | 79.59% |
| `sociacl-core/src/verbs.rs` | 299 | 90.30% |
| `sociacl-core/src/will.rs` | 523 | 81.07% |
| `sociacl-gun/src/adapter.rs` | 217 | 94.47% |
| `sociacl-gun/src/error.rs` | 6 | 0.00% |
| `sociacl-gun/src/feed.rs` | 178 | 66.85% |
| `sociacl-gun/src/hint.rs` | 154 | 87.01% |
| `sociacl-gun/src/hop.rs` | 25 | 84.00% |
| `sociacl-gun/src/leaf.rs` | 77 | 88.31% |
| `sociacl-gun/src/mesh.rs` | 349 | 95.42% |
| `sociacl-gun/src/soul.rs` | 144 | 95.83% |
| `social-light/src/lib.rs` | 269 | 86.62% |
| `social-light/src/localhost.rs` | 40 | 80.00% |
| **TOTAL** | 8356 | **85.50%** |

## How to refresh

```bash
cargo build --workspace --locked
./scripts/coverage.sh
```

Raw summaries: `target/coverage/rust-summary.txt`, `target/coverage/python-report.txt`, `target/coverage/typescript-report.txt`.
