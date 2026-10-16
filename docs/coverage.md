# Coverage

Measured **2026-10-16** by `scripts/coverage.sh`.

| Surface | Result | Line coverage | Tool |
| --- | --- | ---: | --- |
| Rust workspace | 254 tests + 6 examples | 86.24% | cargo-llvm-cov |
| C FFI | 12 unit + 6 examples | 84.56% (`sociacl-c`) | same llvm-cov |
| Python | 28 tests | 86.6% | coverage.py or stdlib trace |
| TypeScript | 22 tests | 87.3% | node --experimental-test-coverage |

C examples are smoke tests against `libsociacl`. Their line hits land in the Rust FFI crate.

## Rust files

| File | Lines | Cover |
| --- | ---: | ---: |
| `sociacl-c/src/lib.rs` | 3090 | 84.56% |
| `sociacl-core/src/attestation.rs` | 215 | 78.14% |
| `sociacl-core/src/bundle.rs` | 296 | 90.20% |
| `sociacl-core/src/cache.rs` | 49 | 91.84% |
| `sociacl-core/src/channel.rs` | 219 | 75.80% |
| `sociacl-core/src/check.rs` | 236 | 92.37% |
| `sociacl-core/src/client.rs` | 244 | 87.30% |
| `sociacl-core/src/codec.rs` | 743 | 86.68% |
| `sociacl-core/src/graph.rs` | 811 | 88.53% |
| `sociacl-core/src/hop.rs` | 255 | 92.16% |
| `sociacl-core/src/network.rs` | 70 | 92.86% |
| `sociacl-core/src/types.rs` | 348 | 79.89% |
| `sociacl-core/src/verbs.rs` | 302 | 90.40% |
| `sociacl-core/src/will.rs` | 544 | 81.25% |
| `sociacl-encdisc/src/account.rs` | 251 | 93.23% |
| `sociacl-encdisc/src/canonical.rs` | 149 | 97.32% |
| `sociacl-encdisc/src/hexutil.rs` | 60 | 95.00% |
| `sociacl-encdisc/src/sea.rs` | 204 | 92.65% |
| `sociacl-encdisc/src/wrap.rs` | 707 | 83.45% |
| `sociacl-gun/src/adapter.rs` | 218 | 94.50% |
| `sociacl-gun/src/error.rs` | 6 | 0.00% |
| `sociacl-gun/src/feed.rs` | 179 | 67.04% |
| `sociacl-gun/src/hint.rs` | 157 | 86.62% |
| `sociacl-gun/src/hop.rs` | 25 | 84.00% |
| `sociacl-gun/src/leaf.rs` | 77 | 88.31% |
| `sociacl-gun/src/mesh.rs` | 357 | 94.68% |
| `sociacl-gun/src/soul.rs` | 147 | 95.92% |
| `social-light/src/lib.rs` | 270 | 86.67% |
| `social-light/src/localhost.rs` | 40 | 80.00% |
| **TOTAL** | 10269 | **86.24%** |

## How to refresh

```bash
cargo build --workspace --locked
./scripts/coverage.sh
```

Raw summaries: `target/coverage/rust-summary.txt`, `target/coverage/python-report.txt`, `target/coverage/typescript-report.txt`.
