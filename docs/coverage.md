# Coverage

Measured **2026-10-27** by `scripts/coverage.sh`.

| Surface | Result | Line coverage | Tool |
| --- | --- | ---: | --- |
| Rust workspace | 413 tests + 6 examples | 91.01% | cargo-llvm-cov |
| C FFI | 12 unit + 6 examples | 83.80% (`sociacl-c`) | same llvm-cov |
| Python | 28 tests | 88.2% | coverage.py or stdlib trace |
| TypeScript | 158 tests | 95.9% | node --experimental-test-coverage |

C examples are smoke tests against `libsociacl`. Their line hits land in the Rust FFI crate.

## Rust files

| File | Lines | Cover |
| --- | ---: | ---: |
| `sociacl-c/src/lib.rs` | 2345 | 83.80% |
| `sociacl-core/src/attestation.rs` | 216 | 77.78% |
| `sociacl-core/src/bundle.rs` | 288 | 90.62% |
| `sociacl-core/src/cache.rs` | 49 | 91.84% |
| `sociacl-core/src/channel.rs` | 218 | 76.15% |
| `sociacl-core/src/check.rs` | 231 | 91.34% |
| `sociacl-core/src/client.rs` | 242 | 87.19% |
| `sociacl-core/src/codec.rs` | 725 | 87.31% |
| `sociacl-core/src/graph.rs` | 799 | 88.74% |
| `sociacl-core/src/hop.rs` | 253 | 92.09% |
| `sociacl-core/src/network.rs` | 69 | 92.75% |
| `sociacl-core/src/types.rs` | 344 | 79.65% |
| `sociacl-core/src/verbs.rs` | 299 | 90.30% |
| `sociacl-core/src/will.rs` | 524 | 80.92% |
| `sociacl-encdisc/src/account.rs` | 254 | 92.91% |
| `sociacl-encdisc/src/canonical.rs` | 453 | 98.68% |
| `sociacl-encdisc/src/consume.rs` | 530 | 91.70% |
| `sociacl-encdisc/src/contact_lane.rs` | 1193 | 98.16% |
| `sociacl-encdisc/src/delivery.rs` | 1249 | 94.00% |
| `sociacl-encdisc/src/emoji_variation.rs` | 21 | 95.24% |
| `sociacl-encdisc/src/epoch.rs` | 789 | 90.24% |
| `sociacl-encdisc/src/grant.rs` | 289 | 95.16% |
| `sociacl-encdisc/src/hexutil.rs` | 60 | 98.33% |
| `sociacl-encdisc/src/identity.rs` | 1647 | 92.23% |
| `sociacl-encdisc/src/inbox.rs` | 546 | 91.76% |
| `sociacl-encdisc/src/keyring.rs` | 2393 | 94.15% |
| `sociacl-encdisc/src/limits.rs` | 3 | 100.00% |
| `sociacl-encdisc/src/migration.rs` | 1087 | 93.38% |
| `sociacl-encdisc/src/passphrase.rs` | 96 | 95.83% |
| `sociacl-encdisc/src/present.rs` | 328 | 89.33% |
| `sociacl-encdisc/src/presenter.rs` | 96 | 88.54% |
| `sociacl-encdisc/src/recovery.rs` | 2913 | 96.19% |
| `sociacl-encdisc/src/rotation.rs` | 311 | 89.39% |
| `sociacl-encdisc/src/sea.rs` | 213 | 98.12% |
| `sociacl-encdisc/src/see.rs` | 223 | 84.30% |
| `sociacl-encdisc/src/store_write.rs` | 139 | 97.12% |
| `sociacl-encdisc/src/unicode16.rs` | 36 | 97.22% |
| `sociacl-encdisc/src/wrap.rs` | 661 | 86.23% |
| `sociacl-encdisc/src/writer.rs` | 76 | 88.16% |
| `sociacl-gun/src/adapter.rs` | 13 | 46.15% |
| `sociacl-gun/src/error.rs` | 6 | 0.00% |
| `sociacl-gun/src/feed.rs` | 148 | 59.46% |
| `sociacl-gun/src/forum.rs` | 581 | 90.02% |
| `sociacl-gun/src/group.rs` | 1115 | 91.30% |
| `sociacl-gun/src/hint.rs` | 154 | 86.36% |
| `sociacl-gun/src/hop.rs` | 25 | 12.00% |
| `sociacl-gun/src/leaf.rs` | 79 | 88.61% |
| `sociacl-gun/src/mesh.rs` | 400 | 91.00% |
| `sociacl-gun/src/post.rs` | 212 | 90.57% |
| `sociacl-gun/src/request.rs` | 214 | 94.86% |
| `sociacl-gun/src/soul.rs` | 62 | 37.10% |
| `sociacl-ids/src/ids.rs` | 587 | 95.40% |
| `sociacl-ids/src/lib.rs` | 113 | 95.58% |
| `sociacl-ids/src/records.rs` | 2413 | 93.29% |
| `sociacl-ids/src/uri.rs` | 91 | 87.91% |
| `social-light/src/lib.rs` | 269 | 86.62% |
| `social-light/src/localhost.rs` | 40 | 80.00% |
| **TOTAL** | 28730 | **91.01%** |

## How to refresh

```bash
cargo build --workspace --locked
./scripts/coverage.sh
```

Raw summaries: `target/coverage/rust-summary.txt`, `target/coverage/python-report.txt`, `target/coverage/typescript-report.txt`.
