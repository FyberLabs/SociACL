# SociACL

Social-graph authority plane for a self-healing mesh of devices and data.

Four verbs on one graph: **Check**, **Remint**, **Discover** / **Elect**, **Destroy**. People, agents, devices, groups, circles, and **networks** are first-class nodes. Grants come from jointly stated edges and named predicates. A network proves ownership and membership; it does not run BFT, elect a leader, or discover peers. Light, radio, and proximity can attest a statement; they do not grant.

This repository is the public core (MIT). It is not Hypermesh, Panopticon acl-service, or LightIFF. Social Light is a named attestation channel here. [FyberLabs/socialight](https://github.com/FyberLabs/socialight) owns badge and hop delivery. `crates/social-light` is a local lab for the hop frame. A flash is a channel, not a grant.

## Verbs

| Verb | When | What it does |
| --- | --- | --- |
| `CHECK(action, object, accessor)` | Hot path | Object-named predicate on a snapshot of jointly stated edges (plus privilege-up delay). Hopcap 1. Reason is the predicate id. Fail closed if the predicate is unknown, mismatched, or does not hold. `delegate` is a keep-operating grant with an action mask (`read` / `write` / `execute`) and optional `until`. Owner stays owner. |
| `REMINT` | Authn holds, authz stale | Fresh capability from ACLs that already name this principal, including a live delegate grant. Not an election. |
| `DISCOVER` / `ELECT` | Authn gone | Object finds or elects an owner from a will written while alive. Elect uses the slow clock. Live principals can cancel. No public vacancy ads. |
| `DESTROY` | No heir, or the will says stay secret | Cryptographic erasure of the object's key material. |

Two clocks: **keep-operating** (fast; no new owner, no rekey) and **Elect** (slow). There is no dead-hand timer. Inactivity is not treated as death.

After a cut, `export_bundle` freezes what a remaining principal already held. The durable file wraps share keys with XChaCha20-Poly1305 and holder-signs the frame. `Client::from_bytes` / `from_path` keep Check, Remint, Discover, and Destroy on that snapshot. Elect refuses. Rejoin continues the same pre-cut snapshot and refuses a union of post-cut Elects. A captured file without the holder secret is not the object.

## Tests and coverage

[![ci](https://github.com/FyberLabs/SociACL/actions/workflows/ci.yml/badge.svg)](https://github.com/FyberLabs/SociACL/actions/workflows/ci.yml)

CI (`.github/workflows/ci.yml`) runs `./scripts/test-all.sh` then `./scripts/coverage.sh` on `[self-hosted, linux, x64]`. Same commands refresh this snapshot.

<!-- coverage:start -->
Measured **2026-09-20** by `scripts/coverage.sh`. CI publishes the same table on the job summary.

| Surface | Result | Line coverage |
| --- | --- | ---: |
| Rust workspace | 229 tests + 6 examples | 85.50% |
| C FFI (`sociacl-c`) | 12 unit + 6 examples | 82.71% |
| Python `python/sociacl` | 28 tests | 86.6% |
| TypeScript `typescript/src` | 20 tests | 85.8% |

C example hits land in `libsociacl`, not in the `.c` files. Full crate table: [docs/coverage.md](docs/coverage.md).
<!-- coverage:end -->

## Build and test

Requires Rust 1.83+ (edition 2021). One script is the full suite; the other refreshes the coverage table above.

```bash
./scripts/test-all.sh
./scripts/coverage.sh
```

The same steps, expanded:

```bash
cargo build --workspace --locked
cargo test --workspace --locked
cargo run --locked -p sociacl-core --example check
cargo run --locked -p sociacl-core --example wills
cargo run --locked -p sociacl-core --example network
cargo run --locked -p sociacl-core --example elect
cargo run --locked -p social-light --example lab
cargo run --locked -p sociacl-gun --example gun
```

The Check example is a 3-node `posix-mode` Check (mode 0640). The wills example parses and writes the templates in `examples/wills/`. The Social Light lab is three devices, one enrolled station, a voluntary badge share, and a quiet node that does not become owner. The Gun example is a hint that is not a grant, then dest `delegate` Check.

C FFI (`sociacl-c`) and the Python package (`python/sociacl`) wrap the live plane (**Check**, **Remint**, **Discover**, **Elect**, **Destroy**, owner-only **delegate** / **undelegate**, network **admit** / **censure**), will write/load, the Case C **Client** (Check, Remint, Discover, Destroy; Elect fails closed), Social Light hop frames (encode / accept / Check / Remint / Discover; Elect fails closed), and the Gun adapter (hint encode / accept / Check / remint / cancel; Elect fails closed). The Gun / s3r.ch product surface stays light Check + `delegate`. s3r.ch copies [docs/s3rch-check.d.ts](docs/s3rch-check.d.ts) and reimplements light Check in the browser. It does not import this crate. AImmune / Brewnix IR copies [docs/aimmune-ir-check.d.ts](docs/aimmune-ir-check.d.ts) the same way. The portable TypeScript light plane in `typescript/` implements the same named predicates and verbs for Panopticon and other adapters; it is a copyable reference, not an s3r.ch npm dependency.

```bash
cargo build --workspace --locked
cc -I crates/sociacl-c/include examples/check.c -L target/debug -lsociacl -o target/sociacl-check-c
LD_LIBRARY_PATH=target/debug target/sociacl-check-c
cc -I crates/sociacl-c/include examples/client.c -L target/debug -lsociacl -o target/sociacl-client-c
LD_LIBRARY_PATH=target/debug target/sociacl-client-c
cc -I crates/sociacl-c/include examples/social_light.c -L target/debug -lsociacl -o target/sociacl-social-light-c
LD_LIBRARY_PATH=target/debug target/sociacl-social-light-c
PYTHONPATH=python python3 python/tests/test_check.py
PYTHONPATH=python python3 python/tests/test_client.py
PYTHONPATH=python python3 python/tests/test_social_light.py
cc -I crates/sociacl-c/include examples/gun.c -L target/debug -lsociacl -o target/sociacl-gun-c
LD_LIBRARY_PATH=target/debug target/sociacl-gun-c
PYTHONPATH=python python3 python/tests/test_gun.py
cc -I crates/sociacl-c/include examples/verbs.c -L target/debug -lsociacl -o target/sociacl-verbs-c
LD_LIBRARY_PATH=target/debug target/sociacl-verbs-c
PYTHONPATH=python python3 python/tests/test_verbs.py
PYTHONPATH=python python3 python/tests/test_network.py
cc -I crates/sociacl-c/include examples/elect.c -L target/debug -lsociacl -o target/sociacl-elect-c
LD_LIBRARY_PATH=target/debug target/sociacl-elect-c
node --test typescript/tests/*.js
```

See [ARCHITECTURE.md](ARCHITECTURE.md), [docs/verbs.md](docs/verbs.md), [docs/networks.md](docs/networks.md), [docs/wills.md](docs/wills.md), [docs/attestations.md](docs/attestations.md), [docs/clocks.md](docs/clocks.md), [docs/social-light.md](docs/social-light.md), [docs/gun.md](docs/gun.md), [docs/s3rch-check.md](docs/s3rch-check.md), [docs/aimmune-ir-check.md](docs/aimmune-ir-check.md), and [docs/coverage.md](docs/coverage.md).

## License

MIT. See [LICENSE](LICENSE).
