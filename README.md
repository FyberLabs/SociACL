# SociACL

Social-graph authority plane for a self-healing mesh of devices and data.

Four verbs on one graph: **Check**, **Remint**, **Discover** / **Elect**, **Destroy**. People, agents, and devices are first-class nodes. Grants come from jointly stated edges and named predicates. Light, radio, and proximity can attest a statement; they do not grant.

This repository is the public core (MIT). It is not Hypermesh, Panopticon acl-service, Social Light, or LightIFF.

## Verbs

| Verb | When | What it does |
| --- | --- | --- |
| `CHECK(action, object, accessor)` | Hot path | Object-named predicate on a snapshot of jointly stated edges (plus privilege-up delay). Hopcap 1. Reason is the predicate id. Fail closed if the predicate is unknown, mismatched, or does not hold. |
| `REMINT` | Authn holds, authz stale | Fresh capability from ACLs that already name this principal. Not an election. |
| `DISCOVER` / `ELECT` | Authn gone | Object finds or elects an owner from a will written while alive. Elect uses the slow clock. Live principals can cancel. No public vacancy ads. |
| `DESTROY` | No heir, or the will says stay secret | Cryptographic erasure of the object's key material. |

Two clocks: **keep-operating** (fast; no new owner, no rekey) and **Elect** (slow). There is no dead-hand timer. Inactivity is not treated as death.

## Build and test

Requires Rust 1.83+ (edition 2021). CI (`.github/workflows/ci.yml`) runs the same steps on `ubuntu-latest`.

```bash
cargo build --workspace --locked
cargo test --workspace --locked
cargo run --locked -p sociacl-core --example check
```

The example is a 3-node `posix-mode` Check (mode 0640).

C FFI (`sociacl-c`) and the Python package (`python/sociacl`) wrap **Check** only:

```bash
cargo build --workspace --locked
cc -I crates/sociacl-c/include examples/check.c -L target/debug -lsociacl -o target/sociacl-check-c
LD_LIBRARY_PATH=target/debug target/sociacl-check-c
PYTHONPATH=python python3 python/tests/test_check.py
```

See [ARCHITECTURE.md](ARCHITECTURE.md), [docs/verbs.md](docs/verbs.md), [docs/wills.md](docs/wills.md), and [docs/clocks.md](docs/clocks.md).

## License

MIT. See [LICENSE](LICENSE).
