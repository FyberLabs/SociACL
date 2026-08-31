# SociACL

Social-graph authority plane for a self-healing mesh of devices and data.

Four verbs on one graph: **Check**, **Remint**, **Discover** / **Elect**, **Destroy**. People, agents, and devices are first-class nodes. Grants come from jointly stated edges and named predicates. Light, radio, and proximity can attest a statement; they do not grant.

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

## Build and test

Requires Rust 1.83+ (edition 2021). CI (`.github/workflows/ci.yml`) runs the same steps on `ubuntu-latest`.

```bash
cargo build --workspace --locked
cargo test --workspace --locked
cargo run --locked -p sociacl-core --example check
cargo run --locked -p sociacl-core --example wills
cargo run --locked -p social-light --example lab
cargo run --locked -p sociacl-gun --example gun
```

The Check example is a 3-node `posix-mode` Check (mode 0640). The wills example parses and writes the templates in `examples/wills/`. The Social Light lab is three devices, one enrolled station, a voluntary badge share, and a quiet node that does not become owner. The Gun example is a hint that is not a grant, then dest `delegate` Check.

C FFI (`sociacl-c`) and the Python package (`python/sociacl`) wrap live **Check**, owner-only **delegate** / **undelegate**, will write/load, the Case C **Client** (Check, Remint, Discover, Destroy; Elect fails closed), Social Light hop frames (encode / accept / Check / Remint / Discover; Elect fails closed), and the Gun adapter (hint encode / accept / Check / remint / cancel; Elect fails closed). The Gun surface is Check + `delegate`. s3r.ch copies [docs/s3rch-check.d.ts](docs/s3rch-check.d.ts) and reimplements light Check in the browser. It does not import this crate.

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
```

See [ARCHITECTURE.md](ARCHITECTURE.md), [docs/verbs.md](docs/verbs.md), [docs/wills.md](docs/wills.md), [docs/attestations.md](docs/attestations.md), [docs/clocks.md](docs/clocks.md), [docs/social-light.md](docs/social-light.md), [docs/gun.md](docs/gun.md), and [docs/s3rch-check.md](docs/s3rch-check.md).

## License

MIT. See [LICENSE](LICENSE).
