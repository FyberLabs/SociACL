# SociACL

Social-graph authority plane for a self-healing mesh of devices and data.

Four verbs on one graph: **Check**, **Remint**, **Discover** / **Elect**, **Destroy**. People, agents, devices, groups, circles, and **networks** are first-class nodes. Grants come from jointly stated edges and named predicates. A network proves ownership and membership; it does not run BFT, elect a leader, or discover peers. Light, radio, and proximity can attest a statement; they do not grant.

This repository is the public core (MIT). It is not Hypermesh or Panopticon acl-service. Social Light is a named attestation channel here. [FyberLabs/socialight](https://github.com/FyberLabs/socialight) owns badge and hop delivery. `crates/social-light` is a local lab for the hop frame. A flash is a channel, not a grant.

## Verbs

| Verb | When | What it does |
| --- | --- | --- |
| `CHECK(action, object, accessor)` | Hot path | Object-named predicate on a snapshot of jointly stated edges (plus privilege-up delay). Hopcap 1. Reason is the predicate id. Fail closed if the predicate is unknown, mismatched, or does not hold. `delegate` is a keep-operating grant with an action mask (`read` / `write` / `execute`) and optional `until`. Owner stays owner. |
| `REMINT` | Authn holds, authz stale | Fresh capability from ACLs that already name this principal, including a live delegate grant. Not an election. |
| `DISCOVER` / `ELECT` | Authn gone | Object finds or elects an owner from a will written while alive. Elect uses the slow clock. Live principals can cancel. No public vacancy ads. |
| `DESTROY` | No heir, or the will says stay secret | Cryptographic erasure of the object's key material. |

Two clocks: **keep-operating** (fast; no new owner, no rekey) and **Elect** (slow). There is no dead-hand timer. Inactivity is not treated as death.

After a cut, `export_bundle` freezes what a remaining principal already held. The durable file wraps share keys with XChaCha20-Poly1305 and holder-signs the frame. `Client::from_bytes` / `from_path` keep Check, Remint, Discover, and Destroy on that snapshot. Elect refuses. Rejoin continues the same pre-cut snapshot and refuses a union of post-cut Elects. A captured file without the holder secret is not the object.

## Features

- **Check, Remint, Discover, Elect, Destroy** on one graph (`crates/sociacl-core`). Hopcap is 1. The object names the predicate (`owner`, `same-group`, `named-circle`, `posix-mode`, `trustee`, `delegate`, `same-network`). Privilege-up waits after the second statement. Privilege-down is immediate. The Check reason is the predicate id.
- **Attestations.** Ed25519 statements from a pre-enrolled issuer. Check may use `identity-live` or `device-live` as a factor on a predicate the object already names. Remint may use enrolled-station liveness for a principal the ACL already names. The plane stores the verify key. Social Light channels here are `convention-badge` and `enrolled-station`. A hop frame can factor Check. `crates/social-light` is the local hop-frame lab.
- **Will templates.** Named macro bodies in `examples/wills/` (`device-will.will`, `named-succession.will`, `posix-poor.will`). Discover and Elect read a will written while the owner was alive. `heir-template` is not a Check predicate.
- **Case C offline bundle.** `export_bundle` writes an `SACL` v4 file for a remaining principal. Share keys are wrapped with XChaCha20-Poly1305. The holder signs the frame. Open runs Check, Remint, Discover, and Destroy on that snapshot. Elect refuses.
- **Gun adapter and group predicates.** `crates/sociacl-gun` evaluates plaintext `MeshSeeGrant` rows and direct `same-group` / `named-circle` edges (`checkGroupSee`). Both edges are jointly stated. Hopcap stays 1. C (`crates/sociacl-c`) and Python (`python/sociacl`) wrap the live plane, will write/load, the Case C client, Social Light hop frames, and the Gun adapter.
- **Encrypted discovery** (`crates/sociacl-encdisc`, spec in [docs/encrypted-discovery.md](docs/encrypted-discovery.md)):
  - **Account key.** One SEA keypair per account. `DeviceEnrollment` copies that keypair onto a device. `priv` and `epriv` stay off the Gun public view (`gun_public_json` is `account`, `pub`, `epub`). Wraps use that one `epub`. The inbox lane is one per account.
  - **Wraps.** A per-item DEK wrapped to each reader's SEA `epub` (`wrap_item_dek_to_readers`). One group epoch key per epoch, wrapped to each member's `epub` (`wrap_group_key_to_members`). The item DEK is wrapped once to that group epoch key (`wrap_item_dek_to_group_epoch`). A wrap does not grant and does not add a member.
  - **Hidden authorship.** `BlindedGrantRow` stores grant ciphertext and a `GrantCommitment` (SHA-256 of a fresh blinding plus the canonical grant). The owner SEA pub is not on the row. The holder opens it in a `GrantPresentation`. Author fast unwrap uses a local DEK bound to `revisionId`. Item content authenticity is an owner signature over the item id, epoch, version, plaintext digest, and `revisionId`, inside the encrypted item.
  - **Presenter binding.** At destination re-check the verifier holds a nonce. The presenter signs the length-prefixed domain, nonce, commitment hash, and verifier audience with the reader's SEA key (`PresenterBinding`). `AuthenticatedPresenterChannel` is the same check when the channel already proves that key. `check_presented_grant` then runs Check. A `GrantPresentation` alone does not grant. Hopcap stays 1.
  - **Inbox lanes.** One `RecipientInbox` per reader. `filter_inbox_append` admits appends under `public-filtered` (default) or `named-writers`. `entryId` is the hash of the canonical entry. The scan rescans each daily shard and dedups by `entryId`. An append does not grant.
  - **Revocation, rotation, and freshness.** `rotate_on_revoke` applies privilege-down, then a new epoch wrapped only to remaining readers, then the owner's `forward-only` or `re-encrypt` choice. Destination re-check requires an owner-signed `EpochStatusProof` beside the Check zookie, bounded by `maxAgeMs` and the verifier's skew allowance. A missing proof, a proof outside that age, a proof for a superseded revision, or a zookie that does not match the graph fails closed. The proof does not grant.
  - **Epochs.** An owner device publishes an `EpochManifest`. `revisionId` is the SHA-256 of the length-prefixed manifest body (object, epoch, previous epoch, device id, key commitment, `settleWindowMs`, ACL snapshot). Devices publish `EpochFinalization` records. Replicas keep the lexicographically smallest `finalizationId` on the current chain. Readers stay on the last settled key until that winner's signed settle window elapses (`epoch_step_current`, `settled_key_open`; minimum 1 hour, maximum 72 hours, default 24 hours). Content, wraps, and further writes under a superseded revision are rejected, including when the epoch number matches. The device id is a local enrollment id. A manifest does not grant.
  - **In-place migration.** `apply_protocol_migration` keeps the object id, encrypts the existing body, and writes each current reader a wrap and a blinded row in that reader's lane. Plaintext for a reader drops after that reader's authenticated wrap receipt. Items left on the public plaintext path are skipped.
- **TypeScript contract and vectors.** `typescript/src` implements the portable light plane (named predicates and the same verbs). `typescript/contract` checks shared canonical bytes, the presenter-channel brand, the writer-channel brand, epoch admission (`epochStepCurrent`, `settledKeyOpen`), structural `rotateOnRevoke`, and structural `applyProtocolMigration`. SEA wrap, unwrap, and signature checks for those paths run in `sociacl-encdisc`. Shared fixtures are `vectors/encrypted-discovery/` (`canonical.json`, `presentation.json`, `inbox.json`, `wrap.json`, `migration.json`, `forbidden-names.json`, `sea-fixture.json`). Rust and the TypeScript contract both load the id fixtures. The reader wrap in `wrap.json` is checked by the Rust crate.

## Not implemented

- [#29](https://github.com/FyberLabs/SociACL/issues/29), [#30](https://github.com/FyberLabs/SociACL/issues/30), and [#31](https://github.com/FyberLabs/SociACL/issues/31) are open questions. This tree does not choose a group epoch length, does not decide whether every membership change starts a new epoch, does not decide whether plaintext `MeshSeeGrant` remains a public-content mode, and does not define group search tokens.
- `crates/sociacl-gun` evaluates plaintext grants and direct `same-group` / `named-circle` edges. It does not evaluate a wrap.
- s3r.ch copies [docs/s3rch-check.d.ts](docs/s3rch-check.d.ts) and reimplements Check in TypeScript. It does not import this crate. AImmune / Brewnix IR copies [docs/aimmune-ir-check.d.ts](docs/aimmune-ir-check.d.ts) the same way.
- A shard-close watermark is not implemented. Private information retrieval, a zero-knowledge presentation, and a SociACL index are not implemented.

## Tests and coverage

[![ci](https://github.com/FyberLabs/SociACL/actions/workflows/ci.yml/badge.svg)](https://github.com/FyberLabs/SociACL/actions/workflows/ci.yml)

CI (`.github/workflows/ci.yml`) runs `./scripts/test-all.sh` then `./scripts/coverage.sh` on `ubuntu-latest`. Same commands refresh this snapshot.

<!-- coverage:start -->
Measured **2026-10-16** by `scripts/coverage.sh`. CI publishes the same table on the job summary.

| Surface | Result | Line coverage |
| --- | --- | ---: |
| Rust workspace | 344 tests + 6 examples | 87.36% |
| C FFI (`sociacl-c`) | 12 unit + 6 examples | 84.56% |
| Python `python/sociacl` | 28 tests | 86.6% |
| TypeScript `typescript/src` and `typescript/contract` | 61 tests | 93.4% |

C example hits land in `libsociacl`, not in the `.c` files. Full crate table: [docs/coverage.md](docs/coverage.md).
<!-- coverage:end -->

## Build and test

Requires Rust 1.83+ (edition 2021) and **Node.js 24+** (20 and 22 are not supported). One script is the full suite; the other refreshes the coverage table above.

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

The C and Python commands below exercise the live plane, wills, the Case C client, Social Light hop frames, and the Gun adapter. The TypeScript tests exercise `typescript/src` and `typescript/contract`. s3r.ch and AImmune / Brewnix IR copy the `.d.ts` files and reimplement Check. They do not import this crate.

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
npx --prefix typescript tsc --strict --noEmit -p typescript/contract
node --experimental-strip-types --test \
  typescript/tests/test_encdisc_vectors.ts \
  typescript/tests/test_presentation.ts \
  typescript/tests/test_inbox.ts \
  typescript/tests/test_epoch.ts \
  typescript/tests/test_migration.ts
```

See [ARCHITECTURE.md](ARCHITECTURE.md), [docs/verbs.md](docs/verbs.md), [docs/networks.md](docs/networks.md), [docs/wills.md](docs/wills.md), [docs/attestations.md](docs/attestations.md), [docs/clocks.md](docs/clocks.md), [docs/social-light.md](docs/social-light.md), [docs/gun.md](docs/gun.md), [docs/s3rch-check.md](docs/s3rch-check.md), [docs/encrypted-discovery.md](docs/encrypted-discovery.md), [docs/aimmune-ir-check.md](docs/aimmune-ir-check.md), and [docs/coverage.md](docs/coverage.md).

## License

MIT. See [LICENSE](LICENSE).
