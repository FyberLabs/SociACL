# Social Light

Social Light is a named attestation channel on SociACL. It is not a verb, a grant, a friend, or a product folder of this repository.

[FyberLabs/socialight](https://github.com/FyberLabs/socialight) is the sibling that owns delivery: badge and station nodes, hops, and later radio or optical carriers. That repo's `socialight-hop` crate published hop frame v1 (`SLHP`). This repository consumes that exact layout. It verifies the attestation bytes and evaluates Check / Remint / Discover. The names stay split. Do not merge them. There is no FyberLabs/SocialLight software repo.

`crates/social-light` is a local in-process lab in this tree. It is not socialight and it is not pulled from that repo. socialight delivers. SociACL verifies.

## Who owns what

| Piece | Owner | Lives |
| --- | --- | --- |
| Graph, enrollments, named predicates, verbs | SociACL | `crates/sociacl-core` |
| Hop frame encode / decode (SLHP v1) | socialight published, SociACL consumes | `crates/sociacl-core/src/hop.rs` |
| Attestation verify | SociACL | `crates/sociacl-core` |
| Channel kinds and verb entry points | SociACL | `crates/sociacl-core/src/channel.rs` |
| C accept / check / remint / discover | SociACL | `crates/sociacl-c` |
| In-process lab and localhost UDP hop | lab here, product later | `crates/social-light` |
| Badge, station, later BT / Wi-Fi / Meshtastic | socialight | https://github.com/FyberLabs/socialight |

socialight's 2026-03-29 notes still describe a hosted control plane and an optical challenge. Those stay on that repo, marked as not the hop contract. This plane does not host accounts, and it does not evaluate a blink as a grant. Devices and data live on a SociACL Plane or a Case C Client.

## Ancestor hardware

FyberLabs/FlexModule (2014) is a light-plus-radio convention badge. Cite it as ancestor hardware. Do not port Diptrace boards. Do not invent a BOM. FlexModule reachability is not a friend edge.

The FyberLabs website mentions Social Light as a convention badge. Leave the site alone.

Panopticon listed Social Light as not started. Do not add a Panopticon product folder or SaaS here.

LightIFF, Tennessee Windage, and LightFight are other products. LightIFF is not implemented. No waveforms, frequencies, challenge-response, or ITAR.

## Product law

A flash, badge ping, or radio hop is a carrier. It is not a grant, friend, heir, or owner.

- Check may use a statement as a factor on an already-named predicate.
- Remint may use enrolled-station liveness for a principal the ACL already names.
- Discover may report a living badge principal and an optional voluntary share-token.
- Elect from a flash always fails. Silence does not Elect.
- Nearby is not a grant. Hearing a frame does not mint a friend.
- No SaaS. MIT.

## Interface

Social Light emits a signed statement. SociACL evaluates it.

```
socialight node                    SociACL plane or Case C client
-----------------                  -----------------------------
badge / station
    | encode SLHP
    v
hop (in-process, localhost UDP,
     later BT / Wi-Fi / Meshtastic)
    | bytes
    v
                              decode -> verify enrollment + sig
                                    -> Check / Remint / Discover
                                    Elect refuses
```

Hops are optional. The first hops in this tree are in-process (`Lab::emit`) and two localhost UDP sockets (`LocalHop`). Two nodes. Not a daemon mesh. Not cloud.

## Hop frame (SLHP v1)

This is the contract `socialight-hop` published. Not a second magic. Not JSON-as-policy. Distinct from the Case C `SACL` bundle. See socialight `docs/DELIVERY.md`.

```
magic        4 bytes   "SLHP"
version      u16 LE    1
payload_len  u32 LE
payload
  channel        u32 LE length + UTF-8
  attestation    u32 LE length + opaque bytes
  has_token      u8 (0 none, 1 present)
  share_token    u32 LE length + UTF-8 if has_token == 1
```

Hop decode does not verify. Max string 4096. Max attestation 65536. SociACL parses the opaque attestation bytes (same field order as a SACL attestation: issuer, subject, claim, issued_at, enrollment, binding, 64-byte Ed25519 signature) and verifies them against a pre-enrolled key.

Named channels only:

| Channel | Carries | Verb may |
| --- | --- | --- |
| `convention-badge` | `identity-live` of a living person, optional share-token | Discover reports the person. Check may use the statement as a factor. The token is not a capability. |
| `enrolled-station` | station liveness, or identity / device liveness | Remint or Check for a principal the ACL already names. |

Fail closed on:

- unnamed channel
- forbidden channel (`lightiff`, `flash`, `ping`, `nearby`, …)
- forbidden claim (`flash`, `ping`, `loud`, `silence`, …)
- unsigned statement (64 zero bytes is not a signature)
- LightIFF-shaped ids (`lightiff`, `field-iff`, `iff`, `*-iff`, `iff-*`)
- forged signature at verify time (`sociacl-core` owns verify)

`social-light` owns delivery of the bytes. `sociacl-core` owns verify.

## File layout

```
docs/social-light.md                 this page
crates/sociacl-core/src/hop.rs       SLHP encode / decode (socialight contract)
crates/sociacl-core/src/channel.rs   named kinds + verb entry
crates/sociacl-c/include/sociacl.h   encode / accept / check / remint / discover / elect
crates/social-light/                 lab + localhost UDP
python/sociacl                       thin ctypes of the C ABI
```

C matches `sociacl.h` style. Elect is visible and always fails (`sociacl_social_light_elect`). Python wraps the same calls.

## What this PR does not do

- Clone or vendor FyberLabs/socialight
- Rewrite the FyberLabs website
- Add billing, accounts, or a control-plane server
- Grow FlexModule hardware
- Implement LightIFF
