# Social Light

Social Light is a named attestation channel on SociACL. It is not a verb, a grant, a friend, or a product folder of this repository.

[FyberLabs/socialight](https://github.com/FyberLabs/socialight) is the sibling that owns delivery: badge and station nodes, hops, and later radio or optical carriers. This repository owns the hop frame those nodes speak, and the Check / Remint / Discover evaluation of what arrives. The names stay split. Do not merge them. There is no FyberLabs/SocialLight software repo.

`crates/social-light` is a local lab in this tree so the hop can be tested without cloning socialight. It can move later. socialight consumes the frame. It does not need to become a SociACL crate.

## Who owns what

| Piece | Owner | Lives |
| --- | --- | --- |
| Graph, enrollments, named predicates, verbs | SociACL | `crates/sociacl-core` |
| Hop frame encode / decode / verify | SociACL | `crates/sociacl-core/src/hop.rs` |
| Channel kinds and verb entry points | SociACL | `crates/sociacl-core/src/channel.rs` |
| C accept / check / remint / discover | SociACL | `crates/sociacl-c` |
| In-process lab and localhost UDP hop | lab here, product later | `crates/social-light` |
| Badge, station, later BT / Wi-Fi / Meshtastic | socialight | https://github.com/FyberLabs/socialight |

socialight's own docs still describe a hosted control plane and an optical challenge. That work stays in socialight. This plane does not host accounts, and it does not evaluate a blink as a grant. Devices and data live on a SociACL Plane or a Case C Client.

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
    | encode SLHF
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

## Hop frame (SLHF v1)

Versioned, length-prefixed. Not JSON-as-policy. Distinct from the Case C `SACL` bundle.

```
magic        4 bytes   "SLHF"
version      u16 LE    1
payload_len  u32 LE
payload
  channel        length-prefixed UTF-8
  attestation
    issuer       length-prefixed UTF-8
    subject      length-prefixed UTF-8
    claim        length-prefixed UTF-8
    issued_at    u64 LE
    enrollment   length-prefixed UTF-8
    binding      "object-version" | "snapshot"
                 object-version: object, version u64
                 snapshot: object, 32-byte hash
    signature    length-prefixed 64-byte Ed25519
  has_token      u8 (0 or 1)
  share_token    length-prefixed UTF-8 if has_token == 1
```

Strings are `u32 LE` length then bytes. Max string 4096. The attestation field order matches the SACL bundle so socialight can reuse one encoder.

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
crates/sociacl-core/src/hop.rs       SLHF encode / decode
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
