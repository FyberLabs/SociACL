# Witness policy export authentication

`verifyWitnessPolicyEnvelope(envelopeJson, root, audience, now)` and Rust's
`verify_witness_policy_envelope` authenticate the export format from
[Panopticon #543](https://github.com/FyberLabs/panopticon/pull/543). This is the
client cryptographic boundary for #68 F4. It does not install a trust policy,
fetch a URL, persist a revision, or prove that a bundle is the latest policy.

The caller supplies the administrative P-256 public key as canonical `x.y`, an
exact deployment audience, and current Unix seconds from a trusted clock. The
root and audience must be provisioned independently of the envelope and delivery
channel. Public scalar keys in shared fixtures are test identities only.

The outer JSON text must contain exactly `type`, `payload`, and `signature`, with
type `sociacl-witness-policy-envelope-v1`. Payload and signature are canonical,
unpadded base64url. The signature is compact 64-byte, low-S ES256 over UTF-8
`sociacl-witness-policy-v1\n` followed by the **original payload bytes**. Parsing
never normalizes or reserializes the signed content. Duplicate members, including
escaped aliases, fail closed in both JSON layers; unknown fields are rejected.

The signed document contains exactly `type`, `audience`, `revision`, `issuedAt`,
`expiresAt`, and `jwks`. Its type is `sociacl-witness-policy-v1`; revision is a
positive safe integer. Integer fields use nonnegative JSON integer spelling
(no fractions, exponents, or negative zero). Transport validity requires
`issuedAt <= now < expiresAt` with a lifetime of at most 86,400 seconds, without
clock-skew expansion. Expiry applies to acceptance of the transport document;
it is distinct from the issuance windows of its witness keys.

Each public key requires `kid`, `kty: EC`, `crv: P-256`, `alg: ES256`, `use: sig`,
`key_ops: [verify]`, canonical on-curve `x` and `y`, and safe-integer
`notBefore < notAfter`. Key IDs contain 1–128 Unicode scalar values. Duplicate
IDs, duplicate public points, private or unknown fields, and using the
administrative root as a witness key are rejected. Retired witness windows may
remain in the registry for historical proofs; an empty key list is a valid
signed removal of all witness trust.

Limits are 262,144 decoded payload bytes and 360,448 UTF-8 envelope bytes. Larger
inputs fail before signature verification; there is no truncation. All policy
verification failures return `bad-attestation`. TypeScript returns a frozen
copy; Rust returns the validated `WitnessPolicy` document.

## Before a client may use the returned JWKS

An authenticated document is not an installed policy. An adapter must still:

1. Establish a trusted bootstrap revision/freshness requirement independently of
   the bundle. A first-time client cannot discover the latest policy from a valid
   old signature alone.
2. Under one durable update transaction, reject revisions below its stored floor,
   reject conflicting same-revision registries, and enforce permanent key history:
   no widened windows, changed key material, or resurrection of removed keys.
3. Recheck the transport clock at commit after waiting for any lock, and atomically
   persist the policy, floor, and key history before exposing new trust to readers.
4. Preserve administrative root custody and define authenticated root rotation and
   compromise recovery. HTTPS delivery alone does not replace these requirements.

These adapter, bootstrap, delivery, root-lifecycle and deployment steps remain
open. Do not assign the verifier's result directly to a production resolver's
JWKS. The helper deliberately performs no installation or rollback-floor reset.
A compromised witness can still forge timestamps within its authorized window;
validity-window enforcement does not detect such forgeries by itself.

## Validation

`vectors/ids/witness-policy.json` is consumed by both language manifests. It has
64 cases, including exact whitespace, empty policies, retired windows, inclusive
issuance/exclusive expiry, a maximum-size payload, domain/root/audience changes,
high-S signatures, malformed UTF-8, duplicate keys/members, and resource limits.
All nine accepted exports were also checked against Panopticon's actual
`verify_policy` implementation at merged source `7b2ddda1`. The deterministic
authoring script uses public test scalars 17–20 and is not a key-provisioning tool.
