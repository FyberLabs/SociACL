# Current-key group row producers

The `sociacl/group` package exports `signMembershipAssent`, `signObjectSet`,
and `signGroupCancel`. Each accepts an unsigned data-only draft, a caller-held
32-byte signing scalar and an independently resolved current signing key. They
reuse the existing row parsers and canonical transcripts, return immutable signed
rows, and retain no key. Signature and witness fields cannot be injected into
a draft; retired-key attestation is a separate operation.

An assent signs only its own party's statement. Producing a row does not enroll
any identity, establish the second assent, grant access, select an epoch or
replace current protected admission. Consumers still resolve the signer and key
under the appropriate current identity history before signing and submitting.
