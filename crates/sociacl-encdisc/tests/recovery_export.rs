//! An adapter outside this crate can hash a recovery envelope before it
//! verifies a store write. `recovery_envelope_hash` is part of that contract.

use sociacl_encdisc::{
    account_id_from_label, recovery_envelope_hash, store_write_message, RecoveryEnvelope,
    DOMAIN_STORE_WRITE,
};

const PRINCIPAL: &str =
    "YP7UuiVanTHJYet0xjVtaMBJuJI7Yfps5mliLmDyn7Y.eQP-EAi4vJmkGunpVii8ZPLxsgwtfp9Rd6PClNRGIpk";
const EPUB: &str =
    "EMvdmXTv89JPyMx5n3blU3L_D70U-6JoVaVzTvSzgYg.B_b0CP3o9X3I7tWrxA_F1VhXpjeMuIJCtQWnOh7LN5c";
const ENVELOPE_HASH: &str = "666a5ef352b1bc810d2346143f5c8e27baaa4a763f8161342454868f3ff384c3";
const PUT_MESSAGE: &str = "16000000736f636961636c2d73746f72652d77726974652d76315700000059503755756956616e54484a59657430786a5674614d424a754a493759667073356d6c694c6d44796e37592e6551502d45416934764a6d6b47756e70566969385a504c787367777466703952643650436c4e524749706b03000000707574010000003240000000363636613565663335326231626338313064323334363134336635633865323762616161346137363366383136313334323435343836386633666633383463330100000032040000006e6f6e65040000006e6f6e650100000030";

struct OutsideRecoveryAdapter;

impl OutsideRecoveryAdapter {
    fn envelope_hash(&self, envelope: &RecoveryEnvelope) -> String {
        recovery_envelope_hash(envelope).expect("pinned sample hashes")
    }
}

#[test]
fn an_outside_adapter_hashes_the_pinned_recovery_envelope() {
    assert_eq!(DOMAIN_STORE_WRITE, "sociacl-store-write-v1");
    let principal = account_id_from_label(PRINCIPAL).unwrap();
    let epub = account_id_from_label(EPUB).unwrap();
    let envelope = RecoveryEnvelope {
        principal: principal.clone(),
        rotation_seq: 2,
        signing_pub: principal.clone(),
        epub,
        bytes: vec![1, 2, 3],
    };
    let adapter = OutsideRecoveryAdapter;
    assert_eq!(adapter.envelope_hash(&envelope), ENVELOPE_HASH);
    let message = store_write_message(
        principal.as_ref(),
        "put",
        "2",
        ENVELOPE_HASH,
        "2",
        "none",
        "none",
        "0",
    )
    .unwrap();
    assert_eq!(hex(&message), PUT_MESSAGE);
}

fn hex(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(ALPHABET[(byte >> 4) as usize] as char);
        out.push(ALPHABET[(byte & 0x0f) as usize] as char);
    }
    out
}
