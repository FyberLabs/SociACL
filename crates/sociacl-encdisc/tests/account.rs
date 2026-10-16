use sociacl_encdisc::{
    accept_first_contact, account_binding_bytes, length_prefixed, sign_sea, verify_item_auth,
    verify_sea, AccountKeyBinding, AccountSeaSecret, EncDiscError, EnrolledSeaPub,
    FirstContactIntro, ItemAuthFields, DOMAIN_ACCOUNT_BINDING,
};

const FIXTURE: &str = include_str!("../../../vectors/encrypted-discovery/sea-fixture.json");

fn alice() -> AccountSeaSecret {
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    AccountSeaSecret::import_local(
        "0xalice",
        fixture["laneId"].as_str().unwrap(),
        fixture["signing"]["pub"].as_str().unwrap(),
        fixture["signing"]["priv"].as_str().unwrap(),
        fixture["encryption"]["epub"].as_str().unwrap(),
        fixture["encryption"]["epriv"].as_str().unwrap(),
    )
    .unwrap()
}

fn intro(secret: &AccountSeaSecret, binding: AccountKeyBinding) -> FirstContactIntro {
    FirstContactIntro {
        account: secret.account().to_string(),
        sea_pub: secret.sea_pub().to_string(),
        epub: secret.epub().to_string(),
        binding,
    }
}

#[test]
fn one_keypair_is_inherited_and_stays_off_gun() {
    let secret = alice();
    assert_ne!(secret.sea_pub(), secret.epub());
    let phone = secret.enroll("phone").unwrap();
    let laptop = secret.enroll("laptop").unwrap();
    assert_eq!(phone.device_id(), "phone");
    assert_eq!(laptop.device_id(), "laptop");
    assert_eq!(phone.secret().sea_pub(), laptop.secret().sea_pub());
    assert_eq!(phone.secret().epub(), laptop.secret().epub());
    assert_eq!(phone.secret().local_priv(), laptop.secret().local_priv());
    assert_eq!(phone.secret().local_epriv(), laptop.secret().local_epriv());
    assert_eq!(phone.inbox(), laptop.inbox());
    assert_eq!(phone.inbox().accessor, "0xalice");
    assert!(!phone.grants_see());
    assert!(secret.enroll("").is_err());

    let json = phone.gun_public_json();
    assert_eq!(
        json,
        format!(
            "{{\"account\":\"0xalice\",\"pub\":\"{}\",\"epub\":\"{}\"}}",
            secret.sea_pub(),
            secret.epub()
        )
    );
    assert!(!json.contains("\"priv\""));
    assert!(!json.contains("\"epriv\""));
    assert!(!json.contains("phone"));
    assert!(!json.contains("laptop"));
    assert!(!json.contains(secret.local_priv()));
    assert!(!json.contains(secret.local_epriv()));
    assert!(!json.contains(&secret.inbox().lane_id));
    let rendered = format!("{secret:?}");
    assert!(!rendered.contains(secret.local_priv()));
    assert!(!rendered.contains(secret.local_epriv()));
    assert!(!rendered.contains(&secret.inbox().lane_id));
    assert!(rendered.contains("<redacted>"));
    let enrolled = format!("{phone:?}");
    assert!(!enrolled.contains(secret.local_priv()));
    assert!(!enrolled.contains(secret.local_epriv()));
    assert!(!enrolled.contains(&secret.inbox().lane_id));
    assert!(enrolled.contains("<redacted>"));
}

#[test]
fn import_rejects_a_pub_that_does_not_match_priv() {
    let secret = alice();
    let err = AccountSeaSecret::import_local(
        "0xalice",
        &secret.inbox().lane_id,
        secret.epub(),
        secret.local_priv(),
        secret.epub(),
        secret.local_epriv(),
    )
    .unwrap_err();
    assert_eq!(err, EncDiscError::PubMismatch);
    assert!(AccountSeaSecret::generate("").is_err());
}

#[test]
fn enrollment_binding_matches_pub_and_epub_and_is_not_a_grant() {
    let secret = alice();
    let enrolled = EnrolledSeaPub::from_account(&secret);
    assert_eq!(enrolled.identity_pub, enrolled.sea_pub);
    let accepted =
        accept_first_contact(&intro(&secret, AccountKeyBinding::Enrollment), &enrolled).unwrap();
    assert!(!accepted.grants_see());
    assert!(!accepted.opens_lane());
    assert_eq!(secret.inbox().lane_id, alice().inbox().lane_id);
}

#[test]
fn oversized_intro_pub_is_rejected() {
    let secret = alice();
    let enrolled = EnrolledSeaPub::from_account(&secret);
    let mut presented = intro(&secret, AccountKeyBinding::Enrollment);
    presented.epub = format!("{}{}", presented.epub, "A".repeat(10_000));
    assert_eq!(
        accept_first_contact(&presented, &enrolled).unwrap_err(),
        EncDiscError::BadKey
    );
    presented = intro(&secret, AccountKeyBinding::Enrollment);
    presented.sea_pub = format!("A{}", presented.sea_pub);
    assert_eq!(
        accept_first_contact(&presented, &enrolled).unwrap_err(),
        EncDiscError::BadKey
    );
}

#[test]
fn introduction_without_epub_fails_closed() {
    let secret = alice();
    let enrolled = EnrolledSeaPub::from_account(&secret);
    let mut presented = intro(&secret, AccountKeyBinding::Enrollment);
    presented.epub.clear();
    assert_eq!(
        accept_first_contact(&presented, &enrolled).unwrap_err(),
        EncDiscError::EpubRequired
    );

    let mut record = enrolled.clone();
    record.epub.clear();
    assert_eq!(
        accept_first_contact(&intro(&secret, AccountKeyBinding::Enrollment), &record).unwrap_err(),
        EncDiscError::EpubRequired
    );
}

#[test]
fn swapped_epub_fails_closed() {
    let secret = alice();
    let other = AccountSeaSecret::generate("0xbob").unwrap();
    let mut enrolled = EnrolledSeaPub::from_account(&secret);
    enrolled.epub = other.epub().to_string();
    assert_eq!(
        accept_first_contact(&intro(&secret, AccountKeyBinding::Enrollment), &enrolled)
            .unwrap_err(),
        EncDiscError::EpubMismatch
    );
}

#[test]
fn account_signature_uses_identity_pub() {
    let secret = alice();
    let signature = secret.sign_account_binding().unwrap();
    let enrolled = EnrolledSeaPub::from_account(&secret);
    let accepted = accept_first_contact(
        &intro(
            &secret,
            AccountKeyBinding::AccountSignature {
                signature: signature.clone(),
            },
        ),
        &enrolled,
    )
    .unwrap();
    assert!(!accepted.grants_see());
    assert!(!accepted.opens_lane());

    let message = account_binding_bytes(secret.account(), secret.sea_pub(), secret.epub()).unwrap();
    verify_sea(secret.sea_pub(), &message, &signature).unwrap();

    let concatenated = format!("{}{}{}", secret.account(), secret.sea_pub(), secret.epub());
    let bad = sign_sea(secret.local_priv(), concatenated.as_bytes()).unwrap();
    assert_eq!(
        accept_first_contact(
            &intro(
                &secret,
                AccountKeyBinding::AccountSignature { signature: bad }
            ),
            &enrolled,
        )
        .unwrap_err(),
        EncDiscError::SignatureRejected
    );

    let omitted =
        length_prefixed(&[DOMAIN_ACCOUNT_BINDING, secret.sea_pub(), secret.epub()]).unwrap();
    let omitted_sig = sign_sea(secret.local_priv(), &omitted).unwrap();
    assert_eq!(
        accept_first_contact(
            &intro(
                &secret,
                AccountKeyBinding::AccountSignature {
                    signature: omitted_sig,
                },
            ),
            &enrolled,
        )
        .unwrap_err(),
        EncDiscError::SignatureRejected
    );
}

#[test]
fn self_signature_is_not_an_account_binding() {
    let secret = alice();
    let signature = secret.sign_account_binding().unwrap();
    let message = account_binding_bytes(secret.account(), secret.sea_pub(), secret.epub()).unwrap();
    verify_sea(secret.sea_pub(), &message, &signature).unwrap();

    let mut enrolled = EnrolledSeaPub::from_account(&secret);
    enrolled.identity_pub.clear();
    assert_eq!(
        accept_first_contact(
            &intro(&secret, AccountKeyBinding::AccountSignature { signature },),
            &enrolled,
        )
        .unwrap_err(),
        EncDiscError::IdentityPubMissing
    );
}

#[test]
fn identity_pub_must_be_the_one_sea_pub() {
    let secret = alice();
    let other = AccountSeaSecret::generate("0xbob").unwrap();
    let mut enrolled = EnrolledSeaPub::from_account(&secret);
    enrolled.identity_pub = other.sea_pub().to_string();
    assert_eq!(
        accept_first_contact(&intro(&secret, AccountKeyBinding::Enrollment), &enrolled)
            .unwrap_err(),
        EncDiscError::PubMismatch
    );

    let mut presented = intro(
        &secret,
        AccountKeyBinding::AccountSignature {
            signature: "ab".repeat(64),
        },
    );
    presented.sea_pub = other.sea_pub().to_string();
    assert_eq!(
        accept_first_contact(&presented, &EnrolledSeaPub::from_account(&secret)).unwrap_err(),
        EncDiscError::PubMismatch
    );
}

#[test]
fn item_auth_signature_covers_the_canonical_tuple() {
    let secret = alice();
    let reader = AccountSeaSecret::generate("0xbob").unwrap();
    let fields = ItemAuthFields {
        object: "s3rch/items/post".to_string(),
        epoch: 1,
        version: 2,
        plaintext_digest: sociacl_encdisc::plaintext_digest(b"hello"),
        revision_id: "7959127078e9212a046160203b536df084c7884f9f1c18f439fda77f28450008".to_string(),
    };
    assert_eq!(
        fields.plaintext_digest,
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
    let signature = secret.sign_item_auth(&fields).unwrap();
    verify_item_auth(secret.sea_pub(), &fields, &signature).unwrap();

    let mut relabeled = fields.clone();
    relabeled.revision_id = "ab".repeat(32);
    assert!(verify_item_auth(secret.sea_pub(), &relabeled, &signature).is_err());

    let reader_sig = reader.sign_item_auth(&fields).unwrap();
    assert!(verify_item_auth(secret.sea_pub(), &fields, &reader_sig).is_err());

    let framed = format!(
        "{}{}{}{}{}",
        fields.object, fields.epoch, fields.version, fields.plaintext_digest, fields.revision_id
    );
    let framed_sig = sign_sea(secret.local_priv(), framed.as_bytes()).unwrap();
    assert!(verify_item_auth(secret.sea_pub(), &fields, &framed_sig).is_err());
    assert!(secret
        .sign_item_auth(&ItemAuthFields {
            plaintext_digest: "ZZ".to_string(),
            ..fields
        })
        .is_err());
}
