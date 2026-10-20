use sociacl_core::{NodeId, Plane, PredicateId, Timestamp};
use sociacl_gun::{
    add_claim, add_item, add_principal, apply_see_grant, check_see_grant, FeedItem, FeedSource,
    IdentitySeeGrant,
};
use sociacl_ids::{derive_claim_id, derive_external_id, grant_soul, parse_principal_id};

fn cases() -> Vec<serde_json::Value> {
    let doc: serde_json::Value =
        serde_json::from_str(include_str!("../../../vectors/mesh/pr6.json")).unwrap();
    doc["cases"].as_array().unwrap().clone()
}

fn case(name: &str) -> serde_json::Value {
    cases()
        .into_iter()
        .find(|row| row["name"] == name)
        .unwrap_or_else(|| panic!("{name}"))
}

#[test]
fn migration_grant_soul_is_ids_grant_soul() {
    let row = case("migration-grant-soul-is-ids-grantSoul");
    assert_eq!(row["name"], "migration-grant-soul-is-ids-grantSoul");
    let owner = parse_principal_id(row["owner"].as_str().unwrap()).unwrap();
    let object = row["object"].as_str().unwrap().parse().unwrap();
    let accessor = parse_principal_id(row["accessor"].as_str().unwrap()).unwrap();
    assert_eq!(
        grant_soul(&owner, &object, &accessor).as_ref(),
        row["soul"].as_str().unwrap()
    );
}

#[test]
fn feed_item_id_is_ext_derived() {
    let row = case("feed-item-id-is-ext-derived");
    assert_eq!(row["name"], "feed-item-id-is-ext-derived");
    let source = row["source"].as_str().unwrap().parse().unwrap();
    let item_id = row["providerItemId"].as_str().unwrap();
    let derived = derive_external_id(&source, item_id).unwrap();
    assert_eq!(derived.as_ref(), row["object"].as_str().unwrap());
    assert_ne!(derived.as_ref(), row["notObject"].as_str().unwrap());
    let mut plane = Plane::new();
    let owner = add_principal(
        &mut plane,
        &row["owner"].as_str().unwrap().parse().unwrap(),
    );
    let item = FeedItem {
        id: item_id.to_string(),
        source: FeedSource::Rss3,
        kind: "social".into(),
        author: "0xalice".into(),
        body: "hello".into(),
        ts: 1,
        permalink: "https://gi.rss3.io/decentralized/0xalice".into(),
        tags: Vec::new(),
        provenance: "rss3:gi".into(),
    };
    let object = add_item(&mut plane, &item, &source, &owner).unwrap();
    assert_eq!(object.as_str(), row["object"].as_str().unwrap());
}

#[test]
fn wallet_accessor_refused_in_core() {
    let row = case("wallet-accessor-refused-in-core");
    assert_eq!(row["name"], "wallet-accessor-refused-in-core");
    let wallet = row["wallet"].as_str().unwrap();
    let gun_path = row["gunPath"].as_str().unwrap();
    assert_eq!(
        parse_principal_id(wallet).unwrap_err().to_string(),
        row["reason"].as_str().unwrap()
    );
    assert_eq!(
        parse_principal_id(gun_path).unwrap_err().to_string(),
        row["reason"].as_str().unwrap()
    );
    let owner = row["owner"].as_str().unwrap().parse().unwrap();
    let accessor = row["accessor"].as_str().unwrap().parse().unwrap();
    let mut plane = Plane::new();
    let alice = add_principal(&mut plane, &owner);
    let bob = add_principal(&mut plane, &accessor);
    let claim = add_claim(&mut plane, row["claimText"].as_str().unwrap(), &alice).unwrap();
    assert_eq!(claim.as_str(), row["object"].as_str().unwrap());
    assert_eq!(
        derive_claim_id(row["claimText"].as_str().unwrap())
            .unwrap()
            .as_ref(),
        claim.as_str()
    );
    plane
        .set_object_property(&claim, "predicate", PredicateId::DELEGATE)
        .unwrap();
    let grant = IdentitySeeGrant {
        object: claim.as_str().parse().unwrap(),
        accessor: accessor,
        from: Timestamp(0),
        until: Timestamp(80),
    };
    assert!(!grant.names_accessor(&NodeId::new(wallet)));
    assert!(!grant.names_accessor(&NodeId::new(gun_path)));
    apply_see_grant(&mut plane, &alice, &grant).unwrap();
    let wallet_check = check_see_grant(&plane, &grant, &claim, &NodeId::new(wallet), None);
    assert!(wallet_check.is_err() || !wallet_check.unwrap().allowed);
    assert!(!row["allowed"].as_bool().unwrap());
    assert!(check_see_grant(&plane, &grant, &claim, &bob, None)
        .unwrap()
        .allowed);
}
