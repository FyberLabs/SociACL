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
    let owner = add_principal(&mut plane, &row["owner"].as_str().unwrap().parse().unwrap());
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
fn provider_item_id_is_not_trimmed() {
    let doc: serde_json::Value =
        serde_json::from_str(include_str!("../../../vectors/mesh/strict-id.json")).unwrap();
    let rows = doc["feed"].as_array().unwrap();
    let plain = rows
        .iter()
        .find(|row| row["name"] == "provider-item-x")
        .unwrap();
    let spaced = rows
        .iter()
        .find(|row| row["name"] == "provider-item-spaced")
        .unwrap();
    let source = plain["source"].as_str().unwrap().parse().unwrap();
    assert_eq!(spaced["source"], plain["source"]);
    let plain_id = plain["providerItemId"].as_str().unwrap();
    let spaced_id = spaced["providerItemId"].as_str().unwrap();
    for row in rows {
        let id = row["providerItemId"].as_str().unwrap();
        let name = row["name"].as_str().unwrap();
        match derive_external_id(&source, id) {
            Ok(derived) => {
                assert!(row["ok"].as_bool().unwrap(), "{name}");
                assert_eq!(derived.as_ref(), row["object"].as_str().unwrap(), "{name}");
            }
            Err(err) => {
                assert!(!row["ok"].as_bool().unwrap(), "{name}");
                assert_eq!(err.to_string(), row["reason"].as_str().unwrap(), "{name}");
            }
        }
    }
    let item = |id: &str| FeedItem {
        id: id.to_string(),
        source: FeedSource::Rss3,
        kind: "social".into(),
        author: String::new(),
        body: String::new(),
        ts: 1,
        permalink: "https://example.com/item".into(),
        tags: Vec::new(),
        provenance: String::new(),
    };
    let plain_item = item(plain_id);
    let spaced_item = item(spaced_id);
    assert_eq!(plain_item.canonical_key().as_deref(), Some(plain_id));
    assert_eq!(spaced_item.canonical_key().as_deref(), Some(spaced_id));
    assert_ne!(plain_item.canonical_key(), spaced_item.canonical_key());
    assert_eq!(
        plain_item.object_id(&source).unwrap().as_ref(),
        plain["object"].as_str().unwrap()
    );
    assert!(spaced_item.object_id(&source).is_err());
    for row in doc["urls"].as_array().unwrap() {
        if row.get("dstLen").is_some() {
            continue;
        }
        let url = row["url"].as_str().unwrap();
        let name = row["name"].as_str().unwrap();
        match sociacl_gun::UrlLeaf::parse(url) {
            Ok(leaf) => {
                assert!(row["ok"].as_bool().unwrap(), "{name}");
                assert_eq!(
                    leaf.normalized(),
                    row["normalized"].as_str().unwrap(),
                    "{name}"
                );
            }
            Err(err) => {
                assert!(!row["ok"].as_bool().unwrap(), "{name}");
                assert_eq!(err.to_string(), row["reason"].as_str().unwrap(), "{name}");
            }
        }
    }
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
    assert!(
        check_see_grant(&plane, &grant, &claim, &bob, None)
            .unwrap()
            .allowed
    );
}

#[test]
fn long_feed_permalinks_keep_normalized_deduplication_outside_the_leaf_cap() {
    let normalized = format!("https://example.com/{}", "a".repeat(300));
    let alternate = format!("HTTPS://EXAMPLE.COM/{}/#fragment", "a".repeat(300));
    assert_eq!(
        sociacl_gun::normalize_permalink(&alternate).unwrap(),
        normalized
    );
    assert_eq!(
        sociacl_gun::UrlLeaf::parse(&alternate)
            .unwrap_err()
            .to_string(),
        "too-long"
    );
    let item = |permalink: String| FeedItem {
        id: String::new(),
        source: FeedSource::Rss,
        kind: "activity".into(),
        author: String::new(),
        body: String::new(),
        ts: 1,
        permalink,
        tags: Vec::new(),
        provenance: String::new(),
    };
    assert_eq!(item(alternate).canonical_key(), Some(normalized.clone()));
    assert_eq!(item(normalized.clone()).canonical_key(), Some(normalized));
}
