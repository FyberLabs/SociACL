use sociacl_gun::{
    accept_hint, accept_hint_bytes, from_gun_node, to_gun_node, FeedItem, FeedSource, FeedTab,
    GunError, GunUserNode, HandoffHint, IdentityClaimKind, ItemShape, OffGraphKind, UrlLeaf,
    HINT_MAGIC, SEE,
};

fn sample_feed_item() -> FeedItem {
    FeedItem {
        id: "rss3:act/1#x".into(),
        source: FeedSource::Rss3,
        kind: "social".into(),
        author: "0xalice".into(),
        body: "hello".into(),
        ts: 1,
        permalink: "https://gi.rss3.io/decentralized/0xalice".into(),
        tags: vec!["Social".into(), "farcaster".into(), "social".into()],
        provenance: "rss3:gi".into(),
    }
}

#[test]
fn url_leaf_is_not_an_in_graph_node() {
    let leaf = UrlLeaf::parse("https://Example.COM/item/1/#frag").unwrap();
    assert_eq!(leaf.normalized(), "https://example.com/item/1");
    assert!(!leaf.is_gun_node());
    assert!(leaf.as_node_id().is_none());

    let mut item = ItemShape::default();
    item.permalink = Some(leaf);
    item.tags = ItemShape::tags_from_csv("mesh, notes");
    assert_eq!(item.tags_as_csv(), "mesh,notes");
    assert_eq!(
        item.dedup_key().as_deref(),
        Some("https://example.com/item/1")
    );
    item.id = Some("claim-1".into());
    assert_eq!(item.dedup_key().as_deref(), Some("claim-1"));

    assert_eq!(
        UrlLeaf::parse("gun://s3rch/users/0xalice").unwrap_err(),
        GunError::InvalidUrl
    );
    assert_eq!(
        UrlLeaf::parse("s3rch/users/0xalice").unwrap_err(),
        GunError::InvalidUrl
    );
}

#[test]
fn hint_decode_does_not_verify_or_mint() {
    let hint = HandoffHint::parse("0xbob", "claim-1", Some(SEE), Some("edge-handoff")).unwrap();
    assert_eq!(accept_hint(hint.clone()), hint);
    let bytes = hint.encode().unwrap();
    assert_eq!(&bytes[..4], HINT_MAGIC);
    let decoded = accept_hint_bytes(&bytes).unwrap();
    assert_eq!(decoded.principal.as_str(), "0xbob");
    assert_eq!(decoded.verb.as_deref(), Some(SEE));
    assert_eq!(
        accept_hint_bytes(b"nope").unwrap_err(),
        GunError::HintCorrupt
    );
}

#[test]
fn from_gun_node_empty_kind_is_activity() {
    let mut node = to_gun_node(&sample_feed_item());
    node.kind = "  ".into();
    assert_eq!(from_gun_node(&node).unwrap().kind, "activity");
    node.kind = String::new();
    assert_eq!(from_gun_node(&node).unwrap().kind, "activity");
}

#[test]
fn feed_tab_is_ux_not_a_check_object() {
    assert_eq!(FeedTab::Public.as_str(), "public");
    assert_eq!(FeedTab::parse("mine"), Some(FeedTab::Mine));
    assert_eq!(FeedTab::parse("network"), Some(FeedTab::Network));
    assert!(FeedTab::parse("secret").is_none());
}

#[test]
fn user_node_is_the_wallet_not_a_second_schema() {
    let user = GunUserNode {
        id: "0xalice".into(),
        indicators: vec![
            "ens:name.eth".into(),
            "unstoppable:name.crypto".into(),
            "fc:name".into(),
            "lens:name".into(),
            "rss3:0xalice".into(),
        ],
        provenance: "overlay".into(),
        ts: 1,
    };
    assert_eq!(
        user.indicators_as_csv(),
        "ens:name.eth,unstoppable:name.crypto,fc:name,lens:name,rss3:0xalice"
    );
    assert_eq!(user.linked_claim_ids().len(), 5);
    assert!(user
        .linked_claim_ids()
        .iter()
        .all(|id| !id.contains("/claims/")));
}

#[test]
fn from_gun_node_refuses_unknown_source() {
    let mut node = to_gun_node(&sample_feed_item());
    node.source = "kyc".into();
    assert!(from_gun_node(&node).is_none());
}

#[test]
fn feed_item_is_data_without_ownership() {
    let item = sample_feed_item();
    let node = to_gun_node(&item);
    assert_eq!(node.tags, "Social,farcaster,social");
    let back = from_gun_node(&node).unwrap();
    assert_eq!(back.source, FeedSource::Rss3);
    assert_eq!(back.tags, vec!["social", "farcaster"]);
    let source = "sr1:rss/https%3A%2F%2Fs3r.ch/feed%2F%CE%B1%231/feed"
        .parse()
        .unwrap();
    assert_eq!(
        item.object_id(&source).unwrap(),
        sociacl_ids::derive_external_id(&source, &item.id).unwrap()
    );
    assert!(IdentityClaimKind::KycAttestation.issuer_is_url());
    assert!(IdentityClaimKind::Email.issuer_is_url());
    assert!(!IdentityClaimKind::Wallet.issuer_is_url());
    assert_eq!(OffGraphKind::Rss3.as_str(), "rss3");
}
