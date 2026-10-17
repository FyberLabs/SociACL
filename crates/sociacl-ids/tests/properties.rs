use proptest::prelude::*;
use sociacl_ids::*;
use std::collections::HashSet;
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn pct(s: &str) -> String {
    s.bytes()
        .map(|c| {
            if c.is_ascii_alphanumeric() || b"-._~".contains(&c) {
                (c as char).to_string()
            } else {
                format!("%{c:02X}")
            }
        })
        .collect()
}
proptest! {
    #![proptest_config(ProptestConfig { cases: 10_000, ..ProptestConfig::default() })]
    #[test]
    fn roundtrip_injectivity_and_segments(mut seed in any::<[u8;32]>(), wallet in any::<[u8;20]>(), object in any::<[u8;16]>(), n in 1u32..1_000_001) {
        seed[0]&=0x7f;seed[31]|=1;
        let secret=p256::SecretKey::from_slice(&seed).unwrap();
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let p=principal_from_sec1(secret.public_key().to_encoded_point(false).as_bytes()).unwrap();
        let w=parse_wallet_input(&format!("0x{}",hex(&wallet))).unwrap();
        let t=parse_tenant_id(&format!("{}-{}-{}-{}-{}",hex(&object[..4]),hex(&object[4..6]),hex(&object[6..8]),hex(&object[8..10]),hex(&object[10..]))).unwrap();
        let o=mint_object_id_with("room",|out|{*out=object;Ok(())}).unwrap();let o=o.object_id();
        let net=parse_network_id(&format!("s3rch:https://node{n}.s3r.ch:443;key={}",hex(&seed))).unwrap();
        let source=parse_source_key(&format!("sr1:{}/{}/{}/chat",pct(net.as_ref()),pct(p.as_ref()),o)).unwrap();
        let cred=parse_oidc_credential(&serde_json::json!({"iss":"https://id.s3r.ch","tenant":t,"sub":format!("subject{n}")})).unwrap();
        prop_assert_eq!(parse_principal_id(p.as_ref()).unwrap(),p.clone());
        prop_assert_eq!(parse_eip55(w.as_ref()).unwrap(),w.clone());
        prop_assert_eq!(parse_tenant_id(t.as_ref()).unwrap(),t);
        prop_assert_eq!(parse_object_id(o.as_ref()).unwrap(),o.clone());
        prop_assert_eq!(parse_network_id(net.as_ref()).unwrap(),net.clone());
        prop_assert_eq!(parse_source_key(source.as_ref()).unwrap(),source.clone());
        prop_assert_eq!(cred.to_string().parse::<OidcCredential>().unwrap(),cred.clone());
        let keys=vec![format_principal_key(&p).to_string(),format_wallet_key(&w).to_string(),format_oidc_key(&cred).to_string(),format_network_key(&net).to_string(),format_source_path_key(&source).to_string(),object_key(o).to_string()];
        prop_assert_eq!(keys.iter().collect::<HashSet<_>>().len(),keys.len());
        let mut seed2=seed;seed2[31]^=2;
        let second=p256::SecretKey::from_slice(&seed2).unwrap();
        let p2=principal_from_sec1(second.public_key().to_encoded_point(false).as_bytes()).unwrap();
        let mut wbytes=wallet;wbytes[0]^=1;
        let w2=parse_wallet_input(&format!("0x{}",hex(&wbytes))).unwrap();
        let n2=parse_network_id(&net.as_ref().replace("https://node","https://other")).unwrap();
        let s2=parse_source_key(&source.as_ref().replace("/chat","/forum")).unwrap();
        let c2=parse_oidc_credential(&serde_json::json!({"iss":cred.issuer(),"tenant":cred.tenant(),"sub":format!("{}x",cred.subject())})).unwrap();
        let o2=parse_object_id(&format!("chat_{}",hex(&object))).unwrap();
        let others=[format_principal_key(&p2).to_string(),format_wallet_key(&w2).to_string(),format_oidc_key(&c2).to_string(),format_network_key(&n2).to_string(),format_source_path_key(&s2).to_string(),object_key(&o2).to_string()];
        for(a,b)in keys.iter().zip(others.iter()){prop_assert_ne!(a,b);}
        let claim=derive_claim_id(&format!("ens:{}",hex(&seed))).unwrap();
        let ext=derive_external_id(&source,&format!("provider/{n}")).unwrap();
        prop_assert_eq!(parse_object_id(claim.as_ref()).unwrap(),claim.clone());
        prop_assert_eq!(parse_object_id(ext.as_ref()).unwrap(),ext.clone());
        prop_assert_ne!(claim,derive_claim_id(&format!("ens:{}",hex(&seed2))).unwrap());
        prop_assert_ne!(ext,derive_external_id(&s2,&format!("provider/{n}")).unwrap());

        for key in &keys{prop_assert!(key.len()<=160&&key.bytes().all(|c|c.is_ascii_alphanumeric()||b"_:-".contains(&c)));prop_assert_eq!(key.parse::<PathKey>().unwrap().to_string(),key.clone());}
        let other=parse_object_id(&format!("chat_{}",hex(&object))).unwrap();
        prop_assert_ne!(object_key(o),object_key(&other));
        prop_assert_ne!(grant_soul(&p,o,&p),grant_soul(&p,&other,&p));
        for(s,count)in[(object_soul(Collection::Items,o),3),(acl_soul(&p),3),(grant_soul(&p,o,&p),5),(post_soul(&p,o,&p),6)]{
            prop_assert_eq!(s.as_ref().split('/').count(),count);
            for seg in s.as_ref().split('/'){prop_assert!(seg.bytes().all(|c|c.is_ascii_alphanumeric()||b"_:-".contains(&c)));}
            prop_assert_eq!(s.as_ref().parse::<Soul>().unwrap(),s);
        }
        prop_assert_eq!(parse_soul(user_soul(&p).as_ref()).unwrap().ids,vec![p.to_string()]);
    }
}
proptest! {
    #![proptest_config(ProptestConfig { cases: 100_000, ..ProptestConfig::default() })]
    #[test]
    fn arbitrary_unicode_never_panics(chars in proptest::collection::vec(any::<char>(),0..100),number in any::<i64>()) {
        let s: String=chars.into_iter().collect();
        let _=parse_principal_id(&s);let _=parse_eip55(&s);let _=parse_wallet_input(&s);let _=parse_tenant_id(&s);let _=parse_object_id(&s);let _=parse_network_id(&s);let _=parse_source_key(&s);let _=parse_soul(&s);let _=parse_path_key(&s);
        for v in [serde_json::json!(s),serde_json::json!(number),serde_json::json!({"principal":s,"v":1,"kind":"wallet","issuedAt":number}),serde_json::json!({"iss":s,"tenant":s,"sub":s})] {
            let _=parse_oidc_credential(&v);let _=verify_wallet_link(&v,1700000000);let _=verify_oidc_link(&v,&Jwks{keys:vec![]},&Default::default(),1700000000);
        }
    }
}
#[test]
fn million_mints_are_unique_and_parse() {
    let mut seen = HashSet::with_capacity(1_000_000);
    for _ in 0..1_000_000 {
        let id = mint_object_id("room").unwrap();
        assert_eq!(&parse_object_id(id.as_ref()).unwrap(), id.object_id());
        assert!(seen.insert(id.to_string()));
    }
}
#[test]
fn deserialization_cannot_bypass_newtypes() {
    assert!(serde_json::from_str::<PrincipalId>(r#""0xattacker""#).is_err());
    assert!(serde_json::from_str::<ObjectId>(r#""room.alpha""#).is_err());
    assert_eq!(
        parse_json_input(r#""\ud800""#),
        Err(Reason::UnpairedSurrogate)
    );
    assert_eq!(parse_json_input(r#"{"a":1,"a":2}"#), Err(Reason::BadRecord));
    assert_eq!(
        mint_object_id_with("room", |_| Err(Reason::RngFailure)),
        Err(Reason::RngFailure)
    );
}
