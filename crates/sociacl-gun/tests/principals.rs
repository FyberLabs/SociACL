//! Shared principal and object-id vectors. TypeScript loads the same file.

use sociacl_core::Timestamp;
use sociacl_gun::{acl_principal_key, grant_soul, GunError, MeshSeeGrant, MeshSeeGraph};

const VECTORS: &str = include_str!("../../../vectors/mesh/principals.json");

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Fixture {
    principals: Vec<PrincipalCase>,
    grants: Vec<GrantCase>,
    objects: Vec<ObjectCase>,
    null_keys: Vec<NullKeyCase>,
}

#[derive(serde::Deserialize)]
struct PrincipalCase {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    repeat: Option<String>,
    #[serde(default)]
    count: Option<usize>,
    canonical: Option<String>,
}

#[derive(serde::Deserialize)]
struct GrantCase {
    owner: String,
    object: String,
    accessor: String,
    soul: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ObjectCase {
    name: String,
    stored: String,
    owner: String,
    #[serde(default)]
    query: Option<String>,
    #[serde(default)]
    accessor: Option<String>,
    #[serde(default)]
    allowed: Option<bool>,
    #[serde(default)]
    put: Option<String>,
    #[serde(default)]
    put_owner: Option<String>,
    #[serde(default)]
    has_put_id: Option<bool>,
    owner_after: String,
}

#[derive(serde::Deserialize)]
struct NullKeyCase {
    secret: String,
    other: String,
    accessor: String,
}

fn principal_id(row: &PrincipalCase) -> String {
    if let Some(unit) = &row.repeat {
        return unit.repeat(row.count.unwrap_or(0));
    }
    row.id.clone().unwrap_or_default()
}

fn expected_principal(row: &PrincipalCase) -> Option<String> {
    match row.canonical.as_deref() {
        Some("repeat") => Some(
            row.repeat
                .clone()
                .unwrap_or_default()
                .repeat(row.count.unwrap_or(0)),
        ),
        other => other.map(str::to_string),
    }
}

#[test]
fn shared_principal_and_object_vectors() {
    let fixture: Fixture = serde_json::from_str(VECTORS).unwrap();
    for row in &fixture.principals {
        let id = principal_id(row);
        assert_eq!(acl_principal_key(&id), expected_principal(row), "{id}");
    }
    for row in &fixture.grants {
        assert_eq!(
            grant_soul(&row.owner, &row.object, &row.accessor)
                .map(|soul| soul.as_str().to_string()),
            row.soul,
            "{}",
            row.accessor
        );
    }
    for row in &fixture.objects {
        let mut graph = MeshSeeGraph::new();
        graph.put_object(&row.stored, &row.owner);
        if let Some(put) = &row.put {
            graph.put_object(put, row.put_owner.as_deref().unwrap_or(""));
        }
        if let Some(has_put) = row.has_put_id {
            assert_eq!(
                graph.has_object(row.put.as_deref().unwrap_or("")),
                has_put,
                "{}",
                row.name
            );
        }
        assert_eq!(
            graph.owner_of(&row.stored),
            Some(row.owner_after.as_str()),
            "{}",
            row.name
        );
        if let (Some(query), Some(accessor), Some(allowed)) =
            (&row.query, &row.accessor, row.allowed)
        {
            assert_eq!(
                graph
                    .check_see_label(query, accessor, Timestamp(10), None, None)
                    .allowed,
                allowed,
                "{}",
                row.name
            );
        }
    }
    for row in &fixture.null_keys {
        let mut graph = MeshSeeGraph::new();
        graph.put_object(&row.other, "0xmallory");
        graph.put_object(&row.secret, "0xalice");
        let rejected = graph.state_see_grant(
            "0xmallory",
            MeshSeeGrant::live(&row.other, &row.accessor, 0, 80),
        );
        assert!(
            matches!(rejected, Err(GunError::EmptyPrincipal)),
            "{}",
            row.accessor
        );
        assert!(graph.grant_edge(&row.secret, &row.accessor).is_none());
        assert!(graph.grant_edge(&row.other, &row.accessor).is_none());
        assert!(
            !graph
                .check_see_label(&row.secret, &row.accessor, Timestamp(10), None, None)
                .allowed
        );
    }
}
