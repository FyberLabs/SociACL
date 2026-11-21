use std::env::var;

pub fn require_infra_nightly() {
    assert_eq!(var("GITHUB_ACTIONS").as_deref(), Ok("true"));
    assert_eq!(
        var("GITHUB_WORKFLOW_REF").as_deref(),
        Ok("FyberLabs/infra/.github/workflows/nightly-integration.yml@refs/heads/main")
    );
    assert_eq!(var("GITHUB_REPOSITORY").as_deref(), Ok("FyberLabs/SociACL"));
    assert_eq!(var("NIGHTLY_SUITE").as_deref(), Ok("sociacl-browser"));
    match var("GITHUB_EVENT_NAME").as_deref() {
        Ok("schedule") => {}
        Ok("workflow_dispatch") => {
            assert_eq!(var("GITHUB_ACTOR").as_deref(), Ok("cchamilt"));
            assert_eq!(var("GITHUB_TRIGGERING_ACTOR").as_deref(), Ok("cchamilt"));
        }
        _ => panic!("Integration execution requires the central Infra nightly batch"),
    }
}
