use serde_json::Value;
use sociacl_ids::{verify_witness_checkpoint, WitnessCheckpointExpectations};

#[test]
fn actual_panopticon_checkpoint_preserves_history_and_request_binding() {
    let f: Value = serde_json::from_str(include_str!(
        "../../../vectors/interop/panopticon-checkpoint.json"
    ))
    .unwrap();
    let c = &f["expected"];
    let mut expected = WitnessCheckpointExpectations {
        management_root: c["managementRoot"].as_str().unwrap(),
        root: c["root"].as_str().unwrap(),
        root_epoch: c["rootEpoch"].as_u64().unwrap(),
        audience: c["audience"].as_str().unwrap(),
        client: c["client"].as_str().unwrap(),
        challenge: c["challenge"].as_str().unwrap(),
        minimum_revision: c["minimumRevision"].as_u64().unwrap(),
        now: c["now"].as_u64().unwrap(),
    };
    let checkpoint = f["response"]["checkpoint"].as_str().unwrap();
    let policy = f["response"]["policy"].as_str().unwrap();
    let result = verify_witness_checkpoint(checkpoint, policy, &expected).unwrap();
    assert!(result.state.history.iter().any(|entry| entry.removed));
    assert_eq!(serde_json::to_value(&result).unwrap(), f["canonical"]);
    expected.client = "another-client";
    assert!(verify_witness_checkpoint(checkpoint, policy, &expected).is_err());
    expected.client = c["client"].as_str().unwrap();
    expected.root_epoch = 2;
    assert!(verify_witness_checkpoint(checkpoint, policy, &expected).is_err());
    expected.root_epoch = 1;
    expected.challenge = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    assert!(verify_witness_checkpoint(checkpoint, policy, &expected).is_err());
    expected.challenge = c["challenge"].as_str().unwrap();
    expected.now = result.expires_at;
    assert!(verify_witness_checkpoint(checkpoint, policy, &expected).is_err());
}
