use rpkv2::{
    identity::ValidatorId,
    leader_schedule::{LeaderSchedule, ProductionKind},
    validator_set::{EpochSlot, ValidatorSet},
};
use std::str::FromStr;

#[path = "common/validator_fixtures.rs"]
mod validator_fixtures;
use validator_fixtures::{hex, verify_key_hex};

fn fixture_genesis() -> String {
    format!(
        r#"
[[validators]]
validator_id = "validator-c"
tls_spki_hex = "{}"
packet_signing_key_hex = "{}"
consensus_voting_key_hex = "{}"
voting_weight = 5
activation_epoch = 1
activation_slot = 0

[[validators]]
validator_id = "validator-a"
tls_spki_hex = "{}"
packet_signing_key_hex = "{}"
consensus_voting_key_hex = "{}"
voting_weight = 1
activation_epoch = 0
activation_slot = 0

[[validators]]
validator_id = "validator-b"
tls_spki_hex = "{}"
packet_signing_key_hex = "{}"
consensus_voting_key_hex = "{}"
voting_weight = 3
activation_epoch = 0
activation_slot = 0
deactivation_epoch = 2
deactivation_slot = 0
"#,
        hex(b"validator-c-spki"),
        verify_key_hex(3),
        verify_key_hex(103),
        hex(b"validator-a-spki"),
        verify_key_hex(1),
        verify_key_hex(101),
        hex(b"validator-b-spki"),
        verify_key_hex(2),
        verify_key_hex(102),
    )
}

#[test]
fn same_genesis_fixture_produces_same_leaders_on_two_nodes() {
    let genesis = fixture_genesis();
    let node_a_set = ValidatorSet::from_toml_str(&genesis).unwrap();
    let node_b_set = ValidatorSet::from_toml_str(&genesis).unwrap();
    let node_a_schedule = LeaderSchedule::new(&node_a_set);
    let node_b_schedule = LeaderSchedule::new(&node_b_set);

    for epoch in 0..3 {
        for slot in 0..16 {
            let at = EpochSlot::new(epoch, slot);
            let node_a_leader = node_a_schedule.leader_id_for_slot(at).unwrap();
            let node_b_leader = node_b_schedule.leader_id_for_slot(at).unwrap();
            assert_eq!(node_a_leader, node_b_leader);
        }
    }
}

#[test]
fn non_leader_proposal_is_rejected_from_fixture_schedule() {
    let genesis = fixture_genesis();
    let set = ValidatorSet::from_toml_str(&genesis).unwrap();
    let schedule = LeaderSchedule::new(&set);
    let non_leader = ValidatorId::from_str("validator-b").unwrap();

    let result =
        schedule.authorize_production(&non_leader, EpochSlot::new(0, 0), ProductionKind::Block);

    assert!(result.is_err());
}
