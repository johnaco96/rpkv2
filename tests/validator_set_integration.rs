use rpkv2::{
    identity::ValidatorId,
    validator_set::{EpochSlot, ValidatorSet},
};
use std::str::FromStr;

#[path = "common/validator_fixtures.rs"]
mod validator_fixtures;
use validator_fixtures::{hex, verify_key_hex};

#[test]
fn multiple_validator_weights_and_activation_are_deterministic() {
    let text = format!(
        r#"
[[validators]]
validator_id = "validator-b"
tls_spki_hex = "{}"
packet_signing_key_hex = "{}"
consensus_voting_key_hex = "{}"
voting_weight = 30
activation_epoch = 0
activation_slot = 10

[[validators]]
validator_id = "validator-a"
tls_spki_hex = "{}"
packet_signing_key_hex = "{}"
consensus_voting_key_hex = "{}"
voting_weight = 10
activation_epoch = 0
activation_slot = 5
deactivation_epoch = 1
deactivation_slot = 0
"#,
        hex(b"validator-b-spki"),
        verify_key_hex(2),
        verify_key_hex(102),
        hex(b"validator-a-spki"),
        verify_key_hex(1),
        verify_key_hex(101),
    );

    let set = ValidatorSet::from_toml_str(&text).unwrap();
    let validator_a = ValidatorId::from_str("validator-a").unwrap();
    let validator_b = ValidatorId::from_str("validator-b").unwrap();
    let unknown = ValidatorId::from_str("unknown").unwrap();

    let ids: Vec<_> = set
        .validator_ids()
        .map(|validator_id| validator_id.as_str())
        .collect();
    assert_eq!(ids, vec!["validator-a", "validator-b"]);

    assert!(set.can_vote(&validator_a, EpochSlot::new(0, 5)));
    assert!(!set.can_vote(&validator_b, EpochSlot::new(0, 5)));
    assert_eq!(set.total_active_weight(EpochSlot::new(0, 5)), 10);

    assert!(set.can_produce(&validator_b, EpochSlot::new(0, 10)));
    assert_eq!(
        set.voting_weight(&validator_a, EpochSlot::new(0, 10)),
        Some(10)
    );
    assert_eq!(
        set.voting_weight(&validator_b, EpochSlot::new(0, 10)),
        Some(30)
    );
    assert_eq!(set.total_active_weight(EpochSlot::new(0, 10)), 40);

    assert!(!set.can_vote(&validator_a, EpochSlot::new(1, 0)));
    assert_eq!(set.total_active_weight(EpochSlot::new(1, 0)), 30);
    assert!(!set.can_produce(&unknown, EpochSlot::new(0, 10)));
}
