use crate::{
    identity::ValidatorId,
    metrics,
    validator_set::{EpochSlot, ValidatorIdentityRecord, ValidatorSet},
};
use anyhow::{Result, bail};
use std::fmt;

const EPOCH_MIXER: u64 = 1_000_000_007;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProductionKind {
    Block,
    Shred,
}

impl fmt::Display for ProductionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Block => f.write_str("block"),
            Self::Shred => f.write_str("shred"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct LeaderSchedule<'a> {
    validator_set: &'a ValidatorSet,
}

impl<'a> LeaderSchedule<'a> {
    pub const fn new(validator_set: &'a ValidatorSet) -> Self {
        Self { validator_set }
    }

    pub fn leader_for_slot(&self, at: EpochSlot) -> Result<&'a ValidatorIdentityRecord> {
        let active: Vec<_> = self.validator_set.active_at(at).collect();
        if active.is_empty() {
            bail!(
                "no active validators at epoch {} slot {}",
                at.epoch,
                at.slot
            );
        }

        let total_weight = active.iter().try_fold(0u64, |total, validator| {
            total
                .checked_add(validator.voting_weight)
                .ok_or_else(|| anyhow::anyhow!("active validator voting weight overflow"))
        })?;
        let mut offset = schedule_index(at) % total_weight;
        for validator in active {
            if offset < validator.voting_weight {
                return Ok(validator);
            }
            offset -= validator.voting_weight;
        }

        unreachable!("leader selection offset is bounded by total active weight")
    }

    pub fn leader_id_for_slot(&self, at: EpochSlot) -> Result<&'a ValidatorId> {
        Ok(&self.leader_for_slot(at)?.validator_id)
    }

    pub fn is_leader(&self, validator_id: &ValidatorId, at: EpochSlot) -> Result<bool> {
        Ok(self.leader_id_for_slot(at)? == validator_id)
    }

    pub fn authorize_production(
        &self,
        validator_id: &ValidatorId,
        at: EpochSlot,
        kind: ProductionKind,
    ) -> Result<()> {
        let leader = self.leader_id_for_slot(at)?;
        if leader == validator_id {
            return Ok(());
        }

        metrics::global().record_non_leader_production_rejection();
        bail!(
            "rejecting {kind} production from non-leader {validator_id} at epoch {} slot {}; expected leader {leader}",
            at.epoch,
            at.slot
        );
    }
}

fn schedule_index(at: EpochSlot) -> u64 {
    at.epoch.wrapping_mul(EPOCH_MIXER).wrapping_add(at.slot)
}

#[cfg(all(test, feature = "ed25519"))]
mod tests {
    use super::*;
    use crate::validator_set::{ValidatorIdentityConfig, ValidatorSetConfig};
    use ed25519_dalek::SigningKey;
    use std::str::FromStr;

    fn hex(bytes: &[u8]) -> String {
        crate::test_support::hex(bytes)
    }

    fn verify_key_hex(seed: u8) -> String {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        hex(&signing_key.verifying_key().to_bytes())
    }

    fn validator_config(id: &str, seed: u8, weight: u64) -> ValidatorIdentityConfig {
        ValidatorIdentityConfig {
            validator_id: id.to_string(),
            tls_spki_hex: hex(format!("{id}-spki").as_bytes()),
            packet_signing_key_hex: verify_key_hex(seed),
            consensus_voting_key_hex: verify_key_hex(seed + 100),
            voting_weight: weight,
            activation_epoch: 0,
            activation_slot: 0,
            deactivation_epoch: None,
            deactivation_slot: None,
        }
    }

    fn validator_set() -> ValidatorSet {
        ValidatorSet::from_config(ValidatorSetConfig {
            validators: vec![
                validator_config("validator-b", 2, 3),
                validator_config("validator-a", 1, 1),
            ],
        })
        .unwrap()
    }

    fn validator_id(id: &str) -> ValidatorId {
        ValidatorId::from_str(id).unwrap()
    }

    #[test]
    fn weighted_schedule_is_deterministic() {
        let set = validator_set();
        let schedule = LeaderSchedule::new(&set);

        let leaders: Vec<_> = (0..8)
            .map(|slot| {
                schedule
                    .leader_id_for_slot(EpochSlot::new(0, slot))
                    .unwrap()
                    .as_str()
                    .to_string()
            })
            .collect();

        assert_eq!(
            leaders,
            vec![
                "validator-a",
                "validator-b",
                "validator-b",
                "validator-b",
                "validator-a",
                "validator-b",
                "validator-b",
                "validator-b"
            ]
        );
    }

    #[test]
    fn schedule_changes_at_activation_boundary() {
        let mut late = validator_config("validator-b", 2, 3);
        late.activation_slot = 3;
        let set = ValidatorSet::from_config(ValidatorSetConfig {
            validators: vec![validator_config("validator-a", 1, 1), late],
        })
        .unwrap();
        let schedule = LeaderSchedule::new(&set);

        assert_eq!(
            schedule
                .leader_id_for_slot(EpochSlot::new(0, 2))
                .unwrap()
                .as_str(),
            "validator-a"
        );
        assert_eq!(
            schedule
                .leader_id_for_slot(EpochSlot::new(0, 3))
                .unwrap()
                .as_str(),
            "validator-b"
        );
    }

    #[test]
    fn non_leader_block_production_is_rejected_and_metered() {
        let set = validator_set();
        let schedule = LeaderSchedule::new(&set);
        let non_leader = validator_id("validator-b");
        let before = non_leader_rejections();

        let result =
            schedule.authorize_production(&non_leader, EpochSlot::new(0, 0), ProductionKind::Block);

        assert!(result.is_err());
        assert_eq!(non_leader_rejections(), before + 1);
    }

    #[test]
    fn non_leader_shred_production_is_rejected() {
        let set = validator_set();
        let schedule = LeaderSchedule::new(&set);
        let non_leader = validator_id("validator-b");

        let result =
            schedule.authorize_production(&non_leader, EpochSlot::new(0, 0), ProductionKind::Shred);

        assert!(result.is_err());
    }

    #[test]
    fn leader_block_and_shred_production_are_allowed() {
        let set = validator_set();
        let schedule = LeaderSchedule::new(&set);
        let leader = validator_id("validator-a");

        schedule
            .authorize_production(&leader, EpochSlot::new(0, 0), ProductionKind::Block)
            .unwrap();
        schedule
            .authorize_production(&leader, EpochSlot::new(0, 0), ProductionKind::Shred)
            .unwrap();
    }

    #[test]
    fn no_active_validator_returns_error() {
        let mut future = validator_config("validator-a", 1, 1);
        future.activation_epoch = 1;
        let set = ValidatorSet::from_config(ValidatorSetConfig {
            validators: vec![future],
        })
        .unwrap();
        let schedule = LeaderSchedule::new(&set);

        assert!(schedule.leader_for_slot(EpochSlot::new(0, 0)).is_err());
    }

    fn non_leader_rejections() -> u64 {
        metrics::global()
            .render_text(&[], None)
            .lines()
            .find_map(|line| {
                line.strip_prefix("rpkv2_non_leader_production_rejections_total ")
                    .and_then(|value| value.parse().ok())
            })
            .unwrap()
    }
}
