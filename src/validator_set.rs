use crate::identity::{ValidatorId, parse_hex_32};
use anyhow::{Result, anyhow, bail};
use serde::Deserialize;
use std::{collections::BTreeMap, str::FromStr};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct EpochSlot {
    pub epoch: u64,
    pub slot: u64,
}

impl EpochSlot {
    pub const fn new(epoch: u64, slot: u64) -> Self {
        Self { epoch, slot }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorIdentityRecord {
    pub validator_id: ValidatorId,
    pub tls_spki_der: Vec<u8>,
    pub packet_signing_key: [u8; 32],
    pub consensus_voting_key: [u8; 32],
    pub voting_weight: u64,
    pub activation: EpochSlot,
    pub deactivation: Option<EpochSlot>,
}

impl ValidatorIdentityRecord {
    pub fn is_active_at(&self, at: EpochSlot) -> bool {
        at >= self.activation
            && self
                .deactivation
                .is_none_or(|deactivation| at < deactivation)
    }

    fn from_config(config: ValidatorIdentityConfig) -> Result<Self> {
        let validator_id = ValidatorId::from_str(&config.validator_id)?;
        if config.voting_weight == 0 {
            bail!("validator {validator_id} voting_weight must be greater than zero");
        }

        let tls_spki_der = parse_hex_bytes("tls_spki_hex", &config.tls_spki_hex)?;
        if tls_spki_der.is_empty() {
            bail!("validator {validator_id} tls_spki_hex must not be empty");
        }

        let packet_signing_key = parse_hex_32(&config.packet_signing_key_hex)
            .map_err(|e| anyhow!("validator {validator_id} packet_signing_key_hex: {e}"))?;
        validate_ed25519_verify_key(&validator_id, "packet_signing_key_hex", &packet_signing_key)?;

        let consensus_voting_key = parse_hex_32(&config.consensus_voting_key_hex)
            .map_err(|e| anyhow!("validator {validator_id} consensus_voting_key_hex: {e}"))?;
        validate_ed25519_verify_key(
            &validator_id,
            "consensus_voting_key_hex",
            &consensus_voting_key,
        )?;

        let deactivation = match (config.deactivation_epoch, config.deactivation_slot) {
            (Some(epoch), Some(slot)) => Some(EpochSlot::new(epoch, slot)),
            (None, None) => None,
            _ => bail!(
                "validator {validator_id} deactivation_epoch and deactivation_slot must be set together"
            ),
        };
        let activation = EpochSlot::new(config.activation_epoch, config.activation_slot);
        if let Some(deactivation) = deactivation
            && activation >= deactivation
        {
            bail!("validator {validator_id} activation must be before deactivation");
        }

        Ok(Self {
            validator_id,
            tls_spki_der,
            packet_signing_key,
            consensus_voting_key,
            voting_weight: config.voting_weight,
            activation,
            deactivation,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct ValidatorSet {
    validators: BTreeMap<ValidatorId, ValidatorIdentityRecord>,
    tls_spki_to_validator: BTreeMap<Vec<u8>, ValidatorId>,
    packet_key_to_validator: BTreeMap<[u8; 32], ValidatorId>,
    consensus_key_to_validator: BTreeMap<[u8; 32], ValidatorId>,
}

impl ValidatorSet {
    pub fn from_toml_str(text: &str) -> Result<Self> {
        let config: ValidatorSetConfig = toml::from_str(text)?;
        Self::from_config(config)
    }

    pub fn from_config(config: ValidatorSetConfig) -> Result<Self> {
        let mut set = Self::default();
        for validator in config.validators {
            set.insert(ValidatorIdentityRecord::from_config(validator)?)?;
        }
        if set.is_empty() {
            bail!("validator set must contain at least one validator");
        }
        Ok(set)
    }

    pub fn insert(&mut self, record: ValidatorIdentityRecord) -> Result<()> {
        if self.validators.contains_key(&record.validator_id) {
            bail!("duplicate validator id: {}", record.validator_id);
        }
        if let Some(existing) = self.tls_spki_to_validator.get(&record.tls_spki_der) {
            bail!(
                "duplicate TLS SPKI for validators {} and {}",
                existing,
                record.validator_id
            );
        }
        if let Some(existing) = self.packet_key_to_validator.get(&record.packet_signing_key) {
            bail!(
                "duplicate packet signing key for validators {} and {}",
                existing,
                record.validator_id
            );
        }
        if let Some(existing) = self
            .consensus_key_to_validator
            .get(&record.packet_signing_key)
        {
            bail!(
                "packet signing key for validator {} is already used as consensus voting key for validator {}",
                record.validator_id,
                existing
            );
        }
        if let Some(existing) = self
            .consensus_key_to_validator
            .get(&record.consensus_voting_key)
        {
            bail!(
                "duplicate consensus voting key for validators {} and {}",
                existing,
                record.validator_id
            );
        }
        if let Some(existing) = self
            .packet_key_to_validator
            .get(&record.consensus_voting_key)
        {
            bail!(
                "consensus voting key for validator {} is already used as packet signing key for validator {}",
                record.validator_id,
                existing
            );
        }

        self.tls_spki_to_validator
            .insert(record.tls_spki_der.clone(), record.validator_id.clone());
        self.packet_key_to_validator
            .insert(record.packet_signing_key, record.validator_id.clone());
        self.consensus_key_to_validator
            .insert(record.consensus_voting_key, record.validator_id.clone());
        self.validators.insert(record.validator_id.clone(), record);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.validators.len()
    }

    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    pub fn get(&self, validator_id: &ValidatorId) -> Option<&ValidatorIdentityRecord> {
        self.validators.get(validator_id)
    }

    pub fn validator_ids(&self) -> impl Iterator<Item = &ValidatorId> {
        self.validators.keys()
    }

    pub fn validators(&self) -> impl Iterator<Item = &ValidatorIdentityRecord> {
        self.validators.values()
    }

    pub fn active_at(&self, at: EpochSlot) -> impl Iterator<Item = &ValidatorIdentityRecord> + '_ {
        self.validators
            .values()
            .filter(move |validator| validator.is_active_at(at))
    }

    pub fn is_active(&self, validator_id: &ValidatorId, at: EpochSlot) -> bool {
        self.get(validator_id)
            .is_some_and(|validator| validator.is_active_at(at))
    }

    pub fn can_produce(&self, validator_id: &ValidatorId, at: EpochSlot) -> bool {
        self.is_active(validator_id, at)
    }

    pub fn can_vote(&self, validator_id: &ValidatorId, at: EpochSlot) -> bool {
        self.is_active(validator_id, at)
    }

    pub fn voting_weight(&self, validator_id: &ValidatorId, at: EpochSlot) -> Option<u64> {
        self.get(validator_id)
            .filter(|validator| validator.is_active_at(at))
            .map(|validator| validator.voting_weight)
    }

    pub fn total_active_weight(&self, at: EpochSlot) -> u64 {
        self.active_at(at)
            .map(|validator| validator.voting_weight)
            .sum()
    }

    pub fn resolve_tls_spki(&self, spki_der: &[u8]) -> Option<&ValidatorId> {
        self.tls_spki_to_validator.get(spki_der)
    }

    pub fn resolve_packet_signing_key(&self, key: &[u8; 32]) -> Option<&ValidatorId> {
        self.packet_key_to_validator.get(key)
    }

    pub fn resolve_consensus_voting_key(&self, key: &[u8; 32]) -> Option<&ValidatorId> {
        self.consensus_key_to_validator.get(key)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorSetConfig {
    pub validators: Vec<ValidatorIdentityConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorIdentityConfig {
    pub validator_id: String,
    pub tls_spki_hex: String,
    pub packet_signing_key_hex: String,
    pub consensus_voting_key_hex: String,
    pub voting_weight: u64,
    pub activation_epoch: u64,
    pub activation_slot: u64,
    pub deactivation_epoch: Option<u64>,
    pub deactivation_slot: Option<u64>,
}

fn parse_hex_bytes(field: &str, value: &str) -> Result<Vec<u8>> {
    crate::hex_utils::decode(field, value)
}

fn validate_ed25519_verify_key(
    validator_id: &ValidatorId,
    field: &str,
    key: &[u8; 32],
) -> Result<()> {
    #[cfg(feature = "ed25519")]
    {
        ed25519_dalek::VerifyingKey::from_bytes(key).map_err(|e| {
            anyhow!("validator {validator_id} {field} is not a valid Ed25519 key: {e}")
        })?;
    }
    #[cfg(not(feature = "ed25519"))]
    {
        let _ = (validator_id, field, key);
    }
    Ok(())
}

#[cfg(all(test, feature = "ed25519"))]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

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
            activation_slot: 10,
            deactivation_epoch: None,
            deactivation_slot: None,
        }
    }

    fn validator_id(id: &str) -> ValidatorId {
        ValidatorId::from_str(id).unwrap()
    }

    #[test]
    fn loads_deterministic_validator_order_from_unsorted_config() {
        let set = ValidatorSet::from_config(ValidatorSetConfig {
            validators: vec![
                validator_config("validator-b", 2, 20),
                validator_config("validator-a", 1, 10),
            ],
        })
        .unwrap();

        let ids: Vec<_> = set
            .validator_ids()
            .map(|validator_id| validator_id.as_str())
            .collect();
        assert_eq!(ids, vec!["validator-a", "validator-b"]);
    }

    #[test]
    fn loads_from_toml() {
        let text = format!(
            r#"
[[validators]]
validator_id = "validator-a"
tls_spki_hex = "{}"
packet_signing_key_hex = "{}"
consensus_voting_key_hex = "{}"
voting_weight = 10
activation_epoch = 0
activation_slot = 1
"#,
            hex(b"validator-a-spki"),
            verify_key_hex(1),
            verify_key_hex(101)
        );

        let set = ValidatorSet::from_toml_str(&text).unwrap();

        assert_eq!(set.len(), 1);
        assert!(set.can_vote(&validator_id("validator-a"), EpochSlot::new(0, 1)));
    }

    #[test]
    fn unknown_validator_cannot_produce_or_vote() {
        let set = ValidatorSet::from_config(ValidatorSetConfig {
            validators: vec![validator_config("validator-a", 1, 10)],
        })
        .unwrap();

        let unknown = validator_id("unknown");
        let at = EpochSlot::new(0, 10);

        assert!(!set.can_produce(&unknown, at));
        assert!(!set.can_vote(&unknown, at));
        assert_eq!(set.voting_weight(&unknown, at), None);
    }

    #[test]
    fn activation_and_deactivation_boundaries_are_enforced() {
        let mut config = validator_config("validator-a", 1, 10);
        config.activation_epoch = 1;
        config.activation_slot = 5;
        config.deactivation_epoch = Some(2);
        config.deactivation_slot = Some(0);
        let set = ValidatorSet::from_config(ValidatorSetConfig {
            validators: vec![config],
        })
        .unwrap();
        let id = validator_id("validator-a");

        assert!(!set.is_active(&id, EpochSlot::new(1, 4)));
        assert!(set.is_active(&id, EpochSlot::new(1, 5)));
        assert!(set.is_active(&id, EpochSlot::new(1, 999)));
        assert!(!set.is_active(&id, EpochSlot::new(2, 0)));
    }

    #[test]
    fn rejects_duplicate_validator_id() {
        let result = ValidatorSet::from_config(ValidatorSetConfig {
            validators: vec![
                validator_config("validator-a", 1, 10),
                validator_config("validator-a", 2, 20),
            ],
        });

        assert!(result.is_err());
    }

    #[test]
    fn rejects_duplicate_tls_spki() {
        let mut second = validator_config("validator-b", 2, 20);
        second.tls_spki_hex = hex(b"validator-a-spki");

        let result = ValidatorSet::from_config(ValidatorSetConfig {
            validators: vec![validator_config("validator-a", 1, 10), second],
        });

        assert!(result.is_err());
    }

    #[test]
    fn rejects_duplicate_packet_signing_key() {
        let mut second = validator_config("validator-b", 2, 20);
        second.packet_signing_key_hex = verify_key_hex(1);

        let result = ValidatorSet::from_config(ValidatorSetConfig {
            validators: vec![validator_config("validator-a", 1, 10), second],
        });

        assert!(result.is_err());
    }

    #[test]
    fn rejects_duplicate_consensus_voting_key() {
        let mut second = validator_config("validator-b", 2, 20);
        second.consensus_voting_key_hex = verify_key_hex(101);

        let result = ValidatorSet::from_config(ValidatorSetConfig {
            validators: vec![validator_config("validator-a", 1, 10), second],
        });

        assert!(result.is_err());
    }

    #[test]
    fn rejects_packet_and_consensus_key_reuse() {
        let mut second = validator_config("validator-b", 2, 20);
        second.consensus_voting_key_hex = verify_key_hex(1);

        let result = ValidatorSet::from_config(ValidatorSetConfig {
            validators: vec![validator_config("validator-a", 1, 10), second],
        });

        assert!(result.is_err());
    }

    #[test]
    fn active_weights_are_exposed_for_multiple_validators() {
        let set = ValidatorSet::from_config(ValidatorSetConfig {
            validators: vec![
                validator_config("validator-b", 2, 30),
                validator_config("validator-a", 1, 10),
            ],
        })
        .unwrap();
        let at = EpochSlot::new(0, 10);

        assert_eq!(
            set.voting_weight(&validator_id("validator-a"), at),
            Some(10)
        );
        assert_eq!(
            set.voting_weight(&validator_id("validator-b"), at),
            Some(30)
        );
        assert_eq!(set.total_active_weight(at), 40);
    }

    #[test]
    fn resolves_keys_to_validator_id() {
        let config = validator_config("validator-a", 1, 10);
        let spki = parse_hex_bytes("tls_spki_hex", &config.tls_spki_hex).unwrap();
        let packet_key = parse_hex_32(&config.packet_signing_key_hex).unwrap();
        let vote_key = parse_hex_32(&config.consensus_voting_key_hex).unwrap();
        let set = ValidatorSet::from_config(ValidatorSetConfig {
            validators: vec![config],
        })
        .unwrap();
        let id = validator_id("validator-a");

        assert_eq!(set.resolve_tls_spki(&spki), Some(&id));
        assert_eq!(set.resolve_packet_signing_key(&packet_key), Some(&id));
        assert_eq!(set.resolve_consensus_voting_key(&vote_key), Some(&id));
    }
}
