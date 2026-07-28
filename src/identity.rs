use crate::{config::ProductionConfig, tls};
use anyhow::{Result, anyhow, bail};
use std::{
    collections::{HashMap, HashSet},
    fmt,
    net::SocketAddr,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ValidatorId(String);

impl ValidatorId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ValidatorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for ValidatorId {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            bail!("validator id must not be empty");
        }
        Ok(Self(trimmed.to_string()))
    }
}

#[derive(Clone, Debug)]
pub struct PeerIdentity {
    pub validator_id: ValidatorId,
    pub tls_spki_ders: Vec<Vec<u8>>,
    pub packet_verify_key: [u8; 32],
    pub expected_address: Option<SocketAddr>,
}

#[derive(Clone, Debug, Default)]
pub struct PeerRegistry {
    peers: HashMap<ValidatorId, PeerIdentity>,
    spki_to_validator: HashMap<Vec<u8>, ValidatorId>,
}

impl PeerRegistry {
    pub fn from_config(config: &ProductionConfig) -> Result<Self> {
        Self::from_config_at(config, current_unix_seconds()?)
    }

    pub fn from_config_at(config: &ProductionConfig, now_unix_seconds: u64) -> Result<Self> {
        let mut registry = Self::default();
        for peer in &config.peers {
            let validator_id = ValidatorId::from_str(&peer.validator_id)?;
            let mut revoked_spkis = HashSet::new();
            for path in &peer.revoked_spki_pin_paths {
                revoked_spkis.insert(load_spki(path)?);
            }
            let mut tls_spki_ders = Vec::new();
            if let Some(path) = &peer.spki_pin_path {
                let spki = load_spki(path)?;
                ensure_not_revoked(&validator_id, &spki, &revoked_spkis)?;
                tls_spki_ders.push(spki);
            }
            for pin in &peer.tls_spki_pins {
                validate_window(
                    &validator_id,
                    pin.valid_from_unix_seconds,
                    pin.valid_until_unix_seconds,
                )?;
                let spki = load_spki(&pin.path)?;
                ensure_not_revoked(&validator_id, &spki, &revoked_spkis)?;
                if is_active(
                    now_unix_seconds,
                    pin.valid_from_unix_seconds,
                    pin.valid_until_unix_seconds,
                ) {
                    tls_spki_ders.push(spki);
                }
            }
            if tls_spki_ders.is_empty() {
                bail!("validator {validator_id} has no active TLS SPKI pins");
            }
            let packet_verify_key = parse_hex_32(&peer.ed25519_verify_key_hex)?;
            registry.insert(PeerIdentity {
                validator_id,
                tls_spki_ders,
                packet_verify_key,
                expected_address: peer.address,
            })?;
        }
        Ok(registry)
    }

    pub fn insert(&mut self, peer: PeerIdentity) -> Result<()> {
        if self.peers.contains_key(&peer.validator_id) {
            bail!("duplicate peer validator id: {}", peer.validator_id);
        }
        let mut peer_spkis = HashSet::new();
        for spki in &peer.tls_spki_ders {
            if !peer_spkis.insert(spki) {
                bail!("duplicate TLS SPKI pin for validator {}", peer.validator_id);
            }
            if let Some(existing) = self.spki_to_validator.get(spki) {
                bail!(
                    "duplicate TLS SPKI pin for validators {} and {}",
                    existing,
                    peer.validator_id
                );
            }
        }
        for spki in &peer.tls_spki_ders {
            self.spki_to_validator
                .insert(spki.clone(), peer.validator_id.clone());
        }
        self.peers.insert(peer.validator_id.clone(), peer);
        Ok(())
    }

    pub fn get(&self, validator_id: &ValidatorId) -> Option<&PeerIdentity> {
        self.peers.get(validator_id)
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    pub fn expected_tls_spki(&self, validator_id: &ValidatorId) -> Result<Vec<u8>> {
        self.active_tls_spkis(validator_id)?
            .first()
            .cloned()
            .ok_or_else(|| anyhow!("validator {validator_id} has no active TLS SPKI pins"))
    }

    pub fn active_tls_spkis(&self, validator_id: &ValidatorId) -> Result<Vec<Vec<u8>>> {
        self.get(validator_id)
            .map(|peer| peer.tls_spki_ders.clone())
            .ok_or_else(|| anyhow!("unknown peer validator id: {validator_id}"))
    }

    pub fn resolve_tls_spki(&self, spki_der: &[u8]) -> Option<&ValidatorId> {
        self.spki_to_validator.get(spki_der)
    }
}

fn current_unix_seconds() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| anyhow!("system clock is before UNIX epoch"))?
        .as_secs())
}

fn load_spki(path: &std::path::Path) -> Result<Vec<u8>> {
    tls::load_spki_from_pem(
        path.to_str()
            .ok_or_else(|| anyhow!("peer SPKI path is not valid UTF-8"))?,
    )
}

fn ensure_not_revoked(
    validator_id: &ValidatorId,
    spki: &[u8],
    revoked_spkis: &HashSet<Vec<u8>>,
) -> Result<()> {
    if revoked_spkis.contains(spki) {
        bail!("validator {validator_id} has a revoked TLS SPKI configured as active");
    }
    Ok(())
}

fn validate_window(
    validator_id: &ValidatorId,
    valid_from: Option<u64>,
    valid_until: Option<u64>,
) -> Result<()> {
    if let (Some(from), Some(until)) = (valid_from, valid_until)
        && from >= until
    {
        bail!(
            "validator {validator_id} has invalid TLS SPKI window: valid_from_unix_seconds must be before valid_until_unix_seconds"
        );
    }
    Ok(())
}

fn is_active(now: u64, valid_from: Option<u64>, valid_until: Option<u64>) -> bool {
    valid_from.is_none_or(|from| now >= from) && valid_until.is_none_or(|until| now < until)
}

pub fn parse_hex_32(hex: &str) -> Result<[u8; 32]> {
    if hex.len() != 64 {
        bail!("Ed25519 verify key must be 64 lowercase/uppercase hex characters");
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let start = i * 2;
        *byte = u8::from_str_radix(&hex[start..start + 2], 16)
            .map_err(|_| anyhow!("Ed25519 verify key contains non-hex characters"))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(id: &str, spki: &[u8]) -> PeerIdentity {
        PeerIdentity {
            validator_id: ValidatorId::from_str(id).unwrap(),
            tls_spki_ders: vec![spki.to_vec()],
            packet_verify_key: [7u8; 32],
            expected_address: None,
        }
    }

    #[test]
    fn registry_resolves_known_identity() {
        let mut registry = PeerRegistry::default();
        registry.insert(peer("validator-a", b"spki-a")).unwrap();
        let id = ValidatorId::from_str("validator-a").unwrap();

        assert_eq!(registry.expected_tls_spki(&id).unwrap(), b"spki-a");
        assert_eq!(registry.resolve_tls_spki(b"spki-a"), Some(&id));
    }

    #[test]
    fn unknown_identity_fails() {
        let registry = PeerRegistry::default();
        let id = ValidatorId::from_str("unknown").unwrap();

        assert!(registry.expected_tls_spki(&id).is_err());
        assert!(registry.resolve_tls_spki(b"unknown-spki").is_none());
    }

    #[test]
    fn duplicate_validator_id_fails() {
        let mut registry = PeerRegistry::default();
        registry.insert(peer("validator-a", b"spki-a")).unwrap();

        assert!(registry.insert(peer("validator-a", b"spki-b")).is_err());
    }

    #[test]
    fn duplicate_spki_fails() {
        let mut registry = PeerRegistry::default();
        registry.insert(peer("validator-a", b"same-spki")).unwrap();

        assert!(registry.insert(peer("validator-b", b"same-spki")).is_err());
    }

    #[test]
    fn multiple_active_spkis_resolve_same_validator() {
        let mut registry = PeerRegistry::default();
        registry
            .insert(PeerIdentity {
                validator_id: ValidatorId::from_str("validator-a").unwrap(),
                tls_spki_ders: vec![b"old-spki".to_vec(), b"new-spki".to_vec()],
                packet_verify_key: [7u8; 32],
                expected_address: None,
            })
            .unwrap();
        let id = ValidatorId::from_str("validator-a").unwrap();

        assert_eq!(registry.resolve_tls_spki(b"old-spki"), Some(&id));
        assert_eq!(registry.resolve_tls_spki(b"new-spki"), Some(&id));
    }

    #[test]
    fn duplicate_spki_for_same_validator_fails() {
        let mut registry = PeerRegistry::default();

        assert!(
            registry
                .insert(PeerIdentity {
                    validator_id: ValidatorId::from_str("validator-a").unwrap(),
                    tls_spki_ders: vec![b"same-spki".to_vec(), b"same-spki".to_vec()],
                    packet_verify_key: [7u8; 32],
                    expected_address: None,
                })
                .is_err()
        );
    }
}
