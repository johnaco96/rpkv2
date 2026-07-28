use crate::{config::GossipConfig, identity::ValidatorId, validator_set::ValidatorSet};
use anyhow::{Result, anyhow, bail};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

const DOMAIN: &[u8] = b"rpkv2.gossip.v1";
const WIRE_MAGIC: &[u8; 4] = b"RPKG";
pub const GOSSIP_VERSION: u8 = 1;
const KIND_PEER_ANNOUNCEMENT: u8 = 1;
const SIGNATURE_LEN: usize = 64;
const DEFAULT_MAX_MESSAGE_BYTES: usize = 2048;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactInfo {
    pub gossip_address: SocketAddr,
    pub transaction_ingress_address: Option<SocketAddr>,
    pub repair_address: Option<SocketAddr>,
    pub rpc_address: Option<SocketAddr>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerAnnouncement {
    pub validator_id: ValidatorId,
    pub sequence: u64,
    pub contact: ContactInfo,
    pub expires_at_unix_seconds: u64,
    pub signature: [u8; 64],
}

impl PeerAnnouncement {
    #[cfg(feature = "ed25519")]
    pub fn sign(
        validator_id: ValidatorId,
        sequence: u64,
        contact: ContactInfo,
        expires_at_unix_seconds: u64,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Self {
        use ed25519_dalek::Signer;

        let preimage = signing_preimage(&validator_id, sequence, &contact, expires_at_unix_seconds);
        let signature = signing_key.sign(&preimage).to_bytes();
        Self {
            validator_id,
            sequence,
            contact,
            expires_at_unix_seconds,
            signature,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = wire_fields(
            &self.validator_id,
            self.sequence,
            &self.contact,
            self.expires_at_unix_seconds,
        );
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        cursor.expect(WIRE_MAGIC)?;
        let version = cursor.u8()?;
        if version != GOSSIP_VERSION {
            bail!("unsupported gossip version: {version}");
        }
        let kind = cursor.u8()?;
        if kind != KIND_PEER_ANNOUNCEMENT {
            bail!("unknown gossip message kind: {kind}");
        }
        let validator_id = cursor.validator_id()?;
        let sequence = cursor.u64()?;
        let contact = ContactInfo {
            gossip_address: cursor.socket_addr()?,
            transaction_ingress_address: cursor.optional_socket_addr()?,
            repair_address: cursor.optional_socket_addr()?,
            rpc_address: cursor.optional_socket_addr()?,
        };
        let expires_at_unix_seconds = cursor.u64()?;
        let signature = cursor.signature()?;
        cursor.finish()?;
        Ok(Self {
            validator_id,
            sequence,
            contact,
            expires_at_unix_seconds,
            signature,
        })
    }

    pub fn signing_preimage(&self) -> Vec<u8> {
        signing_preimage(
            &self.validator_id,
            self.sequence,
            &self.contact,
            self.expires_at_unix_seconds,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerRecord {
    pub validator_id: ValidatorId,
    pub contact: ContactInfo,
    pub sequence: u64,
    pub expires_at_unix_seconds: u64,
    pub source: PeerSource,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerSource {
    Bootstrap,
    Gossip,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GossipMetrics {
    pub bootstrap_peers_loaded: u64,
    pub announcements_accepted: u64,
    pub announcements_expired: u64,
    pub announcements_rejected_unknown_validator: u64,
    pub announcements_rejected_invalid_signature: u64,
    pub announcements_rejected_stale_sequence: u64,
    pub announcements_rejected_oversized: u64,
}

#[derive(Clone, Debug)]
pub struct PeerTable<'a> {
    validator_set: &'a ValidatorSet,
    peers: BTreeMap<ValidatorId, PeerRecord>,
    metrics: GossipMetrics,
    max_message_bytes: usize,
}

impl<'a> PeerTable<'a> {
    pub fn from_bootstrap_config(
        config: &GossipConfig,
        validator_set: &'a ValidatorSet,
        now_unix_seconds: u64,
    ) -> Result<Self> {
        let mut table = Self::new(validator_set);
        for peer in &config.bootstrap_peers {
            let validator_id = ValidatorId::from_str(&peer.validator_id)?;
            table.ensure_known_validator(&validator_id)?;
            let expires_at_unix_seconds = now_unix_seconds.saturating_add(config.peer_ttl_seconds);
            table.peers.insert(
                validator_id.clone(),
                PeerRecord {
                    validator_id,
                    contact: ContactInfo {
                        gossip_address: peer.gossip_address,
                        transaction_ingress_address: peer.transaction_ingress_address,
                        repair_address: peer.repair_address,
                        rpc_address: peer.rpc_address,
                    },
                    sequence: 0,
                    expires_at_unix_seconds,
                    source: PeerSource::Bootstrap,
                },
            );
            table.metrics.bootstrap_peers_loaded =
                table.metrics.bootstrap_peers_loaded.saturating_add(1);
        }
        Ok(table)
    }

    pub fn new(validator_set: &'a ValidatorSet) -> Self {
        Self {
            validator_set,
            peers: BTreeMap::new(),
            metrics: GossipMetrics::default(),
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
        }
    }

    pub fn set_max_message_bytes(&mut self, max_message_bytes: usize) {
        self.max_message_bytes = max_message_bytes;
    }

    pub fn apply_encoded_announcement(
        &mut self,
        bytes: &[u8],
        now_unix_seconds: u64,
    ) -> Result<()> {
        if bytes.len() > self.max_message_bytes {
            self.metrics.announcements_rejected_oversized = self
                .metrics
                .announcements_rejected_oversized
                .saturating_add(1);
            bail!("gossip announcement exceeds max size");
        }
        let announcement = PeerAnnouncement::decode(bytes).inspect_err(|_e| {
            self.metrics.announcements_rejected_invalid_signature = self
                .metrics
                .announcements_rejected_invalid_signature
                .saturating_add(1);
        })?;
        self.apply_announcement(&announcement, now_unix_seconds)
    }

    pub fn apply_announcement(
        &mut self,
        announcement: &PeerAnnouncement,
        now_unix_seconds: u64,
    ) -> Result<()> {
        if announcement.expires_at_unix_seconds <= now_unix_seconds {
            self.metrics.announcements_expired =
                self.metrics.announcements_expired.saturating_add(1);
            bail!("gossip announcement is expired");
        }
        let validator = match self.validator_set.get(&announcement.validator_id) {
            Some(validator) => validator,
            None => {
                self.metrics.announcements_rejected_unknown_validator = self
                    .metrics
                    .announcements_rejected_unknown_validator
                    .saturating_add(1);
                bail!("gossip announcement references unknown validator");
            }
        };
        verify_signature(
            &validator.consensus_voting_key,
            &announcement.signing_preimage(),
            &announcement.signature,
        )
        .inspect_err(|_e| {
            self.metrics.announcements_rejected_invalid_signature = self
                .metrics
                .announcements_rejected_invalid_signature
                .saturating_add(1);
        })?;
        if let Some(existing) = self.peers.get(&announcement.validator_id)
            && announcement.sequence <= existing.sequence
        {
            self.metrics.announcements_rejected_stale_sequence = self
                .metrics
                .announcements_rejected_stale_sequence
                .saturating_add(1);
            bail!("gossip announcement sequence is stale");
        }
        self.peers.insert(
            announcement.validator_id.clone(),
            PeerRecord {
                validator_id: announcement.validator_id.clone(),
                contact: announcement.contact.clone(),
                sequence: announcement.sequence,
                expires_at_unix_seconds: announcement.expires_at_unix_seconds,
                source: PeerSource::Gossip,
            },
        );
        self.metrics.announcements_accepted = self.metrics.announcements_accepted.saturating_add(1);
        Ok(())
    }

    pub fn expire_stale(&mut self, now_unix_seconds: u64) -> usize {
        let before = self.peers.len();
        self.peers
            .retain(|_, peer| peer.expires_at_unix_seconds > now_unix_seconds);
        before.saturating_sub(self.peers.len())
    }

    pub fn get(&self, validator_id: &ValidatorId) -> Option<&PeerRecord> {
        self.peers.get(validator_id)
    }

    pub fn peers(&self) -> impl Iterator<Item = &PeerRecord> {
        self.peers.values()
    }

    pub fn metrics(&self) -> &GossipMetrics {
        &self.metrics
    }

    pub fn metrics_text(&self) -> String {
        format!(
            concat!(
                "rpkv2_gossip_bootstrap_peers_loaded_total {}\n",
                "rpkv2_gossip_announcements_accepted_total {}\n",
                "rpkv2_gossip_announcements_expired_total {}\n",
                "rpkv2_gossip_unknown_validator_total {}\n",
                "rpkv2_gossip_invalid_signature_total {}\n",
                "rpkv2_gossip_stale_sequence_total {}\n",
                "rpkv2_gossip_oversized_total {}\n",
                "rpkv2_gossip_peer_table_size {}\n"
            ),
            self.metrics.bootstrap_peers_loaded,
            self.metrics.announcements_accepted,
            self.metrics.announcements_expired,
            self.metrics.announcements_rejected_unknown_validator,
            self.metrics.announcements_rejected_invalid_signature,
            self.metrics.announcements_rejected_stale_sequence,
            self.metrics.announcements_rejected_oversized,
            self.peers.len()
        )
    }

    fn ensure_known_validator(&self, validator_id: &ValidatorId) -> Result<()> {
        if self.validator_set.get(validator_id).is_none() {
            bail!("bootstrap peer references unknown validator {validator_id}");
        }
        Ok(())
    }
}

pub fn current_unix_seconds() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| anyhow!("system clock is before UNIX epoch"))?
        .as_secs())
}

fn signing_preimage(
    validator_id: &ValidatorId,
    sequence: u64,
    contact: &ContactInfo,
    expires_at_unix_seconds: u64,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(DOMAIN);
    out.push(GOSSIP_VERSION);
    out.push(KIND_PEER_ANNOUNCEMENT);
    encode_validator_id(&mut out, validator_id);
    out.extend_from_slice(&sequence.to_be_bytes());
    encode_contact(&mut out, contact);
    out.extend_from_slice(&expires_at_unix_seconds.to_be_bytes());
    out
}

fn wire_fields(
    validator_id: &ValidatorId,
    sequence: u64,
    contact: &ContactInfo,
    expires_at_unix_seconds: u64,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(WIRE_MAGIC);
    out.push(GOSSIP_VERSION);
    out.push(KIND_PEER_ANNOUNCEMENT);
    encode_validator_id(&mut out, validator_id);
    out.extend_from_slice(&sequence.to_be_bytes());
    encode_contact(&mut out, contact);
    out.extend_from_slice(&expires_at_unix_seconds.to_be_bytes());
    out
}

fn encode_contact(out: &mut Vec<u8>, contact: &ContactInfo) {
    encode_socket_addr(out, contact.gossip_address);
    encode_optional_socket_addr(out, contact.transaction_ingress_address);
    encode_optional_socket_addr(out, contact.repair_address);
    encode_optional_socket_addr(out, contact.rpc_address);
}

fn encode_validator_id(out: &mut Vec<u8>, validator_id: &ValidatorId) {
    encode_string(out, validator_id.as_str());
}

fn encode_socket_addr(out: &mut Vec<u8>, address: SocketAddr) {
    encode_string(out, &address.to_string());
}

fn encode_optional_socket_addr(out: &mut Vec<u8>, address: Option<SocketAddr>) {
    match address {
        Some(address) => {
            out.push(1);
            encode_socket_addr(out, address);
        }
        None => out.push(0),
    }
}

fn encode_string(out: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    let len = u16::try_from(bytes.len()).expect("gossip string length exceeds wire format");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

#[cfg(feature = "ed25519")]
fn verify_signature(pubkey: &[u8; 32], preimage: &[u8], signature: &[u8; 64]) -> Result<()> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let key = VerifyingKey::from_bytes(pubkey)
        .map_err(|e| anyhow!("invalid gossip validator key: {e}"))?;
    let signature = Signature::from_bytes(signature);
    key.verify(preimage, &signature)
        .map_err(|e| anyhow!("invalid gossip signature: {e}"))?;
    Ok(())
}

#[cfg(not(feature = "ed25519"))]
fn verify_signature(_pubkey: &[u8; 32], _preimage: &[u8], _signature: &[u8; 64]) -> Result<()> {
    bail!("gossip verification requires the ed25519 feature")
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn expect(&mut self, expected: &[u8]) -> Result<()> {
        let actual = self.take(expected.len())?;
        if actual != expected {
            bail!("invalid gossip message magic");
        }
        Ok(())
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u64(&mut self) -> Result<u64> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes(
            bytes.try_into().expect("cursor returned exact u64 length"),
        ))
    }

    fn validator_id(&mut self) -> Result<ValidatorId> {
        ValidatorId::from_str(&self.string()?)
    }

    fn socket_addr(&mut self) -> Result<SocketAddr> {
        self.string()?
            .parse()
            .map_err(|e| anyhow!("invalid gossip socket address: {e}"))
    }

    fn optional_socket_addr(&mut self) -> Result<Option<SocketAddr>> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.socket_addr()?)),
            tag => bail!("invalid optional socket address tag: {tag}"),
        }
    }

    fn signature(&mut self) -> Result<[u8; SIGNATURE_LEN]> {
        let bytes = self.take(SIGNATURE_LEN)?;
        Ok(bytes
            .try_into()
            .expect("cursor returned exact signature length"))
    }

    fn string(&mut self) -> Result<String> {
        let len = self.u16()? as usize;
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|e| anyhow!("invalid gossip utf8 string: {e}"))
    }

    fn u16(&mut self) -> Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes(
            bytes.try_into().expect("cursor returned exact u16 length"),
        ))
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| anyhow!("gossip cursor overflow"))?;
        if end > self.bytes.len() {
            bail!("truncated gossip message");
        }
        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn finish(&self) -> Result<()> {
        if self.offset != self.bytes.len() {
            bail!("gossip message has trailing bytes");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator_set::{EpochSlot, ValidatorIdentityRecord, ValidatorSet};
    use ed25519_dalek::SigningKey;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn pubkey(key: &SigningKey) -> [u8; 32] {
        key.verifying_key().to_bytes()
    }

    fn validator_id(id: &str) -> ValidatorId {
        ValidatorId::from_str(id).unwrap()
    }

    fn validator_set(a: &SigningKey, b: &SigningKey, c: &SigningKey) -> ValidatorSet {
        let mut set = ValidatorSet::default();
        for (id, seed, key) in [
            ("validator-a", 11, a),
            ("validator-b", 12, b),
            ("validator-c", 13, c),
        ] {
            set.insert(ValidatorIdentityRecord {
                validator_id: validator_id(id),
                tls_spki_der: vec![seed],
                packet_signing_key: [seed; 32],
                consensus_voting_key: pubkey(key),
                voting_weight: 1,
                activation: EpochSlot::new(0, 0),
                deactivation: None,
            })
            .unwrap();
        }
        set
    }

    fn contact(port: u16) -> ContactInfo {
        ContactInfo {
            gossip_address: SocketAddr::from(([127, 0, 0, 1], port)),
            transaction_ingress_address: Some(SocketAddr::from(([127, 0, 0, 1], port + 1))),
            repair_address: Some(SocketAddr::from(([127, 0, 0, 1], port + 2))),
            rpc_address: None,
        }
    }

    #[test]
    fn multi_node_discovery_from_bootstrap_and_signed_gossip() {
        let key_a = key(101);
        let key_b = key(102);
        let key_c = key(103);
        let set = validator_set(&key_a, &key_b, &key_c);
        let config = GossipConfig {
            bootstrap_peers: vec![crate::config::GossipBootstrapPeerConfig {
                validator_id: "validator-b".to_string(),
                gossip_address: SocketAddr::from(([127, 0, 0, 1], 9101)),
                transaction_ingress_address: None,
                repair_address: None,
                rpc_address: None,
            }],
            peer_ttl_seconds: 30,
        };
        let mut node_a = PeerTable::from_bootstrap_config(&config, &set, 100).unwrap();
        assert!(node_a.get(&validator_id("validator-b")).is_some());

        let announcement =
            PeerAnnouncement::sign(validator_id("validator-c"), 1, contact(9200), 200, &key_c);
        node_a
            .apply_encoded_announcement(&announcement.encode(), 100)
            .unwrap();

        let discovered = node_a.get(&validator_id("validator-c")).unwrap();
        assert_eq!(
            discovered.contact.gossip_address,
            contact(9200).gossip_address
        );
        assert_eq!(discovered.source, PeerSource::Gossip);
        assert_eq!(node_a.metrics().bootstrap_peers_loaded, 1);
        assert_eq!(node_a.metrics().announcements_accepted, 1);
    }

    #[test]
    fn invalid_gossip_signature_is_rejected_and_metered() {
        let key_a = key(101);
        let key_b = key(102);
        let key_c = key(103);
        let set = validator_set(&key_a, &key_b, &key_c);
        let mut table = PeerTable::new(&set);
        let mut announcement =
            PeerAnnouncement::sign(validator_id("validator-b"), 1, contact(9200), 200, &key_c);
        announcement.signature[0] ^= 0xff;

        assert!(table.apply_announcement(&announcement, 100).is_err());
        assert_eq!(table.metrics().announcements_rejected_invalid_signature, 1);
    }

    #[test]
    fn stale_peer_expiration_removes_old_entries() {
        let key_a = key(101);
        let key_b = key(102);
        let key_c = key(103);
        let set = validator_set(&key_a, &key_b, &key_c);
        let mut table = PeerTable::new(&set);
        let announcement =
            PeerAnnouncement::sign(validator_id("validator-b"), 1, contact(9200), 120, &key_b);
        table.apply_announcement(&announcement, 100).unwrap();

        assert_eq!(table.expire_stale(121), 1);
        assert!(table.get(&validator_id("validator-b")).is_none());
    }

    #[test]
    fn unknown_stale_and_oversized_gossip_are_rejected_and_metered() {
        let key_a = key(101);
        let key_b = key(102);
        let key_c = key(103);
        let set = validator_set(&key_a, &key_b, &key_c);
        let mut table = PeerTable::new(&set);
        let first =
            PeerAnnouncement::sign(validator_id("validator-b"), 2, contact(9200), 200, &key_b);
        table.apply_announcement(&first, 100).unwrap();
        let stale =
            PeerAnnouncement::sign(validator_id("validator-b"), 1, contact(9201), 200, &key_b);
        assert!(table.apply_announcement(&stale, 100).is_err());

        let unknown =
            PeerAnnouncement::sign(validator_id("validator-z"), 1, contact(9300), 200, &key_c);
        assert!(table.apply_announcement(&unknown, 100).is_err());

        table.set_max_message_bytes(4);
        assert!(
            table
                .apply_encoded_announcement(&first.encode(), 100)
                .is_err()
        );

        assert_eq!(table.metrics().announcements_rejected_stale_sequence, 1);
        assert_eq!(table.metrics().announcements_rejected_unknown_validator, 1);
        assert_eq!(table.metrics().announcements_rejected_oversized, 1);
        assert!(
            table
                .metrics_text()
                .contains("rpkv2_gossip_oversized_total 1")
        );
    }
}
