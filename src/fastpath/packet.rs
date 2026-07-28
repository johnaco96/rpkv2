use anyhow::{Result, anyhow, bail};
use bloomfilter::Bloom;
use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

pub const SIGNING_DOMAIN: &[u8] = b"rpkv2.validator_packet.v1";
pub const SIGNING_CLUSTER_ID: &[u8] = b"rpkv2.localnet";
pub const PACKET_VERSION: u8 = 1;
pub const MSG_TYPE_TRANSACTION_BATCH: u8 = 1;
pub const MSG_TYPE_SHRED: u8 = 2;
pub const MSG_TYPE_VOTE: u8 = 3;
pub const FLAG_CRITICAL_MASK: u16 = 0x8000;
pub const FLAG_NONCRITICAL_MASK: u16 = 0x7fff;
pub const SUPPORTED_CRITICAL_FLAGS: u16 = 0;
pub const SUPPORTED_NONCRITICAL_FLAGS: u16 = 0;
pub const SUPPORTED_FLAGS: u16 = SUPPORTED_CRITICAL_FLAGS | SUPPORTED_NONCRITICAL_FLAGS;

/// Fixed header for stateless UDP “validator path”.
/// Layout (network byte order / big-endian):
///  v:1 | msg_type:1 | flags:2 | slot:8 | nonce:8 | key_id:2 | pubkey:32 | signature:64
/// Total = 1+1+2+8+8+2+32+64 = 118 bytes.
pub const HEADER_LEN: usize = 118;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub v: u8,
    pub msg_type: u8,
    pub flags: u16,
    pub slot: u64,
    pub nonce: u64,
    pub key_id: u16,
    pub pubkey: [u8; 32],
    pub signature: [u8; 64],
}

impl Default for Header {
    fn default() -> Self {
        Self {
            v: PACKET_VERSION,
            msg_type: MSG_TYPE_TRANSACTION_BATCH,
            flags: 0,
            slot: 0,
            nonce: 0,
            key_id: 0,
            pubkey: [0; 32],
            signature: [0; 64],
        }
    }
}

impl Header {
    /// Encode into `buf` (must be at least `HEADER_LEN` long).
    pub fn encode_into(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() < HEADER_LEN {
            return Err(anyhow!(
                "encode_into: buffer too small (need {})",
                HEADER_LEN
            ));
        }
        buf[0] = self.v;
        buf[1] = self.msg_type;
        buf[2..4].copy_from_slice(&self.flags.to_be_bytes());
        buf[4..12].copy_from_slice(&self.slot.to_be_bytes());
        buf[12..20].copy_from_slice(&self.nonce.to_be_bytes());
        buf[20..22].copy_from_slice(&self.key_id.to_be_bytes());
        buf[22..54].copy_from_slice(&self.pubkey);
        buf[54..118].copy_from_slice(&self.signature);
        Ok(HEADER_LEN)
    }

    /// Decode header from the start of `buf`. Returns (header, bytes_consumed).
    pub fn decode_from(buf: &[u8]) -> Result<(Self, usize)> {
        if buf.len() < HEADER_LEN {
            return Err(anyhow!(
                "decode_from: buffer too small (have {}, need {})",
                buf.len(),
                HEADER_LEN
            ));
        }
        let v = buf[0];
        let msg_type = buf[1];
        let flags = u16::from_be_bytes([buf[2], buf[3]]);
        let slot = u64::from_be_bytes(buf[4..12].try_into().unwrap());
        let nonce = u64::from_be_bytes(buf[12..20].try_into().unwrap());
        let key_id = u16::from_be_bytes(buf[20..22].try_into().unwrap());
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&buf[22..54]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&buf[54..118]);

        let header = Header {
            v,
            msg_type,
            flags,
            slot,
            nonce,
            key_id,
            pubkey,
            signature,
        };
        header.validate_wire_format()?;

        Ok((header, HEADER_LEN))
    }

    pub fn validate_wire_format(&self) -> Result<()> {
        if self.v != PACKET_VERSION {
            bail!(
                "unsupported packet version: got {}, supported {}",
                self.v,
                PACKET_VERSION
            );
        }
        if !is_supported_message_type(self.msg_type) {
            bail!("unsupported packet message type: {}", self.msg_type);
        }
        let unsupported_critical = self.flags & FLAG_CRITICAL_MASK & !SUPPORTED_CRITICAL_FLAGS;
        if unsupported_critical != 0 {
            bail!("unsupported critical packet flags: 0x{unsupported_critical:04x}");
        }
        let unsupported_noncritical =
            self.flags & FLAG_NONCRITICAL_MASK & !SUPPORTED_NONCRITICAL_FLAGS;
        if unsupported_noncritical != 0 {
            bail!("unsupported noncritical packet flags: 0x{unsupported_noncritical:04x}");
        }
        Ok(())
    }

    /// Return payload slice given the full datagram bytes.
    pub fn payload(buf: &[u8]) -> Result<&[u8]> {
        if buf.len() < HEADER_LEN {
            return Err(anyhow!("payload: buffer too small"));
        }
        Ok(&buf[HEADER_LEN..])
    }

    /// Canonical bytes signed by validator packet signatures.
    ///
    /// The preimage intentionally excludes `pubkey` and `signature`: `pubkey`
    /// selects the verification key, and `signature` cannot sign itself.
    /// The payload is represented by its BLAKE3 hash to keep the preimage
    /// fixed-size regardless of payload length.
    pub fn signing_preimage(&self, payload: &[u8]) -> Vec<u8> {
        self.signing_preimage_with_context(SIGNING_DOMAIN, SIGNING_CLUSTER_ID, payload)
    }

    pub fn signing_preimage_with_context(
        &self,
        domain: &[u8],
        cluster_id: &[u8],
        payload: &[u8],
    ) -> Vec<u8> {
        let payload_hash = blake3::hash(payload);
        let domain_len = u16::try_from(domain.len()).expect("signing domain too long");
        let cluster_len = u16::try_from(cluster_id.len()).expect("signing cluster id too long");
        let mut out = Vec::with_capacity(
            domain.len() + cluster_id.len() + 2 + 2 + 1 + 1 + 2 + 8 + 8 + 2 + 32,
        );
        out.extend_from_slice(&domain_len.to_be_bytes());
        out.extend_from_slice(domain);
        out.extend_from_slice(&cluster_len.to_be_bytes());
        out.extend_from_slice(cluster_id);
        out.push(self.v);
        out.push(self.msg_type);
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&self.slot.to_be_bytes());
        out.extend_from_slice(&self.nonce.to_be_bytes());
        out.extend_from_slice(&self.key_id.to_be_bytes());
        out.extend_from_slice(payload_hash.as_bytes());
        out
    }
}

pub fn is_supported_message_type(msg_type: u8) -> bool {
    matches!(
        msg_type,
        MSG_TYPE_TRANSACTION_BATCH | MSG_TYPE_SHRED | MSG_TYPE_VOTE
    )
}

pub type ReplayValidatorId = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayDecision {
    Fresh,
    Replay,
    Stale,
    CapacityExceeded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplayStats {
    pub head_slot: u64,
    pub active_slots: usize,
    pub entries: usize,
    pub max_slots: usize,
    pub max_entries_per_slot: usize,
    pub dropped_replays: u64,
    pub dropped_stale: u64,
    pub dropped_capacity: u64,
    pub bloom_hits: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct ReplayKey {
    nonce: u64,
    validator_id: ReplayValidatorId,
}

/// Deterministic replay state for (slot, nonce, validator_id) tuples.
/// Bloom is only a front-filter hint; exact per-slot sets make the final decision.
pub struct ReplayFilter {
    front_filter: Bloom<[u8; 32]>,
    max_entries_per_slot: usize,
    fp_rate: f64,
    head_slot: u64,
    window: u64,
    slots: HashMap<u64, HashSet<ReplayKey>>,
    seen_signatures: HashSet<[u8; 32]>,
    dropped_replays: u64,
    dropped_stale: u64,
    dropped_capacity: u64,
    bloom_hits: u64,
    last_cleanup: Instant,
    cleanup_period: Duration,
}

impl ReplayFilter {
    /// Create a replay filter.
    ///
    /// * `capacity` — expected unique keys in the active window
    /// * `fp_rate` — false positive rate target (e.g. 1e-6)
    /// * `window` — how many slots behind the current head are considered fresh
    /// * `cleanup_ms` — how often to rebuild the Bloom filter
    pub fn new(capacity: usize, fp_rate: f64, window: u64, cleanup_ms: u64) -> Self {
        let capacity = capacity.max(1);
        let front_filter = Bloom::new_for_fp_rate(capacity, fp_rate);
        Self {
            front_filter,
            max_entries_per_slot: capacity,
            fp_rate,
            head_slot: 0,
            window,
            slots: HashMap::new(),
            seen_signatures: HashSet::new(),
            dropped_replays: 0,
            dropped_stale: 0,
            dropped_capacity: 0,
            bloom_hits: 0,
            last_cleanup: Instant::now(),
            cleanup_period: Duration::from_millis(cleanup_ms.max(1)),
        }
    }

    /// Returns true if we've seen `sig` before; otherwise inserts and returns false.
    pub fn seen_or_insert(&mut self, sig: [u8; 32]) -> bool {
        if self.seen_signatures.contains(&sig) {
            true
        } else {
            if self.seen_signatures.len() >= self.max_entries_per_slot {
                self.seen_signatures.clear();
            }
            self.seen_signatures.insert(sig);
            false
        }
    }

    #[inline]
    fn front_filter_key(slot: u64, nonce: u64, validator_id: &ReplayValidatorId) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..8].copy_from_slice(&slot.to_be_bytes());
        out[8..16].copy_from_slice(&nonce.to_be_bytes());
        let validator_hash = blake3::hash(validator_id);
        out[16..].copy_from_slice(&validator_hash.as_bytes()[..16]);
        out
    }

    /// Returns true if (slot, nonce) is fresh and not seen before; inserts it.
    pub fn accept(&mut self, slot: u64, nonce: u64) -> bool {
        self.accept_for_validator(slot, nonce, [0u8; 32])
    }

    /// Returns true if (slot, nonce, validator_id) is fresh and not seen before.
    pub fn accept_for_validator(
        &mut self,
        slot: u64,
        nonce: u64,
        validator_id: ReplayValidatorId,
    ) -> bool {
        self.decide_for_validator(slot, nonce, validator_id) == ReplayDecision::Fresh
    }

    pub fn decide_for_validator(
        &mut self,
        slot: u64,
        nonce: u64,
        validator_id: ReplayValidatorId,
    ) -> ReplayDecision {
        if slot > self.head_slot {
            self.head_slot = slot;
            self.evict_stale_slots();
        }
        if self.is_stale(slot) {
            self.dropped_stale = self.dropped_stale.saturating_add(1);
            return ReplayDecision::Stale;
        }

        let front_key = Self::front_filter_key(slot, nonce, &validator_id);
        if self.front_filter.check(&front_key) {
            self.bloom_hits = self.bloom_hits.saturating_add(1);
        }

        let key = ReplayKey {
            nonce,
            validator_id,
        };
        let slot_entries = self.slots.entry(slot).or_default();
        if slot_entries.contains(&key) {
            self.dropped_replays = self.dropped_replays.saturating_add(1);
            return ReplayDecision::Replay;
        }
        if slot_entries.len() >= self.max_entries_per_slot {
            self.dropped_capacity = self.dropped_capacity.saturating_add(1);
            return ReplayDecision::CapacityExceeded;
        }
        slot_entries.insert(key);
        self.front_filter.set(&front_key);
        ReplayDecision::Fresh
    }

    pub fn stats(&self) -> ReplayStats {
        ReplayStats {
            head_slot: self.head_slot,
            active_slots: self.slots.len(),
            entries: self.entry_count(),
            max_slots: self.max_slots(),
            max_entries_per_slot: self.max_entries_per_slot,
            dropped_replays: self.dropped_replays,
            dropped_stale: self.dropped_stale,
            dropped_capacity: self.dropped_capacity,
            bloom_hits: self.bloom_hits,
        }
    }

    /// Periodic cleanup hook - evict stale exact state and rebuild the Bloom front filter.
    pub fn maybe_cleanup(&mut self) {
        if self.last_cleanup.elapsed() < self.cleanup_period {
            return;
        }
        self.evict_stale_slots();
        self.rebuild_front_filter();
        self.last_cleanup = Instant::now();
    }

    fn is_stale(&self, slot: u64) -> bool {
        slot < self.stale_cutoff()
    }

    fn stale_cutoff(&self) -> u64 {
        self.head_slot.saturating_sub(self.window)
    }

    fn max_slots(&self) -> usize {
        usize::try_from(self.window.saturating_add(1)).unwrap_or(usize::MAX)
    }

    fn entry_count(&self) -> usize {
        self.slots.values().map(HashSet::len).sum()
    }

    fn evict_stale_slots(&mut self) {
        let cutoff = self.stale_cutoff();
        self.slots.retain(|slot, _| *slot >= cutoff);
    }

    fn rebuild_front_filter(&mut self) {
        let capacity = self
            .entry_count()
            .max(self.max_entries_per_slot)
            .saturating_add(1);
        self.front_filter = Bloom::new_for_fp_rate(capacity, self.fp_rate);
        for (slot, keys) in &self.slots {
            for key in keys {
                self.front_filter
                    .set(&Self::front_filter_key(*slot, key.nonce, &key.validator_id));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let h = Header {
            v: PACKET_VERSION,
            msg_type: MSG_TYPE_SHRED,
            flags: SUPPORTED_FLAGS,
            slot: 42,
            nonce: 9,
            key_id: 7,
            pubkey: [1u8; 32],
            signature: [2u8; 64],
        };
        let mut buf = vec![0u8; HEADER_LEN];
        let n = h.encode_into(&mut buf).unwrap();
        assert_eq!(n, HEADER_LEN);

        let (h2, used) = Header::decode_from(&buf).unwrap();
        assert_eq!(used, HEADER_LEN);
        assert_eq!(h, h2);
    }

    #[test]
    fn unknown_version_is_rejected() {
        let h = Header {
            v: PACKET_VERSION + 1,
            msg_type: MSG_TYPE_TRANSACTION_BATCH,
            ..Header::default()
        };
        let mut buf = vec![0u8; HEADER_LEN];
        h.encode_into(&mut buf).unwrap();

        assert!(Header::decode_from(&buf).is_err());
        assert!(h.validate_wire_format().is_err());
    }

    #[test]
    fn unknown_message_type_is_rejected() {
        let h = Header {
            msg_type: 255,
            ..Header::default()
        };
        let mut buf = vec![0u8; HEADER_LEN];
        h.encode_into(&mut buf).unwrap();

        assert!(Header::decode_from(&buf).is_err());
        assert!(h.validate_wire_format().is_err());
    }

    #[test]
    fn unknown_critical_flag_is_rejected() {
        let h = Header {
            msg_type: MSG_TYPE_TRANSACTION_BATCH,
            flags: FLAG_CRITICAL_MASK,
            ..Header::default()
        };
        let mut buf = vec![0u8; HEADER_LEN];
        h.encode_into(&mut buf).unwrap();

        assert!(Header::decode_from(&buf).is_err());
        assert!(h.validate_wire_format().is_err());
    }

    #[test]
    fn unknown_noncritical_flag_is_rejected_until_supported() {
        let h = Header {
            msg_type: MSG_TYPE_TRANSACTION_BATCH,
            flags: 0x0001,
            ..Header::default()
        };
        let mut buf = vec![0u8; HEADER_LEN];
        h.encode_into(&mut buf).unwrap();

        assert!(Header::decode_from(&buf).is_err());
        assert!(h.validate_wire_format().is_err());
    }

    #[test]
    fn supported_message_types_are_explicit() {
        assert!(is_supported_message_type(MSG_TYPE_TRANSACTION_BATCH));
        assert!(is_supported_message_type(MSG_TYPE_SHRED));
        assert!(is_supported_message_type(MSG_TYPE_VOTE));
        assert!(!is_supported_message_type(0));
        assert!(!is_supported_message_type(255));
    }

    #[test]
    fn parser_rejects_malformed_corpus_without_panicking() {
        let empty = &[][..];
        let short = &[0u8; HEADER_LEN - 1][..];
        let exact = &[0x41u8; HEADER_LEN][..];
        let oversized = &[0x42u8; HEADER_LEN + 4096][..];
        let random = &[
            0x00, 0xff, 0x7f, 0x80, 0x13, 0x37, 0xc0, 0xde, 0x11, 0x22, 0x33, 0x44, 0x55, 0xaa,
            0xbb, 0xcc, 0xdd,
        ][..];

        for input in [empty, short, exact, oversized, random] {
            let decoded = std::panic::catch_unwind(|| Header::decode_from(input));
            assert!(decoded.is_ok());

            let payload = std::panic::catch_unwind(|| Header::payload(input));
            assert!(payload.is_ok());
        }
    }

    #[test]
    fn parser_accepts_exact_valid_header_and_oversized_valid_datagram() {
        let header = Header::default();
        let mut exact = vec![0u8; HEADER_LEN];
        header.encode_into(&mut exact).unwrap();

        let decoded = Header::decode_from(&exact).unwrap();
        assert_eq!(decoded.1, HEADER_LEN);
        assert!(Header::payload(&exact).unwrap().is_empty());

        let mut oversized = exact.clone();
        oversized.extend_from_slice(b"payload bytes");
        let decoded = Header::decode_from(&oversized).unwrap();
        assert_eq!(decoded.1, HEADER_LEN);
        assert_eq!(Header::payload(&oversized).unwrap(), b"payload bytes");
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn signing_preimage_covers_security_fields_and_payload() {
        use ed25519_dalek::{Signer, Verifier};
        use rand::rngs::OsRng;

        let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let verify_key = signing_key.verifying_key();
        let payload = b"transfer payload";
        let header = Header {
            v: PACKET_VERSION,
            msg_type: MSG_TYPE_SHRED,
            flags: SUPPORTED_FLAGS,
            slot: 42,
            nonce: 9,
            key_id: 7,
            pubkey: verify_key.to_bytes(),
            signature: [0u8; 64],
        };
        let sig = signing_key.sign(&header.signing_preimage(payload));

        assert!(
            verify_key
                .verify(&header.signing_preimage(payload), &sig)
                .is_ok()
        );

        let mut tampered = header;
        tampered.slot += 1;
        assert!(
            verify_key
                .verify(&tampered.signing_preimage(payload), &sig)
                .is_err()
        );

        let mut tampered = header;
        tampered.nonce += 1;
        assert!(
            verify_key
                .verify(&tampered.signing_preimage(payload), &sig)
                .is_err()
        );

        let mut tampered = header;
        tampered.msg_type += 1;
        assert!(
            verify_key
                .verify(&tampered.signing_preimage(payload), &sig)
                .is_err()
        );

        let mut tampered = header;
        tampered.flags = 0x0001;
        assert!(
            verify_key
                .verify(&tampered.signing_preimage(payload), &sig)
                .is_err()
        );

        let mut tampered = header;
        tampered.key_id += 1;
        assert!(
            verify_key
                .verify(&tampered.signing_preimage(payload), &sig)
                .is_err()
        );

        assert!(
            verify_key
                .verify(&header.signing_preimage(b"tampered payload"), &sig)
                .is_err()
        );
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn signing_preimage_separates_domain_and_cluster() {
        use ed25519_dalek::{Signer, Verifier};
        use rand::rngs::OsRng;

        let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let verify_key = signing_key.verifying_key();
        let payload = b"transfer payload";
        let header = Header {
            v: PACKET_VERSION,
            msg_type: MSG_TYPE_SHRED,
            flags: SUPPORTED_FLAGS,
            slot: 42,
            nonce: 9,
            key_id: 7,
            pubkey: verify_key.to_bytes(),
            signature: [0u8; 64],
        };
        let sig = signing_key.sign(&header.signing_preimage(payload));

        assert!(
            verify_key
                .verify(&header.signing_preimage(payload), &sig)
                .is_ok()
        );
        assert!(
            verify_key
                .verify(
                    &header.signing_preimage_with_context(
                        b"rpkv2.other_packet.v1",
                        SIGNING_CLUSTER_ID,
                        payload
                    ),
                    &sig
                )
                .is_err()
        );
        assert!(
            verify_key
                .verify(
                    &header.signing_preimage_with_context(
                        SIGNING_DOMAIN,
                        b"rpkv2.testnet",
                        payload
                    ),
                    &sig
                )
                .is_err()
        );
    }

    #[test]
    fn replay_filter_basic() {
        // window=64: slots more than 64 behind head are rejected as stale.
        let mut rf = ReplayFilter::new(1 << 20, 1e-6, 64, 100);
        assert!(rf.accept(100, 1)); // fresh
        assert!(!rf.accept(100, 1)); // duplicate
        assert!(rf.accept(101, 1)); // new slot, head advances to 101
        // slot 10: 10 + 64 = 74 < 101 → stale
        assert!(!rf.accept(10, 1));
    }

    #[test]
    fn replay_filter_allows_same_nonce_from_different_validators() {
        let mut rf = ReplayFilter::new(1024, 1e-6, 64, 100);
        let validator_a = [1u8; 32];
        let validator_b = [2u8; 32];

        assert!(rf.accept_for_validator(100, 7, validator_a));
        assert!(rf.accept_for_validator(100, 7, validator_b));
        assert!(!rf.accept_for_validator(100, 7, validator_a));
        assert_eq!(rf.stats().dropped_replays, 1);
    }

    #[test]
    fn replay_filter_evicts_stale_slots() {
        let mut rf = ReplayFilter::new(1024, 1e-6, 2, 100);

        assert!(rf.accept(10, 1));
        assert!(rf.accept(11, 1));
        assert!(rf.accept(12, 1));
        assert!(rf.accept(13, 1));

        let stats = rf.stats();
        assert_eq!(stats.head_slot, 13);
        assert!(stats.active_slots <= stats.max_slots);
        assert_eq!(stats.entries, 3);
        assert!(!rf.accept(10, 2));
        assert_eq!(rf.stats().dropped_stale, 1);
    }

    #[test]
    fn replay_filter_high_volume_has_no_false_positive_drops() {
        let mut rf = ReplayFilter::new(10_000, 0.5, 8, 100);
        let validator = [9u8; 32];

        for nonce in 0..10_000 {
            assert!(rf.accept_for_validator(5, nonce, validator));
        }
        for nonce in 0..10_000 {
            assert!(!rf.accept_for_validator(5, nonce, validator));
        }

        let stats = rf.stats();
        assert_eq!(stats.entries, 10_000);
        assert_eq!(stats.dropped_replays, 10_000);
        assert_eq!(stats.dropped_capacity, 0);
        assert!(stats.bloom_hits > 0);
    }

    #[test]
    fn replay_filter_capacity_bounds_nonce_spam() {
        let mut rf = ReplayFilter::new(2, 1e-6, 4, 100);
        let validator = [3u8; 32];

        assert!(rf.accept_for_validator(1, 1, validator));
        assert!(rf.accept_for_validator(1, 2, validator));
        assert_eq!(
            rf.decide_for_validator(1, 3, validator),
            ReplayDecision::CapacityExceeded
        );

        let stats = rf.stats();
        assert_eq!(stats.entries, 2);
        assert_eq!(stats.max_entries_per_slot, 2);
        assert_eq!(stats.dropped_capacity, 1);
    }
}
