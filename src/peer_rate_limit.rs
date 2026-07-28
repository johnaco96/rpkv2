use std::{
    collections::BTreeMap,
    fmt,
    hash::{DefaultHasher, Hash, Hasher},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Clone, Debug)]
pub struct PeerRateLimits {
    pub window: Duration,
    pub throttle_for: Duration,
    pub max_packets_per_window: u64,
    pub max_bytes_per_window: u64,
    pub max_malformed_per_window: u64,
    pub max_invalid_signatures_per_window: u64,
    pub max_replays_per_window: u64,
}

impl Default for PeerRateLimits {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(1),
            throttle_for: Duration::from_secs(5),
            max_packets_per_window: 50_000,
            max_bytes_per_window: 64 * 1024 * 1024,
            max_malformed_per_window: 128,
            max_invalid_signatures_per_window: 128,
            max_replays_per_window: 1_024,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerLimitReason {
    PacketRate,
    ByteRate,
    MalformedRate,
    InvalidSignatureRate,
    ReplayRate,
    AlreadyThrottled,
}

impl fmt::Display for PeerLimitReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerLimitReason::PacketRate => write!(f, "packet_rate"),
            PeerLimitReason::ByteRate => write!(f, "byte_rate"),
            PeerLimitReason::MalformedRate => write!(f, "malformed_rate"),
            PeerLimitReason::InvalidSignatureRate => write!(f, "invalid_signature_rate"),
            PeerLimitReason::ReplayRate => write!(f, "replay_rate"),
            PeerLimitReason::AlreadyThrottled => write!(f, "already_throttled"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerLimitDecision {
    Allow,
    Throttle(PeerLimitReason),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerRateSnapshot {
    pub peer: String,
    pub packets: u64,
    pub bytes: u64,
    pub malformed: u64,
    pub invalid_signatures: u64,
    pub replays: u64,
    pub throttled: u64,
}

#[derive(Clone, Debug)]
pub struct PeerRateLimiter {
    limits: Arc<PeerRateLimits>,
    peer_shards: Arc<Vec<Mutex<BTreeMap<String, PeerState>>>>,
}

const PEER_STATE_SHARDS: usize = 64;

impl PeerRateLimiter {
    pub fn new(limits: PeerRateLimits) -> Self {
        Self {
            limits: Arc::new(limits),
            peer_shards: Arc::new(
                (0..PEER_STATE_SHARDS)
                    .map(|_| Mutex::new(BTreeMap::new()))
                    .collect(),
            ),
        }
    }

    pub fn check_packet(&self, peer: &str, bytes: usize) -> PeerLimitDecision {
        let mut peers = self.peer_shard(peer);
        let state = peers.entry(peer.to_string()).or_insert_with(PeerState::new);
        state.roll_window(self.limits.window);

        if state.is_throttled() {
            state.throttled = state.throttled.saturating_add(1);
            return PeerLimitDecision::Throttle(PeerLimitReason::AlreadyThrottled);
        }

        state.packets = state.packets.saturating_add(1);
        state.bytes = state.bytes.saturating_add(bytes as u64);

        if state.packets > self.limits.max_packets_per_window {
            self.throttle(state, peer, PeerLimitReason::PacketRate)
        } else if state.bytes > self.limits.max_bytes_per_window {
            self.throttle(state, peer, PeerLimitReason::ByteRate)
        } else {
            PeerLimitDecision::Allow
        }
    }

    pub fn record_malformed(&self, peer: &str) -> PeerLimitDecision {
        self.record_abuse(peer, PeerLimitReason::MalformedRate, |state| {
            state.malformed = state.malformed.saturating_add(1);
            state.malformed
        })
    }

    pub fn record_invalid_signature(&self, peer: &str) -> PeerLimitDecision {
        self.record_abuse(peer, PeerLimitReason::InvalidSignatureRate, |state| {
            state.invalid_signatures = state.invalid_signatures.saturating_add(1);
            state.invalid_signatures
        })
    }

    pub fn record_replay(&self, peer: &str) -> PeerLimitDecision {
        self.record_abuse(peer, PeerLimitReason::ReplayRate, |state| {
            state.replays = state.replays.saturating_add(1);
            state.replays
        })
    }

    pub fn snapshots(&self) -> Vec<PeerRateSnapshot> {
        self.peer_shards
            .iter()
            .flat_map(|shard| {
                shard
                    .lock()
                    .expect("peer rate limiter lock poisoned")
                    .iter()
                    .map(|(peer, state)| PeerRateSnapshot {
                        peer: peer.clone(),
                        packets: state.total_packets.saturating_add(state.packets),
                        bytes: state.total_bytes.saturating_add(state.bytes),
                        malformed: state.total_malformed.saturating_add(state.malformed),
                        invalid_signatures: state
                            .total_invalid_signatures
                            .saturating_add(state.invalid_signatures),
                        replays: state.total_replays.saturating_add(state.replays),
                        throttled: state.total_throttled.saturating_add(state.throttled),
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    pub fn metrics_text(&self) -> String {
        let mut out = String::new();
        for peer in self.snapshots() {
            out.push_str(&format!(
                "rpkv2_peer_packets_total{{peer=\"{}\"}} {}\n",
                peer.peer, peer.packets
            ));
            out.push_str(&format!(
                "rpkv2_peer_bytes_total{{peer=\"{}\"}} {}\n",
                peer.peer, peer.bytes
            ));
            out.push_str(&format!(
                "rpkv2_peer_malformed_total{{peer=\"{}\"}} {}\n",
                peer.peer, peer.malformed
            ));
            out.push_str(&format!(
                "rpkv2_peer_invalid_signatures_total{{peer=\"{}\"}} {}\n",
                peer.peer, peer.invalid_signatures
            ));
            out.push_str(&format!(
                "rpkv2_peer_replays_total{{peer=\"{}\"}} {}\n",
                peer.peer, peer.replays
            ));
            out.push_str(&format!(
                "rpkv2_peer_throttled_total{{peer=\"{}\"}} {}\n",
                peer.peer, peer.throttled
            ));
        }
        out
    }

    fn record_abuse(
        &self,
        peer: &str,
        reason: PeerLimitReason,
        update: impl FnOnce(&mut PeerState) -> u64,
    ) -> PeerLimitDecision {
        let mut peers = self.peer_shard(peer);
        let state = peers.entry(peer.to_string()).or_insert_with(PeerState::new);
        state.roll_window(self.limits.window);

        let current = update(state);
        match reason {
            PeerLimitReason::MalformedRate if current > self.limits.max_malformed_per_window => {
                self.throttle(state, peer, reason)
            }
            PeerLimitReason::InvalidSignatureRate
                if current > self.limits.max_invalid_signatures_per_window =>
            {
                self.throttle(state, peer, reason)
            }
            PeerLimitReason::ReplayRate if current > self.limits.max_replays_per_window => {
                self.throttle(state, peer, reason)
            }
            _ => PeerLimitDecision::Allow,
        }
    }

    fn throttle(
        &self,
        state: &mut PeerState,
        peer: &str,
        reason: PeerLimitReason,
    ) -> PeerLimitDecision {
        state.throttled = state.throttled.saturating_add(1);
        state.throttled_until = Some(Instant::now() + self.limits.throttle_for);
        if crate::logging::should_log("peer_rate_limit_throttle", Duration::from_secs(1)) {
            tracing::warn!(
                peer_id = peer,
                reason = %reason,
                throttle_ms = self.limits.throttle_for.as_millis(),
                "peer rate limit exceeded; throttling traffic"
            );
        }
        PeerLimitDecision::Throttle(reason)
    }

    fn peer_shard(&self, peer: &str) -> std::sync::MutexGuard<'_, BTreeMap<String, PeerState>> {
        let mut hasher = DefaultHasher::new();
        peer.hash(&mut hasher);
        let index = (hasher.finish() as usize) % self.peer_shards.len();
        self.peer_shards[index]
            .lock()
            .expect("peer rate limiter lock poisoned")
    }
}

#[derive(Debug)]
struct PeerState {
    window_start: Instant,
    throttled_until: Option<Instant>,
    packets: u64,
    bytes: u64,
    malformed: u64,
    invalid_signatures: u64,
    replays: u64,
    throttled: u64,
    total_packets: u64,
    total_bytes: u64,
    total_malformed: u64,
    total_invalid_signatures: u64,
    total_replays: u64,
    total_throttled: u64,
}

impl PeerState {
    fn new() -> Self {
        Self {
            window_start: Instant::now(),
            throttled_until: None,
            packets: 0,
            bytes: 0,
            malformed: 0,
            invalid_signatures: 0,
            replays: 0,
            throttled: 0,
            total_packets: 0,
            total_bytes: 0,
            total_malformed: 0,
            total_invalid_signatures: 0,
            total_replays: 0,
            total_throttled: 0,
        }
    }

    fn roll_window(&mut self, window: Duration) {
        if self.window_start.elapsed() >= window {
            self.total_packets = self.total_packets.saturating_add(self.packets);
            self.total_bytes = self.total_bytes.saturating_add(self.bytes);
            self.total_malformed = self.total_malformed.saturating_add(self.malformed);
            self.total_invalid_signatures = self
                .total_invalid_signatures
                .saturating_add(self.invalid_signatures);
            self.total_replays = self.total_replays.saturating_add(self.replays);
            self.total_throttled = self.total_throttled.saturating_add(self.throttled);
            self.window_start = Instant::now();
            self.packets = 0;
            self.bytes = 0;
            self.malformed = 0;
            self.invalid_signatures = 0;
            self.replays = 0;
            self.throttled = 0;
        }
    }

    fn is_throttled(&mut self) -> bool {
        if let Some(until) = self.throttled_until {
            if Instant::now() < until {
                return true;
            }
            self.throttled_until = None;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tight_limits() -> PeerRateLimiter {
        PeerRateLimiter::new(PeerRateLimits {
            window: Duration::from_secs(60),
            throttle_for: Duration::from_secs(60),
            max_packets_per_window: 2,
            max_bytes_per_window: 100,
            max_malformed_per_window: 1,
            max_invalid_signatures_per_window: 1,
            max_replays_per_window: 1,
        })
    }

    #[test]
    fn peer_flood_is_throttled() {
        let limiter = tight_limits();

        assert_eq!(limiter.check_packet("peer-a", 10), PeerLimitDecision::Allow);
        assert_eq!(limiter.check_packet("peer-a", 10), PeerLimitDecision::Allow);
        assert_eq!(
            limiter.check_packet("peer-a", 10),
            PeerLimitDecision::Throttle(PeerLimitReason::PacketRate)
        );
        assert_eq!(
            limiter.check_packet("peer-a", 10),
            PeerLimitDecision::Throttle(PeerLimitReason::AlreadyThrottled)
        );
        assert!(
            limiter
                .metrics_text()
                .contains("rpkv2_peer_throttled_total")
        );
    }

    #[test]
    fn well_behaved_peer_passes_while_other_peer_is_limited() {
        let limiter = tight_limits();

        for _ in 0..3 {
            let _ = limiter.check_packet("flood", 10);
        }

        assert_eq!(limiter.check_packet("steady", 10), PeerLimitDecision::Allow);
        assert_eq!(limiter.check_packet("steady", 10), PeerLimitDecision::Allow);
    }

    #[test]
    fn malformed_invalid_signature_and_replay_rates_are_counted() {
        let limiter = tight_limits();

        assert_eq!(limiter.record_malformed("peer-a"), PeerLimitDecision::Allow);
        assert_eq!(
            limiter.record_malformed("peer-a"),
            PeerLimitDecision::Throttle(PeerLimitReason::MalformedRate)
        );

        let limiter = tight_limits();
        assert_eq!(
            limiter.record_invalid_signature("peer-a"),
            PeerLimitDecision::Allow
        );
        assert_eq!(
            limiter.record_invalid_signature("peer-a"),
            PeerLimitDecision::Throttle(PeerLimitReason::InvalidSignatureRate)
        );

        let limiter = tight_limits();
        assert_eq!(limiter.record_replay("peer-a"), PeerLimitDecision::Allow);
        assert_eq!(
            limiter.record_replay("peer-a"),
            PeerLimitDecision::Throttle(PeerLimitReason::ReplayRate)
        );
    }
}
