use super::{IdleWait, Tile, Txn, TxnQueue, VerifiedQueue, VerifiedTxn};
use crate::backpressure::{INTERNAL_STAGE_POLICY, push_with_policy};
use crate::metrics;
use crate::peer_rate_limit::PeerRateLimiter;
use crate::shutdown::Shutdown;
use std::thread;

pub struct VerifyRouter {
    pub rx: TxnQueue,
    pub shards: Vec<TxnQueue>,
}

impl Tile for VerifyRouter {
    fn start_with_shutdown(self, shutdown: Shutdown) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let mut idle = IdleWait::new();
            while !shutdown.is_requested() || !self.rx.is_empty() {
                if let Some(txn) = self.rx.pop() {
                    idle.reset();
                    let shard = deterministic_shard(
                        &txn.header.pubkey,
                        txn.header.nonce,
                        self.shards.len(),
                    );
                    push_with_policy(
                        "verify_router_to_shard",
                        &self.shards[shard],
                        txn,
                        INTERNAL_STAGE_POLICY,
                    );
                } else {
                    idle.snooze();
                }
            }
        })
    }
}

fn deterministic_shard(key: &[u8; 32], nonce: u64, shard_count: usize) -> usize {
    let prefix = u64::from_be_bytes(key[..8].try_into().expect("key prefix length"));
    (prefix ^ nonce) as usize % shard_count.max(1)
}

pub struct Verifier {
    pub rx: TxnQueue,
    pub tx: VerifiedQueue,
    pub batch: usize,
    pub peer_limiter: Option<PeerRateLimiter>,
    pub core_id: Option<usize>,
}

impl Verifier {
    pub fn new(rx: TxnQueue, tx: VerifiedQueue, batch: usize) -> Self {
        Self::new_with_peer_limiter(rx, tx, batch, None)
    }

    pub fn new_with_peer_limiter(
        rx: TxnQueue,
        tx: VerifiedQueue,
        batch: usize,
        peer_limiter: Option<PeerRateLimiter>,
    ) -> Self {
        Self {
            rx,
            tx,
            batch,
            peer_limiter,
            core_id: None,
        }
    }

    pub fn with_core_id(mut self, core_id: Option<usize>) -> Self {
        self.core_id = core_id;
        self
    }
}
impl Tile for Verifier {
    fn start_with_shutdown(self, shutdown: Shutdown) -> thread::JoinHandle<()> {
        std::thread::spawn(move || {
            if let Some(core_index) = self.core_id
                && let Some(core) = core_affinity::get_core_ids()
                    .and_then(|cores| cores.into_iter().find(|core| core.id == core_index))
            {
                core_affinity::set_for_current(core);
            }
            let mut buf: Vec<Txn> = Vec::with_capacity(self.batch);
            let mut idle = IdleWait::new();
            while !shutdown.is_requested() || !self.rx.is_empty() || !buf.is_empty() {
                // fill a batch
                while buf.len() < self.batch {
                    if let Some(t) = self.rx.pop() {
                        idle.reset();
                        buf.push(t);
                    } else {
                        break;
                    }
                }
                if buf.is_empty() {
                    idle.snooze();
                    continue;
                }

                let preimages: Vec<Vec<u8>> = buf
                    .iter()
                    .map(|t| t.header.signing_preimage(&t.payload))
                    .collect();

                let verify_start = std::time::Instant::now();
                let oks = verify_direct(&buf, &preimages);
                metrics::global()
                    .record_verification_batch(buf.len() as u64, verify_start.elapsed());
                for (t, ok) in buf.drain(..).zip(oks) {
                    if ok {
                        metrics::global().record_packet_verified();
                    }
                    if !ok && let Some(limiter) = &self.peer_limiter {
                        limiter.record_invalid_signature(&t.peer);
                        metrics::global().record_bad_signature();
                        if crate::logging::should_log(
                            "verify_bad_signature",
                            std::time::Duration::from_secs(1),
                        ) {
                            tracing::warn!(
                                tile = "verify",
                                peer_id = %t.peer,
                                slot = t.header.slot,
                                packet_type = t.header.msg_type,
                                reason = "bad_signature",
                                "packet signature verification failed"
                            );
                        }
                    } else if !ok {
                        metrics::global().record_bad_signature();
                        if crate::logging::should_log(
                            "verify_bad_signature",
                            std::time::Duration::from_secs(1),
                        ) {
                            tracing::warn!(
                                tile = "verify",
                                peer_id = %t.peer,
                                slot = t.header.slot,
                                packet_type = t.header.msg_type,
                                reason = "bad_signature",
                                "packet signature verification failed"
                            );
                        }
                    }
                    push_with_policy(
                        "verify_to_pack",
                        &self.tx,
                        VerifiedTxn { txn: t, ok },
                        INTERNAL_STAGE_POLICY,
                    );
                }
            }
        })
    }
}

#[cfg(feature = "ed25519")]
fn verify_direct(txns: &[Txn], preimages: &[Vec<u8>]) -> Vec<bool> {
    #[cfg(not(feature = "dalek_batch"))]
    use ed25519_dalek::Verifier as _;
    use ed25519_dalek::{Signature, VerifyingKey};

    let mut results = vec![false; txns.len()];
    let mut indexes = Vec::with_capacity(txns.len());
    let mut keys = Vec::with_capacity(txns.len());
    let mut signatures = Vec::with_capacity(txns.len());
    for (index, txn) in txns.iter().enumerate() {
        if let Ok(key) = VerifyingKey::from_bytes(&txn.header.pubkey) {
            indexes.push(index);
            keys.push(key);
            signatures.push(Signature::from_bytes(&txn.header.signature));
        }
    }

    #[cfg(feature = "dalek_batch")]
    let verified = {
        let messages: Vec<&[u8]> = indexes
            .iter()
            .map(|index| preimages[*index].as_slice())
            .collect();
        crate::fastpath::crypto::ed25519_backend::verify_batch(&keys, &messages, &signatures)
    };
    #[cfg(not(feature = "dalek_batch"))]
    let verified: Vec<bool> = indexes
        .iter()
        .zip(keys.iter())
        .zip(signatures.iter())
        .map(|((index, key), signature)| key.verify(&preimages[*index], signature).is_ok())
        .collect();

    for (index, ok) in indexes.into_iter().zip(verified) {
        results[index] = ok;
    }
    results
}

#[cfg(all(not(feature = "ed25519"), feature = "insecure_demo"))]
fn verify_direct(txns: &[Txn], _preimages: &[Vec<u8>]) -> Vec<bool> {
    vec![true; txns.len()]
}

#[cfg(test)]
mod tests {
    use super::deterministic_shard;

    #[test]
    fn validator_key_sharding_is_stable() {
        let mut first = [0u8; 32];
        first[..8].copy_from_slice(&1u64.to_be_bytes());
        let mut second = [0u8; 32];
        second[..8].copy_from_slice(&2u64.to_be_bytes());

        assert_eq!(deterministic_shard(&first, 0, 4), 1);
        assert_eq!(deterministic_shard(&first, 0, 4), 1);
        assert_eq!(deterministic_shard(&first, 1, 4), 0);
        assert_eq!(deterministic_shard(&second, 0, 4), 2);
    }
}
