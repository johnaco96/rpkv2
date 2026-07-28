use crate::backpressure::{INTERNAL_STAGE_POLICY, push_with_policy};
use crate::fastpath::packet::{ReplayDecision, ReplayFilter};
use crate::metrics;
use crate::peer_rate_limit::PeerRateLimiter;
use crate::shutdown::Shutdown;
use crate::tiles::{IdleWait, Tile, TxnQueue};
use std::thread;

/// Pipeline tile: pulls Txn from `rx`, drops replays, pushes fresh to `tx`.
pub struct Deduper {
    pub rx: TxnQueue,
    pub tx: TxnQueue,
    /// Maximum exact replay entries per active slot.
    pub cap: usize,
    /// Max slots to keep before an entry is considered stale.
    pub window: u64,
    /// How often to evict stale slots and rebuild the Bloom front filter (ms).
    pub cleanup_ms: u64,
    /// Target false-positive rate.
    pub fp_rate: f64,
    pub peer_limiter: Option<PeerRateLimiter>,
}

impl Tile for Deduper {
    fn start_with_shutdown(self, shutdown: Shutdown) -> std::thread::JoinHandle<()> {
        thread::spawn(move || {
            // Build replay filter inside the worker
            let mut rf = ReplayFilter::new(self.cap, self.fp_rate, self.window, self.cleanup_ms);
            let mut pipeline_seq = 0u64;
            let mut idle = IdleWait::new();

            while !shutdown.is_requested() || !self.rx.is_empty() {
                if let Some(mut t) = self.rx.pop() {
                    idle.reset();
                    match rf.decide_for_validator(t.header.slot, t.header.nonce, t.header.pubkey) {
                        ReplayDecision::Fresh => {
                            t.pipeline_seq = pipeline_seq;
                            pipeline_seq = pipeline_seq.saturating_add(1);
                            metrics::global().record_packet_deduplicated();
                            push_with_policy(
                                "dedupe_to_verify",
                                &self.tx,
                                t,
                                INTERNAL_STAGE_POLICY,
                            );
                        }
                        ReplayDecision::Replay => {
                            if let Some(limiter) = &self.peer_limiter {
                                limiter.record_replay(&t.peer);
                            }
                            metrics::global().record_replay_drop();
                            log_drop(&t, "replay", "dropping replay packet");
                        }
                        ReplayDecision::Stale => {
                            metrics::global().record_stale_slot_drop();
                            log_drop(&t, "stale_slot", "dropping stale-slot packet");
                        }
                        ReplayDecision::CapacityExceeded => {
                            metrics::global().record_replay_capacity_drop();
                            log_drop(
                                &t,
                                "replay_capacity",
                                "dropping packet because replay state is full",
                            );
                        }
                    }
                    rf.maybe_cleanup();
                } else {
                    // no work; back off a hair
                    idle.snooze();
                }
            }
        })
    }
}

fn log_drop(t: &crate::tiles::Txn, reason: &'static str, message: &'static str) {
    if crate::logging::should_log(reason, std::time::Duration::from_secs(1)) {
        tracing::warn!(
            tile = "dedupe",
            peer_id = %t.peer,
            slot = t.header.slot,
            packet_type = t.header.msg_type,
            reason,
            "{message}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shutdown::Shutdown;
    use crate::tiles::Txn;
    use bytes::Bytes;
    use crossbeam_queue::ArrayQueue;
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn deduper_drops_replays() {
        let rx: TxnQueue = Arc::new(ArrayQueue::new(8));
        let tx: TxnQueue = Arc::new(ArrayQueue::new(8));

        // Push two identical (slot, nonce)
        let mk = |slot, nonce| Txn {
            header: crate::fastpath::packet::Header {
                slot,
                nonce,
                ..Default::default()
            },
            payload: Bytes::from_static(b"x"),
            peer: "test-peer".to_string(),
            recv_ts_ns: 0,
            pipeline_seq: 0,
        };
        rx.push(mk(100, 1)).unwrap();
        rx.push(mk(100, 1)).unwrap();

        let shutdown = Shutdown::new();
        let d = Deduper {
            rx: rx.clone(),
            tx: tx.clone(),
            cap: 1024,
            window: 1024,
            cleanup_ms: 100,
            fp_rate: 1e-6,
            peer_limiter: None,
        };
        let h = d.start_with_shutdown(shutdown.clone());

        // give it a moment to run
        std::thread::sleep(Duration::from_millis(50));

        assert_eq!(tx.len(), 1, "second duplicate should be dropped");
        shutdown.request();
        h.join().unwrap();
    }
}
