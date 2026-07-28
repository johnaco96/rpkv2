use super::{IdleWait, Tile, VerifiedQueue, VerifiedTxn};
use crate::backpressure::{INTERNAL_STAGE_POLICY, push_with_policy};
use crate::metrics;
use crate::shutdown::Shutdown;
use crossbeam_queue::ArrayQueue;
use std::{collections::BTreeMap, sync::Arc, thread};

pub struct Pack {
    pub rx: VerifiedQueue,
    pub to_bank: Arc<ArrayQueue<VerifiedTxn>>,
}

impl Tile for Pack {
    fn start_with_shutdown(self, shutdown: Shutdown) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let mut next_seq = 0u64;
            let mut pending = BTreeMap::new();
            let mut idle = IdleWait::new();
            while !shutdown.is_requested() || !self.rx.is_empty() {
                if let Some(v) = self.rx.pop() {
                    idle.reset();
                    pending.insert(v.txn.pipeline_seq, v);
                    while let Some(ordered) = pending.remove(&next_seq) {
                        forward_verified(&self.to_bank, ordered);
                        next_seq = next_seq.saturating_add(1);
                    }
                } else {
                    idle.snooze();
                }
            }
            if !pending.is_empty() {
                tracing::error!(
                    tile = "pack",
                    next_sequence = next_seq,
                    pending = pending.len(),
                    reason = "verification_sequence_gap",
                    "ordered verification merge stopped with a sequence gap"
                );
            }
        })
    }
}

fn forward_verified(to_bank: &Arc<ArrayQueue<VerifiedTxn>>, verified: VerifiedTxn) {
    if verified.ok {
        let latency = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .saturating_sub(u128::from(verified.txn.recv_ts_ns));
        metrics::global()
            .record_packet_latency(std::time::Duration::from_micros((latency / 1_000) as u64));
        push_with_policy("pack_to_bank", to_bank, verified, INTERNAL_STAGE_POLICY);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{shutdown::Shutdown, tiles::Txn};
    use bytes::Bytes;

    fn verified(sequence: u64, ok: bool) -> VerifiedTxn {
        VerifiedTxn {
            txn: Txn {
                header: Default::default(),
                payload: Bytes::from_static(b"payload"),
                peer: "peer".to_string(),
                recv_ts_ns: 0,
                pipeline_seq: sequence,
            },
            ok,
        }
    }

    #[test]
    fn ordered_merge_waits_for_missing_sequence_and_advances_past_invalid() {
        let input = Arc::new(ArrayQueue::new(8));
        let output = Arc::new(ArrayQueue::new(8));
        assert!(input.push(verified(2, true)).is_ok());
        assert!(input.push(verified(1, true)).is_ok());
        assert!(input.push(verified(0, false)).is_ok());
        let shutdown = Shutdown::new();
        let handle = Pack {
            rx: input,
            to_bank: output.clone(),
        }
        .start_with_shutdown(shutdown.clone());

        for _ in 0..100 {
            if output.len() == 2 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        shutdown.request();
        handle.join().unwrap();

        assert_eq!(output.pop().unwrap().txn.pipeline_seq, 1);
        assert_eq!(output.pop().unwrap().txn.pipeline_seq, 2);
    }
}
