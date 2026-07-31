use crate::backpressure::{INTERNAL_STAGE_POLICY, push_with_policy};
use crate::shutdown::Shutdown;
use crate::tiles::Tile;
use blake3::Hasher;
use crossbeam_queue::ArrayQueue;
use std::{sync::Arc, thread, time::Duration};

use super::bank::BankBatch;

const POH_ENTRY_DOMAIN: &[u8] = b"rpkv2.poh_entry.v1";

#[derive(Clone)]
pub struct PohEntry {
    pub slot: u64,
    pub hash: [u8; 32],
    pub batches: Vec<BankBatch>,
}
pub type PohOutQueue = Arc<ArrayQueue<PohEntry>>;
pub type BankInQueue = Arc<ArrayQueue<BankBatch>>;

pub struct Poh {
    pub rx: BankInQueue,
    pub tx: PohOutQueue,
    /// Maximum delay before available batches are committed to the hash chain.
    pub tick_ms: u64,
}

impl Tile for Poh {
    fn start_with_shutdown(self, shutdown: Shutdown) -> thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let mut acc: Vec<BankBatch> = Vec::new();
            let mut previous_hash = [0u8; 32];
            while !shutdown.is_requested() || !self.rx.is_empty() {
                while let Some(batch) = self.rx.pop() {
                    if acc
                        .first()
                        .is_some_and(|current| current.slot != batch.slot)
                    {
                        previous_hash = emit_entry(&self.tx, previous_hash, &mut acc);
                    }
                    acc.push(batch);
                }
                previous_hash = emit_entry(&self.tx, previous_hash, &mut acc);
                thread::sleep(Duration::from_millis(self.tick_ms));
            }
            while let Some(batch) = self.rx.pop() {
                if acc
                    .first()
                    .is_some_and(|current| current.slot != batch.slot)
                {
                    previous_hash = emit_entry(&self.tx, previous_hash, &mut acc);
                }
                acc.push(batch);
            }
            emit_entry(&self.tx, previous_hash, &mut acc);
        })
    }
}

fn emit_entry(tx: &PohOutQueue, previous_hash: [u8; 32], batches: &mut Vec<BankBatch>) -> [u8; 32] {
    let Some(first) = batches.first() else {
        return previous_hash;
    };
    let slot = first.slot;
    debug_assert!(batches.iter().all(|batch| batch.slot == slot));
    let hash = entry_hash(previous_hash, slot, batches);
    push_with_policy(
        "poh_to_shred",
        tx,
        PohEntry {
            slot,
            hash,
            batches: std::mem::take(batches),
        },
        INTERNAL_STAGE_POLICY,
    );
    hash
}

fn entry_hash(previous_hash: [u8; 32], slot: u64, batches: &[BankBatch]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(POH_ENTRY_DOMAIN);
    hasher.update(&previous_hash);
    hasher.update(&slot.to_le_bytes());
    hasher.update(&(batches.len() as u64).to_le_bytes());
    for batch in batches {
        hasher.update(&(batch.txns.len() as u64).to_le_bytes());
        for verified in &batch.txns {
            hasher.update(&(verified.txn.payload.len() as u64).to_le_bytes());
            hasher.update(&verified.txn.payload);
        }
    }
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tiles::{Txn, VerifiedTxn};
    use bytes::Bytes;

    fn batch(slot: u64, payload: &'static [u8]) -> BankBatch {
        BankBatch {
            slot,
            txns: vec![VerifiedTxn {
                txn: Txn {
                    header: crate::fastpath::packet::Header {
                        slot,
                        ..Default::default()
                    },
                    payload: Bytes::from_static(payload),
                    peer: "test-peer".to_string(),
                    recv_ts_ns: 0,
                    pipeline_seq: 0,
                },
                ok: true,
            }],
        }
    }

    #[test]
    fn entry_hash_is_deterministic_and_chained() {
        let batches = vec![batch(7, b"first")];
        let first = entry_hash([0u8; 32], 7, &batches);
        assert_eq!(first, entry_hash([0u8; 32], 7, &batches));
        assert_ne!(first, entry_hash([1u8; 32], 7, &batches));
        assert_ne!(first, entry_hash(first, 7, &batches));
    }

    #[test]
    fn emit_entry_preserves_slot_boundaries() {
        let output = Arc::new(ArrayQueue::new(4));
        let mut first_slot = vec![batch(10, b"a"), batch(10, b"b")];
        let first_hash = emit_entry(&output, [0u8; 32], &mut first_slot);
        let mut second_slot = vec![batch(11, b"c")];
        emit_entry(&output, first_hash, &mut second_slot);

        let first = output.pop().expect("first entry");
        let second = output.pop().expect("second entry");
        assert_eq!(first.slot, 10);
        assert_eq!(first.batches.len(), 2);
        assert_eq!(second.slot, 11);
        assert_ne!(first.hash, second.hash);
    }
}
