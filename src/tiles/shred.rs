use crate::backpressure::{INTERNAL_STAGE_POLICY, push_with_policy};
use crate::shutdown::Shutdown;
use crate::tiles::{IdleWait, Tile};
use bytes::Bytes;
use crossbeam_queue::ArrayQueue;
use std::{sync::Arc, thread};

use super::poh::PohEntry;

const ENTRY_HASH_LEN: usize = 32;

/// A bounded chunk of a hashed entry. Erasure coding is not implemented.
#[derive(Clone)]
pub struct Shred {
    pub sequence: u64,
    pub slot: u64,
    pub index: u16,
    pub last: bool,
    pub data: Bytes,
    /// Transactions completed by this entry, carried only by its final shred.
    pub completed_transactions: u64,
}
pub type ShredOutQueue = Arc<ArrayQueue<Shred>>;
pub type PohInQueue = Arc<ArrayQueue<PohEntry>>;

pub struct Shredder {
    pub rx: PohInQueue,
    pub tx: ShredOutQueue,
    /// max payload per shred (bytes)
    pub mtu: usize,
}

impl Tile for Shredder {
    fn start_with_shutdown(self, shutdown: Shutdown) -> thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let mtu = self.mtu.max(256);
            let mut idle = IdleWait::new();
            let mut shred_sequence = 0u64;
            while !shutdown.is_requested() || !self.rx.is_empty() {
                if let Some(entry) = self.rx.pop() {
                    idle.reset();
                    // Prefix the payload stream with its chained entry hash so the
                    // digest is retained by downstream signing and storage.
                    let mut blob = Vec::with_capacity(ENTRY_HASH_LEN);
                    blob.extend_from_slice(&entry.hash);
                    for bb in &entry.batches {
                        for v in &bb.txns {
                            blob.extend_from_slice(&v.txn.payload);
                        }
                    }
                    // chunk into shreds
                    let mut idx: u16 = 0;
                    let mut off = 0;
                    let len = blob.len();
                    let completed_transactions = entry
                        .batches
                        .iter()
                        .map(|batch| batch.txns.len() as u64)
                        .sum();
                    while off < len {
                        let end = (off + mtu).min(len);
                        let last = end == len;
                        let s = Shred {
                            sequence: shred_sequence,
                            slot: entry.slot,
                            index: idx,
                            last,
                            data: Bytes::copy_from_slice(&blob[off..end]),
                            completed_transactions: if last { completed_transactions } else { 0 },
                        };
                        crate::metrics::global().record_shred_produced();
                        shred_sequence = shred_sequence.saturating_add(1);
                        push_with_policy("shred_to_sign", &self.tx, s, INTERNAL_STAGE_POLICY);
                        idx = idx.wrapping_add(1);
                        off = end;
                    }
                } else {
                    idle.snooze();
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        shutdown::Shutdown,
        tiles::{Txn, VerifiedTxn, bank::BankBatch},
    };
    use std::time::Duration;

    fn entry(hash: [u8; 32], payload: &'static [u8]) -> PohEntry {
        PohEntry {
            slot: 9,
            hash,
            batches: vec![BankBatch {
                slot: 9,
                txns: vec![VerifiedTxn {
                    txn: Txn {
                        header: crate::fastpath::packet::Header {
                            slot: 9,
                            ..Default::default()
                        },
                        payload: Bytes::from_static(payload),
                        peer: "test-peer".to_string(),
                        recv_ts_ns: 0,
                        pipeline_seq: 0,
                    },
                    ok: true,
                }],
            }],
        }
    }

    #[test]
    fn shreds_retain_entry_hash_and_transaction_count() {
        let input = Arc::new(ArrayQueue::new(2));
        let output = Arc::new(ArrayQueue::new(4));
        let hash = [7u8; 32];
        assert!(input.push(entry(hash, b"payload")).is_ok());
        let shutdown = Shutdown::new();
        let handle = Shredder {
            rx: input,
            tx: output.clone(),
            mtu: 256,
        }
        .start_with_shutdown(shutdown.clone());

        for _ in 0..100 {
            if !output.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        shutdown.request();
        handle.join().expect("shredder thread");

        let shred = output.pop().expect("output shred");
        assert_eq!(&shred.data[..ENTRY_HASH_LEN], &hash);
        assert_eq!(&shred.data[ENTRY_HASH_LEN..], b"payload");
        assert!(shred.last);
        assert_eq!(shred.completed_transactions, 1);
    }
}
