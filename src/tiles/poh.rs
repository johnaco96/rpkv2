use crate::backpressure::{INTERNAL_STAGE_POLICY, push_with_policy};
use crate::shutdown::Shutdown;
use crate::tiles::Tile;
use blake3::Hasher;
use crossbeam_queue::ArrayQueue;
use std::{sync::Arc, thread, time::Duration};

use super::bank::BankBatch;

#[derive(Clone)]
pub struct PohEntry {
    pub slot: u64,
    pub hash: [u8; 32],
    pub batches: Vec<BankBatch>, // you can change to a single batch if you prefer
}
pub type PohOutQueue = Arc<ArrayQueue<PohEntry>>;
pub type BankInQueue = Arc<ArrayQueue<BankBatch>>;

pub struct Poh {
    pub rx: BankInQueue,
    pub tx: PohOutQueue,
    /// milliseconds between PoH ticks (fake PoH for now)
    pub tick_ms: u64,
}

impl Tile for Poh {
    fn start_with_shutdown(self, shutdown: Shutdown) -> thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let mut acc: Vec<BankBatch> = Vec::new();
            while !shutdown.is_requested() || !self.rx.is_empty() {
                // drain whatever is available this tick
                while let Some(b) = self.rx.pop() {
                    acc.push(b);
                }
                if !acc.is_empty() {
                    let slot = acc[0].slot;
                    // simple PoH: hash all txn payload bytes
                    let mut h = Hasher::new();
                    for bb in &acc {
                        for v in &bb.txns {
                            h.update(&v.txn.payload);
                        }
                    }
                    let hash = *h.finalize().as_bytes();
                    let entry = PohEntry {
                        slot,
                        hash,
                        batches: std::mem::take(&mut acc),
                    };
                    push_with_policy("poh_to_shred", &self.tx, entry, INTERNAL_STAGE_POLICY);
                }
                thread::sleep(Duration::from_millis(self.tick_ms));
            }
            while let Some(b) = self.rx.pop() {
                acc.push(b);
            }
            if !acc.is_empty() {
                let slot = acc[0].slot;
                let mut h = Hasher::new();
                for bb in &acc {
                    for v in &bb.txns {
                        h.update(&v.txn.payload);
                    }
                }
                push_with_policy(
                    "poh_to_shred",
                    &self.tx,
                    PohEntry {
                        slot,
                        hash: *h.finalize().as_bytes(),
                        batches: std::mem::take(&mut acc),
                    },
                    INTERNAL_STAGE_POLICY,
                );
            }
        })
    }
}
