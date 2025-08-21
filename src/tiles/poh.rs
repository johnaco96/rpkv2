use crate::tiles::{Tile};
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
    fn start(self) -> thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let mut acc: Vec<BankBatch> = Vec::new();
            loop {
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
                    let entry = PohEntry { slot, hash, batches: std::mem::take(&mut acc) };
                    let _ = self.tx.push(entry);
                }
                thread::sleep(Duration::from_millis(self.tick_ms));
            }
        })
    }
}
