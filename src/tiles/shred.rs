use crate::tiles::Tile;
use bytes::Bytes;
use crossbeam_queue::ArrayQueue;
use std::{sync::Arc, thread, time::Duration};

use super::poh::PohEntry;

/// A tiny "shred": chunk of an entry (no erasure coding yet).
#[derive(Clone)]
pub struct Shred {
    pub slot: u64,
    pub index: u16,
    pub last: bool,
    pub data: Bytes,
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
    fn start(self) -> thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let mtu = self.mtu.max(256);
            loop {
                if let Some(entry) = self.rx.pop() {
                    // concatenate payloads as a simple "block"
                    let mut blob = Vec::new();
                    for bb in &entry.batches {
                        for v in &bb.txns {
                            blob.extend_from_slice(&v.txn.payload);
                        }
                    }
                    // chunk into shreds
                    let mut idx: u16 = 0;
                    let mut off = 0;
                    let len = blob.len();
                    while off < len {
                        let end = (off + mtu).min(len);
                        let last = end == len;
                        let s = Shred {
                            slot: entry.slot,
                            index: idx,
                            last,
                            data: Bytes::copy_from_slice(&blob[off..end]),
                        };
                        let _ = self.tx.push(s);
                        idx = idx.wrapping_add(1);
                        off = end;
                    }
                } else {
                    thread::sleep(Duration::from_micros(50));
                }
            }
        })
    }
}
