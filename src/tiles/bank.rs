use crate::backpressure::{INTERNAL_STAGE_POLICY, push_with_policy};
use crate::shutdown::Shutdown;
use crate::tiles::{IdleWait, Tile, VerifiedQueue, VerifiedTxn};
use crossbeam_queue::ArrayQueue;
use std::{
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

/// A "bank batch" = a group of verified txns for the same slot.
/// (In Phase 2 you’ll adapt this to Agave’s Bank ingestion.)
#[derive(Clone)]
pub struct BankBatch {
    pub slot: u64,
    pub txns: Vec<VerifiedTxn>,
}

pub type BankOutQueue = Arc<ArrayQueue<BankBatch>>;

pub struct Bank {
    pub rx: VerifiedQueue,
    pub tx: BankOutQueue,
    pub batch_size: usize,
    pub flush_ms: u64,
}

impl Tile for Bank {
    fn start_with_shutdown(self, shutdown: Shutdown) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let mut cur_slot: u64 = 0;
            let mut buf: Vec<VerifiedTxn> = Vec::with_capacity(self.batch_size);
            let mut last = Instant::now();
            let mut idle = IdleWait::new();

            while !shutdown.is_requested() || !self.rx.is_empty() {
                if let Some(v) = self.rx.pop() {
                    idle.reset();
                    if !v.ok {
                        continue;
                    }
                    let slot = v.txn.header.slot;
                    if buf.is_empty() {
                        cur_slot = slot;
                    }
                    if slot != cur_slot || buf.len() >= self.batch_size {
                        // flush previous slot/batch
                        if !buf.is_empty() {
                            push_bank_batch(&self.tx, cur_slot, &mut buf);
                        }
                        cur_slot = slot;
                    }
                    buf.push(v);
                    if buf.len() >= self.batch_size {
                        push_bank_batch(&self.tx, cur_slot, &mut buf);
                    }
                    last = Instant::now();
                } else {
                    // periodic flush
                    if !buf.is_empty() && last.elapsed() >= Duration::from_millis(self.flush_ms) {
                        push_bank_batch(&self.tx, cur_slot, &mut buf);
                    }
                    idle.snooze();
                }
            }
            if !buf.is_empty() {
                push_bank_batch(&self.tx, cur_slot, &mut buf);
            }
        })
    }
}

fn push_bank_batch(tx: &BankOutQueue, slot: u64, buf: &mut Vec<VerifiedTxn>) {
    crate::metrics::global().record_transactions_banked(buf.len() as u64);
    push_with_policy(
        "bank_to_poh",
        tx,
        BankBatch {
            slot,
            txns: std::mem::take(buf),
        },
        INTERNAL_STAGE_POLICY,
    );
}
