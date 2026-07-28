use crate::shutdown::Shutdown;
use bytes::Bytes;
use crossbeam_queue::ArrayQueue;
use std::sync::Arc;
use std::time::Duration;

pub mod bank;
pub mod dedupe;
pub mod pack;
pub mod poh;
pub mod shred;
pub mod signing;
pub mod storage;
pub mod verify;

#[derive(Clone, Debug)]
pub struct Txn {
    pub header: crate::fastpath::packet::Header,
    pub payload: Bytes, // zero-copy payload
    pub peer: String,
    pub recv_ts_ns: u64, // for latency
    /// Deterministic order assigned after replay filtering and before parallel verification.
    pub pipeline_seq: u64,
}

#[derive(Clone)]
pub struct VerifiedTxn {
    pub txn: Txn,
    pub ok: bool,
}

pub type TxnQueue = Arc<ArrayQueue<Txn>>;
pub type VerifiedQueue = Arc<ArrayQueue<VerifiedTxn>>;

pub(crate) struct IdleWait {
    empty_polls: u32,
}

impl IdleWait {
    pub(crate) fn new() -> Self {
        Self { empty_polls: 0 }
    }

    pub(crate) fn reset(&mut self) {
        self.empty_polls = 0;
    }

    pub(crate) fn snooze(&mut self) {
        self.empty_polls = self.empty_polls.saturating_add(1);
        match self.empty_polls {
            0..=63 => std::hint::spin_loop(),
            64..=127 => std::thread::yield_now(),
            _ => std::thread::sleep(Duration::from_micros(50)),
        }
    }
}

/// All tiles share this minimal lifecycle.
pub trait Tile: Sized {
    fn start(self) -> std::thread::JoinHandle<()> {
        self.start_with_shutdown(Shutdown::new())
    }

    fn start_with_shutdown(self, shutdown: Shutdown) -> std::thread::JoinHandle<()>;
}
