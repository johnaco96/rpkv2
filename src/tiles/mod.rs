use std::sync::Arc;
use crossbeam_queue::ArrayQueue;
use bytes::Bytes;

pub mod dedupe;
pub mod pack;
pub mod shred;
pub mod verify;
pub mod poh;
pub mod signing;
pub mod storage;
pub mod bank;


#[derive(Clone, Debug)]
pub struct Txn {
    pub header: crate::fastpath::packet::Header,
    pub payload: Bytes,              // zero-copy payload
    pub recv_ts_ns: u64,             // for latency
}

#[derive(Clone)]
pub struct VerifiedTxn {
    pub txn: Txn,
    pub ok: bool,
}

pub type TxnQueue = Arc<ArrayQueue<Txn>>;
pub type VerifiedQueue = Arc<ArrayQueue<VerifiedTxn>>;

/// All tiles share this minimal lifecycle.
pub trait Tile {
    fn start(self) -> std::thread::JoinHandle<()>;
}
