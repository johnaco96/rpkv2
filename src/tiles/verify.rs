use super::{Txn, VerifiedTxn, TxnQueue, VerifiedQueue, Tile};
use crate::fastpath::crypto::{CryptoService, VerifyBatch, VerifyItem};
use bytes::Bytes;
use std::{sync::Arc, thread, time::Duration};

pub struct Verifier {
    pub rx: TxnQueue,
    pub tx: VerifiedQueue,
    pub batch: usize,
    svc: CryptoService,
}

impl Verifier {
    pub fn new(rx: TxnQueue, tx: VerifiedQueue, batch: usize) -> Self {
        Self { rx, tx, batch, svc: CryptoService::start() }
    }
}
impl Tile for Verifier {
    fn start(self) -> thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let mut buf: Vec<Txn> = Vec::with_capacity(self.batch);
            loop {
                // fill a batch
                while buf.len() < self.batch {
                    if let Some(t) = self.rx.pop() { buf.push(t); } else { break; }
                }
                if buf.is_empty() { thread::sleep(Duration::from_micros(50)); continue; }

                // map to VerifyBatch
                let items: Vec<VerifyItem> = buf.iter().map(|t| VerifyItem {
                    key: unsafe { &*(t.header.pubkey.as_ptr() as *const [u8;32]) },
                    sig: unsafe { &*(t.header.signature.as_ptr() as *const [u8;64]) },
                    msg: &t.payload,
                }).collect();

                let oks = self.svc.verify_blocking(VerifyBatch { items }).unwrap_or_default();
                for (t, ok) in buf.drain(..).zip(oks.into_iter()) {
                    let _ = self.tx.push(VerifiedTxn { txn: t, ok });
                }
            }
        })
    }
}
