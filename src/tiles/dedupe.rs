use crate::fastpath::packet::ReplayFilter;
use crate::tiles::{Tile, Txn, TxnQueue};
use std::{thread, time::Duration};

/// Pipeline tile: pulls Txn from `rx`, drops replays, pushes fresh to `tx`.
pub struct Deduper {
    pub rx: TxnQueue,
    pub tx: TxnQueue,
    /// Expected unique (slot,nonce) entries in the active window.
    pub cap: usize,
    /// Max slots to keep before an entry is considered stale.
    pub window: u64,
    /// How often to rebuild the bloom (ms).
    pub cleanup_ms: u64,
    /// Target false-positive rate.
    pub fp_rate: f64,
}

impl Tile for Deduper {
    fn start(self) -> std::thread::JoinHandle<()> {
        thread::spawn(move || {
            // Build replay filter inside the worker
            let mut rf = ReplayFilter::new(self.cap, self.fp_rate, self.window, self.cleanup_ms);

            loop {
                if let Some(t) = self.rx.pop() {
                    if rf.accept(t.header.slot, t.header.nonce) {
                        let _ = self.tx.push(t);
                    }
                    rf.maybe_cleanup();
                } else {
                    // no work; back off a hair
                    thread::sleep(Duration::from_micros(50));
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use crate::tiles::{Txn};
    use crossbeam_queue::ArrayQueue;
    use std::sync::Arc;

    #[test]
    fn deduper_drops_replays() {
        let rx: TxnQueue = Arc::new(ArrayQueue::new(8));
        let tx: TxnQueue = Arc::new(ArrayQueue::new(8));

        // Push two identical (slot, nonce)
        let mk = |slot, nonce| Txn {
            header: crate::fastpath::packet::Header { slot, nonce, ..Default::default() },
            payload: Bytes::from_static(b"x"),
            recv_ts_ns: 0,
        };
        rx.push(mk(100, 1)).unwrap();
        rx.push(mk(100, 1)).unwrap();

        let d = Deduper { rx: rx.clone(), tx: tx.clone(), cap: 1024, window: 1024, cleanup_ms: 100, fp_rate: 1e-6 };
        let h = d.start();

        // give it a moment to run
        std::thread::sleep(Duration::from_millis(50));

        assert_eq!(tx.len(), 1, "second duplicate should be dropped");
        // terminate thread
        drop(h);
    }
}
