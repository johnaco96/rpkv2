use super::{VerifiedQueue, VerifiedTxn, Tile};
use crossbeam_queue::ArrayQueue;
use std::{sync::Arc, thread, time::Duration};

pub struct Pack {
    pub rx: VerifiedQueue,
    pub to_bank: Arc<ArrayQueue<VerifiedTxn>>,
}

impl Tile for Pack {
    fn start(self) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            loop {
                if let Some(v) = self.rx.pop() {
                    if v.ok { let _ = self.to_bank.push(v); }
                } else { thread::sleep(Duration::from_micros(50)); }
            }
        })
    }
}
