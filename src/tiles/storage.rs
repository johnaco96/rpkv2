use crate::tiles::Tile;
use crossbeam_queue::ArrayQueue;
use std::{fs::{self, OpenOptions}, io::Write, path::PathBuf, sync::Arc, thread, time::Duration};

use super::signing::SignedShred;

pub type StoreInQueue = Arc<ArrayQueue<SignedShred>>;

/// Super-simple append-only storage: one file per slot.
/// (Replace with RocksDB/Agave blockstore later.)
pub struct Storage {
    pub rx: StoreInQueue,
    pub dir: PathBuf,
}

impl Tile for Storage {
    fn start(self) -> thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let _ = fs::create_dir_all(&self.dir);
            loop {
                if let Some(s) = self.rx.pop() {
                    let path = self.dir.join(format!("slot-{:012}.shred", s.slot));
                    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
                        let _ = f.write_all(&(s.index as u16).to_le_bytes());
                        let _ = f.write_all(&(s.last as u8).to_le_bytes());
                        let _ = f.write_all(&(s.data.len() as u32).to_le_bytes());
                        let _ = f.write_all(&s.data);
                        let _ = f.write_all(&s.sig.0);
                    }
                } else {
                    thread::sleep(Duration::from_micros(50));
                }
            }
        })
    }
}
