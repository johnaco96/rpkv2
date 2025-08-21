use crate::tiles::Tile;
use crossbeam_queue::ArrayQueue;
use std::{sync::Arc, thread, time::Duration};

use super::shred::{Shred};

#[derive(Clone, Copy)]
pub struct Sig64(pub [u8; 64]);

impl Default for Sig64 {
    fn default() -> Self {
        Sig64([0u8; 64])
    }
}

#[derive(Clone)]
pub struct SignedShred {
    pub slot: u64,
    pub index: u16,
    pub last: bool,
    pub data: Vec<u8>,
    pub sig: Sig64,
}

pub type SignedShredQueue = std::sync::Arc<ArrayQueue<SignedShred>>;
pub type ShredInQueue = std::sync::Arc<ArrayQueue<Shred>>;

pub struct Signer {
    pub rx: ShredInQueue,
    pub tx: SignedShredQueue,
    /// Optional static key for demo; real validator would use keypairs per-role
    #[cfg(feature = "ed25519")]
    pub key: ed25519_dalek::SigningKey,
}

impl Tile for Signer {
    fn start(self) -> thread::JoinHandle<()> {
        std::thread::spawn(move || {
            loop {
                if let Some(s) = self.rx.pop() {
                    #[cfg(feature = "ed25519")]
                    let sig = {
                        use ed25519_dalek::Signer;
                        let msg = &s.data;
                        let sig = self.key.sign(msg);
                        let mut out = [0u8; 64];
                        out.copy_from_slice(&sig.to_bytes());
                        Sig64(out)
                    };
                    #[cfg(not(feature = "ed25519"))]
                    let sig = Sig64([0u8; 64]); // stub if feature is off

                    let out = SignedShred {
                        slot: s.slot,
                        index: s.index,
                        last: s.last,
                        data: s.data.to_vec(),
                        sig,
                    };
                    let _ = self.tx.push(out);
                } else {
                    thread::sleep(Duration::from_micros(50));
                }
            }
        })
    }
}
