use crate::backpressure::{INTERNAL_STAGE_POLICY, push_with_policy};
use crate::shutdown::Shutdown;
use crate::tiles::{IdleWait, Tile};
use crossbeam_queue::ArrayQueue;
use std::{collections::BTreeMap, thread};

use super::shred::Shred;

#[derive(Clone, Copy)]
pub struct Sig64(pub [u8; 64]);

impl Default for Sig64 {
    fn default() -> Self {
        Sig64([0u8; 64])
    }
}

#[derive(Clone)]
pub struct SignedShred {
    pub sequence: u64,
    pub slot: u64,
    pub index: u16,
    pub last: bool,
    pub data: Vec<u8>,
    pub sig: Sig64,
    pub completed_transactions: u64,
}

pub type SignedShredQueue = std::sync::Arc<ArrayQueue<SignedShred>>;
pub type ShredInQueue = std::sync::Arc<ArrayQueue<Shred>>;

pub struct Signer {
    pub rx: ShredInQueue,
    pub tx: SignedShredQueue,
    /// Optional static key for demo; real validator would use keypairs per-role
    #[cfg(feature = "ed25519")]
    pub key: ed25519_dalek::SigningKey,
    pub batch_size: usize,
}

pub struct SigningOrder {
    pub rx: SignedShredQueue,
    pub tx: SignedShredQueue,
}

impl Tile for Signer {
    fn start_with_shutdown(self, shutdown: Shutdown) -> thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let mut idle = IdleWait::new();
            let mut batch = Vec::with_capacity(self.batch_size.max(1));
            while !shutdown.is_requested() || !self.rx.is_empty() {
                while batch.len() < self.batch_size.max(1) {
                    let Some(shred) = self.rx.pop() else {
                        break;
                    };
                    batch.push(shred);
                }
                if batch.is_empty() {
                    idle.snooze();
                    continue;
                }
                idle.reset();
                for s in batch.drain(..) {
                    #[cfg(feature = "ed25519")]
                    let sig = {
                        use ed25519_dalek::Signer;
                        let msg = &s.data;
                        let sig = self.key.sign(msg);
                        let mut out = [0u8; 64];
                        out.copy_from_slice(&sig.to_bytes());
                        Sig64(out)
                    };
                    #[cfg(all(not(feature = "ed25519"), feature = "insecure_demo"))]
                    let sig = Sig64([0u8; 64]); // insecure demo-only stub
                    #[cfg(all(not(feature = "ed25519"), not(feature = "insecure_demo")))]
                    let sig = Sig64([0u8; 64]);

                    let out = SignedShred {
                        sequence: s.sequence,
                        slot: s.slot,
                        index: s.index,
                        last: s.last,
                        data: s.data.to_vec(),
                        sig,
                        completed_transactions: s.completed_transactions,
                    };
                    push_with_policy("sign_to_storage", &self.tx, out, INTERNAL_STAGE_POLICY);
                }
            }
        })
    }
}

impl Tile for SigningOrder {
    fn start_with_shutdown(self, shutdown: Shutdown) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let mut idle = IdleWait::new();
            let mut next_sequence = 0u64;
            let mut pending = BTreeMap::new();
            while !shutdown.is_requested() || !self.rx.is_empty() {
                if let Some(shred) = self.rx.pop() {
                    idle.reset();
                    pending.insert(shred.sequence, shred);
                    while let Some(ordered) = pending.remove(&next_sequence) {
                        push_with_policy(
                            "sign_order_to_storage",
                            &self.tx,
                            ordered,
                            INTERNAL_STAGE_POLICY,
                        );
                        next_sequence = next_sequence.saturating_add(1);
                    }
                } else {
                    idle.snooze();
                }
            }
            if !pending.is_empty() {
                tracing::error!(
                    tile = "sign_order",
                    next_sequence,
                    pending = pending.len(),
                    reason = "signing_sequence_gap",
                    "ordered signing merge stopped with a sequence gap"
                );
            }
        })
    }
}
