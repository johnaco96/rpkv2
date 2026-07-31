use crate::backpressure::{INTERNAL_STAGE_POLICY, push_with_policy};
use crate::shutdown::Shutdown;
use crate::tiles::{IdleWait, Tile};
use crossbeam_queue::ArrayQueue;
use std::{collections::BTreeMap, thread};

use super::shred::Shred;

#[cfg(feature = "ed25519")]
const SHRED_SIGNATURE_DOMAIN: &[u8] = b"rpkv2.signed_shred.v1";

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
    /// Validator signing key for this pipeline role.
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
                        let preimage = signing_preimage(&s);
                        let sig = self.key.sign(&preimage);
                        let mut out = [0u8; 64];
                        out.copy_from_slice(&sig.to_bytes());
                        Sig64(out)
                    };
                    #[cfg(all(not(feature = "ed25519"), feature = "insecure_demo"))]
                    let sig = Sig64([0u8; 64]); // insecure demo-only stub

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

#[cfg(feature = "ed25519")]
fn signing_preimage(shred: &Shred) -> Vec<u8> {
    signing_preimage_fields(shred.slot, shred.index, shred.last, &shred.data)
}

#[cfg(feature = "ed25519")]
fn signing_preimage_fields(slot: u64, index: u16, last: bool, data: &[u8]) -> Vec<u8> {
    let mut preimage =
        Vec::with_capacity(SHRED_SIGNATURE_DOMAIN.len() + 8 + 2 + 1 + 8 + data.len());
    preimage.extend_from_slice(SHRED_SIGNATURE_DOMAIN);
    preimage.extend_from_slice(&slot.to_le_bytes());
    preimage.extend_from_slice(&index.to_le_bytes());
    preimage.push(u8::from(last));
    preimage.extend_from_slice(&(data.len() as u64).to_le_bytes());
    preimage.extend_from_slice(data);
    preimage
}

/// Verify a signed shred against the validator key assigned to the signing role.
#[cfg(feature = "ed25519")]
pub fn verify_signed_shred(
    shred: &SignedShred,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> bool {
    use ed25519_dalek::Verifier;
    let signature = ed25519_dalek::Signature::from_bytes(&shred.sig.0);
    let preimage = signing_preimage_fields(shred.slot, shred.index, shred.last, &shred.data);
    verifying_key.verify(&preimage, &signature).is_ok()
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

#[cfg(all(test, feature = "ed25519"))]
mod tests {
    use super::*;
    use bytes::Bytes;
    use ed25519_dalek::SigningKey;

    fn shred() -> Shred {
        Shred {
            sequence: 3,
            slot: 12,
            index: 2,
            last: true,
            data: Bytes::from_static(b"entry-hash-and-payload"),
            completed_transactions: 4,
        }
    }

    #[test]
    fn signature_preimage_covers_persisted_metadata_and_data() {
        let original = shred();
        let original_preimage = signing_preimage(&original);

        let mut changed_slot = original.clone();
        changed_slot.slot += 1;
        assert_ne!(original_preimage, signing_preimage(&changed_slot));

        let mut changed_index = original.clone();
        changed_index.index += 1;
        assert_ne!(original_preimage, signing_preimage(&changed_index));

        let mut changed_last = original.clone();
        changed_last.last = false;
        assert_ne!(original_preimage, signing_preimage(&changed_last));

        let mut changed_data = original.clone();
        changed_data.data = Bytes::from_static(b"tampered");
        assert_ne!(original_preimage, signing_preimage(&changed_data));
    }

    #[test]
    fn signature_verifies_only_for_the_complete_preimage() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let original = shred();
        let signature = ed25519_dalek::Signer::sign(&key, &signing_preimage(&original));
        let signed = SignedShred {
            sequence: original.sequence,
            slot: original.slot,
            index: original.index,
            last: original.last,
            data: original.data.to_vec(),
            sig: Sig64(signature.to_bytes()),
            completed_transactions: original.completed_transactions,
        };
        assert!(verify_signed_shred(&signed, &key.verifying_key()));

        let mut tampered = signed;
        tampered.slot += 1;
        assert!(!verify_signed_shred(&tampered, &key.verifying_key()));
    }
}
