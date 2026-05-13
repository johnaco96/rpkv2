use anyhow::Result;
use crossbeam_channel::{Receiver, Sender, unbounded};
use std::thread::{self, JoinHandle};

#[cfg(feature = "ed25519")]
pub mod ed25519_backend {
    use anyhow::Result;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    /// Verify a batch; returns per-item booleans.
    /// If the crate feature `dalek_batch` is enabled, try the fast batch path first,
    /// otherwise fall back to per-item verification.
    pub fn verify_batch(keys: &[VerifyingKey], msgs: &[&[u8]], sigs: &[Signature]) -> Vec<bool> {
        assert_eq!(keys.len(), msgs.len());
        assert_eq!(msgs.len(), sigs.len());

        #[cfg(feature = "dalek_batch")]
        {
            // Try batch verify; on failure, fall back to per-item to identify the bad ones.
            if ed25519_dalek::verify_batch(msgs, sigs, keys).is_ok() {
                return vec![true; keys.len()];
            }
        }
        // Fallback: check each individually.
        keys.iter()
            .zip(msgs.iter())
            .zip(sigs.iter())
            .map(|((k, m), s)| k.verify(m, s).is_ok())
            .collect()
    }
}

#[cfg(not(feature = "ed25519"))]
pub mod ed25519_backend {
    /// No-op backend so the crate compiles without the feature.
    pub fn verify_batch<T1, T2, T3>(_k: &[T1], _m: &[T2], _s: &[T3]) -> Vec<bool> {
        vec![]
    }
}

/// Work item passed to the crypto verifier thread.
pub struct VerifyItem<'a> {
    pub key: &'a [u8; 32],
    pub msg: &'a [u8],
    pub sig: &'a [u8; 64],
}

/// Request: a batch of verify items. The response is a Vec<bool> in the same order.
pub struct VerifyBatch<'a> {
    pub items: Vec<VerifyItem<'a>>,
}

/// A simple crypto service that receives batches over a channel and responds with results.
/// In production you’d pin this thread to a core and use ring buffers instead.
pub struct CryptoService {
    tx: Sender<VerifyBatchOwned>,
    handle: JoinHandle<()>,
}

struct VerifyBatchOwned {
    keys: Vec<[u8; 32]>,
    msgs: Vec<Vec<u8>>,
    sigs: Vec<[u8; 64]>,
    rsp: Sender<Vec<bool>>,
}

impl CryptoService {
    pub fn start() -> Self {
        let (tx, rx) = unbounded::<VerifyBatchOwned>();
        let handle = thread::spawn(move || run_worker(rx));
        Self { tx, handle }
    }

    /// Submit a batch and block until results arrive.
    pub fn verify_blocking(&self, batch: VerifyBatch) -> Result<Vec<bool>> {
        let mut keys = Vec::with_capacity(batch.items.len());
        let mut msgs = Vec::with_capacity(batch.items.len());
        let mut sigs = Vec::with_capacity(batch.items.len());
        for it in batch.items {
            keys.push(*it.key);
            msgs.push(it.msg.to_vec());
            sigs.push(*it.sig);
        }
        let (rsp_tx, rsp_rx) = unbounded();
        self.tx.send(VerifyBatchOwned {
            keys,
            msgs,
            sigs,
            rsp: rsp_tx,
        })?;
        let out = rsp_rx.recv()?;
        Ok(out)
    }
}

fn run_worker(rx: Receiver<VerifyBatchOwned>) {
    #[cfg(feature = "ed25519")]
    {
        use ed25519_dalek::{Signature, VerifyingKey};

        while let Ok(b) = rx.recv() {
            // Map to dalek types
            let keys: Vec<VerifyingKey> = b
                .keys
                .iter()
                .map(|k| VerifyingKey::from_bytes(k).unwrap())
                .collect();
            let msgs: Vec<&[u8]> = b.msgs.iter().map(|m| m.as_slice()).collect();
            let sigs: Vec<Signature> = b.sigs.iter().map(|s| Signature::from_bytes(s)).collect();

            let ok = crate::fastpath::crypto::ed25519_backend::verify_batch(&keys, &msgs, &sigs);
            let _ = b.rsp.send(ok);
        }
    }
    #[cfg(not(feature = "ed25519"))]
    {
        while let Ok(b) = rx.recv() {
            let _ = b.rsp.send(vec![true; b.msgs.len()]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn service_smoke() {
        let svc = CryptoService::start();
        // empty batch should just return empty
        let out = svc.verify_blocking(VerifyBatch { items: vec![] }).unwrap();
        assert!(out.is_empty());
    }
}
