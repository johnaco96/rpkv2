#![cfg(feature = "afxdp")]
use anyhow::Result;
use core_affinity::CoreId;
use std::time::{Duration, Instant};

use crate::fastpath::{crypto::CryptoService, packet::{Header, ReplayFilter, HEADER_LEN}};

/// Minimal AF_XDP config. Extend as needed.
#[derive(Clone, Debug)]
pub struct AfxdpConfig {
    pub ifname: String,
    pub queue: u16,
    pub rx_batch: usize,
    pub tx_batch: usize,
    pub core: Option<usize>,
    pub bloom_bits: usize,
    pub bloom_fp: f64,
    pub replay_window: u64,
}

impl Default for AfxdpConfig {
    fn default() -> Self {
        Self {
            ifname: "eth0".into(),
            queue: 0,
            rx_batch: 256,
            tx_batch: 256,
            core: None,
            bloom_bits: 1 << 20,
            bloom_fp: 1e-6,
            replay_window: 2048,
        }
    }
}

/// A single-queue AF_XDP worker. The actual AF_XDP socket setup is TBD — this file
/// focuses on the poll loop structure and integration points (replay + crypto).
pub struct AfxdpWorker {
    cfg: AfxdpConfig,
    crypto: CryptoService,
    replay: ReplayFilter,
    // TODO: add UMEM, rings, and xsk handle once you pull the AF_XDP crate you prefer.
}

impl AfxdpWorker {
    pub fn new(cfg: AfxdpConfig) -> Result<Self> {
        let start_slot = 0;
        Ok(Self {
            crypto: CryptoService::start(),
            replay: ReplayFilter::new(cfg.bloom_bits, cfg.bloom_fp, cfg.replay_window, start_slot),
            cfg,
        })
    }

    /// Pin to core (if configured) and enter the poll loop.
    pub fn run(mut self) -> Result<()> {
        if let Some(core) = self.cfg.core {
            let _ = core_affinity::set_for_current(CoreId { id: core });
        }

        // Placeholder poll loop: in a real AF_XDP integration, replace the
        // dummy batch generation with RX ring peeks.
        let mut last = Instant::now();
        let mut pkts = 0u64;

        loop {
            // === RX batch (TBD: AF_XDP ring) ===
            // let descriptors = self.xsk.rx_peek(self.cfg.rx_batch);
            // for d in descriptors { let frame = self.umem.get(d.addr()); ... }

            // For now, pretend we "received" nothing; just idle a bit
            std::thread::sleep(Duration::from_millis(10));

            // periodic housekeeping
            if last.elapsed() >= Duration::from_secs(1) {
                tracing::info!("afxdp: pps ~{}", pkts);
                pkts = 0;
                last = Instant::now();
                self.replay.maybe_cleanup();
            }
        }
    }

    #[allow(dead_code)]
    fn process_one(&mut self, frame: &[u8]) {
        // Parse header
        let (h, _used) = match Header::decode_from(frame) {
            Ok(t) => t,
            Err(_) => return,
        };
        if !self.replay.accept(h.slot, h.nonce) {
            return; // drop replay
        }

        // Crypto: verify (pubkey, msg, sig)
        // NOTE: in a real pipeline, you'd collect a batch then call crypto.verify_blocking(...)
        // Here we’d call the service once we accumulate enough items.
        // After verification, forward/echo/drop.
    }
}
