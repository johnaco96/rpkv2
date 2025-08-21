#![cfg(feature = "dpdk")]
use anyhow::Result;
use core_affinity::CoreId;
use std::time::{Duration, Instant};

use crate::fastpath::{crypto::CryptoService, packet::{Header, ReplayFilter}};

#[derive(Clone, Debug)]
pub struct DpdkConfig {
    pub port: u16,
    pub queue: u16,
    pub core: Option<usize>,
    pub rx_batch: usize,
    pub tx_batch: usize,
    pub bloom_bits: usize,
    pub bloom_fp: f64,
    pub replay_window: u64,
}

impl Default for DpdkConfig {
    fn default() -> Self {
        Self {
            port: 0,
            queue: 0,
            core: None,
            rx_batch: 256,
            tx_batch: 256,
            bloom_bits: 1 << 20,
            bloom_fp: 1e-6,
            replay_window: 2048,
        }
    }
}

pub struct DpdkWorker {
    cfg: DpdkConfig,
    crypto: CryptoService,
    replay: ReplayFilter,
    // TODO: add Capsule/DPDK port/queue handles
}

impl DpdkWorker {
    pub fn new(cfg: DpdkConfig) -> Result<Self> {
        Ok(Self {
            crypto: CryptoService::start(),
            replay: ReplayFilter::new(cfg.bloom_bits, cfg.bloom_fp, cfg.replay_window, 0),
            cfg,
        })
    }

    pub fn run(mut self) -> Result<()> {
        if let Some(core) = self.cfg.core {
            let _ = core_affinity::set_for_current(CoreId { id: core });
        }

        // TODO: Initialize EAL, configure port, start RX/TX queue, mempools, etc.
        let mut last = Instant::now();
        let mut pkts = 0u64;

        loop {
            // === RX burst (TBD: rte_eth_rx_burst via Capsule) ===
            std::thread::sleep(Duration::from_millis(10));

            if last.elapsed() >= Duration::from_secs(1) {
                tracing::info!("dpdk: pps ~{}", pkts);
                pkts = 0;
                last = Instant::now();
                self.replay.maybe_cleanup();
            }
        }
    }

    #[allow(dead_code)]
    fn process_one(&mut self, frame: &[u8]) {
        if let Ok((h, _)) = Header::decode_from(frame) {
            if !self.replay.accept(h.slot, h.nonce) {
                return;
            }
            // TODO: batch-verify and forward
        }
    }
}
