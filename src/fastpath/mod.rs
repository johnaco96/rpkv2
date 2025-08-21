//! fastpath: low-latency, high-pps pipeline
//!
//! Modules:
//! - packet: header encode/decode + replay filter
//! - crypto: batch Ed25519 verification service
//! - afxdp:  AF_XDP worker (feature = "afxdp")
//! - dpdk:   DPDK/Capsule worker (feature = "dpdk")

pub mod packet;
pub mod crypto;

#[cfg(feature = "afxdp")]
pub mod afxdp;
#[cfg(not(feature = "afxdp"))]
pub mod afxdp {
    /// Stub so the crate always compiles without the feature.
    #[derive(Clone, Debug)]
    pub struct AfxdpConfig {
        pub ifname: String,
        pub queue: u16,
        pub rx_batch: usize,
        pub tx_batch: usize,
        pub core: Option<usize>,
    }
    impl Default for AfxdpConfig {
        fn default() -> Self {
            Self { ifname: "eth0".into(), queue: 0, rx_batch: 256, tx_batch: 256, core: None }
        }
    }
    pub struct AfxdpWorker;
    impl AfxdpWorker {
        pub fn new(_cfg: AfxdpConfig) -> anyhow::Result<Self> {
            anyhow::bail!("feature 'afxdp' not enabled")
        }
        pub fn run(self) -> anyhow::Result<()> {
            anyhow::bail!("feature 'afxdp' not enabled")
        }
    }
}

#[cfg(feature = "dpdk")]
pub mod dpdk;
#[cfg(not(feature = "dpdk"))]
pub mod dpdk {
    /// Stub so the crate always compiles without the feature.
    #[derive(Clone, Debug)]
    pub struct DpdkConfig {
        pub port: u16,
        pub queue: u16,
        pub core: Option<usize>,
        pub rx_batch: usize,
        pub tx_batch: usize,
    }
    impl Default for DpdkConfig {
        fn default() -> Self {
            Self { port: 0, queue: 0, core: None, rx_batch: 256, tx_batch: 256 }
        }
    }
    pub struct DpdkWorker;
    impl DpdkWorker {
        pub fn new(_cfg: DpdkConfig) -> anyhow::Result<Self> {
            anyhow::bail!("feature 'dpdk' not enabled")
        }
        pub fn run(self) -> anyhow::Result<()> {
            anyhow::bail!("feature 'dpdk' not enabled")
        }
    }
}
