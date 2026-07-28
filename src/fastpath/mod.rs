//! fastpath: low-latency, high-pps pipeline
//!
//! Modules:
//! - packet: header encode/decode + replay filter
//! - crypto: batch Ed25519 verification service

pub mod crypto;
pub mod packet;
