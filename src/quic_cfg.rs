use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, EndpointConfig, IdleTimeout, ServerConfig, TransportConfig, VarInt};
use rustls::{ClientConfig as TlsClientConfig, ServerConfig as TlsServerConfig};

#[derive(Clone, Copy, Debug)]
pub struct TransportTuning {
    pub receive_window_bytes: u32,
    pub stream_receive_window_bytes: u32,
    pub send_window_bytes: u64,
    pub datagram_receive_buffer_bytes: usize,
    pub datagram_send_buffer_bytes: usize,
}

impl Default for TransportTuning {
    fn default() -> Self {
        Self {
            receive_window_bytes: 4 * 1024 * 1024,
            stream_receive_window_bytes: 256 * 1024,
            send_window_bytes: 4 * 1024 * 1024,
            datagram_receive_buffer_bytes: 4 * 1024 * 1024,
            datagram_send_buffer_bytes: 4 * 1024 * 1024,
        }
    }
}

pub fn tuned_transport() -> Arc<TransportConfig> {
    tuned_transport_with(TransportTuning::default())
}

pub fn tuned_transport_with(tuning: TransportTuning) -> Arc<TransportConfig> {
    let mut t = TransportConfig::default();

    // --- Timeouts / keepalive ---
    t.max_idle_timeout(Some(IdleTimeout::from(VarInt::from_u32(30_000)))); // 30s in ms
    t.keep_alive_interval(Some(Duration::from_secs(5)));

    // --- Flow control / send limits ---
    // Max connection-level bytes the peer may send that we buffer
    t.receive_window(VarInt::from_u32(tuning.receive_window_bytes));
    // Per-stream receive window
    t.stream_receive_window(VarInt::from_u32(tuning.stream_receive_window_bytes));

    // Cap on our own outstanding bytes in flight (congestion/cc upper bound)
    t.send_window(tuning.send_window_bytes);

    // --- Datagram buffers (unordered, loss-tolerant) ---
    t.datagram_receive_buffer_size(Some(tuning.datagram_receive_buffer_bytes));
    t.datagram_send_buffer_size(tuning.datagram_send_buffer_bytes);

    // --- MTU discovery (optional but useful) ---
    // You can tune the upper bound if you know your network; defaults are safe.
    // let mut mtu = quinn::MtuDiscoveryConfig::default();
    // mtu.upper_bound(1452); // IPv4/IPv6-friendly upper bound (payload bytes)
    // t.mtu_discovery_config(Some(mtu));

    Arc::new(t)
}

pub fn server_config(tls: Arc<TlsServerConfig>) -> ServerConfig {
    server_config_with_tuning(tls, TransportTuning::default())
}

pub fn server_config_with_tuning(
    tls: Arc<TlsServerConfig>,
    tuning: TransportTuning,
) -> ServerConfig {
    let quic_tls = Arc::new(QuicServerConfig::try_from(tls).expect("tls->quic"));
    let mut sc = ServerConfig::with_crypto(quic_tls);
    sc.transport_config(tuned_transport_with(tuning));
    sc
}

pub fn client_config(tls: Arc<TlsClientConfig>) -> ClientConfig {
    client_config_with_tuning(tls, TransportTuning::default())
}

pub fn client_config_with_tuning(
    tls: Arc<TlsClientConfig>,
    tuning: TransportTuning,
) -> ClientConfig {
    let quic_tls = Arc::new(QuicClientConfig::try_from(tls).expect("tls->quic"));
    let mut cc = ClientConfig::new(quic_tls);
    cc.transport_config(tuned_transport_with(tuning));
    cc
}

pub fn endpoint_config() -> EndpointConfig {
    let mut e = EndpointConfig::default();
    // Maximum UDP payload we’ll accept from peers (excludes UDP/IP headers).
    // Method returns Result, ignore if you like:
    let _ = e.max_udp_payload_size(1350);
    e
}
