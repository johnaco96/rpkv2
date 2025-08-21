use std::sync::Arc;
use std::time::Duration;

use quinn::{
    ClientConfig, EndpointConfig, IdleTimeout, ServerConfig, TransportConfig, VarInt,
};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::{ClientConfig as TlsClientConfig, ServerConfig as TlsServerConfig};

pub fn tuned_transport() -> Arc<TransportConfig> {
    let mut t = TransportConfig::default();

    // --- Timeouts / keepalive ---
    t.max_idle_timeout(Some(IdleTimeout::from(VarInt::from_u32(30_000)))); // 30s in ms
    t.keep_alive_interval(Some(Duration::from_secs(5)));

    // --- Flow control / send limits ---
    // Max connection-level bytes the peer may send that we buffer
    t.receive_window(VarInt::from_u32(4 * 1024 * 1024));
    // Per-stream receive window
    t.stream_receive_window(VarInt::from_u32(256 * 1024));

    // Cap on our own outstanding bytes in flight (congestion/cc upper bound)
    t.send_window(4_u64 * 1024 * 1024);

    // --- Datagram buffers (unordered, loss-tolerant) ---
    t.datagram_receive_buffer_size(Some(4 * 1024 * 1024));
    t.datagram_send_buffer_size(4 * 1024 * 1024);

    // --- MTU discovery (optional but useful) ---
    // You can tune the upper bound if you know your network; defaults are safe.
    // let mut mtu = quinn::MtuDiscoveryConfig::default();
    // mtu.upper_bound(1452); // IPv4/IPv6-friendly upper bound (payload bytes)
    // t.mtu_discovery_config(Some(mtu));

    Arc::new(t)
}

pub fn server_config(tls: Arc<TlsServerConfig>) -> ServerConfig {
    let quic_tls = Arc::new(QuicServerConfig::try_from(tls).expect("tls->quic"));
    let mut sc = ServerConfig::with_crypto(quic_tls);
    sc.transport_config(tuned_transport());
    sc
}

pub fn client_config(tls: Arc<TlsClientConfig>) -> ClientConfig {
    let quic_tls = Arc::new(QuicClientConfig::try_from(tls).expect("tls->quic"));
    let mut cc = ClientConfig::new(quic_tls);
    cc.transport_config(tuned_transport());
    cc
}

pub fn endpoint_config() -> EndpointConfig {
    let mut e = EndpointConfig::default();
    // Maximum UDP payload we’ll accept from peers (excludes UDP/IP headers).
    // Method returns Result, ignore if you like:
    let _ = e.max_udp_payload_size(1350);
    e
}
