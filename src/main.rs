fn main() {
    if rpkv2::version::print_if_requested_from_env() {
        return;
    }

    println!("rpkv2 — RPK QUIC validator pipeline");
    println!();
    println!("Available binaries:");
    println!("  demo               — end-to-end pipeline demo (server + load-gen)");
    println!("  server             — RPK QUIC echo server");
    println!("  client             — RPK QUIC client");
    println!("  bench_handshake    — RPK handshake latency benchmark");
    println!("  bench_handshake_tls— standard TLS 1.3 handshake benchmark (comparison)");
    println!("  bench_dgram        — datagram throughput benchmark");
    println!("  bench_stream       — stream write throughput benchmark");
    println!("  fast_rx            — raw UDP receive worker (pps counter)");
    println!("  fast_tx            — raw UDP transmit load generator");
    println!();
    println!("Run any binary with --help for usage.");
}
