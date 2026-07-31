use anyhow::Result;
#[cfg(not(feature = "ed25519"))]
compile_error!("bench_dgram requires the ed25519 feature; stub verification is demo-only.");

use bytes::{BufMut, Bytes, BytesMut};
use clap::Parser;
use quinn::Endpoint;
use rpkv2::util::{Histo, pretty_throughput};
use rpkv2::{quic_cfg, runtime_mode::RuntimeMode, tls, version::VersionArgs};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::time::sleep;
use tracing::info;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:4433")]
    server: String,
    /// Padding bytes per packet (8-byte timestamp prefix is added on top).
    #[arg(long, default_value_t = 504)]
    payload: usize,
    #[arg(long, default_value_t = 10_000)]
    target_pkts: u64,
    /// Target send rate in packets/sec. Keeps the server from dropping packets.
    /// Recommended starting point: 10_000–50_000.
    #[arg(long, default_value_t = 20_000)]
    rate_pps: u64,
    #[arg(long, default_value = "server.pub")]
    pin_spki_pem: String,
    #[arg(long, default_value = "dgram_latency.csv")]
    out_csv: String,
    #[arg(long, value_enum, default_value_t = RuntimeMode::Benchmark)]
    mode: RuntimeMode,
    #[command(flatten)]
    version: VersionArgs,
}

#[tokio::main]
async fn main() -> Result<()> {
    tls::install_provider();
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .without_time()
        .init();

    let args = Args::parse();
    if args.version.print_and_exit_if_requested() {
        return Ok(());
    }
    if args.mode != RuntimeMode::Benchmark {
        anyhow::bail!("bench_dgram only supports --mode benchmark");
    }
    info!(mode = %args.mode, "runtime mode selected");
    let spki = tls::load_spki_from_pem(&args.pin_spki_pem)?;
    let tls_client = tls::build_client_rpk_pinned(spki);
    let client_cfg = quic_cfg::client_config(tls_client);

    let mut ep = Endpoint::client("0.0.0.0:0".parse::<SocketAddr>()?)?;
    ep.set_default_client_config(client_cfg);

    let conn = ep.connect(args.server.parse()?, "localhost")?.await?;
    info!("connected to {}", conn.remote_address());
    info!(
        "sending {} pkts at {} pps, {} bytes each (incl. 8-byte timestamp)",
        args.target_pkts,
        args.rate_pps,
        args.payload + 8
    );

    let start = Arc::new(Instant::now());
    let rtt_hist = Arc::new(Mutex::new(Histo::new(5_000_000)));

    // ── Receiver task — reads echoed datagrams and measures RTT ──────────────
    let c2 = conn.clone();
    let start2 = start.clone();
    let hist2 = rtt_hist.clone();
    let recv_task = tokio::spawn(async move {
        let mut echoed = 0u64;
        while let Ok(data) = c2.read_datagram().await {
            if data.len() >= 8 {
                // Extract the send timestamp (nanos since bench start)
                let t_sent_ns = u64::from_be_bytes(data[..8].try_into().unwrap());
                let now_ns = start2.elapsed().as_nanos() as u64;
                let rtt_us = now_ns.saturating_sub(t_sent_ns) / 1_000;
                hist2.lock().unwrap().record_us(rtt_us.max(1));
                echoed += 1;
            }
        }
        echoed
    });

    // ── Sender ────────────────────────────────────────────────────────────────
    let sleep_ns = 1_000_000_000u64.checked_div(args.rate_pps).unwrap_or(0);
    let mut sent = 0u64;
    let bench_start = Instant::now();

    while sent < args.target_pkts {
        // Embed send timestamp as first 8 bytes
        let t_now_ns = start.elapsed().as_nanos() as u64;
        let mut buf = BytesMut::with_capacity(8 + args.payload);
        buf.put_u64(t_now_ns);
        buf.put_bytes(0u8, args.payload);
        let pkt = Bytes::from(buf);

        match conn.send_datagram(pkt) {
            Ok(_) => sent += 1,
            Err(_) => {
                // QUIC backpressure — yield briefly and retry
                sleep(Duration::from_micros(50)).await;
                continue;
            }
        }

        if sleep_ns > 0 {
            sleep(Duration::from_nanos(sleep_ns)).await;
        }
    }

    // Wait for echoes to drain before closing
    sleep(Duration::from_secs(2)).await;
    conn.close(0u32.into(), b"done");

    let echoed = recv_task.await.unwrap_or(0);
    let dur = bench_start.elapsed();
    let bytes = sent * (args.payload as u64 + 8);

    let h = rtt_hist.lock().unwrap();
    info!(
        "dgrams sent={} echoed={} echo_rate={:.1}% dur={:?} thrpt={}",
        sent,
        echoed,
        (echoed as f64 / sent as f64) * 100.0,
        dur,
        pretty_throughput(bytes, dur)
    );
    info!(
        "RTT  p50={}µs  p99={}µs  p99.9={}µs  mean={:.1}µs",
        h.p(0.50),
        h.p(0.99),
        h.p(0.999),
        h.mean()
    );
    h.write_csv(&args.out_csv)?;
    Ok(())
}
