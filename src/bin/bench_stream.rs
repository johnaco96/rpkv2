use anyhow::Result;
#[cfg(not(feature = "ed25519"))]
compile_error!("bench_stream requires the ed25519 feature; stub verification is demo-only.");

use clap::Parser;
use quinn::Endpoint;
use rpkv2::util::{Histo, pretty_throughput};
use rpkv2::{quic_cfg, runtime_mode::RuntimeMode, tls, version::VersionArgs};
use std::{net::SocketAddr, time::Instant};

use tracing::info;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:4433")]
    server: String,
    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    total_bytes: usize, // e.g. 64 MiB
    #[arg(long, default_value_t = 16 * 1024)]
    chunk: usize, // e.g. 16 KiB
    #[arg(long, default_value = "server.pub")]
    pin_spki_pem: String,
    #[arg(long, default_value = "stream_write_latency.csv")]
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
        anyhow::bail!("bench_stream only supports --mode benchmark");
    }
    info!(mode = %args.mode, "runtime mode selected");
    let spki = tls::load_spki_from_pem(&args.pin_spki_pem)?;
    let tls_client = tls::build_client_rpk_pinned(spki);
    let client_cfg = quic_cfg::client_config(tls_client);

    let mut ep = Endpoint::client("0.0.0.0:0".parse::<SocketAddr>()?)?;
    ep.set_default_client_config(client_cfg);

    let conn = ep.connect(args.server.parse()?, "localhost")?.await?;
    info!("connected to {}", conn.remote_address());

    let mut send = conn.open_uni().await?;
    let mut remaining = args.total_bytes;
    let mut hist = Histo::new(10_000_000);
    let start = Instant::now();

    while remaining > 0 {
        let n = remaining.min(args.chunk);
        let t0 = Instant::now();
        send.write_all(&vec![0u8; n]).await?;
        hist.record_us(t0.elapsed().as_micros() as u64);
        remaining -= n;
    }
    let _ = send.finish();

    // Read the echo back
    let mut recv = conn.accept_uni().await?;
    let echoed = recv.read_to_end(args.total_bytes * 2).await?; // generous limit

    let dur = start.elapsed();
    info!(
        "stream bytes={} echo={} dur={:?} thrpt={}",
        args.total_bytes,
        echoed.len(),
        dur,
        pretty_throughput(args.total_bytes as u64, dur)
    );
    info!(
        "write latency p50={}us p99={}us",
        hist.p(0.50),
        hist.p(0.99)
    );
    hist.write_csv(&args.out_csv)?;
    Ok(())
}
