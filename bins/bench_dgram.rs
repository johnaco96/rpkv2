use anyhow::Result;
use bytes::Bytes;
use clap::Parser;
use quinn::Endpoint;
use rpkv2::{tls, quic_cfg};
use rpkv2::util::{Histo, pretty_throughput};
use std::{net::SocketAddr, time::Instant};
use tokio::time::{sleep, Duration};
use tracing::info;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:4433")]
    server: String,
    #[arg(long, default_value_t = 512)]
    payload: usize,
    #[arg(long, default_value_t = 200_000)]
    target_pkts: u64,
    #[arg(long, default_value = "server.pub")]
    pin_spki_pem: String,
    #[arg(long, default_value = "dgram_latency.csv")]
    out_csv: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tls::install_provider();
    tracing_subscriber::fmt().with_env_filter("info").without_time().init();

    let args = Args::parse();
    let spki = tls::load_spki_from_pem(&args.pin_spki_pem)?;
    let tls_client = tls::build_client_rpk_pinned(spki);
    let client_cfg = quic_cfg::client_config(tls_client);

    let mut ep = Endpoint::client("0.0.0.0:0".parse::<SocketAddr>()?)?;
    ep.set_default_client_config(client_cfg);

    let conn = ep.connect(args.server.parse()?, "localhost")?.await?;
    info!("connected to {}", conn.remote_address());

    // Receiver (echo) counter
    let c2 = conn.clone();
    let recv_task = tokio::spawn(async move {
        let mut echoed = 0u64;
        while let Ok(_d) = c2.read_datagram().await {
            echoed += 1;
        }
        echoed
    });

    // Sender
    let mut hist = Histo::new(5_000_000);
    let start = Instant::now();
    let mut sent: u64 = 0;
    let buf = Bytes::from(vec![0u8; args.payload]);

    while sent < args.target_pkts {
        let t0 = Instant::now();
        if conn.send_datagram(buf.clone()).is_ok() {
            sent += 1;
            hist.record_us(t0.elapsed().as_micros() as u64);
        } else {
            // backpressure
            sleep(Duration::from_micros(50)).await;
        }
    }

    conn.close(0u32.into(), b"done");
    let echoed = recv_task.await.unwrap_or(0);
    let dur = start.elapsed();
    let bytes = sent * (args.payload as u64);

    info!("dgrams sent={} echoed={} dur={:?} thrpt={}", sent, echoed, dur, pretty_throughput(bytes, dur));
    info!("latency p50={}us p99={}us", hist.p(0.50), hist.p(0.99));
    hist.write_csv(&args.out_csv)?;
    Ok(())
}
