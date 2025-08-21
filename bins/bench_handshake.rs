use anyhow::Result;
use clap::Parser;
use quinn::Endpoint;
use rpkv2::{tls, quic_cfg};
use rpkv2::util::{Histo};
use std::net::SocketAddr;
use tracing::info;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:4433")]
    server: String,
    #[arg(long, default_value_t = 100)]
    iters: u32,
    #[arg(long, default_value = "server.pub")]
    pin_spki_pem: String,
    #[arg(long, default_value = "handshake.csv")]
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

    let mut hist = Histo::new(5_000_000); // up to 5s in µs

    for _ in 0..args.iters {
        let mut ep = Endpoint::client("0.0.0.0:0".parse::<SocketAddr>()?)?;
        ep.set_default_client_config(client_cfg.clone());

        let t0 = std::time::Instant::now();
        let conn = ep.connect(args.server.parse()?, "localhost")?.await?;
        hist.record_us(t0.elapsed().as_micros() as u64);
        conn.close(0u32.into(), b"bye");
    }

    info!("handshakes: {}", hist.count());
    info!("p50={}us p99={}us mean={:.0}us", hist.p(0.50), hist.p(0.99), hist.mean());
    hist.write_csv(&args.out_csv)?;
    Ok(())
}
