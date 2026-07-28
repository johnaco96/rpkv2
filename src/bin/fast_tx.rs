use anyhow::{Result, anyhow};
use bytes::BytesMut;
use clap::{Parser, ValueEnum};
#[cfg(not(feature = "ed25519"))]
compile_error!("fast_tx requires the ed25519 feature; stub verification is demo-only.");

use ed25519_dalek::{Signer, SigningKey};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use rpkv2::fastpath::packet::{HEADER_LEN, Header, MSG_TYPE_TRANSACTION_BATCH, PACKET_VERSION};
use rpkv2::runtime_mode::RuntimeMode;
use rpkv2::version::VersionArgs;
use std::{
    fs::File,
    net::{SocketAddr, UdpSocket},
    path::PathBuf,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const BENCH_META_LEN: usize = 16;

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Toggle {
    On,
    Off,
}

#[derive(Parser, Debug)]
#[command(name = "fast_tx")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:9000")]
    target: SocketAddr,
    #[arg(long, default_value_t = 200_000)]
    pps: u64,
    #[arg(long, default_value_t = 256)]
    payload: usize,
    #[arg(long, default_value_t = 10)]
    duration_secs: u64,
    #[arg(long, value_enum, default_value = "on")]
    signing: Toggle,
    #[arg(long, default_value = "fast_tx_summary.csv")]
    out_csv: PathBuf,
    #[arg(long, value_enum, default_value_t = RuntimeMode::Benchmark)]
    mode: RuntimeMode,
    #[command(flatten)]
    version: VersionArgs,
}

fn now_unix_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.version.print_and_exit_if_requested() {
        return Ok(());
    }
    if args.mode != RuntimeMode::Benchmark {
        return Err(anyhow!("fast_tx only supports --mode benchmark"));
    }
    if args.payload < BENCH_META_LEN {
        return Err(anyhow!("--payload must be >= {BENCH_META_LEN}"));
    }

    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_nonblocking(false)?;

    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let pubkey = signing_key.verifying_key().to_bytes();
    let sleep_ns = 1_000_000_000u64.checked_div(args.pps).unwrap_or(0);
    let mut rng = StdRng::seed_from_u64(0xC0FFEE);

    let mut seq: u64 = 0;
    let start = Instant::now();
    let deadline = start + Duration::from_secs(args.duration_secs);
    let mut sent: u64 = 0;
    let mut bytes_sent: u64 = 0;

    while Instant::now() < deadline {
        let mut body = vec![0u8; args.payload];
        body[0..8].copy_from_slice(&seq.to_be_bytes());
        body[8..16].copy_from_slice(&now_unix_ns().to_be_bytes());
        rng.fill_bytes(&mut body[BENCH_META_LEN..]);

        let mut header = Header {
            v: PACKET_VERSION,
            msg_type: MSG_TYPE_TRANSACTION_BATCH,
            flags: 0,
            slot: 1,
            nonce: seq,
            key_id: 0,
            pubkey,
            signature: [0u8; 64],
        };
        if matches!(args.signing, Toggle::On) {
            header.signature = signing_key.sign(&header.signing_preimage(&body)).to_bytes();
        }

        let mut buf = BytesMut::with_capacity(HEADER_LEN + args.payload);
        buf.resize(HEADER_LEN, 0);
        header.encode_into(&mut buf[..HEADER_LEN])?;
        buf.extend_from_slice(&body);

        let n = sock.send_to(&buf, args.target)?;
        sent = sent.saturating_add(1);
        bytes_sent = bytes_sent.saturating_add(n as u64);
        seq = seq.wrapping_add(1);

        if sleep_ns > 0 {
            std::thread::sleep(Duration::from_nanos(sleep_ns));
        }
    }

    let elapsed = start.elapsed().as_secs_f64();
    let mut wtr = csv::Writer::from_writer(File::create(&args.out_csv)?);
    wtr.write_record([
        "target",
        "pps_requested",
        "payload_bytes",
        "duration_secs",
        "signing",
        "packets_sent",
        "bytes_sent",
        "achieved_pps",
        "achieved_mbps",
    ])?;
    wtr.write_record([
        args.target.to_string(),
        args.pps.to_string(),
        args.payload.to_string(),
        format!("{elapsed:.6}"),
        format!("{:?}", args.signing).to_lowercase(),
        sent.to_string(),
        bytes_sent.to_string(),
        format!("{:.3}", sent as f64 / elapsed),
        format!("{:.3}", (bytes_sent as f64 * 8.0) / elapsed / 1_000_000.0),
    ])?;
    wtr.flush()?;

    println!(
        "fast_tx complete sent={sent} csv={}",
        args.out_csv.display()
    );
    Ok(())
}
