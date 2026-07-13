use anyhow::{Result, anyhow};
use clap::{Parser, ValueEnum};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use rpkv2::fastpath::packet::{HEADER_LEN, Header};
use std::{
    fs::File,
    net::{SocketAddr, UdpSocket},
    path::PathBuf,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(feature = "ed25519")]
use ed25519_dalek::{Signer, SigningKey};

const BENCH_META_LEN: usize = 16; // seq:u64 + send_ts_ns:u64

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
    #[arg(long, value_enum, default_value = "off")]
    signing: Toggle,
    #[arg(long, default_value = "fast_tx_summary.csv")]
    out_csv: PathBuf,
}

fn now_unix_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.payload < BENCH_META_LEN {
        return Err(anyhow!("--payload must be >= {BENCH_META_LEN}"));
    }

    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_nonblocking(false)?;

    #[cfg(feature = "ed25519")]
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);

    if matches!(args.signing, Toggle::On) {
        #[cfg(not(feature = "ed25519"))]
        return Err(anyhow!(
            "--signing on requires building with --features ed25519"
        ));
    }

    let sleep_ns = if args.pps > 0 {
        1_000_000_000u64 / args.pps
    } else {
        0
    };
    let mut rng = StdRng::seed_from_u64(0xC0FFEE);

    let mut seq: u64 = 0;
    let start = Instant::now();
    let deadline = start + Duration::from_secs(args.duration_secs);
    let mut sent: u64 = 0;
    let mut bytes_sent: u64 = 0;

    while Instant::now() < deadline {
        let mut buf = vec![0u8; HEADER_LEN + args.payload];

        #[cfg_attr(not(feature = "ed25519"), allow(unused_mut))]
        let mut header = Header {
            v: 1,
            msg_type: 1,
            flags: if matches!(args.signing, Toggle::On) {
                1
            } else {
                0
            },
            slot: 1,
            nonce: seq,
            key_id: 0,
            pubkey: [0u8; 32],
            signature: [0u8; 64],
        };

        // payload starts with benchmark metadata
        buf[HEADER_LEN..HEADER_LEN + 8].copy_from_slice(&seq.to_be_bytes());
        buf[HEADER_LEN + 8..HEADER_LEN + 16].copy_from_slice(&now_unix_ns().to_be_bytes());
        rng.fill_bytes(&mut buf[HEADER_LEN + BENCH_META_LEN..]);

        if matches!(args.signing, Toggle::On) {
            #[cfg(feature = "ed25519")]
            {
                header
                    .pubkey
                    .copy_from_slice(&signing_key.verifying_key().to_bytes());
                let mut msg = Vec::with_capacity(2 + 2 + 8 + 8 + 2 + args.payload);
                msg.push(header.v);
                msg.push(header.msg_type);
                msg.extend_from_slice(&header.flags.to_be_bytes());
                msg.extend_from_slice(&header.slot.to_be_bytes());
                msg.extend_from_slice(&header.nonce.to_be_bytes());
                msg.extend_from_slice(&header.key_id.to_be_bytes());
                msg.extend_from_slice(&buf[HEADER_LEN..]);
                let sig = signing_key.sign(&msg);
                header.signature.copy_from_slice(&sig.to_bytes());
            }
        }

        header.encode_into(&mut buf[..HEADER_LEN])?;
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
        format!("{:.6}", elapsed),
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
