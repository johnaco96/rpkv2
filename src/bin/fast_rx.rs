use anyhow::Result;
use clap::{Parser, ValueEnum};
use hdrhistogram::Histogram;
use rpkv2::fastpath::packet::{HEADER_LEN, Header, ReplayFilter};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    fs::File,
    io::ErrorKind,
    net::SocketAddr,
    path::PathBuf,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(feature = "ed25519")]
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

const BENCH_META_LEN: usize = 16; // seq:u64 + send_ts_ns:u64

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Toggle {
    On,
    Off,
}

#[derive(Parser, Debug)]
#[command(name = "fast_rx")]
struct Args {
    #[arg(long, default_value = "0.0.0.0:9000")]
    bind: SocketAddr,
    #[arg(long, default_value_t = 1)]
    workers: usize,
    #[arg(long, value_enum, default_value = "off")]
    verify: Toggle,
    #[arg(long, value_enum, default_value = "on")]
    dedupe: Toggle,
    #[arg(long, default_value = "fast_rx_summary.csv")]
    out_csv: PathBuf,
}

#[derive(Default)]
struct Stats {
    received: u64,
    verified: u64,
    sig_failures: u64,
    replay_drops: u64,
    min_seq: Option<u64>,
    max_seq: Option<u64>,
    bytes: u64,
}

fn make_socket(addr: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_reuse_address(true)?;
    s.bind(&addr.into())?;
    s.set_recv_buffer_size(4 * 1024 * 1024)?;
    s.set_nonblocking(true)?;
    Ok(s.into())
}

fn now_unix_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

fn main() -> Result<()> {
    let args = Args::parse();
    eprintln!(
        "fast_rx bind={} workers={} verify={:?} dedupe={:?}",
        args.bind, args.workers, args.verify, args.dedupe
    );

    if args.workers > 1 {
        eprintln!(
            "warning: workers>1 currently parsed but v1 runs single-threaded for aggregate stats"
        );
    }

    let sock = make_socket(args.bind)?;
    let mut buf = vec![0u8; 65536];
    let mut stats = Stats::default();
    let mut rf = ReplayFilter::new(1 << 20, 1e-6, 4096, 250);
    let mut hist = Histogram::<u64>::new(3)?;

    let start = Instant::now();
    let mut last_pkt = Instant::now();
    let idle_timeout = Duration::from_secs(2);

    loop {
        match sock.recv_from(&mut buf) {
            Ok((n, _peer)) => {
                stats.received = stats.received.saturating_add(1);
                stats.bytes = stats.bytes.saturating_add(n as u64);
                last_pkt = Instant::now();

                if n < HEADER_LEN + BENCH_META_LEN {
                    continue;
                }

                let (h, _) = match Header::decode_from(&buf[..n]) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                let payload = &buf[HEADER_LEN..n];
                let seq = u64::from_be_bytes(payload[0..8].try_into().unwrap());
                let send_ts_ns = u64::from_be_bytes(payload[8..16].try_into().unwrap());

                stats.min_seq = Some(stats.min_seq.map(|x| x.min(seq)).unwrap_or(seq));
                stats.max_seq = Some(stats.max_seq.map(|x| x.max(seq)).unwrap_or(seq));

                if matches!(args.dedupe, Toggle::On) && !rf.accept(h.slot, h.nonce) {
                    stats.replay_drops = stats.replay_drops.saturating_add(1);
                    continue;
                }

                #[cfg_attr(not(feature = "ed25519"), allow(unused_mut))]
                let mut verified_this = false;
                if matches!(args.verify, Toggle::On) {
                    #[cfg(feature = "ed25519")]
                    {
                        let mut msg = Vec::with_capacity(2 + 2 + 8 + 8 + 2 + payload.len());
                        msg.push(h.v);
                        msg.push(h.msg_type);
                        msg.extend_from_slice(&h.flags.to_be_bytes());
                        msg.extend_from_slice(&h.slot.to_be_bytes());
                        msg.extend_from_slice(&h.nonce.to_be_bytes());
                        msg.extend_from_slice(&h.key_id.to_be_bytes());
                        msg.extend_from_slice(payload);

                        if let (Ok(vk), Ok(sig)) = (
                            VerifyingKey::from_bytes(&h.pubkey),
                            Signature::try_from(&h.signature[..]),
                        ) {
                            if vk.verify(&msg, &sig).is_ok() {
                                verified_this = true;
                            }
                        }
                    }
                    #[cfg(not(feature = "ed25519"))]
                    {
                        eprintln!(
                            "verify requested but binary compiled without --features ed25519"
                        );
                    }

                    if verified_this {
                        stats.verified = stats.verified.saturating_add(1);
                    } else {
                        stats.sig_failures = stats.sig_failures.saturating_add(1);
                    }
                }

                let now = now_unix_ns();
                if now >= send_ts_ns {
                    let _ = hist.record(now - send_ts_ns);
                }
                rf.maybe_cleanup();
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                if last_pkt.elapsed() >= idle_timeout && stats.received > 0 {
                    break;
                }
            }
            Err(e) => {
                eprintln!("recv error: {e}");
            }
        }
    }

    let elapsed = start.elapsed().as_secs_f64();
    let expected = match (stats.min_seq, stats.max_seq) {
        (Some(min_s), Some(max_s)) => max_s.saturating_sub(min_s).saturating_add(1),
        _ => 0,
    };
    let loss = expected.saturating_sub(stats.received.saturating_add(stats.replay_drops));

    let mut wtr = csv::Writer::from_writer(File::create(&args.out_csv)?);
    wtr.write_record([
        "bind",
        "workers",
        "verify",
        "dedupe",
        "received_packets",
        "verified_packets",
        "signature_failures",
        "duplicate_replay_drops",
        "expected_packets",
        "estimated_loss",
        "loss_pct",
        "p50_us",
        "p90_us",
        "p99_us",
        "p999_us",
        "throughput_mbps",
        "run_duration_secs",
    ])?;

    let q = |v: f64| {
        if hist.len() > 0 {
            format!("{:.3}", hist.value_at_quantile(v) as f64 / 1000.0)
        } else {
            "0.000".to_string()
        }
    };

    wtr.write_record([
        args.bind.to_string(),
        args.workers.to_string(),
        format!("{:?}", args.verify).to_lowercase(),
        format!("{:?}", args.dedupe).to_lowercase(),
        stats.received.to_string(),
        stats.verified.to_string(),
        stats.sig_failures.to_string(),
        stats.replay_drops.to_string(),
        expected.to_string(),
        loss.to_string(),
        format!(
            "{:.3}",
            if expected > 0 {
                (loss as f64) * 100.0 / (expected as f64)
            } else {
                0.0
            }
        ),
        q(0.50),
        q(0.90),
        q(0.99),
        q(0.999),
        format!("{:.3}", (stats.bytes as f64 * 8.0) / elapsed / 1_000_000.0),
        format!("{:.6}", elapsed),
    ])?;
    wtr.flush()?;

    println!(
        "fast_rx complete received={} csv={}",
        stats.received,
        args.out_csv.display()
    );
    Ok(())
}
