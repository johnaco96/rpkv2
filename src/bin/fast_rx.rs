use anyhow::Result;
use clap::{Parser, ValueEnum};
#[cfg(not(feature = "ed25519"))]
compile_error!("fast_rx requires the ed25519 feature; stub verification is demo-only.");

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hdrhistogram::Histogram;
use rpkv2::fastpath::packet::{HEADER_LEN, Header, ReplayFilter};
use rpkv2::runtime_mode::RuntimeMode;
use rpkv2::version::VersionArgs;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    fs::File,
    io::ErrorKind,
    net::SocketAddr,
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
#[command(name = "fast_rx")]
struct Args {
    #[arg(long, default_value = "0.0.0.0:9000")]
    bind: SocketAddr,
    #[arg(long, default_value_t = 1)]
    workers: usize,
    #[arg(long, value_enum, default_value = "on")]
    verify: Toggle,
    #[arg(long, value_enum, default_value = "on")]
    dedupe: Toggle,
    #[arg(long, default_value_t = 2)]
    idle_timeout_secs: u64,
    #[arg(long, default_value = "fast_rx_summary.csv")]
    out_csv: PathBuf,
    #[arg(long, value_enum, default_value_t = RuntimeMode::Benchmark)]
    mode: RuntimeMode,
    #[command(flatten)]
    version: VersionArgs,
}

#[derive(Default)]
struct Stats {
    received: u64,
    verified: u64,
    sig_failures: u64,
    replay_drops: u64,
    malformed: u64,
    min_seq: Option<u64>,
    max_seq: Option<u64>,
    bytes: u64,
}

fn make_socket(addr: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_reuse_address(true)?;
    #[cfg(not(windows))]
    s.set_reuse_port(true)?;
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
    if args.version.print_and_exit_if_requested() {
        return Ok(());
    }
    if args.mode != RuntimeMode::Benchmark {
        anyhow::bail!("fast_rx only supports --mode benchmark");
    }
    eprintln!(
        "fast_rx mode={} bind={} workers={} verify={:?} dedupe={:?}",
        args.mode, args.bind, args.workers, args.verify, args.dedupe
    );
    if args.workers > 1 {
        eprintln!(
            "warning: workers>1 is accepted for runbook compatibility; aggregate CSV uses one receiver loop"
        );
    }

    let sock = make_socket(args.bind)?;
    let mut buf = vec![0u8; 65536];
    let mut stats = Stats::default();
    let mut replay = ReplayFilter::new(1 << 20, 1e-6, 4096, 250);
    let mut latency = Histogram::<u64>::new(3)?;

    let start = Instant::now();
    let mut last_packet = Instant::now();
    let idle_timeout = Duration::from_secs(args.idle_timeout_secs);

    loop {
        match sock.recv_from(&mut buf) {
            Ok((n, _peer)) => {
                stats.received = stats.received.saturating_add(1);
                stats.bytes = stats.bytes.saturating_add(n as u64);
                last_packet = Instant::now();

                if n < HEADER_LEN + BENCH_META_LEN {
                    stats.malformed = stats.malformed.saturating_add(1);
                    continue;
                }

                let Ok((header, _)) = Header::decode_from(&buf[..n]) else {
                    stats.malformed = stats.malformed.saturating_add(1);
                    continue;
                };
                let payload = &buf[HEADER_LEN..n];
                let seq = u64::from_be_bytes(payload[0..8].try_into().expect("seq length"));
                let send_ts_ns =
                    u64::from_be_bytes(payload[8..16].try_into().expect("timestamp length"));

                stats.min_seq = Some(stats.min_seq.map_or(seq, |current| current.min(seq)));
                stats.max_seq = Some(stats.max_seq.map_or(seq, |current| current.max(seq)));

                if matches!(args.dedupe, Toggle::On)
                    && !replay.accept_for_validator(header.slot, header.nonce, header.pubkey)
                {
                    stats.replay_drops = stats.replay_drops.saturating_add(1);
                    continue;
                }

                if matches!(args.verify, Toggle::On) {
                    let valid = match (
                        VerifyingKey::from_bytes(&header.pubkey),
                        Signature::try_from(&header.signature[..]),
                    ) {
                        (Ok(vk), Ok(sig)) => {
                            vk.verify(&header.signing_preimage(payload), &sig).is_ok()
                        }
                        _ => false,
                    };
                    if valid {
                        stats.verified = stats.verified.saturating_add(1);
                    } else {
                        stats.sig_failures = stats.sig_failures.saturating_add(1);
                    }
                }

                let now = now_unix_ns();
                if now >= send_ts_ns {
                    let _ = latency.record((now - send_ts_ns) / 1_000);
                }
                replay.maybe_cleanup();
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                if stats.received > 0 && last_packet.elapsed() >= idle_timeout {
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) => {
                eprintln!("recv error: {e}");
            }
        }
    }

    let elapsed = start.elapsed().as_secs_f64();
    let expected = match (stats.min_seq, stats.max_seq) {
        (Some(min), Some(max)) => max.saturating_sub(min).saturating_add(1),
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
        "malformed_packets",
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

    let quantile = |q: f64| {
        if !latency.is_empty() {
            format!("{:.3}", latency.value_at_quantile(q) as f64)
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
        stats.malformed.to_string(),
        expected.to_string(),
        loss.to_string(),
        format!(
            "{:.3}",
            if expected > 0 {
                (loss as f64) * 100.0 / expected as f64
            } else {
                0.0
            }
        ),
        quantile(0.50),
        quantile(0.90),
        quantile(0.99),
        quantile(0.999),
        format!("{:.3}", (stats.bytes as f64 * 8.0) / elapsed / 1_000_000.0),
        format!("{elapsed:.6}"),
    ])?;
    wtr.flush()?;

    println!(
        "fast_rx complete received={} csv={}",
        stats.received,
        args.out_csv.display()
    );
    Ok(())
}
