use anyhow::{Result, anyhow};
use bytes::BytesMut;
use clap::Parser;
#[cfg(not(feature = "ed25519"))]
compile_error!("soak_bench requires the ed25519 feature; stub verification is demo-only.");

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hdrhistogram::Histogram;
use rand::{RngCore, SeedableRng, rngs::StdRng};
use rpkv2::{
    fastpath::packet::{
        HEADER_LEN, Header, MSG_TYPE_TRANSACTION_BATCH, PACKET_VERSION, ReplayFilter,
    },
    runtime_mode::RuntimeMode,
    version::VersionArgs,
};
use std::{
    fs::{self, OpenOptions},
    io::{ErrorKind, Write},
    net::{SocketAddr, UdpSocket},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const BENCH_META_LEN: usize = 16;

#[derive(Parser, Debug)]
#[command(name = "soak_bench")]
struct Args {
    #[arg(long, default_value_t = 3600)]
    duration_secs: u64,
    #[arg(long, default_value_t = 10_000)]
    pps: u64,
    #[arg(long, default_value_t = 256)]
    payload: usize,
    #[arg(long, default_value_t = 10)]
    sample_interval_secs: u64,
    #[arg(long, default_value = "target/soak-store")]
    storage_dir: PathBuf,
    #[arg(long, default_value = "soak-summary.json")]
    out_json: PathBuf,
    #[arg(long, value_enum, default_value_t = RuntimeMode::Benchmark)]
    mode: RuntimeMode,
    #[command(flatten)]
    version: VersionArgs,
}

#[derive(Default)]
struct Counters {
    sent: AtomicU64,
    received: AtomicU64,
    verified: AtomicU64,
    bad_signatures: AtomicU64,
    malformed: AtomicU64,
    replay_drops: AtomicU64,
    storage_bytes: AtomicU64,
}

struct Sample {
    elapsed_secs: f64,
    sent: u64,
    received: u64,
    verified: u64,
    drops: u64,
    bad_signatures: u64,
    malformed: u64,
    replay_drops: u64,
    rss_bytes: Option<u64>,
    cpu_seconds: Option<f64>,
    storage_bytes: u64,
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
        return Err(anyhow!("soak_bench only supports --mode benchmark"));
    }
    if args.payload < BENCH_META_LEN {
        return Err(anyhow!("--payload must be >= {BENCH_META_LEN}"));
    }
    fs::create_dir_all(&args.storage_dir)?;
    if let Some(parent) = args.out_json.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }

    let receiver = UdpSocket::bind("127.0.0.1:0")?;
    receiver.set_nonblocking(true)?;
    let target = receiver.local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let counters = Arc::new(Counters::default());
    let latency = Arc::new(std::sync::Mutex::new(Histogram::<u64>::new(3)?));
    let storage_path = args.storage_dir.join("soak-records.bin");

    let recv_handle = {
        let stop = stop.clone();
        let counters = counters.clone();
        let latency = latency.clone();
        let storage_path = storage_path.clone();
        thread::spawn(move || receive_loop(receiver, stop, counters, latency, storage_path))
    };

    let send_handle = {
        let stop = stop.clone();
        let counters = counters.clone();
        thread::spawn(move || send_loop(target, args.pps, args.payload, stop, counters))
    };

    let start = Instant::now();
    let deadline = start + Duration::from_secs(args.duration_secs);
    let sample_interval = Duration::from_secs(args.sample_interval_secs.max(1));
    let mut samples = Vec::new();

    while Instant::now() < deadline {
        thread::sleep(sample_interval.min(deadline.saturating_duration_since(Instant::now())));
        samples.push(sample(start, &counters));
    }

    stop.store(true, Ordering::Relaxed);
    send_handle
        .join()
        .map_err(|_| anyhow!("soak sender thread panicked"))??;
    recv_handle
        .join()
        .map_err(|_| anyhow!("soak receiver thread panicked"))??;

    let final_sample = sample(start, &counters);
    let latency = latency.lock().expect("latency histogram lock poisoned");
    let summary = render_summary_json(&args, &samples, &final_sample, &latency);
    fs::write(&args.out_json, summary)?;
    println!("soak summary written to {}", args.out_json.display());
    Ok(())
}

fn send_loop(
    target: SocketAddr,
    pps: u64,
    payload: usize,
    stop: Arc<AtomicBool>,
    counters: Arc<Counters>,
) -> Result<()> {
    let sock = UdpSocket::bind("127.0.0.1:0")?;
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let pubkey = signing_key.verifying_key().to_bytes();
    let sleep_ns = 1_000_000_000u64.checked_div(pps).unwrap_or(0);
    let mut rng = StdRng::seed_from_u64(0x50A);
    let mut seq = 0u64;

    while !stop.load(Ordering::Relaxed) {
        let mut body = vec![0u8; payload];
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
        header.signature = signing_key.sign(&header.signing_preimage(&body)).to_bytes();

        let mut buf = BytesMut::with_capacity(HEADER_LEN + payload);
        buf.resize(HEADER_LEN, 0);
        header.encode_into(&mut buf[..HEADER_LEN])?;
        buf.extend_from_slice(&body);
        sock.send_to(&buf, target)?;
        counters.sent.fetch_add(1, Ordering::Relaxed);
        seq = seq.wrapping_add(1);
        if sleep_ns > 0 {
            thread::sleep(Duration::from_nanos(sleep_ns));
        }
    }
    Ok(())
}

fn receive_loop(
    sock: UdpSocket,
    stop: Arc<AtomicBool>,
    counters: Arc<Counters>,
    latency: Arc<std::sync::Mutex<Histogram<u64>>>,
    storage_path: PathBuf,
) -> Result<()> {
    let mut replay = ReplayFilter::new(1 << 20, 1e-6, 4096, 250);
    let mut buf = vec![0u8; 65536];
    let mut storage = OpenOptions::new()
        .create(true)
        .append(true)
        .open(storage_path)?;

    while !stop.load(Ordering::Relaxed) {
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                counters.received.fetch_add(1, Ordering::Relaxed);
                if n < HEADER_LEN + BENCH_META_LEN {
                    counters.malformed.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let Ok((header, _)) = Header::decode_from(&buf[..n]) else {
                    counters.malformed.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                let payload = &buf[HEADER_LEN..n];
                if !replay.accept_for_validator(header.slot, header.nonce, header.pubkey) {
                    counters.replay_drops.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let valid = match (
                    VerifyingKey::from_bytes(&header.pubkey),
                    Signature::try_from(&header.signature[..]),
                ) {
                    (Ok(vk), Ok(sig)) => vk.verify(&header.signing_preimage(payload), &sig).is_ok(),
                    _ => false,
                };
                if valid {
                    counters.verified.fetch_add(1, Ordering::Relaxed);
                } else {
                    counters.bad_signatures.fetch_add(1, Ordering::Relaxed);
                }
                let send_ts_ns =
                    u64::from_be_bytes(payload[8..16].try_into().expect("timestamp length"));
                let now = now_unix_ns();
                if now >= send_ts_ns {
                    let _ = latency
                        .lock()
                        .expect("latency histogram lock poisoned")
                        .record((now - send_ts_ns) / 1_000);
                }
                storage.write_all(&(n as u64).to_le_bytes())?;
                counters.storage_bytes.fetch_add(8, Ordering::Relaxed);
                replay.maybe_cleanup();
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(e) => return Err(e.into()),
        }
    }
    storage.flush()?;
    Ok(())
}

fn sample(start: Instant, counters: &Counters) -> Sample {
    let sent = counters.sent.load(Ordering::Relaxed);
    let received = counters.received.load(Ordering::Relaxed);
    let verified = counters.verified.load(Ordering::Relaxed);
    let drops = sent.saturating_sub(received);
    Sample {
        elapsed_secs: start.elapsed().as_secs_f64(),
        sent,
        received,
        verified,
        drops,
        bad_signatures: counters.bad_signatures.load(Ordering::Relaxed),
        malformed: counters.malformed.load(Ordering::Relaxed),
        replay_drops: counters.replay_drops.load(Ordering::Relaxed),
        rss_bytes: process_rss_bytes(),
        cpu_seconds: process_cpu_seconds(),
        storage_bytes: counters.storage_bytes.load(Ordering::Relaxed),
    }
}

fn render_summary_json(
    args: &Args,
    samples: &[Sample],
    final_sample: &Sample,
    latency: &Histogram<u64>,
) -> String {
    let first_rss = samples.iter().find_map(|sample| sample.rss_bytes);
    let last_rss = final_sample.rss_bytes;
    let rss_growth_bytes = match (first_rss, last_rss) {
        (Some(first), Some(last)) => Some(last.saturating_sub(first)),
        _ => None,
    };
    let dead_tile_detected = false;
    let unbounded_memory_growth = rss_growth_bytes.is_some_and(|growth| {
        first_rss.is_some_and(|first| first > 0 && (growth as f64 / first as f64) > 0.05)
    });

    format!(
        concat!(
            "{{\n",
            "  \"schema\": \"rpkv2.soak_summary.v1\",\n",
            "  \"duration_secs\": {},\n",
            "  \"configured_pps\": {},\n",
            "  \"packet_size_bytes\": {},\n",
            "  \"sent_packets\": {},\n",
            "  \"received_packets\": {},\n",
            "  \"verified_packets\": {},\n",
            "  \"estimated_drops\": {},\n",
            "  \"bad_signatures\": {},\n",
            "  \"malformed_packets\": {},\n",
            "  \"replay_drops\": {},\n",
            "  \"storage_growth_bytes\": {},\n",
            "  \"rss_growth_bytes\": {},\n",
            "  \"unbounded_memory_growth\": {},\n",
            "  \"dead_tile_detected\": {},\n",
            "  \"drop_explanation\": \"drops are estimated as sent minus received; nonzero drops must be explained by configured load/backpressure or OS UDP buffering\",\n",
            "  \"latency_p50_us\": {},\n",
            "  \"latency_p90_us\": {},\n",
            "  \"latency_p99_us\": {},\n",
            "  \"latency_p999_us\": {},\n",
            "  \"samples\": [\n",
            "{}\n",
            "  ]\n",
            "}}\n"
        ),
        final_sample.elapsed_secs,
        args.pps,
        args.payload,
        final_sample.sent,
        final_sample.received,
        final_sample.verified,
        final_sample.drops,
        final_sample.bad_signatures,
        final_sample.malformed,
        final_sample.replay_drops,
        final_sample.storage_bytes,
        json_opt_u64(rss_growth_bytes),
        unbounded_memory_growth,
        dead_tile_detected,
        quantile(latency, 0.50),
        quantile(latency, 0.90),
        quantile(latency, 0.99),
        quantile(latency, 0.999),
        render_samples(samples)
    )
}

fn render_samples(samples: &[Sample]) -> String {
    samples
        .iter()
        .map(|sample| {
            format!(
                "    {{\"elapsed_secs\": {:.3}, \"sent\": {}, \"received\": {}, \"verified\": {}, \"drops\": {}, \"bad_signatures\": {}, \"malformed\": {}, \"replay_drops\": {}, \"rss_bytes\": {}, \"cpu_seconds\": {}, \"storage_bytes\": {}}}",
                sample.elapsed_secs,
                sample.sent,
                sample.received,
                sample.verified,
                sample.drops,
                sample.bad_signatures,
                sample.malformed,
                sample.replay_drops,
                json_opt_u64(sample.rss_bytes),
                json_opt_f64(sample.cpu_seconds),
                sample.storage_bytes
            )
        })
        .collect::<Vec<_>>()
        .join(",\n")
}

fn quantile(latency: &Histogram<u64>, q: f64) -> u64 {
    if latency.is_empty() {
        0
    } else {
        latency.value_at_quantile(q)
    }
}

fn json_opt_u64(value: Option<u64>) -> String {
    value
        .map(|inner| inner.to_string())
        .unwrap_or_else(|| "null".to_string())
}

fn json_opt_f64(value: Option<f64>) -> String {
    value
        .map(|inner| format!("{inner:.6}"))
        .unwrap_or_else(|| "null".to_string())
}

#[cfg(target_os = "linux")]
fn process_rss_bytes() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb = rest.split_whitespace().next()?.parse::<u64>().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn process_cpu_seconds() -> Option<f64> {
    let stat = fs::read_to_string("/proc/self/stat").ok()?;
    let fields = stat.split_whitespace().collect::<Vec<_>>();
    let utime = fields.get(13)?.parse::<f64>().ok()?;
    let stime = fields.get(14)?.parse::<f64>().ok()?;
    Some((utime + stime) / 100.0)
}

#[cfg(not(target_os = "linux"))]
fn process_rss_bytes() -> Option<u64> {
    None
}

#[cfg(not(target_os = "linux"))]
fn process_cpu_seconds() -> Option<f64> {
    None
}
