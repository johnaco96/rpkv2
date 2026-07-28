use anyhow::{Context, Result, anyhow};
use clap::Parser;
use crossbeam_queue::ArrayQueue;
#[cfg(not(feature = "ed25519"))]
compile_error!("overload_suite requires the ed25519 feature; stub verification is demo-only.");

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rpkv2::{
    backpressure::{QueuePolicy, metrics_snapshot, push_with_policy},
    fastpath::packet::{Header, ReplayFilter},
    peer_rate_limit::{PeerLimitDecision, PeerLimitReason, PeerRateLimiter, PeerRateLimits},
    runtime_mode::RuntimeMode,
    tiles::storage::{StorageRecoveryPolicy, recover_storage_dir},
    version::VersionArgs,
};
use std::{
    fs,
    net::{SocketAddr, UdpSocket},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Parser, Debug)]
#[command(name = "overload_suite")]
struct Args {
    #[arg(long, default_value = "target/tmp/overload-suite")]
    work_dir: PathBuf,
    #[arg(long, default_value = "target/tmp/overload-suite/summary.json")]
    out_json: PathBuf,
    #[arg(long, default_value_t = 20_000)]
    offered_packets: u64,
    #[arg(long, default_value_t = 500)]
    replay_packets: u64,
    #[arg(long, default_value_t = 2_000)]
    invalid_signature_packets: u64,
    #[arg(long, value_enum, default_value_t = RuntimeMode::Benchmark)]
    mode: RuntimeMode,
    #[command(flatten)]
    version: VersionArgs,
}

#[derive(Debug)]
struct ScenarioResult {
    name: &'static str,
    passed: bool,
    bottleneck: &'static str,
    metrics: Vec<(&'static str, String)>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.version.print_and_exit_if_requested() {
        return Ok(());
    }
    if args.mode != RuntimeMode::Benchmark {
        return Err(anyhow!("overload_suite only supports --mode benchmark"));
    }
    fs::create_dir_all(&args.work_dir)?;
    if let Some(parent) = args.out_json.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }

    let results = vec![
        offered_load_above_capacity(args.offered_packets),
        invalid_signature_peer(args.invalid_signature_packets),
        replay_storm(args.replay_packets),
        storage_temporarily_unavailable(&args.work_dir)?,
        receiver_restart_during_traffic()?,
    ];

    let passed = results.iter().all(|result| result.passed);
    fs::write(&args.out_json, render_summary(passed, &results))?;
    println!(
        "overload suite {} summary={}",
        if passed { "passed" } else { "failed" },
        args.out_json.display()
    );
    if passed {
        Ok(())
    } else {
        Err(anyhow!("one or more overload scenarios failed"))
    }
}

fn offered_load_above_capacity(offered_packets: u64) -> ScenarioResult {
    let q = ArrayQueue::new(1);
    let stage = "overload_suite_ingress";
    let mut accepted = 0u64;
    let mut rejected = 0u64;

    for i in 0..offered_packets {
        if push_with_policy(stage, &q, i, QueuePolicy::RejectNewest) {
            accepted = accepted.saturating_add(1);
        } else {
            rejected = rejected.saturating_add(1);
        }
    }

    let metric = metrics_snapshot()
        .into_iter()
        .find(|metric| metric.stage == stage);
    let full = metric.as_ref().map_or(0, |metric| metric.full);
    let dropped = metric.as_ref().map_or(0, |metric| metric.dropped);

    ScenarioResult {
        name: "offered_load_above_capacity",
        passed: accepted == 1 && rejected > 0 && full > 0 && dropped > 0,
        bottleneck: "ingress_queue_capacity",
        metrics: vec![
            ("offered_packets", offered_packets.to_string()),
            ("accepted_packets", accepted.to_string()),
            ("rejected_packets", rejected.to_string()),
            ("queue_full_total", full.to_string()),
            ("queue_dropped_total", dropped.to_string()),
        ],
    }
}

fn invalid_signature_peer(packets: u64) -> ScenarioResult {
    let limits = PeerRateLimits {
        window: Duration::from_secs(60),
        throttle_for: Duration::from_secs(60),
        max_packets_per_window: packets.saturating_add(1),
        max_bytes_per_window: u64::MAX,
        max_malformed_per_window: u64::MAX,
        max_invalid_signatures_per_window: 10,
        max_replays_per_window: u64::MAX,
    };
    let limiter = PeerRateLimiter::new(limits);
    let signing_key = SigningKey::from_bytes(&[11u8; 32]);
    let verifying_key = signing_key.verifying_key();
    let payload = b"invalid signature scenario";
    let mut header = Header {
        pubkey: verifying_key.to_bytes(),
        ..Header::default()
    };
    header.signature = signing_key
        .sign(&header.signing_preimage(payload))
        .to_bytes();
    header.signature[0] ^= 0x80;

    let mut invalid = 0u64;
    let mut throttled = 0u64;
    for _ in 0..packets {
        if signature_valid(&header, payload) {
            continue;
        }
        invalid = invalid.saturating_add(1);
        if matches!(
            limiter.record_invalid_signature("invalid-peer"),
            PeerLimitDecision::Throttle(PeerLimitReason::InvalidSignatureRate)
                | PeerLimitDecision::Throttle(PeerLimitReason::AlreadyThrottled)
        ) {
            throttled = throttled.saturating_add(1);
        }
    }

    let snapshot = limiter
        .snapshots()
        .into_iter()
        .find(|snapshot| snapshot.peer == "invalid-peer");
    let metric_invalid = snapshot
        .as_ref()
        .map_or(0, |snapshot| snapshot.invalid_signatures);
    let metric_throttled = snapshot.as_ref().map_or(0, |snapshot| snapshot.throttled);

    ScenarioResult {
        name: "peer_sends_invalid_signatures",
        passed: invalid == packets && metric_invalid == packets && throttled > 0,
        bottleneck: "signature_verification",
        metrics: vec![
            ("offered_invalid_signatures", packets.to_string()),
            ("detected_invalid_signatures", invalid.to_string()),
            (
                "rpkv2_peer_invalid_signatures_total",
                metric_invalid.to_string(),
            ),
            ("rpkv2_peer_throttled_total", metric_throttled.to_string()),
        ],
    }
}

fn replay_storm(packets: u64) -> ScenarioResult {
    let limits = PeerRateLimits {
        window: Duration::from_secs(60),
        throttle_for: Duration::from_secs(60),
        max_packets_per_window: packets.saturating_add(1),
        max_bytes_per_window: u64::MAX,
        max_malformed_per_window: u64::MAX,
        max_invalid_signatures_per_window: u64::MAX,
        max_replays_per_window: 10,
    };
    let limiter = PeerRateLimiter::new(limits);
    let mut replay = ReplayFilter::new(1024, 1e-6, 64, 100);
    let validator = [9u8; 32];
    let mut accepted = 0u64;
    let mut replayed = 0u64;
    let mut throttled = 0u64;

    for _ in 0..packets {
        if replay.accept_for_validator(7, 42, validator) {
            accepted = accepted.saturating_add(1);
        } else {
            replayed = replayed.saturating_add(1);
            if matches!(
                limiter.record_replay("replay-peer"),
                PeerLimitDecision::Throttle(PeerLimitReason::ReplayRate)
                    | PeerLimitDecision::Throttle(PeerLimitReason::AlreadyThrottled)
            ) {
                throttled = throttled.saturating_add(1);
            }
        }
    }
    let replay_stats = replay.stats();

    ScenarioResult {
        name: "peer_sends_replay_storm",
        passed: accepted == 1 && replayed == packets.saturating_sub(1) && throttled > 0,
        bottleneck: "replay_filter",
        metrics: vec![
            ("offered_replays", packets.to_string()),
            ("accepted_unique_packets", accepted.to_string()),
            ("replay_drops", replayed.to_string()),
            (
                "replay_filter_dropped_replays",
                replay_stats.dropped_replays.to_string(),
            ),
            ("peer_throttled_total", throttled.to_string()),
        ],
    }
}

fn storage_temporarily_unavailable(work_dir: &std::path::Path) -> Result<ScenarioResult> {
    let bad_path = work_dir.join("storage-unavailable");
    if bad_path.is_dir() {
        fs::remove_dir_all(&bad_path)?;
    } else if bad_path.exists() {
        fs::remove_file(&bad_path)?;
    }
    fs::write(&bad_path, b"not a directory")?;
    let failed = recover_storage_dir(&bad_path, StorageRecoveryPolicy::FailStartup).is_err();
    fs::remove_file(&bad_path)?;
    fs::create_dir_all(&bad_path)?;
    let recovered = recover_storage_dir(&bad_path, StorageRecoveryPolicy::FailStartup).is_ok();

    Ok(ScenarioResult {
        name: "storage_temporarily_unavailable",
        passed: failed && recovered,
        bottleneck: "storage_path_unavailable",
        metrics: vec![
            ("startup_failed_while_unavailable", failed.to_string()),
            ("recovered_after_directory_restored", recovered.to_string()),
        ],
    })
}

fn receiver_restart_during_traffic() -> Result<ScenarioResult> {
    let first_receiver = UdpSocket::bind("127.0.0.1:0")?;
    first_receiver.set_nonblocking(true)?;
    let target = first_receiver.local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let sent = Arc::new(AtomicU64::new(0));
    let sender = {
        let stop = stop.clone();
        let sent = sent.clone();
        thread::spawn(move || restart_sender(target, stop, sent))
    };

    let before_restart = receive_for(first_receiver, Duration::from_millis(250))?;
    thread::sleep(Duration::from_millis(100));
    let second_receiver = UdpSocket::bind(target)?;
    second_receiver.set_nonblocking(true)?;
    let after_restart = receive_for(second_receiver, Duration::from_millis(250))?;
    stop.store(true, Ordering::Relaxed);
    sender
        .join()
        .map_err(|_| anyhow!("restart sender thread panicked"))??;
    let sent = sent.load(Ordering::Relaxed);
    let received = before_restart.saturating_add(after_restart);

    Ok(ScenarioResult {
        name: "receiver_restart_during_traffic",
        passed: sent > 0 && before_restart > 0 && after_restart > 0,
        bottleneck: "receiver_restart_gap",
        metrics: vec![
            ("sent_packets", sent.to_string()),
            ("received_before_restart", before_restart.to_string()),
            ("received_after_restart", after_restart.to_string()),
            (
                "estimated_restart_gap_drops",
                sent.saturating_sub(received).to_string(),
            ),
        ],
    })
}

fn restart_sender(target: SocketAddr, stop: Arc<AtomicBool>, sent: Arc<AtomicU64>) -> Result<()> {
    let sock = UdpSocket::bind("127.0.0.1:0")?;
    let body = [0xABu8; 128];
    while !stop.load(Ordering::Relaxed) {
        sock.send_to(&body, target)?;
        sent.fetch_add(1, Ordering::Relaxed);
        thread::sleep(Duration::from_micros(500));
    }
    Ok(())
}

fn receive_for(sock: UdpSocket, duration: Duration) -> Result<u64> {
    let deadline = Instant::now() + duration;
    let mut buf = [0u8; 2048];
    let mut received = 0u64;
    while Instant::now() < deadline {
        match sock.recv_from(&mut buf) {
            Ok((_n, _peer)) => received = received.saturating_add(1),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(e) => return Err(e).context("receiver restart recv failed"),
        }
    }
    Ok(received)
}

fn signature_valid(header: &Header, payload: &[u8]) -> bool {
    match (
        VerifyingKey::from_bytes(&header.pubkey),
        ed25519_dalek::Signature::try_from(&header.signature[..]),
    ) {
        (Ok(vk), Ok(sig)) => vk.verify(&header.signing_preimage(payload), &sig).is_ok(),
        _ => false,
    }
}

fn render_summary(passed: bool, results: &[ScenarioResult]) -> String {
    let scenarios = results
        .iter()
        .map(render_scenario)
        .collect::<Vec<_>>()
        .join(",\n");
    format!(
        concat!(
            "{{\n",
            "  \"schema\": \"rpkv2.overload_recovery_suite.v1\",\n",
            "  \"passed\": {},\n",
            "  \"scenario_count\": {},\n",
            "  \"scenarios\": [\n",
            "{}\n",
            "  ]\n",
            "}}\n"
        ),
        passed,
        results.len(),
        scenarios
    )
}

fn render_scenario(result: &ScenarioResult) -> String {
    let metrics = result
        .metrics
        .iter()
        .map(|(name, value)| format!("      \"{}\": \"{}\"", escape(name), escape(value)))
        .collect::<Vec<_>>()
        .join(",\n");
    format!(
        concat!(
            "    {{\n",
            "      \"name\": \"{}\",\n",
            "      \"passed\": {},\n",
            "      \"bottleneck\": \"{}\",\n",
            "      \"metrics\": {{\n",
            "{}\n",
            "      }}\n",
            "    }}"
        ),
        escape(result.name),
        result.passed,
        escape(result.bottleneck),
        metrics
    )
}

fn escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}
