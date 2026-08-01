use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use clap::{Parser, Subcommand, ValueEnum};
#[cfg(not(feature = "ed25519"))]
compile_error!("quic_pipeline_bench requires the ed25519 feature; stub verification is demo-only.");

use ed25519_dalek::Signer;
use hdrhistogram::Histogram;
use quinn::Endpoint;
use rcgen::KeyPair;
use rpkv2::{
    backpressure,
    fastpath::packet::{HEADER_LEN, Header, MSG_TYPE_TRANSACTION_BATCH, PACKET_VERSION},
    identity::{PeerIdentity, PeerRegistry, ValidatorId},
    quic_cfg,
    runtime_mode::RuntimeMode,
    server_pipeline::{ServerPipeline, ServerPipelineConfig},
    shutdown::Shutdown,
    tiles::storage::{StorageRecoveryPolicy, scan_storage_dir},
    tls,
    version::{BuildInfo, VersionArgs},
};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Command,
    str::FromStr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::time::{sleep, sleep_until, timeout};

const CONTROL_MAGIC: &[u8; 8] = b"RPKDONE1";
const ACK_MAGIC: &[u8; 8] = b"RPKACK01";
const START_MAGIC: &[u8; 8] = b"RPKSTRT1";

mod report;
mod runtime_support;

use report::*;
use runtime_support::*;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum DatagramSendPolicy {
    Wait,
    EvictOldest,
}

impl DatagramSendPolicy {
    fn as_str(self) -> &'static str {
        match self {
            Self::Wait => "wait",
            Self::EvictOldest => "evict_oldest",
        }
    }
}

#[derive(Parser, Debug)]
#[command(name = "quic_pipeline_bench")]
struct Args {
    #[arg(long, value_enum, default_value_t = RuntimeMode::Benchmark)]
    mode: RuntimeMode,
    #[command(flatten)]
    version: VersionArgs,
    #[command(subcommand)]
    command: Option<CommandMode>,
}

#[derive(Subcommand, Debug)]
enum CommandMode {
    Local(LocalArgs),
    GenerateKey(GenerateKeyArgs),
    Receiver(ReceiverArgs),
    Sender(SenderArgs),
}

#[derive(clap::Args, Debug)]
struct LocalArgs {
    #[arg(long, default_value_t = 500)]
    packets: u64,
    #[arg(long, default_value_t = 256)]
    payload_bytes: usize,
    #[arg(long, default_value_t = 5)]
    timeout_secs: u64,
    #[arg(long, default_value = "benchmarks/results/quic-runtime")]
    out_dir: PathBuf,
}

#[derive(clap::Args, Debug)]
struct GenerateKeyArgs {
    #[arg(long)]
    key_out: PathBuf,
    #[arg(long)]
    spki_out: PathBuf,
}

#[derive(clap::Args, Debug)]
struct ReceiverArgs {
    #[arg(long, default_value = "0.0.0.0:4433")]
    bind: SocketAddr,
    #[arg(long)]
    server_key: PathBuf,
    #[arg(long, required = true)]
    client_spki: Vec<PathBuf>,
    #[arg(long, default_value_t = 10_000)]
    expected_packets: u64,
    #[arg(long, default_value_t = 10)]
    idle_timeout_secs: u64,
    #[arg(long, default_value_t = 120)]
    startup_timeout_secs: u64,
    #[arg(long, default_value = "benchmarks/results/quic-2node/receiver")]
    out_dir: PathBuf,
    #[arg(long, default_value = "benchmarks/results/quic-2node/receiver/storage")]
    storage_dir: PathBuf,
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    storage_enabled: bool,
    #[arg(long, default_value_t = 256)]
    storage_flush_records: usize,
    #[arg(long, default_value_t = 10)]
    storage_flush_ms: u64,
    #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
    storage_sync_data: bool,
    #[arg(long, default_value_t = 1)]
    verifier_workers: usize,
    #[arg(long, default_value_t = 256)]
    verifier_batch: usize,
    #[arg(long)]
    verifier_affinity_base: Option<usize>,
    #[arg(long, default_value_t = 1)]
    signer_workers: usize,
    #[arg(long, default_value_t = 100)]
    sample_every: u64,
    #[arg(long, default_value_t = 1)]
    connections: usize,
    #[arg(long, default_value_t = 16 * 1024 * 1024)]
    quic_buffer_bytes: usize,
    #[arg(long, default_value_t = 16 * 1024 * 1024)]
    quic_window_bytes: u64,
    #[arg(long, default_value_t = 16_384)]
    queue_capacity: usize,
    #[arg(long, default_value_t = 1_000_000)]
    replay_capacity: usize,
}

#[derive(clap::Args, Debug)]
struct SenderArgs {
    #[arg(long)]
    connect: SocketAddr,
    #[arg(long, required = true)]
    client_key: Vec<PathBuf>,
    #[arg(long)]
    server_spki: PathBuf,
    #[arg(long, default_value_t = 10_000)]
    packets: u64,
    #[arg(long, default_value_t = 256)]
    payload_bytes: usize,
    #[arg(long, default_value_t = 1_000)]
    rate_pps: u64,
    /// Number of packets released per pacing deadline. Zero rate means unlimited.
    #[arg(long, default_value_t = 64)]
    burst_size: u64,
    #[arg(long, default_value_t = 100)]
    sample_every: u64,
    #[arg(long, default_value_t = 1)]
    connections: usize,
    #[arg(long, default_value_t = 16 * 1024 * 1024)]
    quic_buffer_bytes: usize,
    #[arg(long, default_value_t = 16 * 1024 * 1024)]
    quic_window_bytes: u64,
    #[arg(long, value_enum, default_value_t = DatagramSendPolicy::Wait)]
    send_policy: DatagramSendPolicy,
    #[arg(long, default_value = "benchmarks/results/quic-2node/sender")]
    out_dir: PathBuf,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    tls::install_provider();
    let args = Args::parse();
    if args.version.print_and_exit_if_requested() {
        return Ok(());
    }
    if args.mode != RuntimeMode::Benchmark {
        return Err(anyhow!(
            "quic_pipeline_bench only supports --mode benchmark"
        ));
    }

    match args.command.unwrap_or(CommandMode::Local(LocalArgs {
        packets: 500,
        payload_bytes: 256,
        timeout_secs: 5,
        out_dir: PathBuf::from("benchmarks/results/quic-runtime"),
    })) {
        CommandMode::Local(local) => run_local(local).await,
        CommandMode::GenerateKey(generate) => generate_key(generate),
        CommandMode::Receiver(receiver) => run_receiver(receiver).await,
        CommandMode::Sender(sender) => run_sender(sender).await,
    }
}

async fn run_local(args: LocalArgs) -> Result<()> {
    if args.packets == 0 {
        return Err(anyhow!("--packets must be greater than zero"));
    }

    fs::create_dir_all(&args.out_dir)?;
    let temp_dir = temp_dir();
    let storage_dir = temp_dir.join("storage");
    let (server_key_path, server_spki) = write_tls_keypair(&temp_dir, "server")?;
    let (client_key_path, client_spki) = write_tls_keypair(&temp_dir, "client")?;
    let packet_key = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    let shred_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let shutdown = Shutdown::new();
    let metrics_before = rpkv2::metrics::global().snapshot();
    let pipeline = ServerPipeline::start(
        pipeline_config(storage_dir.clone(), args.packets, 16_384),
        shred_key,
        shutdown.clone(),
    );
    let queue_depths = pipeline.queue_depths();

    let server_endpoint = server_endpoint(
        args.out_dir.join("server.local.jsonl"),
        server_key_path.to_str().unwrap(),
        registry_for("client", &client_spki),
        "127.0.0.1:0".parse()?,
    )?;
    let server_addr = server_endpoint.local_addr()?;
    let ingress = pipeline.ingress();
    let expected_packets = args.packets;
    let server_task = tokio::spawn(async move {
        let connecting = server_endpoint
            .accept()
            .await
            .ok_or_else(|| anyhow!("server accept"))?;
        let conn = connecting.await?;
        let mut accepted = 0u64;
        while accepted < expected_packets {
            let datagram = conn.read_datagram().await?;
            if ingress.ingest_datagram("client", &datagram)? {
                accepted += 1;
                conn.send_datagram(Bytes::copy_from_slice(&accepted.to_be_bytes()))?;
            }
        }
        sleep(Duration::from_millis(100)).await;
        conn.close(0u32.into(), b"bench-complete");
        Ok::<u64, anyhow::Error>(accepted)
    });

    let client_endpoint = client_endpoint(
        registry_for("server", &server_spki),
        "server",
        client_key_path.to_str().unwrap(),
    )?;
    let conn = client_endpoint.connect(server_addr, "localhost")?.await?;

    let mut latency = Histogram::<u64>::new(3)?;
    let mut sent = 0u64;
    let mut acked = 0u64;
    let mut errors = 0u64;
    let started = Instant::now();
    for nonce in 0..args.packets {
        let datagram = signed_datagram(&packet_key, 1, nonce, args.payload_bytes);
        let t0 = Instant::now();
        match conn.send_datagram(Bytes::from(datagram)) {
            Ok(()) => sent += 1,
            Err(_) => {
                errors += 1;
                continue;
            }
        }
        match timeout(Duration::from_secs(args.timeout_secs), conn.read_datagram()).await {
            Ok(Ok(_)) => {
                acked += 1;
                let _ = latency.record(t0.elapsed().as_micros().max(1) as u64);
            }
            _ => errors += 1,
        }
    }
    let duration = started.elapsed();
    conn.close(0u32.into(), b"done");

    let accepted = server_task.await??;
    let stored_before_shutdown =
        wait_for_storage_quiescence(&storage_dir, args.timeout_secs).await?;
    let metrics_after = rpkv2::metrics::global().snapshot();
    let metric_delta = pipeline_metrics_delta(&metrics_before, &metrics_after);
    let queue_snapshots: Vec<_> = queue_depths.iter().map(|gauge| gauge.sample()).collect();
    let drop_snapshots = backpressure::metrics_snapshot();
    shutdown.request();
    tokio::task::spawn_blocking(move || pipeline.join()).await?;
    let storage_report = scan_storage_dir(&storage_dir)?;
    let stored = (storage_report.records_scanned as u64).max(stored_before_shutdown);
    let drops = sent.saturating_sub(acked);
    let summary = BenchSummary::new(
        "local mutual-RPK QUIC datagram send to server pipeline ingress ack; stored_records proves downstream tile completion",
        args.packets,
        args.payload_bytes,
        sent,
        acked,
        accepted,
        stored,
        drops,
        errors,
        duration,
        &latency,
    )
    .with_pipeline_evidence(
        &metric_delta,
        &queue_snapshots,
        &drop_snapshots,
        "ingress_ack_round_trip",
    );

    write_summary(&args.out_dir, "summary", &summary)?;
    Ok(())
}

fn generate_key(args: GenerateKeyArgs) -> Result<()> {
    if let Some(parent) = args.key_out.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = args.spki_out.parent() {
        fs::create_dir_all(parent)?;
    }
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    fs::write(&args.key_out, key_pair.serialize_pem())?;
    fs::write(&args.spki_out, key_pair.public_key_der())?;
    println!("private key written to {}", args.key_out.display());
    println!("public SPKI DER written to {}", args.spki_out.display());
    Ok(())
}

async fn run_receiver(args: ReceiverArgs) -> Result<()> {
    fs::create_dir_all(&args.out_dir)?;
    fs::create_dir_all(&args.storage_dir)?;
    let client_spkis: Vec<Vec<u8>> = args
        .client_spki
        .iter()
        .map(|path| fs::read(path).with_context(|| format!("failed to read {}", path.display())))
        .collect::<Result<_>>()?;
    let network_before = network_counters();
    let shutdown = Shutdown::new();
    let shred_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    if args.queue_capacity == 0 {
        return Err(anyhow!("--queue-capacity must be greater than zero"));
    }
    if args.replay_capacity == 0 {
        return Err(anyhow!("--replay-capacity must be greater than zero"));
    }
    let mut config = pipeline_config(
        args.storage_dir.clone(),
        args.expected_packets,
        args.queue_capacity,
    );
    config.storage_enabled = args.storage_enabled;
    config.storage_flush_interval_records = args.storage_flush_records.max(1);
    config.storage_flush_interval_ms = args.storage_flush_ms.max(1);
    config.storage_sync_data = args.storage_sync_data;
    config.verifier_workers = args.verifier_workers.max(1);
    config.verifier_batch = args.verifier_batch.max(1);
    config.verifier_affinity_base = args.verifier_affinity_base;
    config.signer_workers = args.signer_workers.max(1);
    config.replay_capacity = args.replay_capacity;
    let pipeline = ServerPipeline::start(config, shred_key, shutdown.clone());
    let queue_depths = pipeline.queue_depths();
    let monitor_depths = queue_depths.clone();
    let monitor_stop = Arc::new(AtomicBool::new(false));
    let monitor_stop_task = monitor_stop.clone();
    let queue_monitor = tokio::spawn(async move {
        while !monitor_stop_task.load(Ordering::Relaxed) {
            for gauge in &monitor_depths {
                gauge.sample();
            }
            sleep(Duration::from_millis(1)).await;
        }
    });
    let endpoint = server_endpoint_with_tuning(
        args.out_dir.join("receiver.jsonl"),
        args.server_key
            .to_str()
            .ok_or_else(|| anyhow!("bad key path"))?,
        registry_for_spkis("sender", &client_spkis)?,
        args.bind,
        benchmark_transport_tuning(args.quic_buffer_bytes, args.quic_window_bytes),
    )?;
    let actual_bind = endpoint.local_addr()?;
    println!("receiver listening on {actual_bind}");

    let ingress = pipeline.ingress();
    let metrics_before = rpkv2::metrics::global().snapshot();
    let latency = Arc::new(Mutex::new(Histogram::<u64>::new(3)?));
    let mut connection_tasks = Vec::with_capacity(args.connections.max(1));
    for connection_index in 0..args.connections.max(1) {
        let connecting = endpoint
            .accept()
            .await
            .ok_or_else(|| anyhow!("receiver endpoint closed before connection"))?;
        let conn = connecting.await?;
        connection_tasks.push(tokio::spawn(receive_benchmark_connection(
            conn,
            ingress.clone(),
            format!("sender-{}", connection_index % client_spkis.len()),
            args.idle_timeout_secs,
            args.startup_timeout_secs,
            args.sample_every,
            latency.clone(),
        )));
    }
    let mut connection_results = Vec::with_capacity(connection_tasks.len());
    for task in connection_tasks {
        connection_results.push(task.await.context("receiver connection task failed")??);
    }
    let received = connection_results
        .iter()
        .map(|result| result.received)
        .sum();
    let accepted = connection_results
        .iter()
        .map(|result| result.accepted)
        .sum();
    let errors = connection_results.iter().map(|result| result.errors).sum();
    let first_packet = connection_results
        .iter()
        .filter_map(|result| result.first_packet)
        .min();
    let first_cpu_ticks = connection_results
        .iter()
        .filter_map(|result| result.first_cpu_ticks)
        .min();
    let last_packet = connection_results
        .iter()
        .filter_map(|result| result.last_packet)
        .max();
    let receive_duration = first_packet
        .zip(last_packet)
        .map_or(Duration::ZERO, |(first, last)| last.duration_since(first));
    wait_for_pipeline_completion(
        &metrics_before,
        accepted,
        args.idle_timeout_secs,
        args.storage_enabled,
    )
    .await;
    let metrics_after = rpkv2::metrics::global().snapshot();
    let completion_cpu_ticks = process_cpu_ticks();
    let completion_timestamp_ns = if args.storage_enabled {
        metrics_after.last_durable_timestamp_ns
    } else {
        metrics_after.last_completed_timestamp_ns
    };
    let first_packet_wall_ns = connection_results
        .iter()
        .filter_map(|result| result.first_packet_wall_ns)
        .min()
        .unwrap_or(completion_timestamp_ns);
    let processing_duration =
        Duration::from_nanos(completion_timestamp_ns.saturating_sub(first_packet_wall_ns));
    monitor_stop.store(true, Ordering::Relaxed);
    let _ = queue_monitor.await;
    let durable_transactions = metrics_after
        .transactions_durable
        .saturating_sub(metrics_before.transactions_durable);
    let shreds_written = metrics_after
        .shreds_written
        .saturating_sub(metrics_before.shreds_written);
    for result in &mut connection_results {
        let mut completion_ack = Vec::with_capacity(40);
        completion_ack.extend_from_slice(ACK_MAGIC);
        completion_ack.extend_from_slice(&result.received.to_be_bytes());
        completion_ack.extend_from_slice(&result.accepted.to_be_bytes());
        completion_ack.extend_from_slice(&shreds_written.to_be_bytes());
        completion_ack.extend_from_slice(&durable_transactions.to_be_bytes());
        result.control_send.write_all(&completion_ack).await?;
        result.control_send.finish()?;
    }
    let stored_before_shutdown = if args.storage_enabled {
        wait_for_storage_quiescence(&args.storage_dir, args.idle_timeout_secs).await?
    } else {
        metrics_after
            .shreds_written
            .saturating_sub(metrics_before.shreds_written)
    };
    shutdown.request();
    tokio::task::spawn_blocking(move || pipeline.join()).await?;
    let storage_report = scan_storage_dir(&args.storage_dir)?;
    let stored = (storage_report.records_scanned as u64).max(stored_before_shutdown);
    let metric_delta = pipeline_metrics_delta(&metrics_before, &metrics_after);
    let queue_snapshots: Vec<_> = queue_depths.iter().map(|gauge| gauge.sample()).collect();
    let drop_snapshots = backpressure::metrics_snapshot();
    let network_delta = network_counters().saturating_sub(network_before);
    let latency = latency.lock().expect("latency histogram lock poisoned");
    let mut summary = BenchSummary::new(
        "two-node receiver: mutual-RPK QUIC datagrams into configured tile pipeline; latency is one-way only when VM clocks are synchronized",
        args.expected_packets,
        0,
        received,
        0,
        accepted,
        stored,
        received.saturating_sub(accepted),
        errors,
        processing_duration,
        &latency,
    )
    .with_pipeline_evidence(
        &metric_delta,
        &queue_snapshots,
        &drop_snapshots,
        "one_way_unsynchronized",
    )
    .with_network_delta(network_delta)
    .with_run_config(format!(
        "{{\"packets\":{},\"connections\":{},\"startup_timeout_secs\":{},\"idle_timeout_secs\":{},\"storage_enabled\":{},\"storage_flush_records\":{},\"storage_flush_ms\":{},\"storage_sync_data\":{},\"verifier_workers\":{},\"verifier_batch\":{},\"signer_workers\":{},\"queue_capacity\":{},\"replay_capacity\":{},\"quic_buffer_bytes\":{},\"quic_window_bytes\":{},\"transport\":\"quic_datagram\",\"tls\":\"mutual_rpk_tls13\"}}",
        args.expected_packets,
        args.connections.max(1),
        args.startup_timeout_secs,
        args.idle_timeout_secs,
        args.storage_enabled,
        args.storage_flush_records,
        args.storage_flush_ms,
        args.storage_sync_data,
        args.verifier_workers.max(1),
        args.verifier_batch.max(1),
        args.signer_workers.max(1),
        args.queue_capacity,
        args.replay_capacity,
        args.quic_buffer_bytes,
        args.quic_window_bytes,
    ));
    summary.receive_duration_secs = receive_duration.as_secs_f64();
    summary.cpu_percent =
        interval_cpu_percent(first_cpu_ticks, completion_cpu_ticks, processing_duration);
    write_summary(&args.out_dir, "receiver-summary", &summary)?;
    println!("receiver summary written to {}", args.out_dir.display());
    Ok(())
}

struct ReceiverConnectionResult {
    received: u64,
    accepted: u64,
    errors: u64,
    first_packet: Option<Instant>,
    first_cpu_ticks: Option<u64>,
    first_packet_wall_ns: Option<u64>,
    last_packet: Option<Instant>,
    control_send: quinn::SendStream,
}

async fn receive_benchmark_connection(
    conn: quinn::Connection,
    ingress: rpkv2::server_pipeline::ServerPipelineIngress,
    peer: String,
    idle_timeout_secs: u64,
    startup_timeout_secs: u64,
    sample_every: u64,
    latency: Arc<Mutex<Histogram<u64>>>,
) -> Result<ReceiverConnectionResult> {
    let idle = Duration::from_secs(idle_timeout_secs.max(1));
    let startup = Duration::from_secs(startup_timeout_secs.max(1));
    let (control_send, mut control_recv) = timeout(startup, conn.accept_bi())
        .await
        .context("timed out waiting for benchmark completion stream")??;
    let mut start_message = [0u8; 8];
    timeout(startup, control_recv.read_exact(&mut start_message))
        .await
        .context("timed out waiting for benchmark start message")??;
    if &start_message != START_MAGIC {
        return Err(anyhow!("invalid benchmark start message"));
    }
    let mut completion = tokio::spawn(async move {
        let mut message = [0u8; 16];
        control_recv
            .read_exact(&mut message)
            .await
            .context("completion stream closed")?;
        Ok::<_, anyhow::Error>(message)
    });
    let mut announced_packets = None;
    let mut received = 0u64;
    let mut accepted = 0u64;
    let mut errors = 0u64;
    let mut first_packet = None;
    let mut first_cpu_ticks = None;
    let mut first_packet_wall_ns = None;
    let mut last_packet = None;
    let mut last_activity = Instant::now();

    loop {
        tokio::select! {
            datagram = conn.read_datagram() => match datagram {
                Ok(datagram) => {
                    let now = Instant::now();
                    first_packet.get_or_insert(now);
                    if first_cpu_ticks.is_none() {
                        first_cpu_ticks = process_cpu_ticks();
                    }
                    first_packet_wall_ns.get_or_insert_with(now_unix_ns);
                    last_packet = Some(now);
                    last_activity = now;
                    received += 1;
                    {
                        let mut histogram = latency.lock().expect("latency histogram lock poisoned");
                        record_one_way_latency(&mut histogram, &datagram);
                    }
                    if sample_every > 0
                        && let Some(sent_ns) = packet_sent_ns(&datagram)
                        && sent_ns > 0
                    {
                        let mut ack = Vec::with_capacity(16);
                        ack.extend_from_slice(ACK_MAGIC);
                        ack.extend_from_slice(&sent_ns.to_be_bytes());
                        let _ = conn.send_datagram(Bytes::from(ack));
                    }
                    match ingress.ingest_datagram_bytes(&peer, datagram) {
                        Ok(true) => accepted += 1,
                        Ok(false) => {}
                        Err(_) => errors += 1,
                    }
                }
                Err(_) => break,
            },
            completion_result = &mut completion, if announced_packets.is_none() => {
                let control_message = completion_result.context("completion task failed")??;
                if &control_message[..8] != CONTROL_MAGIC {
                    return Err(anyhow!("invalid benchmark completion message"));
                }
                announced_packets = Some(u64::from_be_bytes(control_message[8..16].try_into()?));
            }
            _ = sleep(idle) => {
                if last_activity.elapsed() >= idle {
                    break;
                }
            }
        }
        if announced_packets.is_some_and(|announced| received >= announced) {
            break;
        }
    }

    Ok(ReceiverConnectionResult {
        received,
        accepted,
        errors,
        first_packet,
        first_cpu_ticks,
        first_packet_wall_ns,
        last_packet,
        control_send,
    })
}

async fn run_sender(args: SenderArgs) -> Result<()> {
    fs::create_dir_all(&args.out_dir)?;
    if args.packets == 0 {
        return Err(anyhow!("--packets must be greater than zero"));
    }
    let network_before = network_counters();
    let server_spki = fs::read(&args.server_spki)
        .with_context(|| format!("failed to read {}", args.server_spki.display()))?;
    let latency = Arc::new(Mutex::new(Histogram::<u64>::new(3)?));
    let acked_samples = Arc::new(AtomicU64::new(0));
    let connection_count = args.connections.max(1);
    let mut endpoints = Vec::with_capacity(connection_count);
    let mut connections = Vec::with_capacity(connection_count);
    for index in 0..connection_count {
        let key_path = &args.client_key[index % args.client_key.len()];
        let endpoint = client_endpoint_with_tuning(
            registry_for("receiver", &server_spki),
            "receiver",
            key_path.to_str().ok_or_else(|| anyhow!("bad key path"))?,
            benchmark_transport_tuning(args.quic_buffer_bytes, args.quic_window_bytes),
        )?;
        connections.push(endpoint.connect(args.connect, "localhost")?.await?);
        endpoints.push(endpoint);
    }
    let mut tasks = Vec::with_capacity(connection_count);
    let mut nonce_start = 0u64;
    for (index, conn) in connections.into_iter().enumerate() {
        let packets = args.packets / connection_count as u64
            + u64::from((index as u64) < args.packets % connection_count as u64);
        let connection_rate = if args.rate_pps == 0 {
            0
        } else {
            ((args.rate_pps as u128 * packets as u128) / args.packets as u128).max(1) as u64
        };
        tasks.push(tokio::spawn(send_benchmark_connection(
            conn,
            nonce_start,
            packets,
            args.payload_bytes,
            connection_rate,
            args.burst_size,
            args.sample_every,
            args.send_policy,
            latency.clone(),
            acked_samples.clone(),
        )));
        nonce_start = nonce_start.saturating_add(packets);
    }
    let mut results = Vec::with_capacity(tasks.len());
    for task in tasks {
        results.push(task.await.context("sender connection task failed")??);
    }
    let sent = results.iter().map(|result| result.sent).sum();
    let errors = results.iter().map(|result| result.errors).sum();
    let send_buffer_pressure_events = results
        .iter()
        .map(|result| result.send_buffer_pressure_events)
        .sum();
    let receiver_received = results.iter().map(|result| result.receiver_received).sum();
    let receiver_accepted = results.iter().map(|result| result.receiver_accepted).sum();
    let receiver_shreds = results
        .iter()
        .map(|result| result.receiver_shreds)
        .max()
        .unwrap_or(0);
    let receiver_durable = results
        .iter()
        .map(|result| result.receiver_durable)
        .max()
        .unwrap_or(0);
    let first_send = results.iter().map(|result| result.started).min();
    let last_send = results.iter().map(|result| result.finished).max();
    let first_cpu_ticks = results
        .iter()
        .filter_map(|result| result.started_cpu_ticks)
        .min();
    let last_cpu_ticks = results
        .iter()
        .filter_map(|result| result.finished_cpu_ticks)
        .max();
    let duration = first_send
        .zip(last_send)
        .map_or(Duration::ZERO, |(first, last)| last.duration_since(first));
    let latency = latency.lock().expect("latency histogram lock poisoned");
    let mut summary = BenchSummary::new(
        "two-node sender: offered signed mutual-RPK QUIC datagram load with sampled ingress RTT and receiver completion acknowledgement",
        args.packets,
        args.payload_bytes,
        sent,
        acked_samples.load(Ordering::Relaxed),
        receiver_accepted,
        receiver_shreds,
        sent.saturating_sub(receiver_received),
        errors,
        duration,
        &latency,
    );
    summary.latency_kind = "sampled_ingress_rtt";
    summary.completed_transactions = receiver_accepted;
    summary.durable_transactions = receiver_durable;
    summary.send_buffer_pressure_events = send_buffer_pressure_events;
    (summary.cpu_percent, summary.rss_bytes) = process_stats();
    summary.cpu_percent = interval_cpu_percent(first_cpu_ticks, last_cpu_ticks, duration);
    summary = summary
        .with_network_delta(network_counters().saturating_sub(network_before))
        .with_run_config(format!(
        "{{\"packets\":{},\"payload_bytes\":{},\"offered_rate_pps\":{},\"burst_size\":{},\"connections\":{},\"sample_every\":{},\"send_policy\":\"{}\",\"quic_buffer_bytes\":{},\"quic_window_bytes\":{},\"transport\":\"quic_datagram\",\"tls\":\"mutual_rpk_tls13\"}}",
        args.packets,
        args.payload_bytes,
        args.rate_pps,
        args.burst_size.max(1),
        args.connections.max(1),
        args.sample_every,
        args.send_policy.as_str(),
        args.quic_buffer_bytes,
        args.quic_window_bytes,
        ));
    write_summary(&args.out_dir, "sender-summary", &summary)?;
    println!("sender summary written to {}", args.out_dir.display());
    Ok(())
}

struct SenderConnectionResult {
    sent: u64,
    errors: u64,
    send_buffer_pressure_events: u64,
    receiver_received: u64,
    receiver_accepted: u64,
    receiver_shreds: u64,
    receiver_durable: u64,
    started: Instant,
    finished: Instant,
    started_cpu_ticks: Option<u64>,
    finished_cpu_ticks: Option<u64>,
}

#[allow(clippy::too_many_arguments)]
async fn send_benchmark_connection(
    conn: quinn::Connection,
    nonce_start: u64,
    packets: u64,
    payload_bytes: usize,
    rate_pps: u64,
    burst_size: u64,
    sample_every: u64,
    send_policy: DatagramSendPolicy,
    latency: Arc<Mutex<Histogram<u64>>>,
    acked_samples: Arc<AtomicU64>,
) -> Result<SenderConnectionResult> {
    let prepared = tokio::task::spawn_blocking(move || {
        let packet_key = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
        (0..packets)
            .map(|offset| {
                if sample_every > 0 && (offset + 1) % sample_every == 0 {
                    None
                } else {
                    Some(Bytes::from(signed_datagram_at(
                        &packet_key,
                        1,
                        nonce_start.saturating_add(offset),
                        payload_bytes,
                        0,
                    )))
                }
            })
            .collect::<Vec<_>>()
    })
    .await
    .context("packet preparation task failed")?;
    let packet_key = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    let (mut control_send, mut control_recv) = conn.open_bi().await?;
    control_send.write_all(START_MAGIC).await?;
    let stop_reader = Arc::new(AtomicBool::new(false));
    let stop_reader_task = stop_reader.clone();
    let ack_connection = conn.clone();
    let ack_task = tokio::spawn(async move {
        while !stop_reader_task.load(Ordering::Relaxed) {
            match timeout(Duration::from_millis(100), ack_connection.read_datagram()).await {
                Ok(Ok(ack)) if ack.len() == 16 && &ack[..8] == ACK_MAGIC => {
                    let sent_ns = u64::from_be_bytes(ack[8..16].try_into().expect("ack timestamp"));
                    let rtt_us = now_unix_ns().saturating_sub(sent_ns) / 1_000;
                    let _ = latency
                        .lock()
                        .expect("latency histogram lock poisoned")
                        .record(rtt_us.max(1));
                    acked_samples.fetch_add(1, Ordering::Relaxed);
                }
                Ok(Err(_)) => break,
                _ => {}
            }
        }
    });
    let mut sent = 0u64;
    let mut errors = 0u64;
    let mut send_buffer_pressure_events = 0u64;
    let started_cpu_ticks = process_cpu_ticks();
    let started = Instant::now();
    for offset in 0..packets {
        if rate_pps > 0 && offset > 0 && offset % burst_size.max(1) == 0 {
            let target = started + Duration::from_secs_f64(offset as f64 / rate_pps as f64);
            sleep_until(tokio::time::Instant::from_std(target)).await;
        }
        let datagram = prepared[offset as usize].clone().unwrap_or_else(|| {
            Bytes::from(signed_datagram(
                &packet_key,
                1,
                nonce_start.saturating_add(offset),
                payload_bytes,
            ))
        });
        if conn.datagram_send_buffer_space() < datagram.len() {
            send_buffer_pressure_events = send_buffer_pressure_events.saturating_add(1);
        }
        let send_result = match send_policy {
            DatagramSendPolicy::Wait => conn.send_datagram_wait(datagram).await,
            DatagramSendPolicy::EvictOldest => conn.send_datagram(datagram),
        };
        match send_result {
            Ok(()) => sent += 1,
            Err(_) => errors += 1,
        }
    }
    let finished = Instant::now();
    let finished_cpu_ticks = process_cpu_ticks();
    let mut completion = Vec::with_capacity(16);
    completion.extend_from_slice(CONTROL_MAGIC);
    completion.extend_from_slice(&sent.to_be_bytes());
    control_send.write_all(&completion).await?;
    control_send.finish()?;
    let mut completion_ack = [0u8; 40];
    timeout(
        Duration::from_secs(60),
        control_recv.read_exact(&mut completion_ack),
    )
    .await
    .context("timed out waiting for receiver pipeline completion")??;
    if &completion_ack[..8] != ACK_MAGIC {
        return Err(anyhow!("invalid receiver completion acknowledgement"));
    }
    stop_reader.store(true, Ordering::Relaxed);
    let _ = ack_task.await;
    conn.close(0u32.into(), b"sender-complete");
    Ok(SenderConnectionResult {
        sent,
        errors,
        send_buffer_pressure_events,
        receiver_received: u64::from_be_bytes(completion_ack[8..16].try_into()?),
        receiver_accepted: u64::from_be_bytes(completion_ack[16..24].try_into()?),
        receiver_shreds: u64::from_be_bytes(completion_ack[24..32].try_into()?),
        receiver_durable: u64::from_be_bytes(completion_ack[32..40].try_into()?),
        started,
        finished,
        started_cpu_ticks,
        finished_cpu_ticks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsampled_packet_is_not_recorded_as_one_way_latency() {
        let packet_key = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
        let datagram = signed_datagram_at(&packet_key, 1, 1, 256, 0);
        let mut latency = Histogram::<u64>::new(3).expect("histogram");

        record_one_way_latency(&mut latency, &datagram);

        assert_eq!(latency.len(), 0);
    }

    #[test]
    fn parses_linux_udp_error_counters() {
        let snmp = "Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors\n\
                    Udp: 100 2 7 110 5\n";

        assert_eq!(parse_udp_counters(snmp), (7, 5));
    }

    #[test]
    fn parses_linux_process_cpu_ticks_with_spaces_in_command() {
        let stat = "42 (quic pipeline bench) R 1 2 3 4 5 6 7 8 9 10 120 30 0";

        assert_eq!(parse_process_cpu_ticks(stat), Some(150));
    }
}
