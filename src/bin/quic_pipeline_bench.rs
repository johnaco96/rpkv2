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
    let pipeline = ServerPipeline::start(
        pipeline_config(storage_dir.clone(), args.packets, 16_384),
        shred_key,
        shutdown.clone(),
    );

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

struct BenchSummary {
    build: BuildInfo,
    rust_version: String,
    os: &'static str,
    arch: &'static str,
    cpu_count: usize,
    cpu_model: String,
    memory_bytes: u64,
    kernel: String,
    network_interfaces: String,
    scope: &'static str,
    configured_packets: u64,
    payload_bytes: usize,
    sent: u64,
    acked: u64,
    accepted: u64,
    stored: u64,
    drops: u64,
    errors: u64,
    send_buffer_pressure_events: u64,
    duration_secs: f64,
    receive_duration_secs: f64,
    packet_rate: f64,
    p50_us: u64,
    p90_us: u64,
    p99_us: u64,
    p999_us: u64,
    deduplicated: u64,
    verified: u64,
    banked_transactions: u64,
    shreds_produced: u64,
    durable_transactions: u64,
    completed_transactions: u64,
    storage_bytes: u64,
    cpu_percent: f64,
    rss_bytes: u64,
    udp_in_errors: u64,
    udp_rcvbuf_errors: u64,
    interface_rx_dropped: u64,
    interface_tx_dropped: u64,
    queue_high_water_json: String,
    drop_reasons_json: String,
    latency_kind: &'static str,
    run_config_json: String,
}

impl BenchSummary {
    #[allow(clippy::too_many_arguments)]
    fn new(
        scope: &'static str,
        configured_packets: u64,
        payload_bytes: usize,
        sent: u64,
        acked: u64,
        accepted: u64,
        stored: u64,
        drops: u64,
        errors: u64,
        duration: Duration,
        latency: &Histogram<u64>,
    ) -> Self {
        let system = system_metadata();
        Self {
            build: BuildInfo::current(),
            rust_version: rustc_version(),
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            cpu_count: num_cpus::get(),
            cpu_model: system.cpu_model,
            memory_bytes: system.memory_bytes,
            kernel: system.kernel,
            network_interfaces: system.network_interfaces,
            scope,
            configured_packets,
            payload_bytes,
            sent,
            acked,
            accepted,
            stored,
            drops,
            errors,
            send_buffer_pressure_events: 0,
            duration_secs: duration.as_secs_f64(),
            receive_duration_secs: duration.as_secs_f64(),
            packet_rate: if duration.as_secs_f64() > 0.0 {
                sent as f64 / duration.as_secs_f64()
            } else {
                0.0
            },
            p50_us: quantile(latency, 0.50),
            p90_us: quantile(latency, 0.90),
            p99_us: quantile(latency, 0.99),
            p999_us: quantile(latency, 0.999),
            deduplicated: 0,
            verified: 0,
            banked_transactions: 0,
            shreds_produced: 0,
            durable_transactions: 0,
            completed_transactions: 0,
            storage_bytes: 0,
            cpu_percent: 0.0,
            rss_bytes: 0,
            udp_in_errors: 0,
            udp_rcvbuf_errors: 0,
            interface_rx_dropped: 0,
            interface_tx_dropped: 0,
            queue_high_water_json: "[]".to_string(),
            drop_reasons_json: "[]".to_string(),
            latency_kind: "not_measured",
            run_config_json: format!(
                "{{\"packets\":{configured_packets},\"payload_bytes\":{payload_bytes},\"transport\":\"quic_datagram\",\"tls\":\"mutual_rpk_tls13\",\"pipeline\":\"ingress_rate_limit_dedupe_verify_pack_bank_poh_shred_sign_storage\"}}"
            ),
        }
    }

    fn with_run_config(mut self, run_config_json: String) -> Self {
        self.run_config_json = run_config_json;
        self
    }

    fn with_network_delta(mut self, delta: NetworkCounters) -> Self {
        self.udp_in_errors = delta.udp_in_errors;
        self.udp_rcvbuf_errors = delta.udp_rcvbuf_errors;
        self.interface_rx_dropped = delta.interface_rx_dropped;
        self.interface_tx_dropped = delta.interface_tx_dropped;
        self
    }

    fn with_pipeline_evidence(
        mut self,
        delta: &rpkv2::metrics::PipelineMetricsSnapshot,
        queues: &[rpkv2::metrics::QueueDepthSnapshot],
        drops: &[rpkv2::backpressure::QueueMetricsSnapshot],
        latency_kind: &'static str,
    ) -> Self {
        self.deduplicated = delta.packets_deduplicated;
        self.verified = delta.packets_verified;
        self.banked_transactions = delta.transactions_banked;
        self.shreds_produced = delta.shreds_produced;
        self.durable_transactions = delta.transactions_durable;
        self.completed_transactions = delta.transactions_completed;
        self.storage_bytes = delta.storage_bytes_written;
        (self.cpu_percent, self.rss_bytes) = process_stats();
        self.queue_high_water_json = render_queue_high_water(queues);
        self.drop_reasons_json = render_drop_reasons(drops, delta);
        self.latency_kind = latency_kind;
        self
    }

    fn render_csv(&self) -> String {
        let headers = [
            "schema",
            "git_commit",
            "crate_version",
            "build_features",
            "build_profile",
            "rust_version",
            "os",
            "arch",
            "cpu_count",
            "cpu_model",
            "memory_bytes",
            "kernel",
            "network_interfaces",
            "scope",
            "configured_packets",
            "payload_bytes",
            "sent_packets",
            "acked_packets",
            "accepted_packets",
            "stored_records",
            "drops",
            "errors",
            "send_buffer_pressure_events",
            "duration_secs",
            "receive_duration_secs",
            "packet_rate",
            "latency_p50_us",
            "latency_p90_us",
            "latency_p99_us",
            "latency_p999_us",
            "deduplicated_packets",
            "verified_packets",
            "banked_transactions",
            "shreds_produced",
            "durable_transactions",
            "completed_transactions",
            "storage_bytes",
            "cpu_percent",
            "rss_bytes",
            "udp_in_errors",
            "udp_rcvbuf_errors",
            "interface_rx_dropped",
            "interface_tx_dropped",
            "latency_kind",
            "deduplicated_rate_pps",
            "verified_rate_pps",
            "banked_rate_tps",
            "durable_rate_tps",
            "completed_rate_tps",
        ];
        let values = [
            "rpkv2.quic_pipeline_benchmark.v1".to_string(),
            self.build.git_commit.to_string(),
            self.build.crate_version.to_string(),
            self.build.build_features.clone(),
            self.build.build_profile.to_string(),
            self.rust_version.clone(),
            self.os.to_string(),
            self.arch.to_string(),
            self.cpu_count.to_string(),
            self.cpu_model.clone(),
            self.memory_bytes.to_string(),
            self.kernel.clone(),
            self.network_interfaces.clone(),
            self.scope.to_string(),
            self.configured_packets.to_string(),
            self.payload_bytes.to_string(),
            self.sent.to_string(),
            self.acked.to_string(),
            self.accepted.to_string(),
            self.stored.to_string(),
            self.drops.to_string(),
            self.errors.to_string(),
            self.send_buffer_pressure_events.to_string(),
            format!("{:.6}", self.duration_secs),
            format!("{:.6}", self.receive_duration_secs),
            format!("{:.3}", self.packet_rate),
            self.p50_us.to_string(),
            self.p90_us.to_string(),
            self.p99_us.to_string(),
            self.p999_us.to_string(),
            self.deduplicated.to_string(),
            self.verified.to_string(),
            self.banked_transactions.to_string(),
            self.shreds_produced.to_string(),
            self.durable_transactions.to_string(),
            self.completed_transactions.to_string(),
            self.storage_bytes.to_string(),
            format!("{:.3}", self.cpu_percent),
            self.rss_bytes.to_string(),
            self.udp_in_errors.to_string(),
            self.udp_rcvbuf_errors.to_string(),
            self.interface_rx_dropped.to_string(),
            self.interface_tx_dropped.to_string(),
            self.latency_kind.to_string(),
            format!("{:.3}", stage_rate(self.deduplicated, self.duration_secs)),
            format!("{:.3}", stage_rate(self.verified, self.duration_secs)),
            format!(
                "{:.3}",
                stage_rate(self.banked_transactions, self.duration_secs)
            ),
            format!(
                "{:.3}",
                stage_rate(self.durable_transactions, self.duration_secs)
            ),
            format!(
                "{:.3}",
                stage_rate(self.completed_transactions, self.duration_secs)
            ),
        ];
        let values: Vec<_> = values.iter().map(|value| csv_escape(value)).collect();
        format!("{}\n{}\n", headers.join(","), values.join(","))
    }

    fn render_json(&self) -> String {
        format!(
            concat!(
                "{{\n",
                "  \"schema\": \"rpkv2.quic_pipeline_benchmark.v1\",\n",
                "  \"measurement_scope\": \"{}\",\n",
                "  \"git_commit\": \"{}\",\n",
                "  \"crate_version\": \"{}\",\n",
                "  \"build_features\": \"{}\",\n",
                "  \"build_profile\": \"{}\",\n",
                "  \"rust_version\": \"{}\",\n",
                "  \"hardware\": {{\"cpu_count\": {},\"cpu_model\":\"{}\",\"memory_bytes\":{},\"arch\": \"{}\"}},\n",
                "  \"os\": \"{}\",\n",
                "  \"kernel\": \"{}\",\n",
                "  \"network_interfaces\": \"{}\",\n",
                "  \"config\": {},\n",
                "  \"sent_packets\": {},\n",
                "  \"acked_packets\": {},\n",
                "  \"accepted_packets\": {},\n",
                "  \"stored_records\": {},\n",
                "  \"drops\": {},\n",
                "  \"errors\": {},\n",
                "  \"send_buffer_pressure_events\": {},\n",
                "  \"duration_secs\": {:.6},\n",
                "  \"receive_duration_secs\": {:.6},\n",
                "  \"packet_rate\": {:.3},\n",
                "  \"latency_p50_us\": {},\n",
                "  \"latency_p90_us\": {},\n",
                "  \"latency_p99_us\": {},\n",
                "  \"latency_p999_us\": {},\n",
                "  \"latency_kind\": \"{}\",\n",
                "  \"deduplicated_packets\": {},\n",
                "  \"verified_packets\": {},\n",
                "  \"banked_transactions\": {},\n",
                "  \"shreds_produced\": {},\n",
                "  \"durable_transactions\": {},\n",
                "  \"completed_transactions\": {},\n",
                "  \"stage_rates\": {{\"deduplicated_pps\":{:.3},\"verified_pps\":{:.3},\"banked_tps\":{:.3},\"completed_tps\":{:.3},\"durable_tps\":{:.3}}},\n",
                "  \"storage_bytes\": {},\n",
                "  \"cpu_percent\": {:.3},\n",
                "  \"rss_bytes\": {},\n",
                "  \"network_deltas\": {{\"udp_in_errors\":{},\"udp_rcvbuf_errors\":{},\"interface_rx_dropped\":{},\"interface_tx_dropped\":{}}},\n",
                "  \"queue_high_water\": {},\n",
                "  \"drop_reasons\": {}\n",
                "}}\n"
            ),
            json_escape(self.scope),
            json_escape(self.build.git_commit),
            json_escape(self.build.crate_version),
            json_escape(&self.build.build_features),
            json_escape(self.build.build_profile),
            json_escape(&self.rust_version),
            self.cpu_count,
            json_escape(&self.cpu_model),
            self.memory_bytes,
            json_escape(self.arch),
            json_escape(self.os),
            json_escape(&self.kernel),
            json_escape(&self.network_interfaces),
            self.run_config_json,
            self.sent,
            self.acked,
            self.accepted,
            self.stored,
            self.drops,
            self.errors,
            self.send_buffer_pressure_events,
            self.duration_secs,
            self.receive_duration_secs,
            self.packet_rate,
            self.p50_us,
            self.p90_us,
            self.p99_us,
            self.p999_us,
            json_escape(self.latency_kind),
            self.deduplicated,
            self.verified,
            self.banked_transactions,
            self.shreds_produced,
            self.durable_transactions,
            self.completed_transactions,
            stage_rate(self.deduplicated, self.duration_secs),
            stage_rate(self.verified, self.duration_secs),
            stage_rate(self.banked_transactions, self.duration_secs),
            stage_rate(self.completed_transactions, self.duration_secs),
            stage_rate(self.durable_transactions, self.duration_secs),
            self.storage_bytes,
            self.cpu_percent,
            self.rss_bytes,
            self.udp_in_errors,
            self.udp_rcvbuf_errors,
            self.interface_rx_dropped,
            self.interface_tx_dropped,
            self.queue_high_water_json,
            self.drop_reasons_json,
        )
    }
}

fn write_summary(out_dir: &Path, stem: &str, summary: &BenchSummary) -> Result<()> {
    fs::create_dir_all(out_dir)?;
    let csv_path = out_dir.join(format!("{stem}.csv"));
    let json_path = out_dir.join(format!("{stem}.json"));
    fs::write(&csv_path, summary.render_csv())?;
    fs::write(&json_path, summary.render_json())?;
    println!("CSV written to {}", csv_path.display());
    println!("JSON written to {}", json_path.display());
    Ok(())
}

#[derive(Clone, Copy, Default)]
struct NetworkCounters {
    udp_in_errors: u64,
    udp_rcvbuf_errors: u64,
    interface_rx_dropped: u64,
    interface_tx_dropped: u64,
}

impl NetworkCounters {
    fn saturating_sub(self, before: Self) -> Self {
        Self {
            udp_in_errors: self.udp_in_errors.saturating_sub(before.udp_in_errors),
            udp_rcvbuf_errors: self
                .udp_rcvbuf_errors
                .saturating_sub(before.udp_rcvbuf_errors),
            interface_rx_dropped: self
                .interface_rx_dropped
                .saturating_sub(before.interface_rx_dropped),
            interface_tx_dropped: self
                .interface_tx_dropped
                .saturating_sub(before.interface_tx_dropped),
        }
    }
}

fn network_counters() -> NetworkCounters {
    if !cfg!(target_os = "linux") {
        return NetworkCounters::default();
    }
    let mut counters = NetworkCounters::default();
    if let Ok(snmp) = fs::read_to_string("/proc/net/snmp") {
        (counters.udp_in_errors, counters.udp_rcvbuf_errors) = parse_udp_counters(&snmp);
    }
    if let Ok(interfaces) = fs::read_dir("/sys/class/net") {
        for interface in interfaces.flatten() {
            let statistics = interface.path().join("statistics");
            counters.interface_rx_dropped = counters
                .interface_rx_dropped
                .saturating_add(read_counter(statistics.join("rx_dropped")));
            counters.interface_tx_dropped = counters
                .interface_tx_dropped
                .saturating_add(read_counter(statistics.join("tx_dropped")));
        }
    }
    counters
}

fn parse_udp_counters(snmp: &str) -> (u64, u64) {
    let mut udp_header: Option<Vec<&str>> = None;
    let mut in_errors = 0;
    let mut rcvbuf_errors = 0;
    for line in snmp.lines().filter(|line| line.starts_with("Udp:")) {
        let fields: Vec<_> = line.split_whitespace().skip(1).collect();
        if let Some(header) = udp_header.take() {
            for (name, value) in header.into_iter().zip(fields) {
                let value = value.parse::<u64>().unwrap_or(0);
                match name {
                    "InErrors" => in_errors = value,
                    "RcvbufErrors" => rcvbuf_errors = value,
                    _ => {}
                }
            }
        } else {
            udp_header = Some(fields);
        }
    }
    (in_errors, rcvbuf_errors)
}

fn read_counter(path: PathBuf) -> u64 {
    fs::read_to_string(path)
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(0)
}

fn temp_dir() -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "rpkv2-quic-pipeline-bench-{}-{suffix}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_tls_keypair(dir: &Path, name: &str) -> Result<(PathBuf, Vec<u8>)> {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    let key_path = dir.join(format!("{name}.key"));
    fs::write(&key_path, key_pair.serialize_pem())?;
    Ok((key_path, key_pair.public_key_der().to_vec()))
}

fn registry_for(id: &str, spki: &[u8]) -> PeerRegistry {
    let mut registry = PeerRegistry::default();
    registry
        .insert(PeerIdentity {
            validator_id: ValidatorId::from_str(id).unwrap(),
            tls_spki_ders: vec![spki.to_vec()],
            packet_verify_key: [7u8; 32],
            expected_address: None,
        })
        .unwrap();
    registry
}

fn registry_for_spkis(prefix: &str, spkis: &[Vec<u8>]) -> Result<PeerRegistry> {
    if spkis.is_empty() {
        return Err(anyhow!("at least one peer SPKI is required"));
    }
    let mut registry = PeerRegistry::default();
    for (index, spki) in spkis.iter().enumerate() {
        registry.insert(PeerIdentity {
            validator_id: ValidatorId::from_str(&format!("{prefix}-{index}"))?,
            tls_spki_ders: vec![spki.clone()],
            packet_verify_key: [7u8; 32],
            expected_address: None,
        })?;
    }
    Ok(registry)
}

fn server_endpoint(
    event_log: PathBuf,
    key_path: &str,
    registry: PeerRegistry,
    bind: SocketAddr,
) -> Result<Endpoint> {
    server_endpoint_with_tuning(
        event_log,
        key_path,
        registry,
        bind,
        quic_cfg::TransportTuning::default(),
    )
}

fn server_endpoint_with_tuning(
    event_log: PathBuf,
    key_path: &str,
    registry: PeerRegistry,
    bind: SocketAddr,
    tuning: quic_cfg::TransportTuning,
) -> Result<Endpoint> {
    write_jsonl(&event_log, "{\"event\":\"server_endpoint_start\"}")?;
    let tls = tls::build_server_rpk_mutual(key_path, registry)?;
    Ok(Endpoint::server(
        quic_cfg::server_config_with_tuning(tls, tuning),
        bind,
    )?)
}

fn client_endpoint(registry: PeerRegistry, peer_id: &str, key_path: &str) -> Result<Endpoint> {
    client_endpoint_with_tuning(
        registry,
        peer_id,
        key_path,
        quic_cfg::TransportTuning::default(),
    )
}

fn client_endpoint_with_tuning(
    registry: PeerRegistry,
    peer_id: &str,
    key_path: &str,
    tuning: quic_cfg::TransportTuning,
) -> Result<Endpoint> {
    let peer_id = ValidatorId::from_str(peer_id)?;
    let tls = tls::build_client_rpk_for_validator_with_identity(&registry, &peer_id, key_path)?;
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse::<SocketAddr>()?)?;
    endpoint.set_default_client_config(quic_cfg::client_config_with_tuning(tls, tuning));
    Ok(endpoint)
}

fn benchmark_transport_tuning(buffer_bytes: usize, window_bytes: u64) -> quic_cfg::TransportTuning {
    quic_cfg::TransportTuning {
        receive_window_bytes: window_bytes.min(u64::from(u32::MAX)) as u32,
        stream_receive_window_bytes: 256 * 1024,
        send_window_bytes: window_bytes,
        datagram_receive_buffer_bytes: buffer_bytes,
        datagram_send_buffer_bytes: buffer_bytes,
    }
}

fn pipeline_config(
    storage_dir: PathBuf,
    packets: u64,
    queue_capacity: usize,
) -> ServerPipelineConfig {
    let queue = queue_capacity.max(1);
    ServerPipelineConfig {
        raw_queue: queue,
        deduped_queue: queue,
        verified_queue: queue,
        packed_queue: queue,
        bank_queue: queue,
        poh_queue: queue,
        shred_queue: queue,
        signed_queue: queue,
        replay_capacity: packets.max(1).try_into().unwrap_or(usize::MAX),
        replay_window: packets.max(8),
        packets_per_second: packets.max(1_000_000),
        bytes_per_second: 1024 * 1024 * 1024,
        storage_dir,
        storage_recovery_policy: StorageRecoveryPolicy::FailStartup,
        storage_enabled: true,
        storage_flush_interval_records: 256,
        storage_flush_interval_ms: 10,
        storage_sync_data: false,
        verifier_batch: 64,
        verifier_workers: 1,
        verifier_affinity_base: None,
        bank_batch_size: 64,
        bank_flush_ms: 5,
        poh_tick_ms: 5,
        shred_mtu: 1232,
        signer_batch_size: 256,
        signer_workers: 1,
    }
}

fn signed_datagram(
    packet_key: &ed25519_dalek::SigningKey,
    slot: u64,
    nonce: u64,
    payload_bytes: usize,
) -> Vec<u8> {
    signed_datagram_at(packet_key, slot, nonce, payload_bytes, now_unix_ns())
}

fn signed_datagram_at(
    packet_key: &ed25519_dalek::SigningKey,
    slot: u64,
    nonce: u64,
    payload_bytes: usize,
    sent_ns: u64,
) -> Vec<u8> {
    let mut payload = vec![0u8; payload_bytes.max(16)];
    payload[0..8].copy_from_slice(&nonce.to_be_bytes());
    payload[8..16].copy_from_slice(&sent_ns.to_be_bytes());
    let mut header = Header {
        v: PACKET_VERSION,
        msg_type: MSG_TYPE_TRANSACTION_BATCH,
        flags: 0,
        slot,
        nonce,
        key_id: 0,
        pubkey: packet_key.verifying_key().to_bytes(),
        signature: [0u8; 64],
    };
    let signature = packet_key.sign(&header.signing_preimage(&payload));
    header.signature.copy_from_slice(&signature.to_bytes());
    let mut datagram = vec![0u8; HEADER_LEN];
    header.encode_into(&mut datagram).unwrap();
    datagram.extend_from_slice(&payload);
    datagram
}

fn record_one_way_latency(latency: &mut Histogram<u64>, datagram: &[u8]) {
    let Some(sent_ns) = packet_sent_ns(datagram) else {
        return;
    };
    if sent_ns == 0 {
        return;
    }
    let now_ns = now_unix_ns();
    if now_ns >= sent_ns {
        let _ = latency.record(((now_ns - sent_ns) / 1_000).max(1));
    }
}

fn packet_sent_ns(datagram: &[u8]) -> Option<u64> {
    let payload = datagram.get(HEADER_LEN..)?;
    Some(u64::from_be_bytes(payload.get(8..16)?.try_into().ok()?))
}

async fn wait_for_pipeline_completion(
    before: &rpkv2::metrics::PipelineMetricsSnapshot,
    expected_transactions: u64,
    timeout_secs: u64,
    require_durable: bool,
) {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs.max(1));
    while Instant::now() < deadline {
        let current = rpkv2::metrics::global().snapshot();
        let verified = current
            .packets_verified
            .saturating_sub(before.packets_verified);
        let durable = current
            .transactions_durable
            .saturating_sub(before.transactions_durable);
        let completed = current
            .transactions_completed
            .saturating_sub(before.transactions_completed);
        if verified >= expected_transactions
            && completed >= verified
            && (!require_durable || durable >= verified)
        {
            return;
        }
        sleep(Duration::from_millis(1)).await;
    }
}

fn quantile(latency: &Histogram<u64>, q: f64) -> u64 {
    if latency.is_empty() {
        0
    } else {
        latency.value_at_quantile(q)
    }
}

fn stage_rate(count: u64, duration_secs: f64) -> f64 {
    if duration_secs > 0.0 {
        count as f64 / duration_secs
    } else {
        0.0
    }
}

fn pipeline_metrics_delta(
    before: &rpkv2::metrics::PipelineMetricsSnapshot,
    after: &rpkv2::metrics::PipelineMetricsSnapshot,
) -> rpkv2::metrics::PipelineMetricsSnapshot {
    rpkv2::metrics::PipelineMetricsSnapshot {
        packets_received: after
            .packets_received
            .saturating_sub(before.packets_received),
        packets_accepted: after
            .packets_accepted
            .saturating_sub(before.packets_accepted),
        packets_deduplicated: after
            .packets_deduplicated
            .saturating_sub(before.packets_deduplicated),
        packets_verified: after
            .packets_verified
            .saturating_sub(before.packets_verified),
        transactions_banked: after
            .transactions_banked
            .saturating_sub(before.transactions_banked),
        shreds_produced: after.shreds_produced.saturating_sub(before.shreds_produced),
        shreds_written: after.shreds_written.saturating_sub(before.shreds_written),
        transactions_durable: after
            .transactions_durable
            .saturating_sub(before.transactions_durable),
        transactions_completed: after
            .transactions_completed
            .saturating_sub(before.transactions_completed),
        last_completed_timestamp_ns: after.last_completed_timestamp_ns,
        storage_bytes_written: after
            .storage_bytes_written
            .saturating_sub(before.storage_bytes_written),
        last_durable_timestamp_ns: after.last_durable_timestamp_ns,
        malformed_packets: after
            .malformed_packets
            .saturating_sub(before.malformed_packets),
        replay_drops: after.replay_drops.saturating_sub(before.replay_drops),
        replay_capacity_drops: after
            .replay_capacity_drops
            .saturating_sub(before.replay_capacity_drops),
        stale_slot_drops: after
            .stale_slot_drops
            .saturating_sub(before.stale_slot_drops),
        bad_signatures: after.bad_signatures.saturating_sub(before.bad_signatures),
        unknown_peer_drops: after
            .unknown_peer_drops
            .saturating_sub(before.unknown_peer_drops),
        storage_errors: after.storage_errors.saturating_sub(before.storage_errors),
    }
}

fn render_queue_high_water(queues: &[rpkv2::metrics::QueueDepthSnapshot]) -> String {
    let values: Vec<_> = queues
        .iter()
        .map(|queue| {
            format!(
                "{{\"stage\":\"{}\",\"high_water\":{},\"capacity\":{}}}",
                json_escape(queue.tile),
                queue.high_water,
                queue.capacity
            )
        })
        .collect();
    format!("[{}]", values.join(","))
}

fn render_drop_reasons(
    queues: &[rpkv2::backpressure::QueueMetricsSnapshot],
    metrics: &rpkv2::metrics::PipelineMetricsSnapshot,
) -> String {
    let mut values = vec![
        format!(
            "{{\"reason\":\"malformed\",\"count\":{}}}",
            metrics.malformed_packets
        ),
        format!(
            "{{\"reason\":\"replay\",\"count\":{}}}",
            metrics.replay_drops
        ),
        format!(
            "{{\"reason\":\"replay_capacity\",\"count\":{}}}",
            metrics.replay_capacity_drops
        ),
        format!(
            "{{\"reason\":\"stale_slot\",\"count\":{}}}",
            metrics.stale_slot_drops
        ),
        format!(
            "{{\"reason\":\"bad_signature\",\"count\":{}}}",
            metrics.bad_signatures
        ),
        format!(
            "{{\"reason\":\"unknown_peer\",\"count\":{}}}",
            metrics.unknown_peer_drops
        ),
        format!(
            "{{\"reason\":\"storage_error\",\"count\":{}}}",
            metrics.storage_errors
        ),
    ];
    values.extend(queues.iter().map(|queue| {
        format!(
            "{{\"reason\":\"queue_full\",\"stage\":\"{}\",\"full\":{},\"dropped\":{}}}",
            json_escape(queue.stage),
            queue.full,
            queue.dropped
        )
    }));
    format!("[{}]", values.join(","))
}

fn process_stats() -> (f64, u64) {
    if cfg!(target_os = "linux") {
        let pid = std::process::id().to_string();
        if let Ok(output) = Command::new("ps")
            .args(["-o", "%cpu=,rss=", "-p", &pid])
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            let mut fields = text.split_whitespace();
            let cpu = fields.next().and_then(|v| v.parse().ok()).unwrap_or(0.0);
            let rss_kib: u64 = fields.next().and_then(|v| v.parse().ok()).unwrap_or(0);
            return (cpu, rss_kib.saturating_mul(1024));
        }
    }
    (0.0, 0)
}

fn process_cpu_ticks() -> Option<u64> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let Ok(stat) = fs::read_to_string("/proc/self/stat") else {
        return None;
    };
    parse_process_cpu_ticks(&stat)
}

fn parse_process_cpu_ticks(stat: &str) -> Option<u64> {
    let command_end = stat.rfind(')')?;
    let fields: Vec<_> = stat[command_end + 1..].split_whitespace().collect();
    let user_ticks = fields.get(11).and_then(|value| value.parse::<u64>().ok())?;
    let system_ticks = fields.get(12).and_then(|value| value.parse::<u64>().ok())?;
    Some(user_ticks.saturating_add(system_ticks))
}

fn interval_cpu_percent(
    start_ticks: Option<u64>,
    end_ticks: Option<u64>,
    duration: Duration,
) -> f64 {
    if !cfg!(target_os = "linux") || duration.is_zero() {
        return 0.0;
    }
    let (Some(start_ticks), Some(end_ticks)) = (start_ticks, end_ticks) else {
        return 0.0;
    };
    let ticks_per_second = Command::new("getconf")
        .arg("CLK_TCK")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|value| value.trim().parse::<f64>().ok())
        .unwrap_or(100.0);
    let cpu_seconds = end_ticks.saturating_sub(start_ticks) as f64 / ticks_per_second;
    cpu_seconds / duration.as_secs_f64() * 100.0
}

struct SystemMetadata {
    cpu_model: String,
    memory_bytes: u64,
    kernel: String,
    network_interfaces: String,
}

fn system_metadata() -> SystemMetadata {
    if cfg!(target_os = "linux") {
        let cpu_model = fs::read_to_string("/proc/cpuinfo")
            .ok()
            .and_then(|text| {
                text.lines()
                    .find_map(|line| line.strip_prefix("model name\t: ").map(str::to_string))
            })
            .unwrap_or_else(|| "unknown".to_string());
        let memory_bytes = fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|text| {
                text.lines().find_map(|line| {
                    line.strip_prefix("MemTotal:")?
                        .split_whitespace()
                        .next()?
                        .parse::<u64>()
                        .ok()
                })
            })
            .unwrap_or(0)
            .saturating_mul(1024);
        let kernel = Command::new("uname")
            .args(["-srmo"])
            .output()
            .ok()
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let network_interfaces = fs::read_dir("/sys/class/net")
            .ok()
            .map(|entries| {
                let mut names: Vec<_> = entries
                    .flatten()
                    .filter_map(|entry| entry.file_name().into_string().ok())
                    .collect();
                names.sort();
                names.join(",")
            })
            .unwrap_or_else(|| "unknown".to_string());
        return SystemMetadata {
            cpu_model,
            memory_bytes,
            kernel,
            network_interfaces,
        };
    }

    SystemMetadata {
        cpu_model: std::env::var("PROCESSOR_IDENTIFIER").unwrap_or_else(|_| "unknown".to_string()),
        memory_bytes: 0,
        kernel: std::env::consts::OS.to_string(),
        network_interfaces: "not_collected".to_string(),
    }
}

async fn wait_for_storage_quiescence(dir: &Path, timeout_secs: u64) -> Result<u64> {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs.max(1));
    let mut last_records = 0u64;
    let mut stable_since = Instant::now();
    while Instant::now() < deadline {
        let report = scan_storage_dir(dir)?;
        let records = report.records_scanned as u64;
        if records != last_records {
            last_records = records;
            stable_since = Instant::now();
        }
        if records > 0 && stable_since.elapsed() >= Duration::from_millis(100) {
            return Ok(records);
        }
        sleep(Duration::from_millis(10)).await;
    }
    Ok(last_records)
}

fn now_unix_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .min(u128::from(u64::MAX)) as u64
}

fn rustc_version() -> String {
    Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|version| version.trim().to_string())
        .filter(|version| !version.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn write_jsonl(path: &Path, line: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{line}")?;
    Ok(())
}

fn json_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn csv_escape(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
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
