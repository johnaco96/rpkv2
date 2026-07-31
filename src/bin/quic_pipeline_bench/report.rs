use super::runtime_support::{now_unix_ns, process_stats};
use super::*;

pub(super) struct BenchSummary {
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
    pub(super) send_buffer_pressure_events: u64,
    duration_secs: f64,
    pub(super) receive_duration_secs: f64,
    packet_rate: f64,
    p50_us: u64,
    p90_us: u64,
    p99_us: u64,
    p999_us: u64,
    deduplicated: u64,
    verified: u64,
    banked_transactions: u64,
    shreds_produced: u64,
    pub(super) durable_transactions: u64,
    pub(super) completed_transactions: u64,
    storage_bytes: u64,
    pub(super) cpu_percent: f64,
    pub(super) rss_bytes: u64,
    udp_in_errors: u64,
    udp_rcvbuf_errors: u64,
    interface_rx_dropped: u64,
    interface_tx_dropped: u64,
    queue_high_water_json: String,
    drop_reasons_json: String,
    pub(super) latency_kind: &'static str,
    run_config_json: String,
}

impl BenchSummary {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
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

    pub(super) fn with_run_config(mut self, run_config_json: String) -> Self {
        self.run_config_json = run_config_json;
        self
    }

    pub(super) fn with_network_delta(mut self, delta: NetworkCounters) -> Self {
        self.udp_in_errors = delta.udp_in_errors;
        self.udp_rcvbuf_errors = delta.udp_rcvbuf_errors;
        self.interface_rx_dropped = delta.interface_rx_dropped;
        self.interface_tx_dropped = delta.interface_tx_dropped;
        self
    }

    pub(super) fn with_pipeline_evidence(
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

pub(super) fn write_summary(out_dir: &Path, stem: &str, summary: &BenchSummary) -> Result<()> {
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
pub(super) struct NetworkCounters {
    udp_in_errors: u64,
    udp_rcvbuf_errors: u64,
    interface_rx_dropped: u64,
    interface_tx_dropped: u64,
}

impl NetworkCounters {
    pub(super) fn saturating_sub(self, before: Self) -> Self {
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

pub(super) fn network_counters() -> NetworkCounters {
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

pub(super) fn parse_udp_counters(snmp: &str) -> (u64, u64) {
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

pub(super) fn record_one_way_latency(latency: &mut Histogram<u64>, datagram: &[u8]) {
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

pub(super) fn packet_sent_ns(datagram: &[u8]) -> Option<u64> {
    let payload = datagram.get(HEADER_LEN..)?;
    Some(u64::from_be_bytes(payload.get(8..16)?.try_into().ok()?))
}

pub(super) async fn wait_for_pipeline_completion(
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

pub(super) fn pipeline_metrics_delta(
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

pub(super) async fn wait_for_storage_quiescence(dir: &Path, timeout_secs: u64) -> Result<u64> {
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
