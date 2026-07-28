use crate::{
    backpressure, health::HealthReporter, peer_rate_limit::PeerRateLimiter, shutdown::Shutdown,
};
use std::{
    fmt::Write as _,
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Default)]
pub struct Metrics {
    packets_received: AtomicU64,
    packets_accepted: AtomicU64,
    packets_deduplicated: AtomicU64,
    packets_verified: AtomicU64,
    transactions_banked: AtomicU64,
    shreds_produced: AtomicU64,
    transactions_durable: AtomicU64,
    transactions_completed: AtomicU64,
    last_completed_timestamp_ns: AtomicU64,
    last_durable_timestamp_ns: AtomicU64,
    storage_bytes_written: AtomicU64,
    malformed_packets: AtomicU64,
    replay_drops: AtomicU64,
    replay_capacity_drops: AtomicU64,
    stale_slot_drops: AtomicU64,
    bad_signatures: AtomicU64,
    unknown_peer_drops: AtomicU64,
    shreds_written: AtomicU64,
    storage_errors: AtomicU64,
    active_connections: AtomicU64,
    non_leader_production_rejections: AtomicU64,
    execution_batches: AtomicU64,
    execution_transactions: AtomicU64,
    execution_conflicts: AtomicU64,
    verification_batch_size: Histogram,
    verification_latency_us: Histogram,
    packet_latency_us: Histogram,
}

#[derive(Default)]
struct Histogram {
    count: AtomicU64,
    sum: AtomicU64,
    max: AtomicU64,
}

#[derive(Clone)]
pub struct QueueDepthGauge {
    tile: &'static str,
    depth: Arc<dyn Fn() -> usize + Send + Sync>,
    capacity: usize,
    high_water: Arc<std::sync::atomic::AtomicUsize>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PipelineMetricsSnapshot {
    pub packets_received: u64,
    pub packets_accepted: u64,
    pub packets_deduplicated: u64,
    pub packets_verified: u64,
    pub transactions_banked: u64,
    pub shreds_produced: u64,
    pub shreds_written: u64,
    pub transactions_durable: u64,
    pub transactions_completed: u64,
    pub last_completed_timestamp_ns: u64,
    pub storage_bytes_written: u64,
    pub last_durable_timestamp_ns: u64,
    pub malformed_packets: u64,
    pub replay_drops: u64,
    pub replay_capacity_drops: u64,
    pub stale_slot_drops: u64,
    pub bad_signatures: u64,
    pub unknown_peer_drops: u64,
    pub storage_errors: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueDepthSnapshot {
    pub tile: &'static str,
    pub depth: usize,
    pub capacity: usize,
    pub high_water: usize,
}

impl QueueDepthGauge {
    pub fn new(tile: &'static str, depth: impl Fn() -> usize + Send + Sync + 'static) -> Self {
        Self::new_with_capacity(tile, 0, depth)
    }

    pub fn new_with_capacity(
        tile: &'static str,
        capacity: usize,
        depth: impl Fn() -> usize + Send + Sync + 'static,
    ) -> Self {
        Self {
            tile,
            depth: Arc::new(depth),
            capacity,
            high_water: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    pub fn sample(&self) -> QueueDepthSnapshot {
        let depth = (self.depth)();
        self.high_water.fetch_max(depth, Ordering::Relaxed);
        QueueDepthSnapshot {
            tile: self.tile,
            depth,
            capacity: self.capacity,
            high_water: self.high_water.load(Ordering::Relaxed),
        }
    }
}

static METRICS: OnceLock<Metrics> = OnceLock::new();

pub fn global() -> &'static Metrics {
    METRICS.get_or_init(Metrics::default)
}

impl Metrics {
    pub fn record_packet_received(&self) {
        self.packets_received.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_packet_accepted(&self) {
        self.packets_accepted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_packet_deduplicated(&self) {
        self.packets_deduplicated.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_packet_verified(&self) {
        self.packets_verified.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_transactions_banked(&self, count: u64) {
        self.transactions_banked.fetch_add(count, Ordering::Relaxed);
    }

    pub fn record_shred_produced(&self) {
        self.shreds_produced.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_transactions_durable(&self, count: u64) {
        self.record_transactions_completed(count);
        self.transactions_durable
            .fetch_add(count, Ordering::Relaxed);
        if count > 0 {
            self.last_durable_timestamp_ns
                .store(unix_timestamp_ns(), Ordering::Relaxed);
        }
    }

    pub fn record_transactions_completed(&self, count: u64) {
        self.transactions_completed
            .fetch_add(count, Ordering::Relaxed);
        if count > 0 {
            self.last_completed_timestamp_ns
                .store(unix_timestamp_ns(), Ordering::Relaxed);
        }
    }

    pub fn record_storage_bytes_written(&self, count: u64) {
        self.storage_bytes_written
            .fetch_add(count, Ordering::Relaxed);
    }

    pub fn record_malformed_packet(&self) {
        self.malformed_packets.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_replay_drop(&self) {
        self.replay_drops.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_replay_capacity_drop(&self) {
        self.replay_capacity_drops.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_stale_slot_drop(&self) {
        self.stale_slot_drops.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_bad_signature(&self) {
        self.bad_signatures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_unknown_peer_drop(&self) {
        self.unknown_peer_drops.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_shred_written(&self) {
        self.shreds_written.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_storage_error(&self) {
        self.storage_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn connection_opened(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn connection_closed(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn record_non_leader_production_rejection(&self) {
        self.non_leader_production_rejections
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_execution_batch(&self, transactions: u64, conflicts: u64) {
        self.execution_batches.fetch_add(1, Ordering::Relaxed);
        self.execution_transactions
            .fetch_add(transactions, Ordering::Relaxed);
        self.execution_conflicts
            .fetch_add(conflicts, Ordering::Relaxed);
    }

    pub fn record_verification_batch(&self, size: u64, latency: Duration) {
        self.verification_batch_size.record(size);
        self.verification_latency_us
            .record(latency.as_micros().min(u128::from(u64::MAX)) as u64);
    }

    pub fn record_packet_latency(&self, latency: Duration) {
        self.packet_latency_us
            .record(latency.as_micros().min(u128::from(u64::MAX)) as u64);
    }

    pub fn snapshot(&self) -> PipelineMetricsSnapshot {
        PipelineMetricsSnapshot {
            packets_received: self.packets_received.load(Ordering::Relaxed),
            packets_accepted: self.packets_accepted.load(Ordering::Relaxed),
            packets_deduplicated: self.packets_deduplicated.load(Ordering::Relaxed),
            packets_verified: self.packets_verified.load(Ordering::Relaxed),
            transactions_banked: self.transactions_banked.load(Ordering::Relaxed),
            shreds_produced: self.shreds_produced.load(Ordering::Relaxed),
            shreds_written: self.shreds_written.load(Ordering::Relaxed),
            transactions_durable: self.transactions_durable.load(Ordering::Relaxed),
            transactions_completed: self.transactions_completed.load(Ordering::Relaxed),
            last_completed_timestamp_ns: self.last_completed_timestamp_ns.load(Ordering::Relaxed),
            storage_bytes_written: self.storage_bytes_written.load(Ordering::Relaxed),
            last_durable_timestamp_ns: self.last_durable_timestamp_ns.load(Ordering::Relaxed),
            malformed_packets: self.malformed_packets.load(Ordering::Relaxed),
            replay_drops: self.replay_drops.load(Ordering::Relaxed),
            replay_capacity_drops: self.replay_capacity_drops.load(Ordering::Relaxed),
            stale_slot_drops: self.stale_slot_drops.load(Ordering::Relaxed),
            bad_signatures: self.bad_signatures.load(Ordering::Relaxed),
            unknown_peer_drops: self.unknown_peer_drops.load(Ordering::Relaxed),
            storage_errors: self.storage_errors.load(Ordering::Relaxed),
        }
    }

    pub fn render_text(
        &self,
        queue_depths: &[QueueDepthGauge],
        peer_limiter: Option<&PeerRateLimiter>,
    ) -> String {
        let mut out = String::new();
        metric(
            &mut out,
            "rpkv2_packets_received_total",
            self.packets_received.load(Ordering::Relaxed),
        );
        metric(
            &mut out,
            "rpkv2_packets_accepted_total",
            self.packets_accepted.load(Ordering::Relaxed),
        );
        metric(
            &mut out,
            "rpkv2_packets_deduplicated_total",
            self.packets_deduplicated.load(Ordering::Relaxed),
        );
        metric(
            &mut out,
            "rpkv2_packets_verified_total",
            self.packets_verified.load(Ordering::Relaxed),
        );
        metric(
            &mut out,
            "rpkv2_transactions_banked_total",
            self.transactions_banked.load(Ordering::Relaxed),
        );
        metric(
            &mut out,
            "rpkv2_transactions_completed_total",
            self.transactions_completed.load(Ordering::Relaxed),
        );
        metric(
            &mut out,
            "rpkv2_shreds_produced_total",
            self.shreds_produced.load(Ordering::Relaxed),
        );
        metric(
            &mut out,
            "rpkv2_transactions_durable_total",
            self.transactions_durable.load(Ordering::Relaxed),
        );
        metric(
            &mut out,
            "rpkv2_storage_bytes_written_total",
            self.storage_bytes_written.load(Ordering::Relaxed),
        );
        metric(
            &mut out,
            "rpkv2_malformed_packets_total",
            self.malformed_packets.load(Ordering::Relaxed),
        );
        metric(
            &mut out,
            "rpkv2_replay_drops_total",
            self.replay_drops.load(Ordering::Relaxed),
        );
        metric(
            &mut out,
            "rpkv2_replay_capacity_drops_total",
            self.replay_capacity_drops.load(Ordering::Relaxed),
        );
        metric(
            &mut out,
            "rpkv2_stale_slot_drops_total",
            self.stale_slot_drops.load(Ordering::Relaxed),
        );
        metric(
            &mut out,
            "rpkv2_bad_signatures_total",
            self.bad_signatures.load(Ordering::Relaxed),
        );
        metric(
            &mut out,
            "rpkv2_unknown_peer_drops_total",
            self.unknown_peer_drops.load(Ordering::Relaxed),
        );
        metric(
            &mut out,
            "rpkv2_shreds_written_total",
            self.shreds_written.load(Ordering::Relaxed),
        );
        metric(
            &mut out,
            "rpkv2_storage_errors_total",
            self.storage_errors.load(Ordering::Relaxed),
        );
        metric(
            &mut out,
            "rpkv2_active_connections",
            self.active_connections.load(Ordering::Relaxed),
        );
        metric(
            &mut out,
            "rpkv2_non_leader_production_rejections_total",
            self.non_leader_production_rejections
                .load(Ordering::Relaxed),
        );
        metric(
            &mut out,
            "rpkv2_execution_batches_total",
            self.execution_batches.load(Ordering::Relaxed),
        );
        metric(
            &mut out,
            "rpkv2_execution_transactions_total",
            self.execution_transactions.load(Ordering::Relaxed),
        );
        metric(
            &mut out,
            "rpkv2_execution_conflicts_total",
            self.execution_conflicts.load(Ordering::Relaxed),
        );
        self.verification_batch_size
            .render(&mut out, "rpkv2_verification_batch_size");
        self.verification_latency_us
            .render(&mut out, "rpkv2_verification_latency_us");
        self.packet_latency_us
            .render(&mut out, "rpkv2_packet_latency_us");

        for gauge in queue_depths {
            let snapshot = gauge.sample();
            let _ = writeln!(
                out,
                "rpkv2_queue_depth{{tile=\"{}\"}} {}",
                snapshot.tile, snapshot.depth
            );
            let _ = writeln!(
                out,
                "rpkv2_queue_high_water{{tile=\"{}\"}} {}",
                snapshot.tile, snapshot.high_water
            );
            let _ = writeln!(
                out,
                "rpkv2_queue_capacity{{tile=\"{}\"}} {}",
                snapshot.tile, snapshot.capacity
            );
        }

        out.push_str(&backpressure::metrics_text());
        if let Some(peer_limiter) = peer_limiter {
            out.push_str(&peer_limiter.metrics_text());
        }
        out
    }
}

impl Histogram {
    fn record(&self, value: u64) {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum.fetch_add(value, Ordering::Relaxed);
        let mut current = self.max.load(Ordering::Relaxed);
        while value > current {
            match self
                .max
                .compare_exchange(current, value, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => break,
                Err(next) => current = next,
            }
        }
    }

    fn render(&self, out: &mut String, name: &str) {
        metric(
            out,
            &format!("{name}_count"),
            self.count.load(Ordering::Relaxed),
        );
        metric(
            out,
            &format!("{name}_sum"),
            self.sum.load(Ordering::Relaxed),
        );
        metric(
            out,
            &format!("{name}_max"),
            self.max.load(Ordering::Relaxed),
        );
    }
}

pub fn start_metrics_endpoint(
    bind: SocketAddr,
    shutdown: Shutdown,
    queue_depths: Vec<QueueDepthGauge>,
    peer_limiter: Option<PeerRateLimiter>,
    health: Option<HealthReporter>,
) -> std::io::Result<thread::JoinHandle<()>> {
    let listener = TcpListener::bind(bind)?;
    listener.set_nonblocking(true)?;
    if let Some(health) = &health {
        health.mark_metrics_active();
    }
    let queue_depths = Arc::new(queue_depths);
    let peer_limiter = Arc::new(peer_limiter);
    let health = Arc::new(health);

    Ok(thread::spawn(move || {
        while !shutdown.is_requested() {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut request = [0u8; 512];
                    let read = stream.read(&mut request).unwrap_or(0);
                    let path = request_path(&request[..read]);
                    let response = match path {
                        "/health" => health_response(health.as_ref().as_ref(), false),
                        "/ready" | "/readyz" => health_response(health.as_ref().as_ref(), true),
                        _ => {
                            let body =
                                global().render_text(&queue_depths, peer_limiter.as_ref().as_ref());
                            http_response(200, "OK", "text/plain; version=0.0.4", body)
                        }
                    };
                    let _ = stream.write_all(response.as_bytes());
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(50));
                }
                Err(e) => {
                    if crate::logging::should_log(
                        "metrics_endpoint_accept_failed",
                        Duration::from_secs(1),
                    ) {
                        tracing::warn!(
                            reason = %e,
                            "metrics endpoint accept failed"
                        );
                    }
                    thread::sleep(Duration::from_millis(50));
                }
            }
        }
    }))
}

fn request_path(request: &[u8]) -> &str {
    let request = std::str::from_utf8(request).unwrap_or_default();
    let mut parts = request
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or("/");
    if method == "GET" { path } else { "/" }
}

fn health_response(health: Option<&HealthReporter>, readiness: bool) -> String {
    let Some(health) = health else {
        return http_response(
            503,
            "Service Unavailable",
            "application/json",
            "{\"state\":\"unhealthy\",\"ready\":false,\"reason\":\"health_not_configured\"}\n"
                .to_string(),
        );
    };
    let snapshot = health.snapshot();
    let status = if readiness {
        if snapshot.ready {
            (200, "OK")
        } else {
            (503, "Service Unavailable")
        }
    } else if matches!(snapshot.state, crate::health::HealthState::Unhealthy) {
        (503, "Service Unavailable")
    } else {
        (200, "OK")
    };
    http_response(
        status.0,
        status.1,
        "application/json",
        health.render_health_json(),
    )
}

fn http_response(code: u16, reason: &str, content_type: &str, body: String) -> String {
    format!(
        "HTTP/1.1 {code} {reason}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

fn metric(out: &mut String, name: &str, value: u64) {
    let _ = writeln!(out, "{name} {value}");
}

fn unix_timestamp_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .min(u128::from(u64::MAX)) as u64
}

pub struct ActiveConnectionGuard {
    closed: bool,
}

impl ActiveConnectionGuard {
    pub fn new() -> Self {
        global().connection_opened();
        Self { closed: false }
    }
}

impl Default for ActiveConnectionGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ActiveConnectionGuard {
    fn drop(&mut self) {
        if !self.closed {
            global().connection_closed();
            self.closed = true;
        }
    }
}

pub fn elapsed_since_us(start: Instant) -> Duration {
    start.elapsed()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_output_includes_core_names() {
        let metrics = Metrics::default();
        metrics.record_packet_received();
        metrics.record_packet_accepted();
        metrics.record_verification_batch(8, Duration::from_micros(12));
        metrics.record_execution_batch(2, 1);
        let q_depths = vec![QueueDepthGauge::new("raw", || 3)];

        let text = metrics.render_text(&q_depths, None);

        assert!(text.contains("rpkv2_packets_received_total 1"));
        assert!(text.contains("rpkv2_packets_accepted_total 1"));
        assert!(text.contains("rpkv2_verification_batch_size_count 1"));
        assert!(text.contains("rpkv2_queue_depth{tile=\"raw\"} 3"));
        assert!(text.contains("rpkv2_non_leader_production_rejections_total 0"));
        assert!(text.contains("rpkv2_execution_batches_total 1"));
        assert!(text.contains("rpkv2_execution_transactions_total 2"));
        assert!(text.contains("rpkv2_execution_conflicts_total 1"));
    }

    #[test]
    fn health_endpoint_reports_ready_json() {
        let health = HealthReporter::new("validator-a");
        health.mark_config_valid();
        health.mark_keys_loaded();
        health.mark_socket_bound();
        health.mark_storage_writable();
        health.mark_metrics_active();
        health.set_ready();

        let response = health_response(Some(&health), true);

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("\"state\":\"ready\""));
        assert!(response.contains("\"ready\":true"));
    }

    #[test]
    fn readiness_endpoint_fails_when_storage_is_not_writable() {
        let health = HealthReporter::new("validator-a");
        health.mark_config_valid();
        health.mark_keys_loaded();
        health.mark_socket_bound();
        health.mark_metrics_active();
        health.set_ready();

        let response = health_response(Some(&health), true);

        assert!(response.starts_with("HTTP/1.1 503 Service Unavailable"));
        assert!(response.contains("\"storage_writable\":false"));
    }
}
