use crossbeam_queue::ArrayQueue;
use std::{
    collections::BTreeMap,
    fmt,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueuePolicy {
    RejectNewest,
    SpinThenDropNewest { spins: usize },
}

impl fmt::Display for QueuePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QueuePolicy::RejectNewest => write!(f, "reject_newest"),
            QueuePolicy::SpinThenDropNewest { spins } => {
                write!(f, "spin_then_drop_newest:{spins}")
            }
        }
    }
}

#[derive(Debug)]
pub struct QueueMetrics {
    stage: &'static str,
    policy: QueuePolicy,
    full: AtomicU64,
    dropped: AtomicU64,
    accepted_after_spin: AtomicU64,
    last_log_ms: AtomicU64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueMetricsSnapshot {
    pub stage: &'static str,
    pub policy: QueuePolicy,
    pub full: u64,
    pub dropped: u64,
    pub accepted_after_spin: u64,
}

impl QueueMetrics {
    fn new(stage: &'static str, policy: QueuePolicy) -> Self {
        Self {
            stage,
            policy,
            full: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            accepted_after_spin: AtomicU64::new(0),
            last_log_ms: AtomicU64::new(0),
        }
    }

    fn snapshot(&self) -> QueueMetricsSnapshot {
        QueueMetricsSnapshot {
            stage: self.stage,
            policy: self.policy,
            full: self.full.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            accepted_after_spin: self.accepted_after_spin.load(Ordering::Relaxed),
        }
    }
}

static METRICS: OnceLock<Mutex<BTreeMap<&'static str, Arc<QueueMetrics>>>> = OnceLock::new();

pub const INGRESS_POLICY: QueuePolicy = QueuePolicy::RejectNewest;
pub const INTERNAL_STAGE_POLICY: QueuePolicy = QueuePolicy::SpinThenDropNewest { spins: 64 };

pub fn push_with_policy<T>(
    stage: &'static str,
    queue: &ArrayQueue<T>,
    item: T,
    policy: QueuePolicy,
) -> bool {
    let metrics = metrics_for(stage, policy);
    match queue.push(item) {
        Ok(()) => true,
        Err(mut item) => {
            metrics.full.fetch_add(1, Ordering::Relaxed);
            log_queue_full(&metrics);

            match policy {
                QueuePolicy::RejectNewest => {
                    metrics.dropped.fetch_add(1, Ordering::Relaxed);
                    false
                }
                QueuePolicy::SpinThenDropNewest { spins } => {
                    for _ in 0..spins {
                        thread::yield_now();
                        match queue.push(item) {
                            Ok(()) => {
                                metrics.accepted_after_spin.fetch_add(1, Ordering::Relaxed);
                                return true;
                            }
                            Err(returned) => item = returned,
                        }
                    }
                    metrics.dropped.fetch_add(1, Ordering::Relaxed);
                    false
                }
            }
        }
    }
}

pub fn metrics_snapshot() -> Vec<QueueMetricsSnapshot> {
    METRICS
        .get()
        .map(|registry| {
            registry
                .lock()
                .expect("backpressure metrics lock poisoned")
                .values()
                .map(|metrics| metrics.snapshot())
                .collect()
        })
        .unwrap_or_default()
}

pub fn metrics_text() -> String {
    let mut out = String::new();
    for metric in metrics_snapshot() {
        out.push_str(&format!(
            "rpkv2_queue_full_total{{stage=\"{}\",policy=\"{}\"}} {}\n",
            metric.stage, metric.policy, metric.full
        ));
        out.push_str(&format!(
            "rpkv2_queue_dropped_total{{stage=\"{}\",policy=\"{}\"}} {}\n",
            metric.stage, metric.policy, metric.dropped
        ));
        out.push_str(&format!(
            "rpkv2_queue_accepted_after_spin_total{{stage=\"{}\",policy=\"{}\"}} {}\n",
            metric.stage, metric.policy, metric.accepted_after_spin
        ));
    }
    out
}

fn metrics_for(stage: &'static str, policy: QueuePolicy) -> Arc<QueueMetrics> {
    let registry = METRICS.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut registry = registry.lock().expect("backpressure metrics lock poisoned");
    registry
        .entry(stage)
        .or_insert_with(|| Arc::new(QueueMetrics::new(stage, policy)))
        .clone()
}

fn log_queue_full(metrics: &QueueMetrics) {
    let now_ms = now_ms();
    let last = metrics.last_log_ms.load(Ordering::Relaxed);
    if now_ms.saturating_sub(last) < 1_000 {
        return;
    }
    if metrics
        .last_log_ms
        .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
    {
        tracing::warn!(
            tile = metrics.stage,
            stage = metrics.stage,
            policy = %metrics.policy,
            reason = "queue_full",
            full = metrics.full.load(Ordering::Relaxed),
            dropped = metrics.dropped.load(Ordering::Relaxed),
            "queue full; applying backpressure policy"
        );
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_newest_counts_drop_and_keeps_process_alive() {
        let q = ArrayQueue::new(1);
        assert!(push_with_policy(
            "test_reject_newest",
            &q,
            1,
            QueuePolicy::RejectNewest
        ));
        assert!(!push_with_policy(
            "test_reject_newest",
            &q,
            2,
            QueuePolicy::RejectNewest
        ));

        let metric = metrics_snapshot()
            .into_iter()
            .find(|metric| metric.stage == "test_reject_newest")
            .expect("missing test metric");
        assert_eq!(metric.full, 1);
        assert_eq!(metric.dropped, 1);
        assert_eq!(q.pop(), Some(1));
    }

    #[test]
    fn spin_then_drop_counts_drop_when_queue_stays_full() {
        let q = ArrayQueue::new(1);
        assert!(push_with_policy(
            "test_spin_then_drop",
            &q,
            1,
            QueuePolicy::SpinThenDropNewest { spins: 1 }
        ));
        assert!(!push_with_policy(
            "test_spin_then_drop",
            &q,
            2,
            QueuePolicy::SpinThenDropNewest { spins: 1 }
        ));

        let metric = metrics_snapshot()
            .into_iter()
            .find(|metric| metric.stage == "test_spin_then_drop")
            .expect("missing test metric");
        assert_eq!(metric.full, 1);
        assert_eq!(metric.dropped, 1);
        assert!(metrics_text().contains("rpkv2_queue_dropped_total"));
    }
}
