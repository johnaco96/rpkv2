use std::{
    collections::HashMap,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);
static RATE_LIMITS: OnceLock<Mutex<HashMap<&'static str, Instant>>> = OnceLock::new();

pub fn next_connection_id() -> u64 {
    NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed)
}

pub fn should_log(key: &'static str, interval: Duration) -> bool {
    let limits = RATE_LIMITS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut limits = limits.lock().expect("logging rate limit lock poisoned");
    let now = Instant::now();
    match limits.get(&key) {
        Some(last) if now.duration_since(*last) < interval => false,
        _ => {
            limits.insert(key, now);
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_ids_increase() {
        let first = next_connection_id();
        let second = next_connection_id();
        assert!(second > first);
    }

    #[test]
    fn rate_limit_suppresses_repeated_key() {
        let key = "test_rate_limit_suppresses_repeated_key";
        assert!(should_log(key, Duration::from_secs(60)));
        assert!(!should_log(key, Duration::from_secs(60)));
    }
}
