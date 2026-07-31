use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn temp_dir(label: &str) -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after the Unix epoch")
        .as_nanos();
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "rpkv2-{label}-{}-{timestamp}-{counter}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("test directory should be created");
    dir
}
