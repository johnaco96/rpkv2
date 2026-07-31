use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

pub(crate) fn temp_dir(label: &str) -> PathBuf {
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

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers_create_unique_directories_and_encode_hex() {
        let first = temp_dir("support");
        let second = temp_dir("support");
        assert_ne!(first, second);
        assert!(first.is_dir());
        assert!(second.is_dir());
        assert_eq!(hex(&[0x00, 0xab, 0xff]), "00abff");
        fs::remove_dir_all(first).unwrap();
        fs::remove_dir_all(second).unwrap();
    }
}
