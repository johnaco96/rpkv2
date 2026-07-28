use crate::{
    config::ProductionConfig,
    identity_keys::{GeneratedIdentityFiles, generate_validator_identity},
    snapshot::LedgerSnapshot,
    tiles::storage::{StorageRecovery, StorageRecoveryPolicy, StorageScanReport},
};
use anyhow::{Result, anyhow, bail};
use serde::Serialize;
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeInitReport {
    pub node_dir: PathBuf,
    pub config_template_path: PathBuf,
    pub storage_dir: PathBuf,
    pub run_dir: PathBuf,
    pub snapshot_dir: PathBuf,
    pub identity: GeneratedIdentityFiles,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NodeStatusReport {
    pub config_path: PathBuf,
    pub config_valid: bool,
    pub validator_id: Option<String>,
    pub storage_dir: Option<PathBuf>,
    pub storage_clean: Option<bool>,
    pub storage_records_scanned: Option<usize>,
    pub pid_file: Option<PathBuf>,
    pub pid: Option<u32>,
    pub running: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StartPlan {
    pub config_path: PathBuf,
    pub validator_id: String,
    pub bind_address: String,
    pub storage_dir: PathBuf,
    pub metrics_address: String,
    pub command: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotFileReport {
    pub source_path: PathBuf,
    pub destination_path: PathBuf,
    pub bytes_written: u64,
    pub slot_epoch: u64,
    pub slot: u64,
    pub block_hash_hex: String,
    pub state_root_hex: String,
}

pub fn init_node(
    validator_id: &str,
    node_dir: impl AsRef<Path>,
    overwrite: bool,
) -> Result<NodeInitReport> {
    let node_dir = node_dir.as_ref();
    fs::create_dir_all(node_dir)?;
    let key_dir = node_dir.join("keys");
    let storage_dir = node_dir.join("storage");
    let run_dir = node_dir.join("run");
    let snapshot_dir = node_dir.join("snapshots");
    fs::create_dir_all(&storage_dir)?;
    fs::create_dir_all(&run_dir)?;
    fs::create_dir_all(&snapshot_dir)?;

    let identity = generate_validator_identity(validator_id, &key_dir, overwrite)?;
    let config_template_path = node_dir.join("production.toml.template");
    write_new_file(
        &config_template_path,
        config_template(
            validator_id,
            &identity.transport_private_key_path,
            &identity.packet_signing_key_path,
            &storage_dir,
        ),
        overwrite,
    )?;

    Ok(NodeInitReport {
        node_dir: node_dir.to_path_buf(),
        config_template_path,
        storage_dir,
        run_dir,
        snapshot_dir,
        identity,
    })
}

pub fn validate_config(path: impl AsRef<Path>) -> Result<ProductionConfig> {
    ProductionConfig::load(path)
}

pub fn start_plan(config_path: impl AsRef<Path>) -> Result<StartPlan> {
    let config_path = config_path.as_ref();
    let config = ProductionConfig::load(config_path)?;
    Ok(StartPlan {
        config_path: config_path.to_path_buf(),
        validator_id: config.local.validator_id,
        bind_address: config.local.bind_address.to_string(),
        storage_dir: config.storage.directory,
        metrics_address: config.metrics.bind_address.to_string(),
        command: vec![
            "server".to_string(),
            "--mode".to_string(),
            "production".to_string(),
            "--config".to_string(),
            config_path.display().to_string(),
        ],
    })
}

pub fn status_report(
    config_path: impl AsRef<Path>,
    pid_file: Option<impl AsRef<Path>>,
) -> NodeStatusReport {
    let config_path = config_path.as_ref().to_path_buf();
    let pid_file = pid_file.map(|path| path.as_ref().to_path_buf());
    let mut report = NodeStatusReport {
        config_path: config_path.clone(),
        config_valid: false,
        validator_id: None,
        storage_dir: None,
        storage_clean: None,
        storage_records_scanned: None,
        pid_file: pid_file.clone(),
        pid: pid_file.as_ref().and_then(|path| read_pid(path).ok()),
        running: false,
    };

    if let Ok(config) = ProductionConfig::load(&config_path) {
        report.config_valid = true;
        report.validator_id = Some(config.local.validator_id);
        report.storage_dir = Some(config.storage.directory.clone());
        if let Ok(storage) = crate::tiles::storage::scan_storage_dir(&config.storage.directory) {
            report.storage_clean = Some(storage.is_clean());
            report.storage_records_scanned = Some(storage.records_scanned);
        }
    }
    report.running = report.pid.is_some();
    report
}

pub fn repair_ledger(
    storage_dir: impl AsRef<Path>,
    policy: StorageRecoveryPolicy,
) -> Result<StorageRecovery> {
    crate::tiles::storage::recover_storage_dir(storage_dir.as_ref(), policy).map_err(|e| anyhow!(e))
}

pub fn scan_ledger(storage_dir: impl AsRef<Path>) -> Result<StorageScanReport> {
    Ok(crate::tiles::storage::scan_storage_dir(
        storage_dir.as_ref(),
    )?)
}

pub fn validate_snapshot_file(path: impl AsRef<Path>) -> Result<LedgerSnapshot> {
    LedgerSnapshot::decode(&fs::read(path)?)
}

pub fn copy_validated_snapshot(
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    overwrite: bool,
) -> Result<SnapshotFileReport> {
    let source = source.as_ref();
    let destination = destination.as_ref();
    let bytes = fs::read(source)?;
    let snapshot = LedgerSnapshot::decode(&bytes)?;
    if destination.exists() && !overwrite {
        bail!("refusing to overwrite existing snapshot: {destination:?}");
    }
    if let Some(parent) = destination.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    fs::write(destination, &bytes)?;
    Ok(SnapshotFileReport {
        source_path: source.to_path_buf(),
        destination_path: destination.to_path_buf(),
        bytes_written: bytes.len() as u64,
        slot_epoch: snapshot.slot.epoch,
        slot: snapshot.slot.slot,
        block_hash_hex: hex(&snapshot.block_hash),
        state_root_hex: hex(&snapshot.state_root),
    })
}

pub fn stop_with_pid_file(
    pid_file: impl AsRef<Path>,
    remove_pid_file: bool,
) -> Result<Option<u32>> {
    let pid_file = pid_file.as_ref();
    let pid = if pid_file.exists() {
        Some(read_pid(pid_file)?)
    } else {
        None
    };
    if remove_pid_file && pid_file.exists() {
        fs::remove_file(pid_file)?;
    }
    Ok(pid)
}

fn config_template(
    validator_id: &str,
    private_key_path: &Path,
    packet_signing_key_path: &Path,
    storage_dir: &Path,
) -> String {
    format!(
        r#"# Copy this file to production.toml and fill in peer identity values before starting.
format_version = 1

[local]
bind_address = "0.0.0.0:4433"
validator_id = "{validator_id}"
private_key_path = '{}'
packet_signing_key_path = '{}'

[[peers]]
validator_id = "replace-with-peer-validator-id"
spki_pin_path = "replace-with-peer-transport.pub"
ed25519_verify_key_hex = "replace-with-peer-packet-verify-key-hex"

[replay]
slot_window = 1024

[queues]
raw = 8192
deduped = 8192
verified = 8192
packed = 8192
bank = 1024
poh = 1024
shred = 4096
signed = 4096

[rate_limits]
packets_per_second = 50000
bytes_per_second = 64000000

[storage]
directory = '{}'
allow_unsafe_demo_storage = true
recovery_policy = "fail_startup"

[metrics]
bind_address = "127.0.0.1:9100"
"#,
        private_key_path.display(),
        packet_signing_key_path.display(),
        storage_dir.display()
    )
}

fn write_new_file(path: &Path, contents: String, overwrite: bool) -> Result<()> {
    if path.exists() && !overwrite {
        bail!("refusing to overwrite existing file: {path:?}");
    }
    fs::write(path, contents)?;
    Ok(())
}

fn read_pid(path: &Path) -> Result<u32> {
    fs::read_to_string(path)?
        .trim()
        .parse::<u32>()
        .map_err(|e| anyhow!("invalid pid file {}: {e}", path.display()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir() -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "rpkv2-node-lifecycle-test-{}-{suffix}-{counter}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn init_node_creates_repeatable_directory_layout() {
        let dir = temp_dir();

        let report = init_node("validator-a", &dir, false).unwrap();

        assert!(report.config_template_path.is_file());
        assert!(report.storage_dir.is_dir());
        assert!(report.run_dir.is_dir());
        assert!(report.snapshot_dir.is_dir());
        assert!(report.identity.public_identity_path.is_file());
        let template = fs::read_to_string(report.config_template_path).unwrap();
        assert!(template.contains("validator-a"));
        assert!(template.contains("replace-with-peer-validator-id"));
    }

    #[test]
    fn bad_config_fails_before_start_plan() {
        let dir = temp_dir();
        let config_path = dir.join("bad.toml");
        fs::write(&config_path, "not = [valid").unwrap();

        assert!(start_plan(&config_path).is_err());
    }

    #[test]
    fn status_reports_invalid_config_without_panicking() {
        let dir = temp_dir();
        let config_path = dir.join("missing.toml");

        let status = status_report(&config_path, Option::<&Path>::None);

        assert!(!status.config_valid);
        assert!(!status.running);
    }

    #[test]
    fn stop_reads_and_removes_pid_file_when_requested() {
        let dir = temp_dir();
        let pid_file = dir.join("node.pid");
        fs::write(&pid_file, "12345").unwrap();

        let pid = stop_with_pid_file(&pid_file, true).unwrap();

        assert_eq!(pid, Some(12345));
        assert!(!pid_file.exists());
    }
}
