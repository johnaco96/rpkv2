use crate::metrics;
use crate::shutdown::Shutdown;
use crate::tiles::{IdleWait, Tile};
use crossbeam_queue::ArrayQueue;
use serde::Deserialize;
use std::{
    error::Error,
    fs::{self, File, OpenOptions},
    io::{self, BufWriter, Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use super::signing::{Sig64, SignedShred};

const RECORD_MAGIC: &[u8; 4] = b"RPSR";
pub const STORAGE_RECORD_VERSION: u8 = 1;
const RECORD_HEADER_LEN: usize = 4 + 1 + 8 + 2 + 1 + 4 + 64 + 32;

pub type StoreInQueue = Arc<ArrayQueue<SignedShred>>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StorageIssue {
    Partial {
        path: PathBuf,
        offset: u64,
        expected: usize,
        actual: usize,
    },
    Corrupt {
        path: PathBuf,
        offset: u64,
        reason: String,
    },
}

impl StorageIssue {
    pub fn path(&self) -> &Path {
        match self {
            StorageIssue::Partial { path, .. } | StorageIssue::Corrupt { path, .. } => path,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StorageScanReport {
    pub files_scanned: usize,
    pub records_scanned: usize,
    pub latest_slot: Option<u64>,
    pub latest_index: Option<u16>,
    pub issues: Vec<StorageIssue>,
}

impl StorageScanReport {
    pub fn is_clean(&self) -> bool {
        self.issues.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StorageRecoveryPolicy {
    #[default]
    FailStartup,
    QuarantineCorrupt,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StorageRecovery {
    pub report: StorageScanReport,
    pub quarantined_files: Vec<PathBuf>,
}

#[derive(Debug)]
pub struct StorageRecoveryError {
    pub report: StorageScanReport,
}

impl std::fmt::Display for StorageRecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(issue) = self.report.issues.first() {
            write!(
                f,
                "storage recovery failed: first issue at {}; inspect or quarantine the file before accepting traffic",
                issue.path().display()
            )
        } else {
            write!(f, "storage recovery failed")
        }
    }
}

impl Error for StorageRecoveryError {}

/// Super-simple append-only storage: one file per slot.
/// (Replace with RocksDB/Agave blockstore later.)
pub struct Storage {
    pub rx: StoreInQueue,
    pub dir: PathBuf,
    pub recovery_policy: StorageRecoveryPolicy,
    pub enabled: bool,
    /// Flush after this many records. A value of one preserves per-record durability.
    pub flush_interval_records: usize,
    pub flush_interval_ms: u64,
    /// Request an OS data sync whenever a buffered batch is flushed.
    pub sync_data: bool,
}

impl Tile for Storage {
    fn start_with_shutdown(self, shutdown: Shutdown) -> thread::JoinHandle<()> {
        std::thread::spawn(move || {
            match recover_storage_dir(&self.dir, self.recovery_policy) {
                Ok(recovery) => {
                    tracing::info!(
                        tile = "storage",
                        dir = %self.dir.display(),
                        records = recovery.report.records_scanned,
                        latest_slot = ?recovery.report.latest_slot,
                        latest_index = ?recovery.report.latest_index,
                        quarantined_files = recovery.quarantined_files.len(),
                        "storage recovery completed"
                    );
                }
                Err(e) => {
                    metrics::global().record_storage_error();
                    tracing::error!(
                        tile = "storage",
                        dir = %self.dir.display(),
                        reason = %e,
                        "storage recovery failed"
                    );
                    panic!("{e}");
                }
            }

            let _ = fs::create_dir_all(&self.dir);
            let mut writer: Option<(u64, BufWriter<File>)> = None;
            let mut pending_records = 0usize;
            let mut pending_transactions = 0u64;
            let mut pending_bytes = 0u64;
            let mut last_flush = Instant::now();
            let mut idle = IdleWait::new();
            while !shutdown.is_requested() || !self.rx.is_empty() {
                if let Some(s) = self.rx.pop() {
                    idle.reset();
                    if !self.enabled {
                        metrics::global().record_shred_written();
                        metrics::global().record_transactions_completed(s.completed_transactions);
                        continue;
                    }
                    if writer.as_ref().is_none_or(|(slot, _)| *slot != s.slot) {
                        if flush_pending(
                            &mut writer,
                            self.sync_data,
                            &mut pending_records,
                            &mut pending_transactions,
                            &mut pending_bytes,
                        )
                        .is_err()
                        {
                            metrics::global().record_storage_error();
                        }
                        let path = self.dir.join(slot_file_name(s.slot));
                        match OpenOptions::new().create(true).append(true).open(path) {
                            Ok(file) => {
                                writer = Some((s.slot, BufWriter::with_capacity(1024 * 1024, file)))
                            }
                            Err(_) => {
                                metrics::global().record_storage_error();
                                continue;
                            }
                        }
                    }
                    let record_bytes = (RECORD_HEADER_LEN + s.data.len()) as u64;
                    let result = writer
                        .as_mut()
                        .map(|(_, writer)| write_record(writer, &s))
                        .unwrap_or_else(|| Err(io::Error::other("storage writer unavailable")));
                    if result.is_err() {
                        metrics::global().record_storage_error();
                        continue;
                    }
                    pending_records += 1;
                    pending_transactions =
                        pending_transactions.saturating_add(s.completed_transactions);
                    pending_bytes = pending_bytes.saturating_add(record_bytes);
                    if pending_records >= self.flush_interval_records.max(1)
                        && flush_pending(
                            &mut writer,
                            self.sync_data,
                            &mut pending_records,
                            &mut pending_transactions,
                            &mut pending_bytes,
                        )
                        .is_err()
                    {
                        metrics::global().record_storage_error();
                    } else if pending_records == 0 {
                        last_flush = Instant::now();
                    }
                } else {
                    if pending_records > 0
                        && last_flush.elapsed()
                            >= Duration::from_millis(self.flush_interval_ms.max(1))
                    {
                        if flush_pending(
                            &mut writer,
                            self.sync_data,
                            &mut pending_records,
                            &mut pending_transactions,
                            &mut pending_bytes,
                        )
                        .is_err()
                        {
                            metrics::global().record_storage_error();
                        }
                        last_flush = Instant::now();
                    }
                    idle.snooze();
                }
            }
            if flush_pending(
                &mut writer,
                self.sync_data,
                &mut pending_records,
                &mut pending_transactions,
                &mut pending_bytes,
            )
            .is_err()
            {
                metrics::global().record_storage_error();
            }
        })
    }
}

fn flush_pending(
    writer: &mut Option<(u64, BufWriter<File>)>,
    sync_data: bool,
    pending_records: &mut usize,
    pending_transactions: &mut u64,
    pending_bytes: &mut u64,
) -> io::Result<()> {
    if *pending_records == 0 {
        return Ok(());
    }
    let (_, writer) = writer
        .as_mut()
        .ok_or_else(|| io::Error::other("storage writer unavailable"))?;
    writer.flush()?;
    if sync_data {
        writer.get_ref().sync_data()?;
    }
    for _ in 0..*pending_records {
        metrics::global().record_shred_written();
    }
    metrics::global().record_transactions_durable(*pending_transactions);
    metrics::global().record_storage_bytes_written(*pending_bytes);
    *pending_records = 0;
    *pending_transactions = 0;
    *pending_bytes = 0;
    Ok(())
}

pub fn recover_storage_dir(
    dir: &Path,
    policy: StorageRecoveryPolicy,
) -> Result<StorageRecovery, StorageRecoveryError> {
    let report = scan_storage_dir(dir).map_err(|e| StorageRecoveryError {
        report: StorageScanReport {
            issues: vec![StorageIssue::Corrupt {
                path: dir.to_path_buf(),
                offset: 0,
                reason: e.to_string(),
            }],
            ..StorageScanReport::default()
        },
    })?;
    if report.is_clean() {
        return Ok(StorageRecovery {
            report,
            quarantined_files: Vec::new(),
        });
    }

    match policy {
        StorageRecoveryPolicy::FailStartup => Err(StorageRecoveryError { report }),
        StorageRecoveryPolicy::QuarantineCorrupt => {
            let quarantined_files =
                quarantine_issue_files(dir, &report).map_err(|_| StorageRecoveryError {
                    report: report.clone(),
                })?;
            let clean_report = scan_storage_dir(dir).map_err(|_| StorageRecoveryError {
                report: report.clone(),
            })?;
            Ok(StorageRecovery {
                report: clean_report,
                quarantined_files,
            })
        }
    }
}

pub fn scan_storage_dir(dir: &Path) -> io::Result<StorageScanReport> {
    let mut report = StorageScanReport::default();
    if !dir.exists() {
        return Ok(report);
    }

    let mut entries = fs::read_dir(dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("slot-") && name.ends_with(".shred"))
        })
        .collect::<Vec<_>>();
    entries.sort();

    for path in entries {
        report.files_scanned += 1;
        scan_file(&path, &mut report)?;
    }

    Ok(report)
}

pub fn write_record(mut writer: impl Write, shred: &SignedShred) -> io::Result<()> {
    let len = u32::try_from(shred.data.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "shred data too large"))?;
    let checksum = record_checksum(
        shred.slot,
        shred.index,
        shred.last,
        len,
        &shred.sig,
        &shred.data,
    );

    writer.write_all(RECORD_MAGIC)?;
    writer.write_all(&[STORAGE_RECORD_VERSION])?;
    writer.write_all(&shred.slot.to_le_bytes())?;
    writer.write_all(&shred.index.to_le_bytes())?;
    writer.write_all(&[u8::from(shred.last)])?;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(&shred.sig.0)?;
    writer.write_all(&checksum)?;
    writer.write_all(&shred.data)?;
    Ok(())
}

fn scan_file(path: &Path, report: &mut StorageScanReport) -> io::Result<()> {
    let mut file = File::open(path)?;
    let mut offset = 0u64;

    loop {
        let mut header = [0u8; RECORD_HEADER_LEN];
        let read = read_exact_or_partial(&mut file, &mut header)?;
        if read == 0 {
            break;
        }
        if read < RECORD_HEADER_LEN {
            report.issues.push(StorageIssue::Partial {
                path: path.to_path_buf(),
                offset,
                expected: RECORD_HEADER_LEN,
                actual: read,
            });
            break;
        }

        let parsed = parse_header(&header);
        let Ok(parsed) = parsed else {
            report.issues.push(StorageIssue::Corrupt {
                path: path.to_path_buf(),
                offset,
                reason: parsed.err().unwrap_or_else(|| "invalid header".to_string()),
            });
            break;
        };

        let mut data = vec![0u8; parsed.len as usize];
        let data_read = read_exact_or_partial(&mut file, &mut data)?;
        if data_read < data.len() {
            report.issues.push(StorageIssue::Partial {
                path: path.to_path_buf(),
                offset,
                expected: RECORD_HEADER_LEN + data.len(),
                actual: RECORD_HEADER_LEN + data_read,
            });
            break;
        }

        let checksum = record_checksum(
            parsed.slot,
            parsed.index,
            parsed.last,
            parsed.len,
            &parsed.sig,
            &data,
        );
        if checksum != parsed.checksum {
            report.issues.push(StorageIssue::Corrupt {
                path: path.to_path_buf(),
                offset,
                reason: "checksum mismatch".to_string(),
            });
            break;
        }

        report.records_scanned += 1;
        update_latest(report, parsed.slot, parsed.index);
        offset += (RECORD_HEADER_LEN + data.len()) as u64;
    }

    Ok(())
}

fn update_latest(report: &mut StorageScanReport, slot: u64, index: u16) {
    let is_newer = match (report.latest_slot, report.latest_index) {
        (Some(current_slot), Some(current_index)) => {
            slot > current_slot || (slot == current_slot && index > current_index)
        }
        _ => true,
    };
    if is_newer {
        report.latest_slot = Some(slot);
        report.latest_index = Some(index);
    }
}

fn quarantine_issue_files(dir: &Path, report: &StorageScanReport) -> io::Result<Vec<PathBuf>> {
    let quarantine_dir = dir.join("quarantine");
    fs::create_dir_all(&quarantine_dir)?;
    let mut paths = report
        .issues
        .iter()
        .map(|issue| issue.path().to_path_buf())
        .collect::<Vec<_>>();
    paths.sort();
    paths.dedup();

    let mut quarantined = Vec::new();
    for path in paths {
        let Some(file_name) = path.file_name() else {
            continue;
        };
        let mut target = quarantine_dir.join(file_name);
        if target.exists() {
            let mut suffix = 1u64;
            while target.exists() {
                target = quarantine_dir.join(format!("{}.{}", file_name.to_string_lossy(), suffix));
                suffix += 1;
            }
        }
        fs::rename(&path, &target)?;
        quarantined.push(target);
    }

    Ok(quarantined)
}

fn read_exact_or_partial(reader: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut read = 0;
    while read < buf.len() {
        match reader.read(&mut buf[read..])? {
            0 => break,
            n => read += n,
        }
    }
    Ok(read)
}

struct ParsedHeader {
    slot: u64,
    index: u16,
    last: bool,
    len: u32,
    sig: Sig64,
    checksum: [u8; 32],
}

fn parse_header(header: &[u8; RECORD_HEADER_LEN]) -> Result<ParsedHeader, String> {
    if &header[0..4] != RECORD_MAGIC {
        return Err("bad record magic".to_string());
    }
    if header[4] != STORAGE_RECORD_VERSION {
        return Err(format!("unsupported record version {}", header[4]));
    }
    let slot = u64::from_le_bytes(header[5..13].try_into().expect("slot length"));
    let index = u16::from_le_bytes(header[13..15].try_into().expect("index length"));
    let last = match header[15] {
        0 => false,
        1 => true,
        other => return Err(format!("invalid last flag {other}")),
    };
    let len = u32::from_le_bytes(header[16..20].try_into().expect("length field length"));
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&header[20..84]);
    let mut checksum = [0u8; 32];
    checksum.copy_from_slice(&header[84..116]);

    Ok(ParsedHeader {
        slot,
        index,
        last,
        len,
        sig: Sig64(sig),
        checksum,
    })
}

fn record_checksum(
    slot: u64,
    index: u16,
    last: bool,
    len: u32,
    sig: &Sig64,
    data: &[u8],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(RECORD_MAGIC);
    hasher.update(&[STORAGE_RECORD_VERSION]);
    hasher.update(&slot.to_le_bytes());
    hasher.update(&index.to_le_bytes());
    hasher.update(&[u8::from(last)]);
    hasher.update(&len.to_le_bytes());
    hasher.update(&sig.0);
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

fn slot_file_name(slot: u64) -> String {
    format!("slot-{slot:012}.shred")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        io::{Seek, SeekFrom},
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
            "rpkv2-storage-test-{}-{suffix}-{counter}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn shred(slot: u64, index: u16, data: &[u8]) -> SignedShred {
        SignedShred {
            sequence: index as u64,
            slot,
            index,
            last: true,
            data: data.to_vec(),
            sig: Sig64([7u8; 64]),
            completed_transactions: 1,
        }
    }

    fn write_shred(dir: &Path, shred: &SignedShred) -> PathBuf {
        let path = dir.join(slot_file_name(shred.slot));
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap();
        write_record(&mut file, shred).unwrap();
        path
    }

    #[test]
    fn scan_accepts_complete_records() {
        let dir = temp_dir();
        write_shred(&dir, &shred(1, 0, b"hello"));
        write_shred(&dir, &shred(1, 1, b"world"));

        let report = scan_storage_dir(&dir).unwrap();

        assert!(report.is_clean());
        assert_eq!(report.files_scanned, 1);
        assert_eq!(report.records_scanned, 2);
        assert_eq!(report.latest_slot, Some(1));
        assert_eq!(report.latest_index, Some(1));
    }

    #[test]
    fn scan_detects_partial_record() {
        let dir = temp_dir();
        let path = write_shred(&dir, &shred(2, 0, b"partial"));
        let len = fs::metadata(&path).unwrap().len();
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(len - 3)
            .unwrap();

        let report = scan_storage_dir(&dir).unwrap();

        assert_eq!(report.records_scanned, 0);
        assert!(matches!(
            report.issues.as_slice(),
            [StorageIssue::Partial { .. }]
        ));
    }

    #[test]
    fn scan_detects_corrupt_record() {
        let dir = temp_dir();
        let path = write_shred(&dir, &shred(3, 0, b"corrupt"));
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.seek(SeekFrom::Start(RECORD_HEADER_LEN as u64 + 2))
            .unwrap();
        file.write_all(&[0xFF]).unwrap();

        let report = scan_storage_dir(&dir).unwrap();

        assert_eq!(report.records_scanned, 0);
        assert!(matches!(
            report.issues.as_slice(),
            [StorageIssue::Corrupt { reason, .. }] if reason == "checksum mismatch"
        ));
    }

    #[test]
    fn recovery_reconstructs_latest_known_slot_and_index() {
        let dir = temp_dir();
        write_shred(&dir, &shred(10, 0, b"a"));
        write_shred(&dir, &shred(10, 3, b"b"));
        write_shred(&dir, &shred(11, 1, b"c"));

        let recovery = recover_storage_dir(&dir, StorageRecoveryPolicy::FailStartup).unwrap();

        assert_eq!(recovery.report.records_scanned, 3);
        assert_eq!(recovery.report.latest_slot, Some(11));
        assert_eq!(recovery.report.latest_index, Some(1));
        assert!(recovery.quarantined_files.is_empty());
    }

    #[test]
    fn recovery_fails_startup_on_truncated_file() {
        let dir = temp_dir();
        let path = write_shred(&dir, &shred(12, 0, b"crash"));
        let len = fs::metadata(&path).unwrap().len();
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(len - 1)
            .unwrap();

        let err = recover_storage_dir(&dir, StorageRecoveryPolicy::FailStartup).unwrap_err();

        assert!(matches!(
            err.report.issues.as_slice(),
            [StorageIssue::Partial { .. }]
        ));
    }

    #[test]
    fn recovery_quarantines_corrupt_file_and_rescans_clean_state() {
        let dir = temp_dir();
        write_shred(&dir, &shred(12, 0, b"good"));
        let path = write_shred(&dir, &shred(13, 0, b"bad"));
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.seek(SeekFrom::Start(RECORD_HEADER_LEN as u64 + 1))
            .unwrap();
        file.write_all(&[0xAA]).unwrap();

        let recovery = recover_storage_dir(&dir, StorageRecoveryPolicy::QuarantineCorrupt).unwrap();

        assert!(recovery.report.is_clean());
        assert_eq!(recovery.report.records_scanned, 1);
        assert_eq!(recovery.report.latest_slot, Some(12));
        assert_eq!(recovery.report.latest_index, Some(0));
        assert_eq!(recovery.quarantined_files.len(), 1);
        assert!(recovery.quarantined_files[0].exists());
        assert!(!path.exists());
    }
}
