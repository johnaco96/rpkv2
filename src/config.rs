use crate::tiles::storage::StorageRecoveryPolicy;
use anyhow::{Result, anyhow, bail};
use serde::Deserialize;
use std::{
    fs::File,
    io::BufReader,
    net::SocketAddr,
    path::{Path, PathBuf},
};

pub const PRODUCTION_CONFIG_VERSION: u32 = 1;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionConfig {
    #[serde(default = "default_format_version")]
    pub format_version: u32,
    pub local: LocalConfig,
    pub peers: Vec<PeerConfig>,
    pub replay: ReplayConfig,
    pub queues: QueueConfig,
    pub rate_limits: RateLimitConfig,
    pub storage: StorageConfig,
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub processing: ProcessingConfig,
    #[serde(default)]
    pub gossip: GossipConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalConfig {
    pub bind_address: SocketAddr,
    pub validator_id: String,
    pub private_key_path: PathBuf,
    #[serde(default)]
    pub packet_signing_key_path: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    pub validator_id: String,
    pub spki_pin_path: Option<PathBuf>,
    #[serde(default)]
    pub tls_spki_pins: Vec<PeerSpkiPinConfig>,
    #[serde(default)]
    pub revoked_spki_pin_paths: Vec<PathBuf>,
    pub ed25519_verify_key_hex: String,
    pub address: Option<SocketAddr>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerSpkiPinConfig {
    pub path: PathBuf,
    pub valid_from_unix_seconds: Option<u64>,
    pub valid_until_unix_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayConfig {
    pub slot_window: u64,
    #[serde(default = "default_replay_capacity_per_slot")]
    pub capacity_per_slot: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueConfig {
    pub raw: usize,
    pub deduped: usize,
    pub verified: usize,
    pub packed: usize,
    pub bank: usize,
    pub poh: usize,
    pub shred: usize,
    pub signed: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    pub packets_per_second: u64,
    pub bytes_per_second: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    pub directory: PathBuf,
    #[serde(default)]
    pub allow_unsafe_demo_storage: bool,
    #[serde(default)]
    pub recovery_policy: StorageRecoveryPolicy,
    #[serde(default = "default_storage_flush_records")]
    pub flush_interval_records: usize,
    #[serde(default = "default_storage_flush_ms")]
    pub flush_interval_ms: u64,
    #[serde(default = "default_storage_sync_data")]
    pub sync_data: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessingConfig {
    #[serde(default = "default_verifier_workers")]
    pub verifier_workers: usize,
    #[serde(default = "default_verifier_batch")]
    pub verifier_batch: usize,
    #[serde(default)]
    pub verifier_affinity_base: Option<usize>,
    #[serde(default = "default_signer_batch")]
    pub signer_batch: usize,
    #[serde(default = "default_signer_workers")]
    pub signer_workers: usize,
}

impl Default for ProcessingConfig {
    fn default() -> Self {
        Self {
            verifier_workers: default_verifier_workers(),
            verifier_batch: default_verifier_batch(),
            verifier_affinity_base: None,
            signer_batch: default_signer_batch(),
            signer_workers: default_signer_workers(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    pub bind_address: SocketAddr,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GossipConfig {
    #[serde(default)]
    pub bootstrap_peers: Vec<GossipBootstrapPeerConfig>,
    #[serde(default = "default_gossip_peer_ttl_seconds")]
    pub peer_ttl_seconds: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GossipBootstrapPeerConfig {
    pub validator_id: String,
    pub gossip_address: SocketAddr,
    pub transaction_ingress_address: Option<SocketAddr>,
    pub repair_address: Option<SocketAddr>,
    pub rpc_address: Option<SocketAddr>,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            bootstrap_peers: Vec::new(),
            peer_ttl_seconds: default_gossip_peer_ttl_seconds(),
        }
    }
}

impl ProductionConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let cfg: Self = toml::from_str(&text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if self.format_version != PRODUCTION_CONFIG_VERSION {
            bail!(
                "unsupported production config format_version {}; supported {}",
                self.format_version,
                PRODUCTION_CONFIG_VERSION
            );
        }
        validate_id("local.validator_id", &self.local.validator_id)?;
        validate_private_key_path(&self.local.private_key_path)?;
        if let Some(path) = &self.local.packet_signing_key_path {
            validate_ed25519_private_key_path(path)?;
        }

        if self.peers.is_empty() {
            bail!("peers must contain at least one allowed peer");
        }
        for peer in &self.peers {
            validate_id("peer.validator_id", &peer.validator_id)?;
            if let Some(path) = &peer.spki_pin_path {
                validate_spki_path(path)?;
            }
            for pin in &peer.tls_spki_pins {
                validate_spki_path(&pin.path)?;
            }
            for revoked_path in &peer.revoked_spki_pin_paths {
                validate_spki_path(revoked_path)?;
            }
            validate_ed25519_key_hex(&peer.ed25519_verify_key_hex)?;
        }
        crate::identity::PeerRegistry::from_config(self)?;

        if self.replay.slot_window == 0 {
            bail!("replay.slot_window must be greater than zero");
        }
        if self.replay.capacity_per_slot == 0 {
            bail!("replay.capacity_per_slot must be greater than zero");
        }

        validate_queue("queues.raw", self.queues.raw)?;
        validate_queue("queues.deduped", self.queues.deduped)?;
        validate_queue("queues.verified", self.queues.verified)?;
        validate_queue("queues.packed", self.queues.packed)?;
        validate_queue("queues.bank", self.queues.bank)?;
        validate_queue("queues.poh", self.queues.poh)?;
        validate_queue("queues.shred", self.queues.shred)?;
        validate_queue("queues.signed", self.queues.signed)?;

        if self.rate_limits.packets_per_second == 0 {
            bail!("rate_limits.packets_per_second must be greater than zero");
        }
        if self.rate_limits.bytes_per_second == 0 {
            bail!("rate_limits.bytes_per_second must be greater than zero");
        }

        if self.storage.directory.as_os_str().is_empty() {
            bail!("storage.directory must not be empty");
        }
        if self.storage.flush_interval_records == 0 {
            bail!("storage.flush_interval_records must be greater than zero");
        }
        if self.storage.flush_interval_ms == 0 {
            bail!("storage.flush_interval_ms must be greater than zero");
        }
        if self.processing.verifier_workers == 0 {
            bail!("processing.verifier_workers must be greater than zero");
        }
        if self.processing.verifier_batch == 0 {
            bail!("processing.verifier_batch must be greater than zero");
        }
        if self.processing.signer_batch == 0 {
            bail!("processing.signer_batch must be greater than zero");
        }
        if self.processing.signer_workers == 0 {
            bail!("processing.signer_workers must be greater than zero");
        }
        if !self.storage.allow_unsafe_demo_storage {
            bail!(
                "storage.allow_unsafe_demo_storage must be true to use the current demo append-file storage; validator-grade storage is not implemented"
            );
        }

        if self.gossip.peer_ttl_seconds == 0 {
            bail!("gossip.peer_ttl_seconds must be greater than zero");
        }
        for peer in &self.gossip.bootstrap_peers {
            validate_id("gossip.bootstrap_peers.validator_id", &peer.validator_id)?;
        }

        Ok(())
    }
}

fn default_format_version() -> u32 {
    PRODUCTION_CONFIG_VERSION
}

fn default_gossip_peer_ttl_seconds() -> u64 {
    60
}

fn default_storage_flush_records() -> usize {
    1
}

fn default_replay_capacity_per_slot() -> usize {
    131_072
}

fn default_storage_flush_ms() -> u64 {
    1
}

fn default_storage_sync_data() -> bool {
    true
}

fn default_verifier_workers() -> usize {
    1
}

fn default_verifier_batch() -> usize {
    256
}

fn default_signer_batch() -> usize {
    256
}

fn default_signer_workers() -> usize {
    1
}

fn validate_id(field: &str, id: &str) -> Result<()> {
    if id.trim().is_empty() {
        bail!("{field} must not be empty");
    }
    Ok(())
}

fn validate_private_key_path(path: &Path) -> Result<()> {
    if !path.is_file() {
        bail!("local.private_key_path does not exist or is not a file: {path:?}");
    }
    let mut rdr = BufReader::new(File::open(path)?);
    match rustls_pemfile::read_one(&mut rdr)? {
        Some(rustls_pemfile::Item::Pkcs8Key(_)) => Ok(()),
        other => Err(anyhow!(
            "local.private_key_path must contain a PKCS#8 private key, got {other:?}"
        )),
    }
}

fn validate_spki_path(path: &Path) -> Result<()> {
    crate::tls::load_spki_from_pem(
        path.to_str()
            .ok_or_else(|| anyhow!("peer SPKI path is not valid UTF-8"))?,
    )?;
    Ok(())
}

fn validate_ed25519_key_hex(hex: &str) -> Result<()> {
    #[cfg(feature = "ed25519")]
    {
        let key = crate::identity::parse_hex_32(hex)?;
        ed25519_dalek::VerifyingKey::from_bytes(&key)
            .map_err(|e| anyhow!("peer ed25519_verify_key_hex is not a valid Ed25519 key: {e}"))?;
    }
    #[cfg(not(feature = "ed25519"))]
    {
        crate::identity::parse_hex_32(hex)?;
    }
    Ok(())
}

fn validate_ed25519_private_key_path(path: &Path) -> Result<()> {
    if !path.is_file() {
        bail!("local.packet_signing_key_path does not exist or is not a file: {path:?}");
    }
    #[cfg(feature = "ed25519")]
    {
        crate::identity_keys::load_ed25519_signing_key(path)?;
    }
    #[cfg(not(feature = "ed25519"))]
    {
        let text = std::fs::read_to_string(path)?;
        crate::identity::parse_hex_32(text.trim())?;
    }
    Ok(())
}

fn validate_queue(field: &str, value: usize) -> Result<()> {
    if value == 0 {
        bail!("{field} must be greater than zero");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair};
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
            "rpkv2-config-test-{}-{suffix}-{counter}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_keypair(dir: &Path) -> (PathBuf, PathBuf) {
        write_named_keypair(dir, "server")
    }

    fn write_named_keypair(dir: &Path, name: &str) -> (PathBuf, PathBuf) {
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let _cert = params.self_signed(&key_pair).unwrap();

        let key_path = dir.join(format!("{name}.key"));
        let pub_path = dir.join(format!("{name}.pub"));
        fs::write(&key_path, key_pair.serialize_pem()).unwrap();
        let spki_pem = pem::encode(&pem::Pem::new("PUBLIC KEY", key_pair.public_key_der()));
        fs::write(&pub_path, spki_pem).unwrap();
        (key_path, pub_path)
    }

    fn valid_config_text(key_path: &Path, spki_path: &Path, verify_key_hex: &str) -> String {
        format!(
            r#"
[local]
bind_address = "127.0.0.1:4433"
validator_id = "validator-a"
private_key_path = '{}'

[[peers]]
validator_id = "validator-b"
spki_pin_path = '{}'
ed25519_verify_key_hex = "{}"

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
directory = "store"
allow_unsafe_demo_storage = true

[metrics]
bind_address = "127.0.0.1:9100"
"#,
            key_path.display(),
            spki_path.display(),
            verify_key_hex
        )
    }

    fn valid_verify_key_hex() -> String {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        signing_key
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    #[test]
    fn valid_config_loads() {
        let dir = temp_dir();
        let (key_path, spki_path) = write_keypair(&dir);
        let cfg = toml::from_str::<ProductionConfig>(&valid_config_text(
            &key_path,
            &spki_path,
            &valid_verify_key_hex(),
        ))
        .unwrap();
        cfg.validate().unwrap();
    }

    #[test]
    fn valid_config_file_loads() {
        let dir = temp_dir();
        let (key_path, spki_path) = write_keypair(&dir);
        let config_path = dir.join("production.toml");
        fs::write(
            &config_path,
            valid_config_text(&key_path, &spki_path, &valid_verify_key_hex()),
        )
        .unwrap();

        ProductionConfig::load(&config_path).unwrap();
    }

    #[test]
    fn missing_peer_key_fails() {
        let dir = temp_dir();
        let (key_path, spki_path) = write_keypair(&dir);
        let cfg_text = valid_config_text(&key_path, &spki_path, "");
        let cfg = toml::from_str::<ProductionConfig>(&cfg_text).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn invalid_private_key_path_fails() {
        let dir = temp_dir();
        let (key_path, spki_path) = write_keypair(&dir);
        let cfg = toml::from_str::<ProductionConfig>(&valid_config_text(
            &key_path.with_file_name("missing.key"),
            &spki_path,
            &valid_verify_key_hex(),
        ))
        .unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn invalid_spki_fails() {
        let dir = temp_dir();
        let (key_path, spki_path) = write_keypair(&dir);
        fs::write(&spki_path, "not a public key").unwrap();
        let cfg = toml::from_str::<ProductionConfig>(&valid_config_text(
            &key_path,
            &spki_path,
            &valid_verify_key_hex(),
        ))
        .unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn invalid_queue_size_fails() {
        let dir = temp_dir();
        let (key_path, spki_path) = write_keypair(&dir);
        let cfg_text = valid_config_text(&key_path, &spki_path, &valid_verify_key_hex())
            .replace("raw = 8192", "raw = 0");
        let cfg = toml::from_str::<ProductionConfig>(&cfg_text).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn invalid_replay_capacity_fails() {
        let dir = temp_dir();
        let (key_path, spki_path) = write_keypair(&dir);
        let cfg_text = valid_config_text(&key_path, &spki_path, &valid_verify_key_hex()).replace(
            "slot_window = 1024",
            "slot_window = 1024\ncapacity_per_slot = 0",
        );
        let cfg = toml::from_str::<ProductionConfig>(&cfg_text).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn invalid_processing_worker_count_fails() {
        let dir = temp_dir();
        let (key_path, spki_path) = write_keypair(&dir);
        let text = format!(
            "{}\n[processing]\nverifier_workers = 0\n",
            valid_config_text(&key_path, &spki_path, &valid_verify_key_hex())
        );
        let cfg = toml::from_str::<ProductionConfig>(&text).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn invalid_storage_flush_interval_fails() {
        let dir = temp_dir();
        let (key_path, spki_path) = write_keypair(&dir);
        let text = valid_config_text(&key_path, &spki_path, &valid_verify_key_hex()).replace(
            "directory = \"store\"\n",
            "directory = \"store\"\nflush_interval_records = 0\n",
        );
        let cfg = toml::from_str::<ProductionConfig>(&text).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn unsafe_demo_storage_requires_explicit_acknowledgement() {
        let dir = temp_dir();
        let (key_path, spki_path) = write_keypair(&dir);
        let cfg_text = valid_config_text(&key_path, &spki_path, &valid_verify_key_hex())
            .replace("allow_unsafe_demo_storage = true\n", "");
        let cfg = toml::from_str::<ProductionConfig>(&cfg_text).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn duplicate_peer_identity_fails() {
        let dir = temp_dir();
        let (key_path, spki_path) = write_keypair(&dir);
        let verify_key_hex = valid_verify_key_hex();
        let cfg_text = format!(
            r#"
[local]
bind_address = "127.0.0.1:4433"
validator_id = "validator-a"
private_key_path = '{}'

[[peers]]
validator_id = "validator-b"
spki_pin_path = '{}'
ed25519_verify_key_hex = "{}"

[[peers]]
validator_id = "validator-b"
spki_pin_path = '{}'
ed25519_verify_key_hex = "{}"

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
directory = "store"
allow_unsafe_demo_storage = true

[metrics]
bind_address = "127.0.0.1:9100"
"#,
            key_path.display(),
            spki_path.display(),
            verify_key_hex,
            spki_path.display(),
            valid_verify_key_hex()
        );
        let cfg = toml::from_str::<ProductionConfig>(&cfg_text).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn duplicate_peer_spki_fails() {
        let dir = temp_dir();
        let (key_path, spki_path) = write_keypair(&dir);
        let verify_key_hex = valid_verify_key_hex();
        let cfg_text = format!(
            r#"
[local]
bind_address = "127.0.0.1:4433"
validator_id = "validator-a"
private_key_path = '{}'

[[peers]]
validator_id = "validator-b"
spki_pin_path = '{}'
ed25519_verify_key_hex = "{}"

[[peers]]
validator_id = "validator-c"
spki_pin_path = '{}'
ed25519_verify_key_hex = "{}"

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
directory = "store"
allow_unsafe_demo_storage = true

[metrics]
bind_address = "127.0.0.1:9100"
"#,
            key_path.display(),
            spki_path.display(),
            verify_key_hex,
            spki_path.display(),
            valid_verify_key_hex()
        );
        let cfg = toml::from_str::<ProductionConfig>(&cfg_text).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rotation_accepts_old_key_before_cutoff() {
        let dir = temp_dir();
        let (key_path, _) = write_named_keypair(&dir, "local");
        let (_, old_spki_path) = write_named_keypair(&dir, "old");
        let (_, new_spki_path) = write_named_keypair(&dir, "new");
        let cfg = toml::from_str::<ProductionConfig>(&rotation_config_text(
            &key_path,
            &old_spki_path,
            &new_spki_path,
        ))
        .unwrap();
        let registry = crate::identity::PeerRegistry::from_config_at(&cfg, 100).unwrap();
        let old_spki = crate::tls::load_spki_from_pem(old_spki_path.to_str().unwrap()).unwrap();
        let new_spki = crate::tls::load_spki_from_pem(new_spki_path.to_str().unwrap()).unwrap();

        assert!(registry.resolve_tls_spki(&old_spki).is_some());
        assert!(registry.resolve_tls_spki(&new_spki).is_none());
    }

    #[test]
    fn rotation_accepts_new_key_during_overlap() {
        let dir = temp_dir();
        let (key_path, _) = write_named_keypair(&dir, "local");
        let (_, old_spki_path) = write_named_keypair(&dir, "old");
        let (_, new_spki_path) = write_named_keypair(&dir, "new");
        let cfg = toml::from_str::<ProductionConfig>(&rotation_config_text(
            &key_path,
            &old_spki_path,
            &new_spki_path,
        ))
        .unwrap();
        let registry = crate::identity::PeerRegistry::from_config_at(&cfg, 175).unwrap();
        let old_spki = crate::tls::load_spki_from_pem(old_spki_path.to_str().unwrap()).unwrap();
        let new_spki = crate::tls::load_spki_from_pem(new_spki_path.to_str().unwrap()).unwrap();

        assert!(registry.resolve_tls_spki(&old_spki).is_some());
        assert!(registry.resolve_tls_spki(&new_spki).is_some());
    }

    #[test]
    fn rotation_rejects_old_key_after_cutoff() {
        let dir = temp_dir();
        let (key_path, _) = write_named_keypair(&dir, "local");
        let (_, old_spki_path) = write_named_keypair(&dir, "old");
        let (_, new_spki_path) = write_named_keypair(&dir, "new");
        let cfg = toml::from_str::<ProductionConfig>(&rotation_config_text(
            &key_path,
            &old_spki_path,
            &new_spki_path,
        ))
        .unwrap();
        let registry = crate::identity::PeerRegistry::from_config_at(&cfg, 225).unwrap();
        let old_spki = crate::tls::load_spki_from_pem(old_spki_path.to_str().unwrap()).unwrap();
        let new_spki = crate::tls::load_spki_from_pem(new_spki_path.to_str().unwrap()).unwrap();

        assert!(registry.resolve_tls_spki(&old_spki).is_none());
        assert!(registry.resolve_tls_spki(&new_spki).is_some());
    }

    #[test]
    fn revoked_key_is_rejected_even_when_active() {
        let dir = temp_dir();
        let (key_path, _) = write_named_keypair(&dir, "local");
        let (_, revoked_spki_path) = write_named_keypair(&dir, "revoked");
        let cfg_text = format!(
            r#"
[local]
bind_address = "127.0.0.1:4433"
validator_id = "validator-a"
private_key_path = '{}'

[[peers]]
validator_id = "validator-b"
ed25519_verify_key_hex = "{}"
revoked_spki_pin_paths = ['{}']

[[peers.tls_spki_pins]]
path = '{}'
valid_from_unix_seconds = 1

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
directory = "store"
allow_unsafe_demo_storage = true

[metrics]
bind_address = "127.0.0.1:9100"
"#,
            key_path.display(),
            valid_verify_key_hex(),
            revoked_spki_path.display(),
            revoked_spki_path.display()
        );
        let cfg = toml::from_str::<ProductionConfig>(&cfg_text).unwrap();

        assert!(crate::identity::PeerRegistry::from_config_at(&cfg, 100).is_err());
    }

    fn rotation_config_text(key_path: &Path, old_spki_path: &Path, new_spki_path: &Path) -> String {
        format!(
            r#"
[local]
bind_address = "127.0.0.1:4433"
validator_id = "validator-a"
private_key_path = '{}'

[[peers]]
validator_id = "validator-b"
ed25519_verify_key_hex = "{}"

[[peers.tls_spki_pins]]
path = '{}'
valid_until_unix_seconds = 200

[[peers.tls_spki_pins]]
path = '{}'
valid_from_unix_seconds = 150

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
directory = "store"
allow_unsafe_demo_storage = true

[metrics]
bind_address = "127.0.0.1:9100"
"#,
            key_path.display(),
            valid_verify_key_hex(),
            old_spki_path.display(),
            new_spki_path.display()
        )
    }
}
