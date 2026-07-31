use crate::{config::ProductionConfig, identity::ValidatorId};
use anyhow::{Result, anyhow, bail};
use rcgen::KeyPair;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::BufReader,
    path::{Path, PathBuf},
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicIdentity {
    pub validator_id: String,
    pub transport_spki_der_hex: String,
    pub packet_verify_key_hex: String,
    pub consensus_verify_key_hex: String,
    pub generated_unix_seconds: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneratedIdentityFiles {
    pub transport_private_key_path: PathBuf,
    pub transport_public_spki_path: PathBuf,
    pub packet_signing_key_path: PathBuf,
    pub packet_verify_key_path: PathBuf,
    pub consensus_voting_key_path: PathBuf,
    pub consensus_verify_key_path: PathBuf,
    pub public_identity_path: PathBuf,
    pub public_identity: PublicIdentity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ed25519KeyRole {
    PacketSigning,
    ConsensusVoting,
}

impl Ed25519KeyRole {
    pub fn private_file_name(self) -> &'static str {
        match self {
            Self::PacketSigning => "packet-signing.key",
            Self::ConsensusVoting => "consensus-voting.key",
        }
    }

    pub fn public_file_name(self) -> &'static str {
        match self {
            Self::PacketSigning => "packet-signing.pub",
            Self::ConsensusVoting => "consensus-voting.pub",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneratedKeyFiles {
    pub private_key_path: PathBuf,
    pub public_key_path: PathBuf,
}

pub fn generate_validator_identity(
    validator_id: &str,
    out_dir: impl AsRef<Path>,
    overwrite: bool,
) -> Result<GeneratedIdentityFiles> {
    ValidatorId::from_str(validator_id)?;
    let out_dir = out_dir.as_ref();
    fs::create_dir_all(out_dir)?;

    let transport = generate_transport_key_files(out_dir, overwrite)?;
    let packet = generate_ed25519_key_files(out_dir, Ed25519KeyRole::PacketSigning, overwrite)?;
    let consensus =
        generate_ed25519_key_files(out_dir, Ed25519KeyRole::ConsensusVoting, overwrite)?;
    let public_identity = PublicIdentity {
        validator_id: validator_id.to_string(),
        transport_spki_der_hex: hex(&load_transport_spki_from_private_key(
            &transport.private_key_path,
        )?),
        packet_verify_key_hex: read_trimmed(&packet.public_key_path)?,
        consensus_verify_key_hex: read_trimmed(&consensus.public_key_path)?,
        generated_unix_seconds: now_unix_seconds()?,
    };
    let public_identity_path = out_dir.join("identity-public.toml");
    write_new_file(
        &public_identity_path,
        toml::to_string_pretty(&public_identity)?,
        overwrite,
    )?;

    Ok(GeneratedIdentityFiles {
        transport_private_key_path: transport.private_key_path,
        transport_public_spki_path: transport.public_key_path,
        packet_signing_key_path: packet.private_key_path,
        packet_verify_key_path: packet.public_key_path,
        consensus_voting_key_path: consensus.private_key_path,
        consensus_verify_key_path: consensus.public_key_path,
        public_identity_path,
        public_identity,
    })
}

pub fn generate_transport_key_files(
    out_dir: impl AsRef<Path>,
    overwrite: bool,
) -> Result<GeneratedKeyFiles> {
    let out_dir = out_dir.as_ref();
    fs::create_dir_all(out_dir)?;
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    let private_key_path = out_dir.join("transport.key");
    let public_key_path = out_dir.join("transport.pub");
    write_new_file(&private_key_path, key_pair.serialize_pem(), overwrite)?;
    let spki_pem = pem::encode(&pem::Pem::new("PUBLIC KEY", key_pair.public_key_der()));
    write_new_file(&public_key_path, spki_pem, overwrite)?;
    Ok(GeneratedKeyFiles {
        private_key_path,
        public_key_path,
    })
}

pub fn generate_ed25519_key_files(
    out_dir: impl AsRef<Path>,
    role: Ed25519KeyRole,
    overwrite: bool,
) -> Result<GeneratedKeyFiles> {
    #[cfg(feature = "ed25519")]
    {
        use ed25519_dalek::SigningKey;

        let out_dir = out_dir.as_ref();
        fs::create_dir_all(out_dir)?;
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let private_key_path = out_dir.join(role.private_file_name());
        let public_key_path = out_dir.join(role.public_file_name());
        write_new_file(&private_key_path, hex(&signing_key.to_bytes()), overwrite)?;
        write_new_file(
            &public_key_path,
            hex(&signing_key.verifying_key().to_bytes()),
            overwrite,
        )?;
        Ok(GeneratedKeyFiles {
            private_key_path,
            public_key_path,
        })
    }
    #[cfg(not(feature = "ed25519"))]
    {
        let _ = (out_dir, role, overwrite);
        bail!("identity key generation requires the ed25519 feature");
    }
}

pub fn load_public_identity(path: impl AsRef<Path>) -> Result<PublicIdentity> {
    let identity: PublicIdentity = toml::from_str(&fs::read_to_string(path)?)?;
    ValidatorId::from_str(&identity.validator_id)?;
    validate_hex_len(
        "transport_spki_der_hex",
        &identity.transport_spki_der_hex,
        None,
    )?;
    validate_hex_len(
        "packet_verify_key_hex",
        &identity.packet_verify_key_hex,
        Some(64),
    )?;
    validate_hex_len(
        "consensus_verify_key_hex",
        &identity.consensus_verify_key_hex,
        Some(64),
    )?;
    Ok(identity)
}

pub fn validate_config_consistency(
    config_path: impl AsRef<Path>,
    public_identity_path: impl AsRef<Path>,
) -> Result<PublicIdentity> {
    let config = ProductionConfig::load(config_path)?;
    let identity = load_public_identity(public_identity_path)?;
    if config.local.validator_id != identity.validator_id {
        bail!(
            "config local.validator_id {} does not match public identity {}",
            config.local.validator_id,
            identity.validator_id
        );
    }
    let local_spki = load_transport_spki_from_private_key(&config.local.private_key_path)?;
    if hex(&local_spki) != identity.transport_spki_der_hex {
        bail!("config local.private_key_path does not match public identity transport SPKI");
    }
    Ok(identity)
}

pub fn load_transport_spki_from_private_key(path: impl AsRef<Path>) -> Result<Vec<u8>> {
    let pkcs8 = load_pkcs8_private_key(path.as_ref())?;
    let signing_key =
        rustls::crypto::ring::sign::any_supported_type(&PrivateKeyDer::Pkcs8(pkcs8.clone_key()))
            .map_err(|e| anyhow!("unsupported transport private key: {e}"))?;
    signing_key
        .public_key()
        .map(|key| key.as_ref().to_vec())
        .ok_or_else(|| anyhow!("transport private key did not expose an SPKI public key"))
}

pub fn public_key_hex_from_private_ed25519(path: impl AsRef<Path>) -> Result<String> {
    #[cfg(feature = "ed25519")]
    {
        let private_hex = read_trimmed(path)?;
        validate_hex_len("ed25519 private key", &private_hex, Some(64))?;
        let private = crate::identity::parse_hex_32(&private_hex)?;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&private);
        Ok(hex(&signing_key.verifying_key().to_bytes()))
    }
    #[cfg(not(feature = "ed25519"))]
    {
        let _ = path;
        bail!("ed25519 public key export requires the ed25519 feature");
    }
}

#[cfg(feature = "ed25519")]
pub fn load_ed25519_signing_key(path: impl AsRef<Path>) -> Result<ed25519_dalek::SigningKey> {
    let private_hex = read_trimmed(path)?;
    validate_hex_len("ed25519 private key", &private_hex, Some(64))?;
    let private = crate::identity::parse_hex_32(&private_hex)?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&private))
}

#[cfg(not(feature = "ed25519"))]
pub fn load_ed25519_signing_key(path: impl AsRef<Path>) -> Result<()> {
    let _ = path;
    bail!("ed25519 signing key loading requires the ed25519 feature");
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn load_pkcs8_private_key(path: &Path) -> Result<PrivatePkcs8KeyDer<'static>> {
    let mut reader = BufReader::new(fs::File::open(path)?);
    match rustls_pemfile::read_one(&mut reader)? {
        Some(rustls_pemfile::Item::Pkcs8Key(key)) => Ok(key),
        other => Err(anyhow!("expected PKCS#8 private key, got {other:?}")),
    }
}

fn write_new_file(path: &Path, contents: String, overwrite: bool) -> Result<()> {
    if path.exists() && !overwrite {
        bail!("refusing to overwrite existing file: {path:?}");
    }
    fs::write(path, contents)?;
    Ok(())
}

fn read_trimmed(path: impl AsRef<Path>) -> Result<String> {
    Ok(fs::read_to_string(path)?.trim().to_string())
}

fn validate_hex_len(field: &str, value: &str, expected_len: Option<usize>) -> Result<()> {
    if let Some(expected_len) = expected_len
        && value.len() != expected_len
    {
        bail!("{field} must be {expected_len} hex characters");
    }
    if value.len() % 2 != 0 {
        bail!("{field} must contain an even number of hex characters");
    }
    for byte in value.as_bytes() {
        if !byte.is_ascii_hexdigit() {
            bail!("{field} contains non-hex characters");
        }
    }
    Ok(())
}

fn now_unix_seconds() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| anyhow!("system clock is before UNIX epoch"))?
        .as_secs())
}

#[cfg(all(test, feature = "ed25519"))]
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
            "rpkv2-identity-keys-test-{}-{suffix}-{counter}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
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
raw = 8
deduped = 8
verified = 8
packed = 8
bank = 8
poh = 8
shred = 8
signed = 8

[rate_limits]
packets_per_second = 1
bytes_per_second = 1

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

    #[test]
    fn generate_validator_identity_writes_public_export_without_secrets() {
        let dir = temp_dir();

        let generated = generate_validator_identity("validator-a", &dir, false).unwrap();
        let public_text = fs::read_to_string(&generated.public_identity_path).unwrap();

        assert!(generated.transport_private_key_path.is_file());
        assert!(generated.transport_public_spki_path.is_file());
        assert!(generated.packet_signing_key_path.is_file());
        assert!(generated.consensus_voting_key_path.is_file());
        assert!(public_text.contains("validator-a"));
        assert!(public_text.contains("transport_spki_der_hex"));
        assert!(!public_text.contains("PRIVATE KEY"));
        assert!(!public_text.contains("packet-signing.key"));
        assert!(!public_text.contains("consensus-voting.key"));
        assert_eq!(
            load_public_identity(&generated.public_identity_path).unwrap(),
            generated.public_identity
        );
    }

    #[test]
    fn generated_private_ed25519_key_exports_matching_public_key() {
        let dir = temp_dir();
        let generated =
            generate_ed25519_key_files(&dir, Ed25519KeyRole::PacketSigning, false).unwrap();

        assert_eq!(
            public_key_hex_from_private_ed25519(&generated.private_key_path).unwrap(),
            fs::read_to_string(&generated.public_key_path)
                .unwrap()
                .trim()
                .to_string()
        );
    }

    #[test]
    fn validate_config_consistency_accepts_matching_identity() {
        let dir = temp_dir();
        let generated = generate_validator_identity("validator-a", &dir, false).unwrap();
        let config_path = dir.join("production.toml");
        fs::write(
            &config_path,
            valid_config_text(
                &generated.transport_private_key_path,
                &generated.transport_public_spki_path,
                &generated.public_identity.packet_verify_key_hex,
            ),
        )
        .unwrap();

        validate_config_consistency(&config_path, &generated.public_identity_path).unwrap();
    }

    #[test]
    fn validate_config_consistency_rejects_mismatched_identity() {
        let dir = temp_dir();
        let generated = generate_validator_identity("validator-a", &dir, false).unwrap();
        let other = generate_validator_identity("validator-a", dir.join("other"), false).unwrap();
        let config_path = dir.join("production.toml");
        fs::write(
            &config_path,
            valid_config_text(
                &generated.transport_private_key_path,
                &generated.transport_public_spki_path,
                &generated.public_identity.packet_verify_key_hex,
            ),
        )
        .unwrap();

        assert!(validate_config_consistency(&config_path, &other.public_identity_path).is_err());
    }
}
