// src/tls.rs
use crate::identity::{PeerRegistry, ValidatorId};
use anyhow::{Result, anyhow};
use rustls::client::{AlwaysResolvesClientRawPublicKeys, danger::HandshakeSignatureValid};
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer,
};
use rustls::server::{
    AlwaysResolvesServerRawPublicKeys,
    danger::{ClientCertVerified, ClientCertVerifier},
};
use rustls::sign::CertifiedKey;
use rustls::{
    ClientConfig as TlsClientConfig, DigitallySignedStruct, DistinguishedName, Error as TlsError,
    ServerConfig as TlsServerConfig, SignatureScheme,
};
use rustls_pemfile::{Item, read_one};
use std::{any::Any, fs::File, io::BufReader, str::FromStr, sync::Arc};

/// Must be called once at startup in each binary.
/// Ensures exactly one crypto provider is installed (aws-lc here).
pub fn install_provider() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("install ring provider");
}

/// Build a rustls::ServerConfig that serves a Raw Public Key (SPKI only).
pub fn build_server_rpk(pkcs8_path: &str) -> Result<Arc<TlsServerConfig>> {
    let resolver = Arc::new(AlwaysResolvesServerRawPublicKeys::new(certified_rpk_key(
        pkcs8_path,
    )?));

    Ok(Arc::new(
        TlsServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver),
    ))
}

pub fn build_server_rpk_mutual(
    pkcs8_path: &str,
    registry: PeerRegistry,
) -> Result<Arc<TlsServerConfig>> {
    let resolver = Arc::new(AlwaysResolvesServerRawPublicKeys::new(certified_rpk_key(
        pkcs8_path,
    )?));
    Ok(Arc::new(
        TlsServerConfig::builder()
            .with_client_cert_verifier(Arc::new(RawPublicKeyClientVerifier::new(registry)))
            .with_cert_resolver(resolver),
    ))
}

#[derive(Clone)]
struct IdentityPinVerifier {
    validator_id: ValidatorId,
    spkis: Vec<Vec<u8>>,
}

impl IdentityPinVerifier {
    fn verifies_spki(&self, presented_spki: &[u8]) -> bool {
        self.spkis
            .iter()
            .any(|spki| presented_spki == spki.as_slice())
    }
}

impl std::fmt::Debug for IdentityPinVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityPinVerifier")
            .field("validator_id", &self.validator_id)
            .finish_non_exhaustive()
    }
}

impl rustls::client::danger::ServerCertVerifier for IdentityPinVerifier {
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }

    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, TlsError> {
        if self.verifies_spki(end_entity.as_ref()) {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            crate::metrics::global().record_unknown_peer_drop();
            if crate::logging::should_log(
                "tls_unknown_peer_spki",
                std::time::Duration::from_secs(1),
            ) {
                tracing::warn!(
                    peer_id = %self.validator_id,
                    reason = "spki_pin_mismatch",
                    "rejecting peer identity"
                );
            }
            Err(TlsError::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::General("TLS1.2 not used".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        let spki = SubjectPublicKeyInfoDer::from(cert.as_ref());
        rustls::crypto::verify_tls13_signature_with_raw_key(
            message,
            &spki,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
}

#[derive(Clone)]
struct RawPublicKeyClientVerifier {
    registry: PeerRegistry,
    root_hint_subjects: Vec<DistinguishedName>,
}

impl RawPublicKeyClientVerifier {
    fn new(registry: PeerRegistry) -> Self {
        Self {
            registry,
            root_hint_subjects: Vec::new(),
        }
    }

    fn resolve_validator_id(&self, presented_spki: &[u8]) -> Option<&ValidatorId> {
        self.registry.resolve_tls_spki(presented_spki)
    }
}

impl std::fmt::Debug for RawPublicKeyClientVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawPublicKeyClientVerifier")
            .field("peer_count", &self.registry.len())
            .finish()
    }
}

impl ClientCertVerifier for RawPublicKeyClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.root_hint_subjects
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        if !intermediates.is_empty() {
            return Err(TlsError::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ));
        }
        if let Some(validator_id) = self.resolve_validator_id(end_entity.as_ref()) {
            tracing::info!(
                peer_id = %validator_id,
                "accepted mutual RPK client identity"
            );
            Ok(ClientCertVerified::assertion())
        } else {
            crate::metrics::global().record_unknown_peer_drop();
            tracing::warn!(
                reason = "unknown_client_spki",
                "rejecting unconfigured mutual RPK client identity"
            );
            Err(TlsError::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::General("TLS1.2 not used".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        let spki = SubjectPublicKeyInfoDer::from(cert.as_ref());
        rustls::crypto::verify_tls13_signature_with_raw_key(
            message,
            &spki,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// Build a rustls::ClientConfig that REQUIRES RPK and pins the server SPKI (bytes).
pub fn build_client_rpk_pinned(spki_der: Vec<u8>) -> Arc<TlsClientConfig> {
    build_client_rpk_pinned_for_identity(
        ValidatorId::from_str("pinned-spki").expect("static validator id is valid"),
        spki_der,
    )
}

pub fn build_client_rpk_for_validator(
    registry: &PeerRegistry,
    validator_id: &ValidatorId,
) -> Result<Arc<TlsClientConfig>> {
    let spki_ders = registry.active_tls_spkis(validator_id)?;
    Ok(build_client_rpk_pinned_for_identities(
        validator_id.clone(),
        spki_ders,
    ))
}

pub fn build_client_rpk_for_validator_with_identity(
    registry: &PeerRegistry,
    validator_id: &ValidatorId,
    client_pkcs8_path: &str,
) -> Result<Arc<TlsClientConfig>> {
    let spki_ders = registry.active_tls_spkis(validator_id)?;
    Ok(build_client_rpk_pinned_for_identities_with_identity(
        validator_id.clone(),
        spki_ders,
        certified_rpk_key(client_pkcs8_path)?,
    ))
}

fn build_client_rpk_pinned_for_identity(
    validator_id: ValidatorId,
    spki_der: Vec<u8>,
) -> Arc<TlsClientConfig> {
    build_client_rpk_pinned_for_identities(validator_id, vec![spki_der])
}

fn build_client_rpk_pinned_for_identities(
    validator_id: ValidatorId,
    spki_ders: Vec<Vec<u8>>,
) -> Arc<TlsClientConfig> {
    let v = Arc::new(IdentityPinVerifier {
        validator_id,
        spkis: spki_ders,
    });
    Arc::new(
        TlsClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(v)
            .with_no_client_auth(),
    )
}

fn build_client_rpk_pinned_for_identities_with_identity(
    validator_id: ValidatorId,
    spki_ders: Vec<Vec<u8>>,
    client_certified_key: Arc<CertifiedKey>,
) -> Arc<TlsClientConfig> {
    let v = Arc::new(IdentityPinVerifier {
        validator_id,
        spkis: spki_ders,
    });
    Arc::new(
        TlsClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(v)
            .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(
                client_certified_key,
            ))),
    )
}

pub fn peer_validator_id_from_identity(
    registry: &PeerRegistry,
    peer_identity: Option<Box<dyn Any>>,
) -> Option<ValidatorId> {
    let certificates = peer_identity?
        .downcast::<Vec<CertificateDer<'static>>>()
        .ok()?;
    let first = certificates.first()?;
    registry.resolve_tls_spki(first.as_ref()).cloned()
}

/// Load a PUBLIC KEY (SPKI) from PEM into a DER-encoded `Vec<u8>`.
pub fn load_spki_from_pem(path: &str) -> Result<Vec<u8>> {
    let mut rdr = BufReader::new(File::open(path)?);
    match read_one(&mut rdr)? {
        Some(Item::SubjectPublicKeyInfo(spki)) => Ok(spki.as_ref().to_vec()),
        other => Err(anyhow!("Expected PUBLIC KEY (SPKI), got {:?}", other)),
    }
}

fn load_pkcs8(path: &str) -> Result<PrivatePkcs8KeyDer<'static>> {
    let mut rdr = BufReader::new(File::open(path)?);
    match read_one(&mut rdr)? {
        Some(Item::Pkcs8Key(k)) => Ok(k),
        other => Err(anyhow!("Expected PKCS#8 key, got {:?}", other)),
    }
}

fn certified_rpk_key(pkcs8_path: &str) -> Result<Arc<CertifiedKey>> {
    use rustls::crypto::ring::sign::any_supported_type;

    let pkcs8: PrivatePkcs8KeyDer<'static> = load_pkcs8(pkcs8_path)?;
    let signing_key = any_supported_type(&PrivateKeyDer::Pkcs8(pkcs8.clone_key()))
        .map_err(|e| anyhow!("unsupported private key: {e}"))?;

    let spki = signing_key.public_key().ok_or_else(|| anyhow!("no SPKI"))?;
    let rpk_cert: CertificateDer<'static> = CertificateDer::from(spki.as_ref().to_vec());
    Ok(Arc::new(CertifiedKey::new(vec![rpk_cert], signing_key)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::PeerIdentity;
    use rcgen::{CertificateParams, KeyPair};
    use rustls::{ClientConnection, ProtocolVersion, ServerConnection};
    use std::{
        fs,
        io::Cursor,
        path::{Path, PathBuf},
        sync::Once,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static INSTALL_PROVIDER: Once = Once::new();
    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn verifier(expected_spki: &[u8]) -> IdentityPinVerifier {
        IdentityPinVerifier {
            validator_id: ValidatorId::from_str("validator-a").unwrap(),
            spkis: vec![expected_spki.to_vec()],
        }
    }

    fn install_provider_once() {
        INSTALL_PROVIDER.call_once(install_provider);
    }

    fn temp_dir() -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "rpkv2-mutual-rpk-test-{}-{suffix}-{counter}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_keypair(dir: &Path, name: &str) -> (PathBuf, Vec<u8>) {
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let key_path = dir.join(format!("{name}.key"));
        fs::write(&key_path, key_pair.serialize_pem()).unwrap();
        (key_path, key_pair.public_key_der().to_vec())
    }

    fn registry_for_client(spki: &[u8]) -> PeerRegistry {
        let mut registry = PeerRegistry::default();
        registry
            .insert(PeerIdentity {
                validator_id: ValidatorId::from_str("validator-a").unwrap(),
                tls_spki_ders: vec![spki.to_vec()],
                packet_verify_key: [7u8; 32],
                expected_address: None,
            })
            .unwrap();
        registry
    }

    fn drive_handshake(
        client: &mut ClientConnection,
        server: &mut ServerConnection,
    ) -> std::result::Result<(), String> {
        for _ in 0..64 {
            transfer_client_to_server(client, server)?;
            transfer_server_to_client(server, client)?;
            if !client.is_handshaking() && !server.is_handshaking() {
                return Ok(());
            }
        }
        Err("handshake did not complete".to_string())
    }

    fn transfer_client_to_server(
        client: &mut ClientConnection,
        server: &mut ServerConnection,
    ) -> std::result::Result<(), String> {
        let mut bytes = Vec::new();
        client.write_tls(&mut bytes).map_err(|e| e.to_string())?;
        if !bytes.is_empty() {
            server
                .read_tls(&mut Cursor::new(bytes))
                .map_err(|e| e.to_string())?;
            server.process_new_packets().map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    fn transfer_server_to_client(
        server: &mut ServerConnection,
        client: &mut ClientConnection,
    ) -> std::result::Result<(), String> {
        let mut bytes = Vec::new();
        server.write_tls(&mut bytes).map_err(|e| e.to_string())?;
        if !bytes.is_empty() {
            client
                .read_tls(&mut Cursor::new(bytes))
                .map_err(|e| e.to_string())?;
            client.process_new_packets().map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    #[test]
    fn identity_verifier_accepts_expected_spki() {
        let verifier = verifier(b"known-spki");

        assert!(verifier.verifies_spki(b"known-spki"));
    }

    #[test]
    fn identity_verifier_rejects_wrong_spki() {
        let verifier = verifier(b"known-spki");

        assert!(!verifier.verifies_spki(b"wrong-spki"));
    }

    #[test]
    fn identity_verifier_requires_raw_public_keys() {
        let verifier = verifier(b"known-spki");

        assert!(rustls::client::danger::ServerCertVerifier::requires_raw_public_keys(&verifier));
    }

    #[test]
    fn identity_verifier_rejects_certificate_mode_fallback() {
        let verifier = verifier(b"known-spki");
        let presented_certificate = CertificateDer::from(b"x509-certificate-der".to_vec());
        let server_name = ServerName::try_from("validator-a.example").unwrap();

        let result = rustls::client::danger::ServerCertVerifier::verify_server_cert(
            &verifier,
            &presented_certificate,
            &[],
            &server_name,
            &[],
            rustls::pki_types::UnixTime::now(),
        );

        assert!(result.is_err());
    }

    #[test]
    fn identity_verifier_accepts_any_active_spki() {
        let verifier = IdentityPinVerifier {
            validator_id: ValidatorId::from_str("validator-a").unwrap(),
            spkis: vec![b"old-spki".to_vec(), b"new-spki".to_vec()],
        };

        assert!(verifier.verifies_spki(b"old-spki"));
        assert!(verifier.verifies_spki(b"new-spki"));
        assert!(!verifier.verifies_spki(b"revoked-spki"));
    }

    #[test]
    fn identity_client_config_rejects_unknown_validator() {
        let registry = PeerRegistry::default();
        let id = ValidatorId::from_str("unknown-validator").unwrap();

        assert!(build_client_rpk_for_validator(&registry, &id).is_err());
    }

    #[test]
    fn mutual_rpk_handshake_succeeds_and_negotiates_tls13() {
        install_provider_once();
        let dir = temp_dir();
        let (server_key, server_spki) = write_keypair(&dir, "server");
        let (client_key, client_spki) = write_keypair(&dir, "client");
        let server_registry = registry_for_client(&client_spki);
        let mut client_registry = PeerRegistry::default();
        let server_id = ValidatorId::from_str("server-validator").unwrap();
        client_registry
            .insert(PeerIdentity {
                validator_id: server_id.clone(),
                tls_spki_ders: vec![server_spki],
                packet_verify_key: [9u8; 32],
                expected_address: None,
            })
            .unwrap();
        let server_config =
            build_server_rpk_mutual(server_key.to_str().unwrap(), server_registry).unwrap();
        let client_config = build_client_rpk_for_validator_with_identity(
            &client_registry,
            &server_id,
            client_key.to_str().unwrap(),
        )
        .unwrap();
        let server_name = ServerName::try_from("server-validator.example").unwrap();
        let mut client = ClientConnection::new(client_config, server_name).unwrap();
        let mut server = ServerConnection::new(server_config).unwrap();

        drive_handshake(&mut client, &mut server).unwrap();

        assert_eq!(client.protocol_version(), Some(ProtocolVersion::TLSv1_3));
        assert_eq!(server.protocol_version(), Some(ProtocolVersion::TLSv1_3));
    }

    #[test]
    fn mutual_rpk_rejects_unknown_client_spki() {
        install_provider_once();
        let dir = temp_dir();
        let (server_key, server_spki) = write_keypair(&dir, "server");
        let (client_key, _client_spki) = write_keypair(&dir, "client");
        let server_registry = registry_for_client(b"not-the-client-spki");
        let mut client_registry = PeerRegistry::default();
        let server_id = ValidatorId::from_str("server-validator").unwrap();
        client_registry
            .insert(PeerIdentity {
                validator_id: server_id.clone(),
                tls_spki_ders: vec![server_spki],
                packet_verify_key: [9u8; 32],
                expected_address: None,
            })
            .unwrap();
        let server_config =
            build_server_rpk_mutual(server_key.to_str().unwrap(), server_registry).unwrap();
        let client_config = build_client_rpk_for_validator_with_identity(
            &client_registry,
            &server_id,
            client_key.to_str().unwrap(),
        )
        .unwrap();
        let server_name = ServerName::try_from("server-validator.example").unwrap();
        let mut client = ClientConnection::new(client_config, server_name).unwrap();
        let mut server = ServerConnection::new(server_config).unwrap();

        assert!(drive_handshake(&mut client, &mut server).is_err());
    }

    #[test]
    fn rpk_client_rejects_x509_server_end_to_end() {
        install_provider_once();
        let dir = temp_dir();
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        let server_config = Arc::new(
            TlsServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], key_der)
                .unwrap(),
        );
        let (_client_key, expected_spki) = write_keypair(&dir, "unrelated-rpk-pin");
        let client_config = build_client_rpk_pinned(expected_spki);
        let server_name = ServerName::try_from("localhost").unwrap();
        let mut client = ClientConnection::new(client_config, server_name).unwrap();
        let mut server = ServerConnection::new(server_config).unwrap();

        assert!(drive_handshake(&mut client, &mut server).is_err());
    }
}
