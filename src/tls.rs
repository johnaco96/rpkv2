// src/tls.rs
use anyhow::{anyhow, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::AlwaysResolvesServerRawPublicKeys;
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig as TlsClientConfig, ServerConfig as TlsServerConfig};
use rustls_pemfile::{read_one, Item};
use std::{fs::File, io::BufReader, sync::Arc};

/// Must be called once at startup in each binary.
/// Ensures exactly one crypto provider is installed (aws-lc here).
pub fn install_provider() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("install aws-lc provider");
}

/// Build a rustls::ServerConfig that serves a Raw Public Key (SPKI only).
pub fn build_server_rpk(pkcs8_path: &str) -> Result<Arc<TlsServerConfig>> {
    use rustls::crypto::aws_lc_rs::sign::any_supported_type;

    let pkcs8: PrivatePkcs8KeyDer<'static> = load_pkcs8(pkcs8_path)?;
    let signing_key = any_supported_type(&PrivateKeyDer::Pkcs8(pkcs8.clone_key()))
        .map_err(|e| anyhow!("unsupported private key: {e}"))?;

    let spki = signing_key.public_key().ok_or_else(|| anyhow!("no SPKI"))?;
    let rpk_cert: CertificateDer<'static> = CertificateDer::from(spki.as_ref().to_vec());
    let certified = Arc::new(CertifiedKey::new(vec![rpk_cert], signing_key));

    let resolver = Arc::new(AlwaysResolvesServerRawPublicKeys::new(certified));

    Ok(Arc::new(
        TlsServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver),
    ))
}

/// Build a rustls::ClientConfig that REQUIRES RPK and pins the server SPKI (bytes).
pub fn build_client_rpk_pinned(spki_der: Vec<u8>) -> Arc<TlsClientConfig> {
    use rustls::client::danger::{ServerCertVerifier, ServerCertVerified, HandshakeSignatureValid};
    use rustls::{SignatureScheme};
    use rustls::pki_types::UnixTime;

    #[derive(Clone)]
    struct PinVerifier { spki: Vec<u8> }
    impl std::fmt::Debug for PinVerifier {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("PinVerifier").finish()
        }
    }
    impl ServerCertVerifier for PinVerifier {
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> { vec![SignatureScheme::ED25519] }
        fn requires_raw_public_keys(&self) -> bool { true }
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            if end_entity.as_ref() == self.spki.as_slice() {
                Ok(ServerCertVerified::assertion())
            } else {
                Err(rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer))
            }
        }
        fn verify_tls12_signature(
            &self, _m:&[u8], _c:&CertificateDer<'_>, _d:&rustls::DigitallySignedStruct
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Err(rustls::Error::General("TLS1.2 not used".into()))
        }
        fn verify_tls13_signature(
            &self, _m:&[u8], _c:&CertificateDer<'_>, _d:&rustls::DigitallySignedStruct
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
    }

    let v = Arc::new(PinVerifier { spki: spki_der });
    Arc::new(
        TlsClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(v)
            .with_no_client_auth()
    )
}

/// Load a PUBLIC KEY (SPKI) from PEM -> Vec<u8> (DER)
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
