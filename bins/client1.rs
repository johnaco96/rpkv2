use anyhow::{anyhow, Result};
use quinn::{ClientConfig, Endpoint};
use quinn::crypto::rustls::QuicClientConfig;

use rustls::client::danger::{ServerCertVerifier, HandshakeSignatureValid, ServerCertVerified};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig as TlsClientConfig, SignatureScheme};
use rustls_pemfile::{read_one, Item};

use std::{fmt, fs::File, io::BufReader, sync::Arc};
use tokio::io::AsyncWriteExt; // for .write_all()

#[derive(Clone)]
struct RpkPinVerifier { expected_spki: Vec<u8> }
impl fmt::Debug for RpkPinVerifier { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.debug_struct("RpkPinVerifier").finish() } }
impl ServerCertVerifier for RpkPinVerifier {
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> { vec![SignatureScheme::ED25519] }
    fn requires_raw_public_keys(&self) -> bool { true }
    fn verify_server_cert(
        &self, end_entity: &CertificateDer<'_>, _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>, _ocsp: &[u8], _now: UnixTime
    ) -> Result<ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.expected_spki.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer))
        }
    }
    fn verify_tls12_signature(&self, _m:&[u8], _c:&CertificateDer<'_>, _d:&rustls::DigitallySignedStruct)
        -> Result<HandshakeSignatureValid, rustls::Error> { Err(rustls::Error::General("TLS1.2 not used".into())) }
    fn verify_tls13_signature(&self, _m:&[u8], _c:&CertificateDer<'_>, _d:&rustls::DigitallySignedStruct)
        -> Result<HandshakeSignatureValid, rustls::Error> { Ok(HandshakeSignatureValid::assertion()) }
}

fn load_server_spki(path: &str) -> Result<Vec<u8>> {
    let mut rdr = BufReader::new(File::open(path)?);
    match read_one(&mut rdr)? {
        Some(Item::SubjectPublicKeyInfo(spki)) => Ok(spki.as_ref().to_vec()),
        other => Err(anyhow!("Expected PUBLIC KEY (SPKI), got {:?}", other)),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Select provider explicitly
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("install aws-lc provider");

    tracing_subscriber::fmt().with_env_filter("info").without_time().init();

    // Pin server SPKI
    let expected_spki = load_server_spki("server.pub")?;
    let verifier = Arc::new(RpkPinVerifier { expected_spki });

    // rustls client that REQUIRES RPK and pins SPKI
    let tls_client: Arc<TlsClientConfig> = Arc::new(
        TlsClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth()
    );

    // QUIC connect
    let quic_tls = Arc::new(QuicClientConfig::try_from(tls_client)?);
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())?;
    endpoint.set_default_client_config(ClientConfig::new(quic_tls));

    let conn = endpoint.connect("127.0.0.1:4433".parse().unwrap(), "localhost")?.await?;
    tracing::info!("connected to {}", conn.remote_address());

    // Send a uni message to server
    let mut send = conn.open_uni().await?;
    send.write_all(b"hello from client").await?;
    let _ = send.finish(); // not async

    // Read server's uni greeting
    match conn.accept_uni().await {
        Ok(mut recv) => {
            match recv.read_to_end(64 * 1024).await {
                Ok(data) => println!("client got: {}", String::from_utf8_lossy(&data)),
                Err(e) => eprintln!("client read_to_end error: {e}"),
            }
        }
        Err(e) => eprintln!("client accept_uni error: {e}"),
    }

    Ok(())
}
