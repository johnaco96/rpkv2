use anyhow::{anyhow, Result};
use quinn::{Endpoint, ServerConfig};
use quinn::crypto::rustls::QuicServerConfig;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::AlwaysResolvesServerRawPublicKeys;
use rustls::sign::CertifiedKey;
use rustls::{ServerConfig as TlsServerConfig};
use rustls::crypto::aws_lc_rs::sign::any_supported_type;

use rustls_pemfile::{read_one, Item};

use std::{fs::File, io::BufReader, net::SocketAddr, sync::Arc};
use tokio::io::AsyncWriteExt; // for .write_all()

fn load_pkcs8_key(path: &str) -> Result<PrivatePkcs8KeyDer<'static>> {
    let mut rdr = BufReader::new(File::open(path)?);
    match read_one(&mut rdr)? {
        Some(Item::Pkcs8Key(k)) => Ok(k),
        other => Err(anyhow!("Expected PKCS#8 key, got {:?}", other)),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Select provider explicitly
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("install aws-lc provider");

    tracing_subscriber::fmt().with_env_filter("info").without_time().init();

    // Load Ed25519 PKCS#8 private key
    let pkcs8: PrivatePkcs8KeyDer<'static> = load_pkcs8_key("server.key")?;
    let signing_key = any_supported_type(&PrivateKeyDer::Pkcs8(pkcs8.clone_key()))
        .map_err(|e| anyhow!("unsupported private key: {e}"))?;

    // Build RPK “cert”: single SPKI in the certs vec
    let spki = signing_key.public_key().ok_or_else(|| anyhow!("no SPKI"))?;
    let rpk_cert_der: CertificateDer<'static> = CertificateDer::from(spki.as_ref().to_vec());
    let certified = Arc::new(CertifiedKey::new(vec![rpk_cert_der], signing_key));

    // Server will present a raw public key (RFC 7250)
    let resolver = Arc::new(AlwaysResolvesServerRawPublicKeys::new(certified));
    let tls_server: Arc<TlsServerConfig> = Arc::new(
        TlsServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver)
    );

    // QUIC + bind
    let quic_tls = Arc::new(QuicServerConfig::try_from(tls_server)?);
    let server_cfg = ServerConfig::with_crypto(quic_tls);
    let addr: SocketAddr = "0.0.0.0:4433".parse().unwrap();

    let endpoint = Endpoint::server(server_cfg, addr)?;
    tracing::info!("RPK QUIC server listening on {}", addr);

    loop {
        let Some(connecting) = endpoint.accept().await else { break };

        tokio::spawn(async move {
            match connecting.await {
                Ok(conn) => {
                    // conn is quinn::Connection (no .connection field)
                    tracing::info!("peer connected: {}", conn.remote_address());

                    // (optional) send a greeting
                    if let Ok(mut send) = conn.open_uni().await {
                        use tokio::io::AsyncWriteExt; // only needed if you call write_all
                        let _ = send.write_all(b"hello from server").await;
                        let _ = send.finish(); // not async
                    }

                    // (optional) receive one uni stream from client
                    match conn.accept_uni().await {
                        Ok(mut recv) => {
                            match recv.read_to_end(64 * 1024).await {
                                Ok(data) => tracing::info!(
                                    "got {}B from client: {}",
                                    data.len(),
                                    String::from_utf8_lossy(&data)
                                ),
                                Err(e) => tracing::warn!("read_to_end error: {e}"),
                            }
                        }
                        Err(e) => tracing::warn!("no client uni stream: {e}"),
                    }
                }
                Err(e) => tracing::warn!("accept error: {e}"),
            }
        });
    }


    Ok(())
}
