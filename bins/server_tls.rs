/// Standard TLS 1.3 QUIC server — two-node benchmark counterpart to server.rs.
///
/// Generates a self-signed Ed25519 certificate at startup. The client
/// (bench_handshake_tls) uses an accept-any verifier, so no key exchange is needed.
///
/// Run on the second machine alongside server.exe:
///   server.exe     --bind 0.0.0.0:4433   (RPK)
///   server_tls.exe --bind 0.0.0.0:4434   (standard TLS 1.3)
use anyhow::Result;
use clap::Parser;
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Connection, Endpoint, ServerConfig};
use rcgen::{CertificateParams, KeyPair};
use rpkv2::{quic_cfg, runtime_mode::RuntimeMode, tls, version::VersionArgs};
use rustls::{
    ServerConfig as TlsServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use std::{net::SocketAddr, sync::Arc};
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(about = "Standard TLS 1.3 QUIC server for two-node handshake comparison")]
struct Args {
    #[arg(long, default_value = "0.0.0.0:4434")]
    bind: String,
    #[arg(long, value_enum, default_value_t = RuntimeMode::Benchmark)]
    mode: RuntimeMode,
    #[command(flatten)]
    version: VersionArgs,
}

fn build_tls_server() -> Result<Arc<TlsServerConfig>> {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    let params = CertificateParams::new(vec!["localhost".to_string()])?;
    let cert = params.self_signed(&key_pair)?;
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    Ok(Arc::new(
        TlsServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)?,
    ))
}

#[tokio::main]
async fn main() -> Result<()> {
    tls::install_provider();
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .without_time()
        .init();
    let args = Args::parse();
    if args.version.print_and_exit_if_requested() {
        return Ok(());
    }
    if args.mode != RuntimeMode::Benchmark {
        anyhow::bail!("server_tls only supports --mode benchmark");
    }
    info!(mode = %args.mode, "runtime mode selected");

    let tls_server = build_tls_server()?;
    let quic_tls = Arc::new(QuicServerConfig::try_from(tls_server)?);
    let mut server_cfg = ServerConfig::with_crypto(quic_tls);
    server_cfg.transport_config(quic_cfg::tuned_transport());

    let addr: SocketAddr = args.bind.parse()?;
    let endpoint = Endpoint::server(server_cfg, addr)?;
    info!("standard-TLS QUIC server listening on {addr}");
    info!("(ephemeral self-signed Ed25519 cert — client uses accept-any verifier)");

    while let Some(connecting) = endpoint.accept().await {
        tokio::spawn(async move {
            match connecting.await {
                Ok(conn) => handle_conn(conn).await,
                Err(e) => warn!("accept error: {e}"),
            }
        });
    }
    Ok(())
}

async fn handle_conn(conn: Connection) {
    info!("peer connected: {}", conn.remote_address());

    let dconn = conn.clone();
    tokio::spawn(async move {
        loop {
            match dconn.read_datagram().await {
                Ok(data) => {
                    let _ = dconn.send_datagram(data);
                }
                Err(e) => {
                    break warn!("datagram loop end: {e}");
                }
            }
        }
    });

    let sconn = conn.clone();
    tokio::spawn(async move {
        while let Ok(mut recv) = sconn.accept_uni().await {
            match recv.read_to_end(64 * 1024 * 1024).await {
                Ok(data) => {
                    if let Ok(mut send) = sconn.open_uni().await {
                        let _ = send.write_all(&data).await;
                        let _ = send.finish();
                    }
                }
                Err(e) => warn!("stream read err: {e}"),
            }
        }
    });
}
