/// Standard TLS 1.3 handshake benchmark — comparison baseline for RPK.
///
/// Generates a self-signed Ed25519 certificate at startup, runs N QUIC
/// handshakes, and writes latency quantiles to CSV.
///
/// Run alongside bench_handshake (RPK) and compare the two CSVs.
use anyhow::Result;
use clap::Parser;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Endpoint, ServerConfig};
use rcgen::{CertificateParams, KeyPair};
use rpkv2::{quic_cfg, runtime_mode::RuntimeMode, tls, util::Histo, version::VersionArgs};
use rustls::{
    ClientConfig as TlsClientConfig, ServerConfig as TlsServerConfig, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
};
use std::{fmt, net::SocketAddr, sync::Arc};
use tracing::info;

#[derive(Parser, Debug)]
#[command(about = "Standard TLS 1.3 handshake benchmark (compare with bench_handshake for RPK)")]
struct Args {
    /// Address of the TLS server to connect to.
    /// For loopback testing omit --bind and this binary starts its own server.
    /// For two-node testing point this at the remote server_tls.exe.
    #[arg(long, default_value = "127.0.0.1:4434")]
    server: String,
    /// If set, start an embedded TLS server on this address (loopback mode only).
    /// Leave unset when --server points to a remote machine.
    #[arg(long)]
    bind: Option<String>,
    #[arg(long, default_value_t = 200)]
    iters: u32,
    #[arg(long, default_value = "handshake_tls.csv")]
    out_csv: String,
    #[arg(long, value_enum, default_value_t = RuntimeMode::Benchmark)]
    mode: RuntimeMode,
    #[command(flatten)]
    version: VersionArgs,
}

// ── Accept-any verifier (benchmark only — not for production) ─────────────────
#[derive(Clone)]
struct AcceptAny;
impl fmt::Debug for AcceptAny {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AcceptAny")
    }
}
impl ServerCertVerifier for AcceptAny {
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 not used".into()))
    }
    fn verify_tls13_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
}

fn build_tls_server() -> Result<Arc<TlsServerConfig>> {
    // Generate an Ed25519 key pair and self-signed certificate using rcgen 0.13 API.
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    let params = CertificateParams::new(vec!["localhost".to_string()])?;
    let cert = params.self_signed(&key_pair)?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    let tls = TlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)?;

    Ok(Arc::new(tls))
}

fn build_tls_client() -> Arc<TlsClientConfig> {
    let v = Arc::new(AcceptAny);
    Arc::new(
        TlsClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(v)
            .with_no_client_auth(),
    )
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
        anyhow::bail!("bench_handshake_tls only supports --mode benchmark");
    }
    info!(mode = %args.mode, "runtime mode selected");

    // ── Optionally start an embedded TLS server (loopback mode) ──────────────
    let addr: SocketAddr = args.server.parse()?;
    let bind_addr = args.bind.as_deref().unwrap_or("127.0.0.1:4434");

    if args.bind.is_some() || addr.ip().is_loopback() {
        let tls_server = build_tls_server()?;
        let quic_server_tls = Arc::new(QuicServerConfig::try_from(tls_server)?);
        let mut server_cfg = ServerConfig::with_crypto(quic_server_tls);
        server_cfg.transport_config(quic_cfg::tuned_transport());
        let server_ep = Endpoint::server(server_cfg, bind_addr.parse::<SocketAddr>()?)?;
        info!("standard-TLS server on {bind_addr}");
        tokio::spawn(async move {
            while let Some(conn) = server_ep.accept().await {
                tokio::spawn(async move { if let Ok(_c) = conn.await {} });
            }
        });
    } else {
        info!("client-only mode → connecting to remote server at {addr}");
    }

    // ── Client: measure N handshakes ──────────────────────────────────────────
    let tls_client = build_tls_client();
    let quic_client_tls = Arc::new(QuicClientConfig::try_from(tls_client)?);
    let base_client_cfg = ClientConfig::new(quic_client_tls);

    let mut hist = Histo::new(5_000_000);

    // Warmup
    {
        let mut ep = Endpoint::client("0.0.0.0:0".parse::<SocketAddr>()?)?;
        let mut ccfg = base_client_cfg.clone();
        ccfg.transport_config(quic_cfg::tuned_transport());
        ep.set_default_client_config(ccfg);
        let _ = ep.connect(addr, "localhost")?.await?;
    }

    for _ in 0..args.iters {
        let mut ep = Endpoint::client("0.0.0.0:0".parse::<SocketAddr>()?)?;
        let mut ccfg = base_client_cfg.clone();
        ccfg.transport_config(quic_cfg::tuned_transport());
        ep.set_default_client_config(ccfg);

        let t0 = std::time::Instant::now();
        let conn = ep.connect(addr, "localhost")?.await?;
        hist.record_us(t0.elapsed().as_micros() as u64);
        conn.close(0u32.into(), b"bye");
    }

    info!(
        "TLS handshakes={} p50={}µs p99={}µs mean={:.0}µs",
        hist.count(),
        hist.p(0.50),
        hist.p(0.99),
        hist.mean()
    );
    hist.write_csv(&args.out_csv)?;
    info!("wrote {}", args.out_csv);
    Ok(())
}
