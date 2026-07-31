use anyhow::{Result, anyhow};
#[cfg(not(feature = "ed25519"))]
compile_error!("client requires the ed25519 feature; stub verification is demo-only.");

use clap::Parser;
use quinn::Endpoint;
use rpkv2::{
    config::ProductionConfig,
    identity::{PeerRegistry, ValidatorId},
    quic_cfg,
    runtime_mode::{RuntimeMode, StartupGuardrails},
    tls,
    version::VersionArgs,
};
use std::{net::SocketAddr, path::PathBuf, str::FromStr};

use tracing::info;

#[derive(Parser, Debug)]
#[command(about = "RPK QUIC client")]
struct Args {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = RuntimeMode::Demo)]
    mode: RuntimeMode,
    #[arg(long)]
    peer_validator_id: Option<String>,
    #[arg(long, default_value = "127.0.0.1:4433")]
    connect: SocketAddr,
    #[arg(long, default_value = "server.pub")]
    pin_spki_pem: String,
    #[command(flatten)]
    version: VersionArgs,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Select TLS crypto provider (aws-lc) before building configs
    tls::install_provider();

    // Simple logging
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .without_time()
        .init();
    let args = Args::parse();
    if args.version.print_and_exit_if_requested() {
        return Ok(());
    }
    info!(mode = %args.mode, "runtime mode selected");

    let (tls_client, server_addr, peer_label) = if let Some(config_path) = &args.config {
        let config = ProductionConfig::load(config_path)?;
        let registry = PeerRegistry::from_config(&config)?;
        StartupGuardrails {
            mode: args.mode,
            has_config: true,
            generated_ephemeral_keys: false,
            metrics_enabled: true,
            peer_count: registry.len(),
            accepted_demo_storage: config.storage.allow_unsafe_demo_storage,
        }
        .validate()?;
        let peer_id = ValidatorId::from_str(
            args.peer_validator_id
                .as_deref()
                .ok_or_else(|| anyhow!("--peer-validator-id is required with --config"))?,
        )?;
        let peer = registry
            .get(&peer_id)
            .ok_or_else(|| anyhow!("unknown peer validator id: {peer_id}"))?;
        let server_addr = peer.expected_address.unwrap_or(args.connect);
        let tls_client = tls::build_client_rpk_for_validator_with_identity(
            &registry,
            &peer_id,
            config
                .local
                .private_key_path
                .to_str()
                .ok_or_else(|| anyhow!("local.private_key_path is not valid UTF-8"))?,
        )?;
        info!(
            mode = %args.mode,
            peer_id = %peer_id,
            server_address = %server_addr,
            config_path = %config_path.display(),
            "connecting to configured validator"
        );
        (tls_client, server_addr, peer_id.to_string())
    } else {
        StartupGuardrails {
            mode: args.mode,
            has_config: false,
            generated_ephemeral_keys: false,
            metrics_enabled: false,
            peer_count: 0,
            accepted_demo_storage: false,
        }
        .validate()?;
        // Load pinned SPKI (DER) from PEM for demo/manual pinning mode.
        let spki = tls::load_spki_from_pem(&args.pin_spki_pem)?;
        let tls_client = tls::build_client_rpk_pinned(spki);
        (tls_client, args.connect, "pinned-spki".to_string())
    };

    // Quinn client config with our tuned transport
    let client_cfg = quic_cfg::client_config(tls_client);

    // Bind a client endpoint and apply the client config
    let bind_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let mut ep = Endpoint::client(bind_addr)?;
    ep.set_default_client_config(client_cfg);

    let conn = ep.connect(server_addr, "localhost")?.await?;
    info!(
        mode = %args.mode,
        "connected to validator {} at {}",
        peer_label,
        conn.remote_address()
    );
    let _ = conn.send_datagram(bytes::Bytes::from_static(b"ping dgram"));

    // Send a message on a unidirectional stream
    let mut send = conn.open_uni().await?;
    send.write_all(b"hello from client").await?;
    let _ = send.finish(); // not async in quinn 0.11

    // Read the server's uni-stream echo/greeting (optional but nice)
    if let Ok(mut recv) = conn.accept_uni().await {
        let data = recv.read_to_end(64 * 1024).await?; // 64 KiB limit
        println!("client got: {}", String::from_utf8_lossy(&data));
    } else {
        eprintln!("client: no uni stream from server");
    }

    Ok(())
}
