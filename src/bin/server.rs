use anyhow::Result;
#[cfg(not(feature = "ed25519"))]
compile_error!("server requires the ed25519 feature; stub verification is demo-only.");

use clap::Parser;
use pem::Pem;
use quinn::{Connection, Endpoint};
use rcgen::{CertificateParams, KeyPair};
use rpkv2::{
    config::ProductionConfig,
    health::{HealthReporter, ensure_storage_writable},
    identity::PeerRegistry,
    identity_keys, logging,
    metrics::{self, ActiveConnectionGuard},
    quic_cfg,
    runtime_mode::{RuntimeMode, StartupGuardrails},
    server_pipeline::{ServerPipeline, ServerPipelineConfig, ServerPipelineIngress},
    shutdown::Shutdown,
    tls,
    version::VersionArgs,
};
use std::{fs, net::SocketAddr, path::PathBuf, time::Duration};
use tokio::task::JoinSet;
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(about = "RPK QUIC server — auto-generates keys on first run")]
struct Args {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = RuntimeMode::Demo)]
    mode: RuntimeMode,
    #[arg(long)]
    check_config: bool,
    #[arg(long, default_value = "0.0.0.0:4433")]
    bind: String,
    #[arg(long, default_value = "server.key")]
    key: String,
    #[arg(long, default_value = "server.pub")]
    r#pub: String,
    #[command(flatten)]
    version: VersionArgs,
}

fn ensure_key_files(key_path: &str, pub_path: &str) -> Result<bool> {
    if std::path::Path::new(key_path).exists() && std::path::Path::new(pub_path).exists() {
        return Ok(false);
    }
    info!(
        validator_id = "adhoc-server",
        reason = "missing_key_files",
        "generating ephemeral Ed25519 key pair for local non-configured server"
    );
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    let params = CertificateParams::new(vec!["localhost".to_string()])?;
    let _cert = params.self_signed(&key_pair)?;
    fs::write(key_path, key_pair.serialize_pem())?;
    let spki_pem = pem::encode(&Pem::new("PUBLIC KEY", key_pair.public_key_der()));
    fs::write(pub_path, &spki_pem)?;
    Ok(true)
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

    info!(mode = %args.mode, "runtime mode selected");

    let (
        validator_id,
        bind_addr,
        key_path,
        metrics_addr,
        storage_dir,
        pipeline_config,
        packet_key_path,
        peer_registry,
    ) = if let Some(config_path) = &args.config {
        let config = ProductionConfig::load(config_path)?;
        let registry = PeerRegistry::from_config(&config)?;
        let packet_key_path = config
            .local
            .packet_signing_key_path
            .clone()
            .ok_or_else(|| {
                anyhow::anyhow!("configured server pipeline requires local.packet_signing_key_path")
            })?;
        let pipeline_config = ServerPipelineConfig::from_production_config(&config);
        StartupGuardrails {
            mode: args.mode,
            has_config: true,
            generated_ephemeral_keys: false,
            metrics_enabled: true,
            peer_count: registry.len(),
            accepted_demo_storage: config.storage.allow_unsafe_demo_storage,
        }
        .validate()?;
        info!(
            validator_id = %config.local.validator_id,
            mode = %args.mode,
            peer_count = registry.len(),
            config_path = %config_path.display(),
            bind_address = %config.local.bind_address,
            metrics_address = %config.metrics.bind_address,
            storage_dir = %config.storage.directory.display(),
            storage_recovery_policy = ?config.storage.recovery_policy,
            "loaded startup config summary"
        );
        if args.check_config {
            info!(
                validator_id = %config.local.validator_id,
                reason = "check_config",
                "config validation succeeded"
            );
            return Ok(());
        }
        (
            config.local.validator_id,
            config.local.bind_address,
            config.local.private_key_path,
            config.metrics.bind_address,
            Some(config.storage.directory),
            Some(pipeline_config),
            Some(packet_key_path),
            Some(registry),
        )
    } else {
        StartupGuardrails {
            mode: args.mode,
            has_config: false,
            generated_ephemeral_keys: true,
            metrics_enabled: true,
            peer_count: 0,
            accepted_demo_storage: false,
        }
        .validate()?;
        let generated_ephemeral_keys = ensure_key_files(&args.key, &args.r#pub)?;

        info!(
            validator_id = "adhoc-server",
            mode = %args.mode,
            bind_address = %args.bind,
            metrics_address = "127.0.0.1:9100",
            reason = "no_config",
            generated_ephemeral_keys,
            "starting non-configured server; distribute SPKI pin out of band"
        );

        (
            "adhoc-server".to_string(),
            args.bind.parse::<SocketAddr>()?,
            PathBuf::from(&args.key),
            "127.0.0.1:9100".parse::<SocketAddr>()?,
            None,
            None,
            None,
            None,
        )
    };

    let health = HealthReporter::new(&validator_id);
    health.mark_config_valid();
    if let Some(storage_dir) = &storage_dir {
        ensure_storage_writable(storage_dir)?;
        health.mark_storage_writable();
    } else {
        health.mark_storage_writable();
    }
    let packet_signing_key = if let Some(packet_key_path) = &packet_key_path {
        Some(identity_keys::load_ed25519_signing_key(packet_key_path)?)
    } else {
        None
    };
    let key_path_str = key_path.to_str().ok_or_else(|| {
        anyhow::anyhow!("local private key path is not valid UTF-8: {key_path:?}")
    })?;
    let tls = if let Some(registry) = &peer_registry {
        tls::build_server_rpk_mutual(key_path_str, registry.clone())?
    } else {
        tls::build_server_rpk(key_path_str)?
    };
    health.mark_keys_loaded();
    let server_cfg = quic_cfg::server_config(tls);
    let endpoint = Endpoint::server(server_cfg, bind_addr)?;
    health.mark_socket_bound();
    info!(
        validator_id = %validator_id,
        mode = %args.mode,
        bind_address = %bind_addr,
        "RPK QUIC server listening"
    );
    let shutdown = Shutdown::new();
    let pipeline = match (pipeline_config, packet_signing_key) {
        (Some(config), Some(packet_signing_key)) => {
            info!(
                validator_id = %validator_id,
                storage_dir = %config.storage_dir.display(),
                "starting validator tile pipeline"
            );
            Some(ServerPipeline::start(
                config,
                packet_signing_key,
                shutdown.clone(),
            ))
        }
        _ => None,
    };
    let pipeline_ingress = pipeline.as_ref().map(ServerPipeline::ingress);
    let queue_depths = pipeline
        .as_ref()
        .map(ServerPipeline::queue_depths)
        .unwrap_or_default();
    let peer_limiter = pipeline.as_ref().map(ServerPipeline::peer_limiter);
    let metrics_handle = metrics::start_metrics_endpoint(
        metrics_addr,
        shutdown.clone(),
        queue_depths,
        peer_limiter,
        Some(health.clone()),
    )?;
    health.set_ready();
    info!(
        validator_id = %validator_id,
        mode = %args.mode,
        metrics_address = %metrics_addr,
        "metrics endpoint listening"
    );

    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!(
                    validator_id = %validator_id,
                    reason = "ctrl_c",
                    "shutdown requested; closing QUIC endpoint"
                );
                health.set_shutting_down();
                shutdown.request();
                endpoint.close(0u32.into(), b"shutdown");
                break;
            }
            accepted = endpoint.accept() => {
                let Some(connecting) = accepted else {
                    break;
                };
                let pipeline_ingress = pipeline_ingress.clone();
                let peer_registry = peer_registry.clone();
                connections.spawn(async move {
                    let connection_id = logging::next_connection_id();
                    match connecting.await {
                        Ok(conn) => {
                            handle_conn(conn, connection_id, pipeline_ingress, peer_registry).await
                        }
                        Err(e) => warn!(
                            connection_id,
                            reason = %e,
                            "connection accept failed"
                        ),
                    }
                });
            }
        }
    }

    while let Some(result) = connections.join_next().await {
        if let Err(e) = result {
            warn!(
                validator_id = %validator_id,
                reason = %e,
                "connection task failed during shutdown"
            );
        }
    }
    shutdown.request();
    let _ = metrics_handle.join();
    if let Some(pipeline) = pipeline {
        pipeline.join();
    }
    info!(validator_id = %validator_id, "server shutdown complete");
    Ok(())
}

async fn handle_conn(
    conn: Connection,
    connection_id: u64,
    pipeline_ingress: Option<ServerPipelineIngress>,
    peer_registry: Option<PeerRegistry>,
) {
    let _connection = ActiveConnectionGuard::new();
    let peer_id = peer_registry
        .as_ref()
        .and_then(|registry| tls::peer_validator_id_from_identity(registry, conn.peer_identity()))
        .map(|id| id.to_string())
        .unwrap_or_else(|| conn.remote_address().to_string());
    info!(
        connection_id,
        peer_id = %peer_id,
        "peer connected"
    );

    let dconn = conn.clone();
    let dpeer_id = peer_id.clone();
    let dgrams = tokio::spawn(async move {
        loop {
            match dconn.read_datagram().await {
                Ok(data) => {
                    if let Some(pipeline_ingress) = &pipeline_ingress {
                        let _ = pipeline_ingress.ingest_datagram_bytes(&dpeer_id, data);
                    } else {
                        metrics::global().record_packet_received();
                        let _ = dconn.send_datagram(data);
                        metrics::global().record_packet_accepted();
                    }
                }
                Err(e) => {
                    if logging::should_log("server_datagram_loop_end", Duration::from_secs(1)) {
                        warn!(
                            connection_id,
                            peer_id = %dpeer_id,
                            reason = %e,
                            "datagram loop ended"
                        );
                    }
                    break;
                }
            }
        }
    });

    let sconn = conn.clone();
    let speer_id = peer_id.clone();
    let streams = tokio::spawn(async move {
        while let Ok(mut recv) = sconn.accept_uni().await {
            match recv.read_to_end(64 * 1024 * 1024).await {
                Ok(data) => {
                    if let Ok(mut send) = sconn.open_uni().await {
                        let _ = send.write_all(&data).await;
                        let _ = send.finish();
                    }
                }
                Err(e) => warn!(
                    connection_id,
                    peer_id = %speer_id,
                    reason = %e,
                    "stream read failed"
                ),
            }
        }
    });

    let _ = tokio::join!(dgrams, streams);
}
