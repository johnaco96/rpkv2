/// End-to-end pipeline demo.
///
/// Starts a QUIC/RPK server and wires the full tile chain:
///   QUIC-rx → Deduper → Verifier → Pack → Bank → Poh → Shredder → Signer → Storage
///
/// A built-in load generator connects as a client and sends --txns datagrams,
/// each carrying a valid packet Header + 256-byte payload.
///
/// Usage: demo [--key server.key] [--pub server.pub] [--txns 5000] [--store ./store]
use anyhow::Result;
use bytes::{Bytes, BytesMut};
use clap::Parser;
use crossbeam_queue::ArrayQueue;
use quinn::Endpoint;
use rcgen::{CertificateParams, KeyPair};
use rpkv2::{
    backpressure::{INGRESS_POLICY, push_with_policy},
    fastpath::packet::{HEADER_LEN, Header},
    health::{HealthReporter, ensure_storage_writable},
    logging,
    metrics::{self, ActiveConnectionGuard, QueueDepthGauge},
    peer_rate_limit::{PeerLimitDecision, PeerRateLimiter, PeerRateLimits},
    quic_cfg,
    runtime_mode::RuntimeMode,
    shutdown::Shutdown,
    supervision::TileSupervisor,
    tiles::{
        Txn, TxnQueue, VerifiedQueue,
        bank::{Bank, BankOutQueue},
        dedupe::Deduper,
        pack::Pack,
        poh::{Poh, PohOutQueue},
        shred::{ShredOutQueue, Shredder},
        signing::{SignedShredQueue, Signer},
        storage::{Storage, StorageRecoveryPolicy},
        verify::Verifier,
    },
    tls,
    version::VersionArgs,
};
use std::{fs, net::SocketAddr, path::PathBuf, sync::Arc, time::Instant};
use tracing::info;

const VALIDATOR_ID: &str = "demo-validator";

/// Generate ephemeral Ed25519 key files (PKCS#8 + SPKI PEM) if they don't exist.
fn ensure_key_files(key_path: &str, pub_path: &str) -> Result<()> {
    if std::path::Path::new(key_path).exists() && std::path::Path::new(pub_path).exists() {
        return Ok(());
    }
    info!(
        validator_id = VALIDATOR_ID,
        reason = "missing_key_files",
        "generating ephemeral Ed25519 key pair for demo"
    );
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    let params = CertificateParams::new(vec!["localhost".to_string()])?;
    let _cert = params.self_signed(&key_pair)?;

    // Write PKCS#8 private key as PEM
    fs::write(key_path, key_pair.serialize_pem())?;

    // Write SPKI (SubjectPublicKeyInfo) as PEM — what clients pin
    let spki_der = key_pair.public_key_der();
    let spki_pem = pem::encode(&pem::Pem::new("PUBLIC KEY", spki_der));
    fs::write(pub_path, spki_pem)?;

    Ok(())
}

#[derive(Parser, Debug)]
#[command(about = "RPK QUIC pipeline demo — full tile chain")]
struct Args {
    #[arg(long, default_value = "server.key")]
    key: String,
    #[arg(long, default_value = "server.pub")]
    r#pub: String,
    #[arg(long, default_value_t = 5_000)]
    txns: u64,
    #[arg(long, default_value = "store")]
    store: PathBuf,
    #[arg(long, default_value = "127.0.0.1:4433")]
    addr: String,
    #[arg(long, default_value = "127.0.0.1:9100")]
    metrics_addr: String,
    #[arg(long, value_enum, default_value_t = RuntimeMode::Demo)]
    mode: RuntimeMode,
    #[command(flatten)]
    version: VersionArgs,
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
    if args.mode != RuntimeMode::Demo {
        anyhow::bail!(
            "demo binary only supports --mode demo; use server/client for production or benchmark binaries for benchmark mode"
        );
    }
    info!(
        validator_id = VALIDATOR_ID,
        mode = %args.mode,
        "runtime mode selected; demo mode is insecure and may generate ephemeral keys"
    );
    ensure_key_files(&args.key, &args.r#pub)?;
    ensure_storage_writable(&args.store)?;

    // ── Queues (lock-free, bounded) ───────────────────────────────────────────
    let q_raw: TxnQueue = Arc::new(ArrayQueue::new(8_192));
    let q_dedup: TxnQueue = Arc::new(ArrayQueue::new(8_192));
    let q_verified: VerifiedQueue = Arc::new(ArrayQueue::new(8_192));
    let q_packed: VerifiedQueue = Arc::new(ArrayQueue::new(8_192));
    let q_bank: BankOutQueue = Arc::new(ArrayQueue::new(1_024));
    let q_poh: PohOutQueue = Arc::new(ArrayQueue::new(1_024));
    let q_shred: ShredOutQueue = Arc::new(ArrayQueue::new(4_096));
    let q_signed: SignedShredQueue = Arc::new(ArrayQueue::new(4_096));
    let shutdown = Shutdown::new();
    let metrics_shutdown = shutdown.clone();
    let mut supervisor = TileSupervisor::new(shutdown);
    let health = HealthReporter::new(VALIDATOR_ID).with_tiles(supervisor.health());
    health.mark_config_valid();
    health.mark_keys_loaded();
    health.mark_storage_writable();
    let peer_limiter = PeerRateLimiter::new(PeerRateLimits::default());
    let metrics_addr: SocketAddr = args.metrics_addr.parse()?;
    let metrics_handle = metrics::start_metrics_endpoint(
        metrics_addr,
        metrics_shutdown,
        vec![
            QueueDepthGauge::new("raw", {
                let q = q_raw.clone();
                move || q.len()
            }),
            QueueDepthGauge::new("deduped", {
                let q = q_dedup.clone();
                move || q.len()
            }),
            QueueDepthGauge::new("verified", {
                let q = q_verified.clone();
                move || q.len()
            }),
            QueueDepthGauge::new("packed", {
                let q = q_packed.clone();
                move || q.len()
            }),
            QueueDepthGauge::new("bank", {
                let q = q_bank.clone();
                move || q.len()
            }),
            QueueDepthGauge::new("poh", {
                let q = q_poh.clone();
                move || q.len()
            }),
            QueueDepthGauge::new("shred", {
                let q = q_shred.clone();
                move || q.len()
            }),
            QueueDepthGauge::new("signed", {
                let q = q_signed.clone();
                move || q.len()
            }),
        ],
        Some(peer_limiter.clone()),
        Some(health.clone()),
    )?;
    info!(
        validator_id = VALIDATOR_ID,
        metrics_address = %metrics_addr,
        "metrics endpoint listening"
    );

    // ── Tile chain ────────────────────────────────────────────────────────────
    supervisor.spawn_critical(
        "deduper",
        Deduper {
            rx: q_raw.clone(),
            tx: q_dedup.clone(),
            cap: 1 << 17,
            window: 1024,
            cleanup_ms: 500,
            fp_rate: 1e-6,
            peer_limiter: Some(peer_limiter.clone()),
        },
    );

    supervisor.spawn_critical(
        "verifier",
        Verifier::new_with_peer_limiter(
            q_dedup.clone(),
            q_verified.clone(),
            64,
            Some(peer_limiter.clone()),
        ),
    );

    supervisor.spawn_critical(
        "pack",
        Pack {
            rx: q_verified.clone(),
            to_bank: q_packed.clone(),
        },
    );

    supervisor.spawn_critical(
        "bank",
        Bank {
            rx: q_packed.clone(),
            tx: q_bank.clone(),
            batch_size: 256,
            flush_ms: 20,
        },
    );

    supervisor.spawn_critical(
        "poh",
        Poh {
            rx: q_bank.clone(),
            tx: q_poh.clone(),
            tick_ms: 20,
        },
    );

    supervisor.spawn_critical(
        "shredder",
        Shredder {
            rx: q_poh.clone(),
            tx: q_shred.clone(),
            mtu: 1_232,
        },
    );

    supervisor.spawn_critical(
        "signer",
        Signer {
            rx: q_shred.clone(),
            tx: q_signed.clone(),
            #[cfg(feature = "ed25519")]
            key: {
                use ed25519_dalek::SigningKey;
                use rand::rngs::OsRng;
                SigningKey::generate(&mut OsRng)
            },
            batch_size: 64,
        },
    );

    supervisor.spawn_critical(
        "storage",
        Storage {
            rx: q_signed.clone(),
            dir: args.store.clone(),
            recovery_policy: StorageRecoveryPolicy::QuarantineCorrupt,
            enabled: true,
            flush_interval_records: 1,
            flush_interval_ms: 1,
            sync_data: true,
        },
    );

    // ── QUIC server ───────────────────────────────────────────────────────────
    let tls_server = tls::build_server_rpk(&args.key)?;
    let server_cfg = quic_cfg::server_config(tls_server);
    let addr: SocketAddr = args.addr.parse()?;
    let endpoint = Endpoint::server(server_cfg, addr)?;
    health.mark_socket_bound();
    health.set_ready();
    let txns_goal = args.txns;
    info!(
        validator_id = VALIDATOR_ID,
        bind_address = %addr,
        storage_dir = %args.store.display(),
        txns_goal,
        "pipeline server listening"
    );

    // ── Load generator ────────────────────────────────────────────────────────
    let spki = tls::load_spki_from_pem(&args.r#pub)?;
    #[cfg(feature = "ed25519")]
    let tx_signing_key = {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        SigningKey::generate(&mut OsRng)
    };
    #[cfg(feature = "ed25519")]
    let tx_pubkey = tx_signing_key.verifying_key().to_bytes();
    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let tls_client = tls::build_client_rpk_pinned(spki);
        let client_cfg = quic_cfg::client_config(tls_client);
        let mut ep = Endpoint::client("0.0.0.0:0".parse::<SocketAddr>().unwrap()).unwrap();
        ep.set_default_client_config(client_cfg);

        let conn = ep.connect(addr, "localhost").unwrap().await.unwrap();
        info!(
            validator_id = VALIDATOR_ID,
            txns_goal, "load generator connected"
        );

        let body = vec![0xABu8; 256];
        for nonce in 0..txns_goal {
            let mut buf = BytesMut::zeroed(HEADER_LEN + body.len());
            #[cfg(feature = "ed25519")]
            let mut h = Header {
                v: 1,
                msg_type: 1,
                slot: nonce / 256 + 1,
                nonce,
                pubkey: tx_pubkey,
                ..Default::default()
            };
            #[cfg(not(feature = "ed25519"))]
            let h = Header {
                v: 1,
                msg_type: 1,
                slot: nonce / 256 + 1,
                nonce,
                ..Default::default()
            };
            #[cfg(feature = "ed25519")]
            {
                use ed25519_dalek::Signer;
                h.signature = tx_signing_key.sign(&h.signing_preimage(&body)).to_bytes();
            }
            h.encode_into(&mut buf[..HEADER_LEN]).unwrap();
            buf[HEADER_LEN..].copy_from_slice(&body);
            // backpressure: retry if datagram buffer is full
            loop {
                match conn.send_datagram(Bytes::copy_from_slice(&buf)) {
                    Ok(_) => break,
                    Err(_) => tokio::time::sleep(tokio::time::Duration::from_micros(50)).await,
                }
            }
        }
        info!(
            validator_id = VALIDATOR_ID,
            txns_goal, "load generator sent all datagrams"
        );
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        conn.close(0u32.into(), b"done");
    });

    // ── Accept loop: parse header, feed raw queue ─────────────────────────────
    let start = Instant::now();
    if let Some(connecting) = endpoint.accept().await {
        let conn = connecting.await?;
        let _connection = ActiveConnectionGuard::new();
        let connection_id = logging::next_connection_id();
        let peer = conn.remote_address().to_string();
        info!(
            validator_id = VALIDATOR_ID,
            connection_id,
            peer_id = %peer,
            "peer connected"
        );

        while let Ok(data) = conn.read_datagram().await {
            supervisor.poll()?;
            metrics::global().record_packet_received();
            if let PeerLimitDecision::Throttle(reason) =
                peer_limiter.check_packet(&peer, data.len())
            {
                if logging::should_log("demo_rate_limit_drop", std::time::Duration::from_secs(1)) {
                    info!(
                        validator_id = VALIDATOR_ID,
                        connection_id,
                        peer_id = %peer,
                        reason = %reason,
                        "dropping peer datagram due to rate limit"
                    );
                }
                continue;
            }
            if data.len() < HEADER_LEN {
                peer_limiter.record_malformed(&peer);
                metrics::global().record_malformed_packet();
                if logging::should_log("demo_short_packet_drop", std::time::Duration::from_secs(1))
                {
                    tracing::warn!(
                        validator_id = VALIDATOR_ID,
                        connection_id,
                        peer_id = %peer,
                        reason = "packet_too_short",
                        actual_len = data.len(),
                        required_len = HEADER_LEN,
                        "dropping malformed packet"
                    );
                }
                continue;
            }
            let Ok((hdr, _)) = Header::decode_from(&data) else {
                peer_limiter.record_malformed(&peer);
                metrics::global().record_malformed_packet();
                if logging::should_log("demo_decode_packet_drop", std::time::Duration::from_secs(1))
                {
                    tracing::warn!(
                        validator_id = VALIDATOR_ID,
                        connection_id,
                        peer_id = %peer,
                        reason = "header_decode_failed",
                        "dropping malformed packet"
                    );
                }
                continue;
            };

            let now_ns = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            let payload = data.slice(HEADER_LEN..);
            let slot = hdr.slot;
            let packet_type = hdr.msg_type;
            if push_with_policy(
                "quic_ingress_to_dedupe",
                &q_raw,
                Txn {
                    header: hdr,
                    payload,
                    peer: peer.clone(),
                    recv_ts_ns: now_ns,
                    pipeline_seq: 0,
                },
                INGRESS_POLICY,
            ) {
                metrics::global().record_packet_accepted();
            } else if logging::should_log(
                "demo_ingress_queue_drop",
                std::time::Duration::from_secs(1),
            ) {
                tracing::warn!(
                    validator_id = VALIDATOR_ID,
                    connection_id,
                    peer_id = %peer,
                    slot,
                    packet_type,
                    reason = "ingress_queue_full",
                    "dropping packet"
                );
            }
        }
    }
    supervisor.poll()?;
    health.set_shutting_down();
    endpoint.close(0u32.into(), b"demo complete");

    // Give pipeline tiles time to drain
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    supervisor.shutdown_and_join()?;
    let _ = metrics_handle.join();

    let elapsed = start.elapsed();
    info!(
        validator_id = VALIDATOR_ID,
        txns_goal,
        elapsed_ms = elapsed.as_millis(),
        tx_per_second = txns_goal as f64 / elapsed.as_secs_f64(),
        storage_dir = %args.store.display(),
        "demo completed"
    );

    Ok(())
}
