#![cfg(feature = "ed25519")]

use bytes::Bytes;
use ed25519_dalek::Signer;
use quinn::Endpoint;
use rcgen::KeyPair;
use rpkv2::{
    fastpath::packet::{HEADER_LEN, Header, MSG_TYPE_TRANSACTION_BATCH, PACKET_VERSION},
    identity::{PeerIdentity, PeerRegistry, ValidatorId},
    quic_cfg,
    server_pipeline::{ServerPipeline, ServerPipelineConfig},
    shutdown::Shutdown,
    tiles::storage::{StorageRecoveryPolicy, scan_storage_dir},
    tls,
};
use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Once,
    time::Duration,
};
use tokio::time::{sleep, timeout};

#[path = "common/temp_dir.rs"]
mod test_temp;
use test_temp::temp_dir;

static INSTALL_PROVIDER: Once = Once::new();

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configured_mutual_rpk_quic_packet_reaches_tile_pipeline() {
    install_provider_once();
    let dir = temp_dir("quic-runtime-proof");
    let (server_key_path, server_spki) = write_tls_keypair(&dir, "server");
    let (client_key_path, client_spki) = write_tls_keypair(&dir, "client");
    let packet_key = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    let shred_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let storage_dir = dir.join("storage");
    let shutdown = Shutdown::new();
    let pipeline = ServerPipeline::start(
        pipeline_config(storage_dir.clone()),
        shred_key,
        shutdown.clone(),
    );

    let server_endpoint = server_endpoint(&server_key_path, registry_for("client", &client_spki));
    let server_addr = server_endpoint.local_addr().unwrap();
    let ingress = pipeline.ingress();
    let server_task = tokio::spawn(async move {
        let connecting = server_endpoint.accept().await.expect("server accept");
        let conn = connecting.await.expect("configured peer must connect");
        let datagram = conn.read_datagram().await.expect("validator datagram");
        let accepted = ingress
            .ingest_datagram("client", &datagram)
            .expect("packet enters configured pipeline");
        assert!(accepted);
        conn.send_datagram(Bytes::from_static(b"ack")).expect("ack");
        sleep(Duration::from_millis(100)).await;
        conn.close(0u32.into(), b"done");
    });

    let client_endpoint = client_endpoint(
        registry_for("server", &server_spki),
        "server",
        &client_key_path,
    );
    let conn = client_endpoint
        .connect(server_addr, "localhost")
        .expect("connect builder")
        .await
        .expect("valid configured peer connects");
    conn.send_datagram(Bytes::from(signed_datagram(&packet_key, 1, 42)))
        .expect("send signed datagram");
    let ack = conn.read_datagram().await.expect("ingress ack");
    assert_eq!(&ack[..], b"ack");
    conn.close(0u32.into(), b"done");
    server_task.await.expect("server task");

    wait_for_storage_records(&storage_dir, 1).await;
    shutdown.request();
    tokio::task::spawn_blocking(move || pipeline.join())
        .await
        .expect("pipeline join");

    let report = scan_storage_dir(&storage_dir).expect("storage scan");
    assert!(report.is_clean());
    assert_eq!(report.records_scanned, 1);
    assert_eq!(report.latest_slot, Some(1));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configured_mutual_rpk_quic_rejects_unknown_client_spki() {
    install_provider_once();
    let dir = temp_dir("quic-runtime-proof");
    let (server_key_path, server_spki) = write_tls_keypair(&dir, "server");
    let (client_key_path, _client_spki) = write_tls_keypair(&dir, "client");

    let server_endpoint = server_endpoint(&server_key_path, registry_for("client", b"wrong-spki"));
    let server_addr = server_endpoint.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        if let Some(connecting) = server_endpoint.accept().await {
            assert!(connecting.await.is_err());
        }
    });

    let client_endpoint = client_endpoint(
        registry_for("server", &server_spki),
        "server",
        &client_key_path,
    );
    let connected = client_endpoint
        .connect(server_addr, "localhost")
        .expect("connect builder")
        .await;
    if let Ok(conn) = connected {
        let _ = conn.send_datagram(Bytes::from_static(b"should-fail"));
        let read = timeout(Duration::from_secs(2), conn.read_datagram()).await;
        assert!(read.is_err() || matches!(read, Ok(Err(_))));
    }
    server_task.await.expect("server task");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configured_mutual_rpk_quic_rejects_wrong_server_spki() {
    install_provider_once();
    let dir = temp_dir("quic-runtime-proof");
    let (server_key_path, _server_spki) = write_tls_keypair(&dir, "server");
    let (client_key_path, client_spki) = write_tls_keypair(&dir, "client");
    let (_, wrong_server_spki) = write_tls_keypair(&dir, "wrong-server");

    let server_endpoint = server_endpoint(&server_key_path, registry_for("client", &client_spki));
    let server_addr = server_endpoint.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        if let Some(connecting) = server_endpoint.accept().await {
            assert!(connecting.await.is_err());
        }
    });

    let client_endpoint = client_endpoint(
        registry_for("server", &wrong_server_spki),
        "server",
        &client_key_path,
    );
    let connected = client_endpoint
        .connect(server_addr, "localhost")
        .expect("connect builder")
        .await;
    if let Ok(conn) = connected {
        let _ = conn.send_datagram(Bytes::from_static(b"should-fail"));
        let read = timeout(Duration::from_secs(2), conn.read_datagram()).await;
        assert!(read.is_err() || matches!(read, Ok(Err(_))));
    }
    server_task.await.expect("server task");
}

fn install_provider_once() {
    INSTALL_PROVIDER.call_once(tls::install_provider);
}

fn write_tls_keypair(dir: &Path, name: &str) -> (PathBuf, Vec<u8>) {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let key_path = dir.join(format!("{name}.key"));
    fs::write(&key_path, key_pair.serialize_pem()).unwrap();
    (key_path, key_pair.public_key_der().to_vec())
}

fn registry_for(id: &str, spki: &[u8]) -> PeerRegistry {
    let mut registry = PeerRegistry::default();
    registry
        .insert(PeerIdentity {
            validator_id: ValidatorId::from_str(id).unwrap(),
            tls_spki_ders: vec![spki.to_vec()],
            packet_verify_key: [7u8; 32],
            expected_address: None,
        })
        .unwrap();
    registry
}

fn server_endpoint(key_path: &Path, registry: PeerRegistry) -> Endpoint {
    let tls = tls::build_server_rpk_mutual(key_path.to_str().unwrap(), registry).unwrap();
    Endpoint::server(
        quic_cfg::server_config(tls),
        "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
    )
    .unwrap()
}

fn client_endpoint(registry: PeerRegistry, peer_id: &str, key_path: &Path) -> Endpoint {
    let peer_id = ValidatorId::from_str(peer_id).unwrap();
    let tls = tls::build_client_rpk_for_validator_with_identity(
        &registry,
        &peer_id,
        key_path.to_str().unwrap(),
    )
    .unwrap();
    let mut endpoint = Endpoint::client("127.0.0.1:0".parse::<SocketAddr>().unwrap()).unwrap();
    endpoint.set_default_client_config(quic_cfg::client_config(tls));
    endpoint
}

fn pipeline_config(storage_dir: PathBuf) -> ServerPipelineConfig {
    ServerPipelineConfig {
        raw_queue: 32,
        deduped_queue: 32,
        verified_queue: 32,
        packed_queue: 32,
        bank_queue: 32,
        poh_queue: 32,
        shred_queue: 32,
        signed_queue: 32,
        replay_capacity: 128,
        replay_window: 8,
        packets_per_second: 100,
        bytes_per_second: 1_000_000,
        storage_dir,
        storage_recovery_policy: StorageRecoveryPolicy::FailStartup,
        storage_enabled: true,
        storage_flush_interval_records: 1,
        storage_flush_interval_ms: 1,
        storage_sync_data: false,
        verifier_batch: 4,
        verifier_workers: 1,
        verifier_affinity_base: None,
        bank_batch_size: 1,
        bank_flush_ms: 1,
        poh_tick_ms: 1,
        shred_mtu: 512,
        signer_batch_size: 4,
        signer_workers: 1,
    }
}

fn signed_datagram(packet_key: &ed25519_dalek::SigningKey, slot: u64, nonce: u64) -> Vec<u8> {
    let payload = b"hello-configured-quic-runtime";
    let mut header = Header {
        v: PACKET_VERSION,
        msg_type: MSG_TYPE_TRANSACTION_BATCH,
        flags: 0,
        slot,
        nonce,
        key_id: 0,
        pubkey: packet_key.verifying_key().to_bytes(),
        signature: [0u8; 64],
    };
    let signature = packet_key.sign(&header.signing_preimage(payload));
    header.signature.copy_from_slice(&signature.to_bytes());
    let mut datagram = vec![0u8; HEADER_LEN];
    header.encode_into(&mut datagram).unwrap();
    datagram.extend_from_slice(payload);
    datagram
}

async fn wait_for_storage_records(dir: &Path, expected: usize) {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        if scan_storage_dir(dir)
            .map(|report| report.records_scanned >= expected)
            .unwrap_or(false)
        {
            return;
        }
        sleep(Duration::from_millis(10)).await;
    }
}
