use super::*;

fn write_jsonl(path: &Path, line: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{line}")?;
    Ok(())
}

pub(super) fn temp_dir() -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "rpkv2-quic-pipeline-bench-{}-{suffix}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

pub(super) fn write_tls_keypair(dir: &Path, name: &str) -> Result<(PathBuf, Vec<u8>)> {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    let key_path = dir.join(format!("{name}.key"));
    fs::write(&key_path, key_pair.serialize_pem())?;
    Ok((key_path, key_pair.public_key_der().to_vec()))
}

pub(super) fn registry_for(id: &str, spki: &[u8]) -> PeerRegistry {
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

pub(super) fn registry_for_spkis(prefix: &str, spkis: &[Vec<u8>]) -> Result<PeerRegistry> {
    if spkis.is_empty() {
        return Err(anyhow!("at least one peer SPKI is required"));
    }
    let mut registry = PeerRegistry::default();
    for (index, spki) in spkis.iter().enumerate() {
        registry.insert(PeerIdentity {
            validator_id: ValidatorId::from_str(&format!("{prefix}-{index}"))?,
            tls_spki_ders: vec![spki.clone()],
            packet_verify_key: [7u8; 32],
            expected_address: None,
        })?;
    }
    Ok(registry)
}

pub(super) fn server_endpoint(
    event_log: PathBuf,
    key_path: &str,
    registry: PeerRegistry,
    bind: SocketAddr,
) -> Result<Endpoint> {
    server_endpoint_with_tuning(
        event_log,
        key_path,
        registry,
        bind,
        quic_cfg::TransportTuning::default(),
    )
}

pub(super) fn server_endpoint_with_tuning(
    event_log: PathBuf,
    key_path: &str,
    registry: PeerRegistry,
    bind: SocketAddr,
    tuning: quic_cfg::TransportTuning,
) -> Result<Endpoint> {
    write_jsonl(&event_log, "{\"event\":\"server_endpoint_start\"}")?;
    let tls = tls::build_server_rpk_mutual(key_path, registry)?;
    Ok(Endpoint::server(
        quic_cfg::server_config_with_tuning(tls, tuning),
        bind,
    )?)
}

pub(super) fn client_endpoint(
    registry: PeerRegistry,
    peer_id: &str,
    key_path: &str,
) -> Result<Endpoint> {
    client_endpoint_with_tuning(
        registry,
        peer_id,
        key_path,
        quic_cfg::TransportTuning::default(),
    )
}

pub(super) fn client_endpoint_with_tuning(
    registry: PeerRegistry,
    peer_id: &str,
    key_path: &str,
    tuning: quic_cfg::TransportTuning,
) -> Result<Endpoint> {
    let peer_id = ValidatorId::from_str(peer_id)?;
    let tls = tls::build_client_rpk_for_validator_with_identity(&registry, &peer_id, key_path)?;
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse::<SocketAddr>()?)?;
    endpoint.set_default_client_config(quic_cfg::client_config_with_tuning(tls, tuning));
    Ok(endpoint)
}

pub(super) fn benchmark_transport_tuning(
    buffer_bytes: usize,
    window_bytes: u64,
) -> quic_cfg::TransportTuning {
    quic_cfg::TransportTuning {
        receive_window_bytes: window_bytes.min(u64::from(u32::MAX)) as u32,
        stream_receive_window_bytes: 256 * 1024,
        send_window_bytes: window_bytes,
        datagram_receive_buffer_bytes: buffer_bytes,
        datagram_send_buffer_bytes: buffer_bytes,
    }
}

pub(super) fn pipeline_config(
    storage_dir: PathBuf,
    packets: u64,
    queue_capacity: usize,
) -> ServerPipelineConfig {
    let queue = queue_capacity.max(1);
    ServerPipelineConfig {
        raw_queue: queue,
        deduped_queue: queue,
        verified_queue: queue,
        packed_queue: queue,
        bank_queue: queue,
        poh_queue: queue,
        shred_queue: queue,
        signed_queue: queue,
        replay_capacity: packets.max(1).try_into().unwrap_or(usize::MAX),
        replay_window: packets.max(8),
        packets_per_second: packets.max(1_000_000),
        bytes_per_second: 1024 * 1024 * 1024,
        storage_dir,
        storage_recovery_policy: StorageRecoveryPolicy::FailStartup,
        storage_enabled: true,
        storage_flush_interval_records: 256,
        storage_flush_interval_ms: 10,
        storage_sync_data: false,
        verifier_batch: 64,
        verifier_workers: 1,
        verifier_affinity_base: None,
        bank_batch_size: 64,
        bank_flush_ms: 5,
        poh_tick_ms: 5,
        shred_mtu: 1232,
        signer_batch_size: 256,
        signer_workers: 1,
    }
}

pub(super) fn signed_datagram(
    packet_key: &ed25519_dalek::SigningKey,
    slot: u64,
    nonce: u64,
    payload_bytes: usize,
) -> Vec<u8> {
    signed_datagram_at(packet_key, slot, nonce, payload_bytes, now_unix_ns())
}

pub(super) fn signed_datagram_at(
    packet_key: &ed25519_dalek::SigningKey,
    slot: u64,
    nonce: u64,
    payload_bytes: usize,
    sent_ns: u64,
) -> Vec<u8> {
    let mut payload = vec![0u8; payload_bytes.max(16)];
    payload[0..8].copy_from_slice(&nonce.to_be_bytes());
    payload[8..16].copy_from_slice(&sent_ns.to_be_bytes());
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
    let signature = packet_key.sign(&header.signing_preimage(&payload));
    header.signature.copy_from_slice(&signature.to_bytes());
    let mut datagram = vec![0u8; HEADER_LEN];
    header.encode_into(&mut datagram).unwrap();
    datagram.extend_from_slice(&payload);
    datagram
}

pub(super) fn process_stats() -> (f64, u64) {
    if cfg!(target_os = "linux") {
        let pid = std::process::id().to_string();
        if let Ok(output) = Command::new("ps")
            .args(["-o", "%cpu=,rss=", "-p", &pid])
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            let mut fields = text.split_whitespace();
            let cpu = fields.next().and_then(|v| v.parse().ok()).unwrap_or(0.0);
            let rss_kib: u64 = fields.next().and_then(|v| v.parse().ok()).unwrap_or(0);
            return (cpu, rss_kib.saturating_mul(1024));
        }
    }
    (0.0, 0)
}

pub(super) fn process_cpu_ticks() -> Option<u64> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let Ok(stat) = fs::read_to_string("/proc/self/stat") else {
        return None;
    };
    parse_process_cpu_ticks(&stat)
}

pub(super) fn parse_process_cpu_ticks(stat: &str) -> Option<u64> {
    let command_end = stat.rfind(')')?;
    let fields: Vec<_> = stat[command_end + 1..].split_whitespace().collect();
    let user_ticks = fields.get(11).and_then(|value| value.parse::<u64>().ok())?;
    let system_ticks = fields.get(12).and_then(|value| value.parse::<u64>().ok())?;
    Some(user_ticks.saturating_add(system_ticks))
}

pub(super) fn interval_cpu_percent(
    start_ticks: Option<u64>,
    end_ticks: Option<u64>,
    duration: Duration,
) -> f64 {
    if !cfg!(target_os = "linux") || duration.is_zero() {
        return 0.0;
    }
    let (Some(start_ticks), Some(end_ticks)) = (start_ticks, end_ticks) else {
        return 0.0;
    };
    let ticks_per_second = Command::new("getconf")
        .arg("CLK_TCK")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|value| value.trim().parse::<f64>().ok())
        .unwrap_or(100.0);
    let cpu_seconds = end_ticks.saturating_sub(start_ticks) as f64 / ticks_per_second;
    cpu_seconds / duration.as_secs_f64() * 100.0
}

pub(super) fn now_unix_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .min(u128::from(u64::MAX)) as u64
}
