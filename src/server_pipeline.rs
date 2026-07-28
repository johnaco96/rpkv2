use crate::{
    backpressure::{INGRESS_POLICY, push_with_policy},
    config::ProductionConfig,
    fastpath::packet::Header,
    metrics::{QueueDepthGauge, global},
    peer_rate_limit::{PeerLimitDecision, PeerRateLimiter},
    tiles::{Txn, TxnQueue},
};
#[cfg(feature = "ed25519")]
use crate::{
    peer_rate_limit::PeerRateLimits,
    shutdown::Shutdown,
    tiles::{
        Tile,
        bank::Bank,
        dedupe::Deduper,
        pack::Pack,
        poh::Poh,
        shred::Shredder,
        signing::{Signer, SigningOrder},
        storage::Storage,
        verify::{Verifier, VerifyRouter},
    },
};
use anyhow::{Result, anyhow, bail};
use bytes::Bytes;
#[cfg(feature = "ed25519")]
use crossbeam_queue::ArrayQueue;
#[cfg(feature = "ed25519")]
use std::sync::Arc;
use std::{
    path::PathBuf,
    thread::JoinHandle,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone)]
pub struct ServerPipelineIngress {
    raw: TxnQueue,
    peer_limiter: PeerRateLimiter,
}

pub struct ServerPipeline {
    ingress: ServerPipelineIngress,
    queue_depths: Vec<QueueDepthGauge>,
    handles: Vec<JoinHandle<()>>,
}

#[derive(Clone, Debug)]
pub struct ServerPipelineConfig {
    pub raw_queue: usize,
    pub deduped_queue: usize,
    pub verified_queue: usize,
    pub packed_queue: usize,
    pub bank_queue: usize,
    pub poh_queue: usize,
    pub shred_queue: usize,
    pub signed_queue: usize,
    pub replay_capacity: usize,
    pub replay_window: u64,
    pub packets_per_second: u64,
    pub bytes_per_second: u64,
    pub storage_dir: PathBuf,
    pub storage_recovery_policy: crate::tiles::storage::StorageRecoveryPolicy,
    pub storage_enabled: bool,
    pub storage_flush_interval_records: usize,
    pub storage_flush_interval_ms: u64,
    pub storage_sync_data: bool,
    pub verifier_batch: usize,
    pub verifier_workers: usize,
    pub verifier_affinity_base: Option<usize>,
    pub bank_batch_size: usize,
    pub bank_flush_ms: u64,
    pub poh_tick_ms: u64,
    pub shred_mtu: usize,
    pub signer_batch_size: usize,
    pub signer_workers: usize,
}

impl ServerPipelineConfig {
    pub fn from_production_config(config: &ProductionConfig) -> Self {
        Self {
            raw_queue: config.queues.raw,
            deduped_queue: config.queues.deduped,
            verified_queue: config.queues.verified,
            packed_queue: config.queues.packed,
            bank_queue: config.queues.bank,
            poh_queue: config.queues.poh,
            shred_queue: config.queues.shred,
            signed_queue: config.queues.signed,
            replay_capacity: config.replay.capacity_per_slot,
            replay_window: config.replay.slot_window,
            packets_per_second: config.rate_limits.packets_per_second,
            bytes_per_second: config.rate_limits.bytes_per_second,
            storage_dir: config.storage.directory.clone(),
            storage_recovery_policy: config.storage.recovery_policy,
            storage_enabled: true,
            storage_flush_interval_records: config.storage.flush_interval_records,
            storage_flush_interval_ms: config.storage.flush_interval_ms,
            storage_sync_data: config.storage.sync_data,
            verifier_batch: config.processing.verifier_batch,
            verifier_workers: config.processing.verifier_workers,
            verifier_affinity_base: config.processing.verifier_affinity_base,
            bank_batch_size: 512,
            bank_flush_ms: 10,
            poh_tick_ms: 10,
            shred_mtu: 1232,
            signer_batch_size: config.processing.signer_batch,
            signer_workers: config.processing.signer_workers,
        }
    }
}

impl ServerPipeline {
    #[cfg(feature = "ed25519")]
    pub fn start(
        config: ServerPipelineConfig,
        signing_key: ed25519_dalek::SigningKey,
        shutdown: Shutdown,
    ) -> Self {
        let raw = queue(config.raw_queue);
        let deduped = queue(config.deduped_queue);
        let verified = queue(config.verified_queue);
        let packed = queue(config.packed_queue);
        let bank_out = queue(config.bank_queue);
        let poh_out = queue(config.poh_queue);
        let shred_out = queue(config.shred_queue);
        let signed_unordered = queue(config.signed_queue);
        let signed_out = queue(config.signed_queue);
        let verifier_shards: Vec<TxnQueue> = (0..config.verifier_workers.max(1))
            .map(|_| queue(config.deduped_queue))
            .collect();

        let peer_limiter = PeerRateLimiter::new(PeerRateLimits {
            max_packets_per_window: config.packets_per_second,
            max_bytes_per_window: config.bytes_per_second,
            ..PeerRateLimits::default()
        });

        let mut handles = vec![
            Deduper {
                rx: raw.clone(),
                tx: deduped.clone(),
                cap: config.replay_capacity.max(1),
                window: config.replay_window,
                cleanup_ms: 100,
                fp_rate: 1e-6,
                peer_limiter: Some(peer_limiter.clone()),
            }
            .start_with_shutdown(shutdown.clone()),
        ];
        handles.push(
            VerifyRouter {
                rx: deduped.clone(),
                shards: verifier_shards.clone(),
            }
            .start_with_shutdown(shutdown.clone()),
        );
        for (worker, shard) in verifier_shards.iter().enumerate() {
            handles.push(
                Verifier::new_with_peer_limiter(
                    shard.clone(),
                    verified.clone(),
                    config.verifier_batch.max(1),
                    Some(peer_limiter.clone()),
                )
                .with_core_id(config.verifier_affinity_base.map(|base| base + worker))
                .start_with_shutdown(shutdown.clone()),
            );
        }
        handles.extend([
            Pack {
                rx: verified.clone(),
                to_bank: packed.clone(),
            }
            .start_with_shutdown(shutdown.clone()),
            Bank {
                rx: packed.clone(),
                tx: bank_out.clone(),
                batch_size: config.bank_batch_size.max(1),
                flush_ms: config.bank_flush_ms.max(1),
            }
            .start_with_shutdown(shutdown.clone()),
            Poh {
                rx: bank_out.clone(),
                tx: poh_out.clone(),
                tick_ms: config.poh_tick_ms.max(1),
            }
            .start_with_shutdown(shutdown.clone()),
            Shredder {
                rx: poh_out.clone(),
                tx: shred_out.clone(),
                mtu: config.shred_mtu.max(256),
            }
            .start_with_shutdown(shutdown.clone()),
        ]);
        for _ in 0..config.signer_workers.max(1) {
            handles.push(
                Signer {
                    rx: shred_out.clone(),
                    tx: signed_unordered.clone(),
                    key: signing_key.clone(),
                    batch_size: config.signer_batch_size.max(1),
                }
                .start_with_shutdown(shutdown.clone()),
            );
        }
        handles.push(
            SigningOrder {
                rx: signed_unordered.clone(),
                tx: signed_out.clone(),
            }
            .start_with_shutdown(shutdown.clone()),
        );
        handles.push(
            Storage {
                rx: signed_out.clone(),
                dir: config.storage_dir,
                recovery_policy: config.storage_recovery_policy,
                enabled: config.storage_enabled,
                flush_interval_records: config.storage_flush_interval_records.max(1),
                flush_interval_ms: config.storage_flush_interval_ms.max(1),
                sync_data: config.storage_sync_data,
            }
            .start_with_shutdown(shutdown),
        );

        let shard_depths = verifier_shards.clone();
        let shard_capacity = config.deduped_queue.saturating_mul(verifier_shards.len());
        let queue_depths = vec![
            gauge("raw", &raw),
            gauge("deduped", &deduped),
            QueueDepthGauge::new_with_capacity("verify_shards", shard_capacity, move || {
                shard_depths.iter().map(|queue| queue.len()).sum()
            }),
            gauge("verified", &verified),
            gauge("packed", &packed),
            gauge("bank", &bank_out),
            gauge("poh", &poh_out),
            gauge("shred", &shred_out),
            gauge("signed_unordered", &signed_unordered),
            gauge("signed", &signed_out),
        ];

        Self {
            ingress: ServerPipelineIngress { raw, peer_limiter },
            queue_depths,
            handles,
        }
    }

    pub fn ingress(&self) -> ServerPipelineIngress {
        self.ingress.clone()
    }

    pub fn queue_depths(&self) -> Vec<QueueDepthGauge> {
        self.queue_depths.clone()
    }

    pub fn peer_limiter(&self) -> PeerRateLimiter {
        self.ingress.peer_limiter.clone()
    }

    pub fn join(self) {
        for handle in self.handles {
            let _ = handle.join();
        }
    }
}

impl ServerPipelineIngress {
    pub fn ingest_datagram(&self, peer: &str, datagram: &[u8]) -> Result<bool> {
        self.ingest_datagram_bytes(peer, Bytes::copy_from_slice(datagram))
    }

    pub fn ingest_datagram_bytes(&self, peer: &str, datagram: Bytes) -> Result<bool> {
        match self.peer_limiter.check_packet(peer, datagram.len()) {
            PeerLimitDecision::Allow => {}
            PeerLimitDecision::Throttle(reason) => {
                tracing::warn!(
                    peer_id = peer,
                    reason = %reason,
                    "dropping throttled peer packet before pipeline ingress"
                );
                return Ok(false);
            }
        }

        let (header, used) = match Header::decode_from(&datagram) {
            Ok(decoded) => decoded,
            Err(e) => {
                global().record_malformed_packet();
                let _ = self.peer_limiter.record_malformed(peer);
                tracing::warn!(
                    peer_id = peer,
                    reason = %e,
                    "dropping malformed validator packet"
                );
                return Err(e);
            }
        };
        let payload = datagram
            .get(used..)
            .ok_or_else(|| anyhow!("packet payload offset out of range"))?;
        let txn = Txn {
            header,
            payload: datagram.slice(used..used + payload.len()),
            peer: peer.to_string(),
            recv_ts_ns: now_ns(),
            pipeline_seq: 0,
        };
        if push_with_policy("quic_ingress_to_dedupe", &self.raw, txn, INGRESS_POLICY) {
            global().record_packet_received();
            global().record_packet_accepted();
            Ok(true)
        } else {
            bail!("ingress queue is full")
        }
    }
}

#[cfg(feature = "ed25519")]
fn queue<T>(capacity: usize) -> Arc<ArrayQueue<T>> {
    Arc::new(ArrayQueue::new(capacity.max(1)))
}

#[cfg(feature = "ed25519")]
fn gauge<T: Send + Sync + 'static>(
    tile: &'static str,
    queue: &Arc<ArrayQueue<T>>,
) -> QueueDepthGauge {
    let queue = queue.clone();
    QueueDepthGauge::new_with_capacity(tile, queue.capacity(), move || queue.len())
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .min(u128::from(u64::MAX)) as u64
}

#[cfg(all(test, feature = "ed25519"))]
mod tests {
    use super::*;
    use crate::{
        fastpath::packet::{HEADER_LEN, MSG_TYPE_TRANSACTION_BATCH, PACKET_VERSION},
        tiles::storage::StorageRecoveryPolicy,
    };
    use ed25519_dalek::Signer;
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
        time::{Duration, SystemTime},
    };

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir() -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "rpkv2-server-pipeline-test-{}-{suffix}-{counter}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn malformed_datagram_is_rejected_before_ingress() {
        let raw = queue(1);
        let limiter = PeerRateLimiter::new(PeerRateLimits::default());
        let ingress = ServerPipelineIngress {
            raw: raw.clone(),
            peer_limiter: limiter,
        };

        assert!(ingress.ingest_datagram("peer-a", b"short").is_err());
        assert!(raw.is_empty());
    }

    #[test]
    fn signed_datagram_flows_to_storage() {
        let dir = temp_dir();
        let shutdown = Shutdown::new();
        let packet_key = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
        let shred_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let pipeline = ServerPipeline::start(
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
                storage_dir: dir.clone(),
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
            },
            shred_key,
            shutdown.clone(),
        );

        let payload = b"hello-validator-pipeline";
        let mut header = Header {
            v: PACKET_VERSION,
            msg_type: MSG_TYPE_TRANSACTION_BATCH,
            flags: 0,
            slot: 1,
            nonce: 42,
            key_id: 0,
            pubkey: packet_key.verifying_key().to_bytes(),
            signature: [0u8; 64],
        };
        let signature = packet_key.sign(&header.signing_preimage(payload));
        header.signature.copy_from_slice(&signature.to_bytes());
        let mut datagram = vec![0u8; HEADER_LEN];
        header.encode_into(&mut datagram).unwrap();
        datagram.extend_from_slice(payload);

        assert!(
            pipeline
                .ingress()
                .ingest_datagram("validator-a", &datagram)
                .unwrap()
        );

        let slot_file = dir.join("slot-000000000001.shred");
        for _ in 0..100 {
            if slot_file.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        shutdown.request();
        pipeline.join();

        assert!(slot_file.exists());
        let report = crate::tiles::storage::scan_storage_dir(&dir).unwrap();
        assert!(report.is_clean());
        assert_eq!(report.records_scanned, 1);
    }
}
