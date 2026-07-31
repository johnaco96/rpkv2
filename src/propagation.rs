use crate::{
    identity::ValidatorId,
    leader_schedule::LeaderSchedule,
    ledger::{LedgerBlock, LedgerHash, LedgerShred, reconstruct_block_from_shreds},
    validator_set::{EpochSlot, ValidatorSet},
    wire::Cursor as WireCursor,
};
use anyhow::{Result, anyhow, bail};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    str::FromStr,
};

const DOMAIN: &[u8] = b"rpkv2.propagation.v1";
const WIRE_MAGIC: &[u8; 4] = b"RPKP";
pub const PROPAGATION_VERSION: u8 = 1;
const KIND_BLOCK: u8 = 1;
const KIND_SHRED: u8 = 2;
const KIND_REPAIR_REQUEST: u8 = 3;
const KIND_REPAIR_RESPONSE: u8 = 4;
const SIGNATURE_LEN: usize = 64;
const HASH_LEN: usize = 32;
const MAX_BLOB_LEN: usize = 16 * 1024 * 1024;
const MAX_REPAIR_INDICES: usize = 4096;
const MAX_REPAIR_SHREDS: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PropagationTransport {
    QuicDatagram,
    UdpPacket,
    Stream,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PropagationTarget {
    pub peer: ValidatorId,
    pub address: SocketAddr,
    pub transport: PropagationTransport,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboundPropagation {
    pub target: PropagationTarget,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PropagationMessage {
    Block(BlockPropagation),
    Shred(ShredPropagation),
    RepairRequest(RepairRequest),
    RepairResponse(RepairResponse),
}

impl PropagationMessage {
    pub fn encode(&self) -> Result<Vec<u8>> {
        match self {
            Self::Block(message) => message.encode(),
            Self::Shred(message) => message.encode(),
            Self::RepairRequest(message) => message.encode(),
            Self::RepairResponse(message) => message.encode(),
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        cursor.expect(WIRE_MAGIC)?;
        let version = cursor.u8()?;
        if version != PROPAGATION_VERSION {
            bail!("unsupported propagation version: {version}");
        }
        let kind = cursor.u8()?;
        let signer = cursor.validator_id()?;
        let message = match kind {
            KIND_BLOCK => {
                let block = LedgerBlock::decode(&cursor.blob()?)?;
                let signature = cursor.signature()?;
                Self::Block(BlockPropagation {
                    signer,
                    block,
                    signature,
                })
            }
            KIND_SHRED => {
                let producer = cursor.validator_id()?;
                let shred = LedgerShred::decode(&cursor.blob()?)?;
                let signature = cursor.signature()?;
                Self::Shred(ShredPropagation {
                    signer,
                    producer,
                    shred,
                    signature,
                })
            }
            KIND_REPAIR_REQUEST => {
                let slot = EpochSlot::new(cursor.u64()?, cursor.u64()?);
                let block_hash = cursor.hash()?;
                let count = cursor.u16()? as usize;
                if count > MAX_REPAIR_INDICES {
                    bail!("repair request has too many indices");
                }
                let mut missing_indices = Vec::with_capacity(count);
                for _ in 0..count {
                    missing_indices.push(cursor.u32()?);
                }
                let signature = cursor.signature()?;
                Self::RepairRequest(RepairRequest {
                    requester: signer,
                    slot,
                    block_hash,
                    missing_indices,
                    signature,
                })
            }
            KIND_REPAIR_RESPONSE => {
                let responder = signer;
                let requester = cursor.validator_id()?;
                let count = cursor.u16()? as usize;
                if count > MAX_REPAIR_SHREDS {
                    bail!("repair response has too many shreds");
                }
                let mut shreds = Vec::with_capacity(count);
                for _ in 0..count {
                    shreds.push(LedgerShred::decode(&cursor.blob()?)?);
                }
                let signature = cursor.signature()?;
                Self::RepairResponse(RepairResponse {
                    responder,
                    requester,
                    shreds,
                    signature,
                })
            }
            _ => bail!("unknown propagation message kind: {kind}"),
        };
        cursor.finish()?;
        Ok(message)
    }

    pub fn signer(&self) -> &ValidatorId {
        match self {
            Self::Block(message) => &message.signer,
            Self::Shred(message) => &message.signer,
            Self::RepairRequest(message) => &message.requester,
            Self::RepairResponse(message) => &message.responder,
        }
    }

    pub fn signature(&self) -> &[u8; SIGNATURE_LEN] {
        match self {
            Self::Block(message) => &message.signature,
            Self::Shred(message) => &message.signature,
            Self::RepairRequest(message) => &message.signature,
            Self::RepairResponse(message) => &message.signature,
        }
    }

    pub fn signing_preimage(&self) -> Result<Vec<u8>> {
        match self {
            Self::Block(message) => message.signing_preimage(),
            Self::Shred(message) => message.signing_preimage(),
            Self::RepairRequest(message) => Ok(message.signing_preimage()),
            Self::RepairResponse(message) => message.signing_preimage(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockPropagation {
    pub signer: ValidatorId,
    pub block: LedgerBlock,
    pub signature: [u8; 64],
}

impl BlockPropagation {
    #[cfg(feature = "ed25519")]
    pub fn sign(block: LedgerBlock, signing_key: &ed25519_dalek::SigningKey) -> Result<Self> {
        use ed25519_dalek::Signer;

        let signer = block.producer.clone();
        let preimage = block_preimage(&signer, &block)?;
        let signature = signing_key.sign(&preimage).to_bytes();
        Ok(Self {
            signer,
            block,
            signature,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = prefix(KIND_BLOCK, &self.signer);
        put_blob(&mut out, &self.block.encode()?)?;
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    pub fn signing_preimage(&self) -> Result<Vec<u8>> {
        block_preimage(&self.signer, &self.block)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShredPropagation {
    pub signer: ValidatorId,
    pub producer: ValidatorId,
    pub shred: LedgerShred,
    pub signature: [u8; 64],
}

impl ShredPropagation {
    #[cfg(feature = "ed25519")]
    pub fn sign(
        producer: ValidatorId,
        shred: LedgerShred,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<Self> {
        use ed25519_dalek::Signer;

        let signer = producer.clone();
        let preimage = shred_preimage(&signer, &producer, &shred)?;
        let signature = signing_key.sign(&preimage).to_bytes();
        Ok(Self {
            signer,
            producer,
            shred,
            signature,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = prefix(KIND_SHRED, &self.signer);
        put_validator_id(&mut out, &self.producer)?;
        put_blob(&mut out, &self.shred.encode()?)?;
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    pub fn signing_preimage(&self) -> Result<Vec<u8>> {
        shred_preimage(&self.signer, &self.producer, &self.shred)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepairRequest {
    pub requester: ValidatorId,
    pub slot: EpochSlot,
    pub block_hash: LedgerHash,
    pub missing_indices: Vec<u32>,
    pub signature: [u8; 64],
}

impl RepairRequest {
    #[cfg(feature = "ed25519")]
    pub fn sign(
        requester: ValidatorId,
        slot: EpochSlot,
        block_hash: LedgerHash,
        missing_indices: Vec<u32>,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<Self> {
        use ed25519_dalek::Signer;

        validate_repair_indices(&missing_indices)?;
        let preimage = repair_request_preimage(&requester, slot, block_hash, &missing_indices);
        let signature = signing_key.sign(&preimage).to_bytes();
        Ok(Self {
            requester,
            slot,
            block_hash,
            missing_indices,
            signature,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        validate_repair_indices(&self.missing_indices)?;
        let mut out = prefix(KIND_REPAIR_REQUEST, &self.requester);
        put_slot(&mut out, self.slot);
        out.extend_from_slice(&self.block_hash);
        put_u16_len(&mut out, self.missing_indices.len(), "repair index count")?;
        for index in &self.missing_indices {
            out.extend_from_slice(&index.to_be_bytes());
        }
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    pub fn signing_preimage(&self) -> Vec<u8> {
        repair_request_preimage(
            &self.requester,
            self.slot,
            self.block_hash,
            &self.missing_indices,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepairResponse {
    pub responder: ValidatorId,
    pub requester: ValidatorId,
    pub shreds: Vec<LedgerShred>,
    pub signature: [u8; 64],
}

impl RepairResponse {
    #[cfg(feature = "ed25519")]
    pub fn sign(
        responder: ValidatorId,
        requester: ValidatorId,
        shreds: Vec<LedgerShred>,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<Self> {
        use ed25519_dalek::Signer;

        validate_repair_shreds(&shreds)?;
        let preimage = repair_response_preimage(&responder, &requester, &shreds)?;
        let signature = signing_key.sign(&preimage).to_bytes();
        Ok(Self {
            responder,
            requester,
            shreds,
            signature,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        validate_repair_shreds(&self.shreds)?;
        let mut out = prefix(KIND_REPAIR_RESPONSE, &self.responder);
        put_validator_id(&mut out, &self.requester)?;
        put_u16_len(&mut out, self.shreds.len(), "repair shred count")?;
        for shred in &self.shreds {
            put_blob(&mut out, &shred.encode()?)?;
        }
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    pub fn signing_preimage(&self) -> Result<Vec<u8>> {
        repair_response_preimage(&self.responder, &self.requester, &self.shreds)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PropagationMetrics {
    pub blocks_received: u64,
    pub shreds_received: u64,
    pub repair_requests_received: u64,
    pub repair_responses_received: u64,
    pub invalid_messages: u64,
    pub invalid_signatures: u64,
    pub invalid_leaders: u64,
    pub corrupt_shreds: u64,
    pub missing_repairs: u64,
}

impl PropagationMetrics {
    pub fn metrics_text(&self) -> String {
        format!(
            concat!(
                "rpkv2_propagation_blocks_received_total {}\n",
                "rpkv2_propagation_shreds_received_total {}\n",
                "rpkv2_propagation_repair_requests_total {}\n",
                "rpkv2_propagation_repair_responses_total {}\n",
                "rpkv2_propagation_invalid_messages_total {}\n",
                "rpkv2_propagation_invalid_signatures_total {}\n",
                "rpkv2_propagation_invalid_leaders_total {}\n",
                "rpkv2_propagation_corrupt_shreds_total {}\n",
                "rpkv2_propagation_missing_repairs_total {}\n",
            ),
            self.blocks_received,
            self.shreds_received,
            self.repair_requests_received,
            self.repair_responses_received,
            self.invalid_messages,
            self.invalid_signatures,
            self.invalid_leaders,
            self.corrupt_shreds,
            self.missing_repairs
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PropagationOutcome {
    BlockAccepted(LedgerHash),
    ShredAccepted {
        block_hash: LedgerHash,
        index: u32,
    },
    RepairRequestAccepted {
        requester: ValidatorId,
        shreds: Vec<LedgerShred>,
    },
    RepairResponseAccepted {
        shreds: usize,
        reconstructed_block: Option<LedgerHash>,
    },
}

#[derive(Clone, Debug, Default)]
pub struct PropagationStore {
    blocks: BTreeMap<LedgerHash, LedgerBlock>,
    shreds: BTreeMap<ShredKey, LedgerShred>,
}

impl PropagationStore {
    pub fn put_block(&mut self, block: LedgerBlock) {
        self.blocks.insert(block.block_hash, block);
    }

    pub fn put_shred(&mut self, shred: LedgerShred) {
        self.shreds.insert(ShredKey::from(&shred), shred);
    }

    pub fn get_block(&self, block_hash: &LedgerHash) -> Option<&LedgerBlock> {
        self.blocks.get(block_hash)
    }

    pub fn get_shred(
        &self,
        slot: EpochSlot,
        block_hash: LedgerHash,
        index: u32,
    ) -> Option<&LedgerShred> {
        self.shreds.get(&ShredKey {
            slot,
            block_hash,
            index,
        })
    }

    pub fn shreds_for_block(&self, slot: EpochSlot, block_hash: LedgerHash) -> Vec<LedgerShred> {
        self.shreds
            .range(
                ShredKey {
                    slot,
                    block_hash,
                    index: 0,
                }..=ShredKey {
                    slot,
                    block_hash,
                    index: u32::MAX,
                },
            )
            .map(|(_, shred)| shred.clone())
            .collect()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ShredKey {
    slot: EpochSlot,
    block_hash: LedgerHash,
    index: u32,
}

impl From<&LedgerShred> for ShredKey {
    fn from(value: &LedgerShred) -> Self {
        Self {
            slot: value.slot,
            block_hash: value.block_hash,
            index: value.index,
        }
    }
}

pub struct PropagationReceiver<'a> {
    validator_set: &'a ValidatorSet,
    schedule: LeaderSchedule<'a>,
    store: PropagationStore,
    metrics: PropagationMetrics,
}

impl<'a> PropagationReceiver<'a> {
    pub fn new(validator_set: &'a ValidatorSet) -> Self {
        Self {
            validator_set,
            schedule: LeaderSchedule::new(validator_set),
            store: PropagationStore::default(),
            metrics: PropagationMetrics::default(),
        }
    }

    pub fn with_store(validator_set: &'a ValidatorSet, store: PropagationStore) -> Self {
        Self {
            validator_set,
            schedule: LeaderSchedule::new(validator_set),
            store,
            metrics: PropagationMetrics::default(),
        }
    }

    pub fn handle_encoded(&mut self, bytes: &[u8]) -> Result<PropagationOutcome> {
        let message = PropagationMessage::decode(bytes).inspect_err(|_e| {
            self.metrics.invalid_messages = self.metrics.invalid_messages.saturating_add(1);
        })?;
        self.handle_message(message)
    }

    pub fn handle_message(&mut self, message: PropagationMessage) -> Result<PropagationOutcome> {
        self.verify_message_signature(&message)?;
        match message {
            PropagationMessage::Block(message) => self.accept_block(message),
            PropagationMessage::Shred(message) => self.accept_shred(message),
            PropagationMessage::RepairRequest(message) => self.accept_repair_request(message),
            PropagationMessage::RepairResponse(message) => self.accept_repair_response(message),
        }
    }

    pub fn store(&self) -> &PropagationStore {
        &self.store
    }

    pub fn metrics(&self) -> &PropagationMetrics {
        &self.metrics
    }

    fn verify_message_signature(&mut self, message: &PropagationMessage) -> Result<()> {
        let validator = self
            .validator_set
            .get(message.signer())
            .ok_or_else(|| anyhow!("unknown propagation signer {}", message.signer()))?;
        verify_signature(
            &validator.consensus_voting_key,
            &message.signing_preimage()?,
            message.signature(),
        )
        .inspect_err(|_e| {
            self.metrics.invalid_signatures = self.metrics.invalid_signatures.saturating_add(1);
        })
    }

    fn accept_block(&mut self, message: BlockPropagation) -> Result<PropagationOutcome> {
        if message.signer != message.block.producer {
            self.metrics.invalid_signatures = self.metrics.invalid_signatures.saturating_add(1);
            bail!("block propagation signer does not match block producer");
        }
        if let Err(e) = self.ensure_leader(&message.block.producer, message.block.slot, "block") {
            self.metrics.invalid_leaders = self.metrics.invalid_leaders.saturating_add(1);
            return Err(e);
        }
        message.block.validate_integrity()?;
        let block_hash = message.block.block_hash;
        self.store.put_block(message.block);
        self.metrics.blocks_received = self.metrics.blocks_received.saturating_add(1);
        Ok(PropagationOutcome::BlockAccepted(block_hash))
    }

    fn accept_shred(&mut self, message: ShredPropagation) -> Result<PropagationOutcome> {
        if message.signer != message.producer {
            self.metrics.invalid_signatures = self.metrics.invalid_signatures.saturating_add(1);
            bail!("shred propagation signer does not match producer");
        }
        if let Err(e) = self.ensure_leader(&message.producer, message.shred.slot, "shred") {
            self.metrics.invalid_leaders = self.metrics.invalid_leaders.saturating_add(1);
            return Err(e);
        }
        message.shred.validate_integrity().inspect_err(|_e| {
            self.metrics.corrupt_shreds = self.metrics.corrupt_shreds.saturating_add(1);
        })?;
        let block_hash = message.shred.block_hash;
        let index = message.shred.index;
        self.store.put_shred(message.shred);
        self.metrics.shreds_received = self.metrics.shreds_received.saturating_add(1);
        Ok(PropagationOutcome::ShredAccepted { block_hash, index })
    }

    fn accept_repair_request(&mut self, message: RepairRequest) -> Result<PropagationOutcome> {
        validate_repair_indices(&message.missing_indices)?;
        let mut shreds = Vec::new();
        for index in &message.missing_indices {
            match self
                .store
                .get_shred(message.slot, message.block_hash, *index)
            {
                Some(shred) => shreds.push(shred.clone()),
                None => {
                    self.metrics.missing_repairs = self.metrics.missing_repairs.saturating_add(1)
                }
            }
        }
        self.metrics.repair_requests_received =
            self.metrics.repair_requests_received.saturating_add(1);
        Ok(PropagationOutcome::RepairRequestAccepted {
            requester: message.requester,
            shreds,
        })
    }

    fn accept_repair_response(&mut self, message: RepairResponse) -> Result<PropagationOutcome> {
        validate_repair_shreds(&message.shreds)?;
        let mut reconstructed_block = None;
        for shred in &message.shreds {
            shred.validate_integrity().inspect_err(|_e| {
                self.metrics.corrupt_shreds = self.metrics.corrupt_shreds.saturating_add(1);
            })?;
            self.store.put_shred(shred.clone());
            let shreds = self.store.shreds_for_block(shred.slot, shred.block_hash);
            if let Ok(block) = reconstruct_block_from_shreds(&shreds) {
                reconstructed_block = Some(block.block_hash);
                self.store.put_block(block);
            }
        }
        self.metrics.repair_responses_received =
            self.metrics.repair_responses_received.saturating_add(1);
        Ok(PropagationOutcome::RepairResponseAccepted {
            shreds: message.shreds.len(),
            reconstructed_block,
        })
    }

    fn ensure_leader(&self, producer: &ValidatorId, slot: EpochSlot, kind: &str) -> Result<()> {
        let leader = self.schedule.leader_id_for_slot(slot)?;
        if leader != producer {
            bail!(
                "rejecting {kind} propagation from non-leader {producer} at epoch {} slot {}; expected leader {leader}",
                slot.epoch,
                slot.slot
            );
        }
        Ok(())
    }
}

pub struct PropagationSender {
    transport: PropagationTransport,
}

impl PropagationSender {
    pub const fn new(transport: PropagationTransport) -> Self {
        Self { transport }
    }

    pub fn enqueue(
        &self,
        peer: ValidatorId,
        address: SocketAddr,
        message: &PropagationMessage,
    ) -> Result<OutboundPropagation> {
        Ok(OutboundPropagation {
            target: PropagationTarget {
                peer,
                address,
                transport: self.transport,
            },
            bytes: message.encode()?,
        })
    }
}

fn block_preimage(signer: &ValidatorId, block: &LedgerBlock) -> Result<Vec<u8>> {
    let mut out = signing_prefix(KIND_BLOCK, signer)?;
    put_blob(&mut out, &block.encode()?)?;
    Ok(out)
}

fn shred_preimage(
    signer: &ValidatorId,
    producer: &ValidatorId,
    shred: &LedgerShred,
) -> Result<Vec<u8>> {
    let mut out = signing_prefix(KIND_SHRED, signer)?;
    put_validator_id(&mut out, producer)?;
    put_blob(&mut out, &shred.encode()?)?;
    Ok(out)
}

fn repair_request_preimage(
    requester: &ValidatorId,
    slot: EpochSlot,
    block_hash: LedgerHash,
    missing_indices: &[u32],
) -> Vec<u8> {
    let mut out = signing_prefix(KIND_REPAIR_REQUEST, requester)
        .expect("validator id length was validated on construction");
    put_slot(&mut out, slot);
    out.extend_from_slice(&block_hash);
    put_u16_len(&mut out, missing_indices.len(), "repair index count")
        .expect("repair index count was validated on construction");
    for index in missing_indices {
        out.extend_from_slice(&index.to_be_bytes());
    }
    out
}

fn repair_response_preimage(
    responder: &ValidatorId,
    requester: &ValidatorId,
    shreds: &[LedgerShred],
) -> Result<Vec<u8>> {
    validate_repair_shreds(shreds)?;
    let mut out = signing_prefix(KIND_REPAIR_RESPONSE, responder)?;
    put_validator_id(&mut out, requester)?;
    put_u16_len(&mut out, shreds.len(), "repair shred count")?;
    for shred in shreds {
        put_blob(&mut out, &shred.encode()?)?;
    }
    Ok(out)
}

fn prefix(kind: u8, signer: &ValidatorId) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(WIRE_MAGIC);
    out.push(PROPAGATION_VERSION);
    out.push(kind);
    put_validator_id(&mut out, signer).expect("validator id length exceeds wire format");
    out
}

fn signing_prefix(kind: u8, signer: &ValidatorId) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(DOMAIN);
    out.push(PROPAGATION_VERSION);
    out.push(kind);
    put_validator_id(&mut out, signer)?;
    Ok(out)
}

fn put_slot(out: &mut Vec<u8>, slot: EpochSlot) {
    out.extend_from_slice(&slot.epoch.to_be_bytes());
    out.extend_from_slice(&slot.slot.to_be_bytes());
}

fn put_validator_id(out: &mut Vec<u8>, validator_id: &ValidatorId) -> Result<()> {
    put_u16_len(out, validator_id.as_str().len(), "validator id length")?;
    out.extend_from_slice(validator_id.as_str().as_bytes());
    Ok(())
}

fn put_u16_len(out: &mut Vec<u8>, len: usize, name: &str) -> Result<()> {
    let len = u16::try_from(len).map_err(|_| anyhow!("{name} exceeds u16 length"))?;
    out.extend_from_slice(&len.to_be_bytes());
    Ok(())
}

fn put_blob(out: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    if value.len() > MAX_BLOB_LEN {
        bail!("propagation blob is too large");
    }
    let len = u32::try_from(value.len()).map_err(|_| anyhow!("blob exceeds u32 length"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn validate_repair_indices(indices: &[u32]) -> Result<()> {
    if indices.is_empty() {
        bail!("repair request must include at least one missing index");
    }
    if indices.len() > MAX_REPAIR_INDICES {
        bail!("repair request has too many indices");
    }
    let mut seen = BTreeSet::new();
    for index in indices {
        if !seen.insert(*index) {
            bail!("repair request contains duplicate index");
        }
    }
    Ok(())
}

fn validate_repair_shreds(shreds: &[LedgerShred]) -> Result<()> {
    if shreds.len() > MAX_REPAIR_SHREDS {
        bail!("repair response has too many shreds");
    }
    for shred in shreds {
        shred.validate_integrity()?;
    }
    Ok(())
}

#[cfg(feature = "ed25519")]
fn verify_signature(pubkey: &[u8; 32], preimage: &[u8], signature: &[u8; 64]) -> Result<()> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let key = VerifyingKey::from_bytes(pubkey)
        .map_err(|e| anyhow!("invalid propagation validator key: {e}"))?;
    let signature = Signature::from_bytes(signature);
    key.verify(preimage, &signature)
        .map_err(|e| anyhow!("invalid propagation signature: {e}"))?;
    Ok(())
}

#[cfg(not(feature = "ed25519"))]
fn verify_signature(_pubkey: &[u8; 32], _preimage: &[u8], _signature: &[u8; 64]) -> Result<()> {
    bail!("propagation verification requires the ed25519 feature")
}

struct Cursor<'a> {
    inner: WireCursor<'a>,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            inner: WireCursor::new(bytes, "propagation message"),
        }
    }

    fn expect(&mut self, expected: &[u8]) -> Result<()> {
        self.inner.expect(expected, "invalid propagation magic")
    }

    fn u8(&mut self) -> Result<u8> {
        self.inner.u8()
    }

    fn u16(&mut self) -> Result<u16> {
        self.inner.u16()
    }

    fn u32(&mut self) -> Result<u32> {
        self.inner.u32()
    }

    fn u64(&mut self) -> Result<u64> {
        self.inner.u64()
    }

    fn hash(&mut self) -> Result<LedgerHash> {
        Ok(self
            .take(HASH_LEN)?
            .try_into()
            .expect("cursor returned exact hash length"))
    }

    fn signature(&mut self) -> Result<[u8; SIGNATURE_LEN]> {
        Ok(self
            .take(SIGNATURE_LEN)?
            .try_into()
            .expect("cursor returned exact signature length"))
    }

    fn validator_id(&mut self) -> Result<ValidatorId> {
        ValidatorId::from_str(&self.string()?)
    }

    fn string(&mut self) -> Result<String> {
        let len = self.u16()? as usize;
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec())
            .map_err(|e| anyhow!("invalid propagation utf8 string: {e}"))
    }

    fn blob(&mut self) -> Result<Vec<u8>> {
        let len = self.u32()? as usize;
        if len > MAX_BLOB_LEN {
            bail!("propagation blob is too large");
        }
        Ok(self.take(len)?.to_vec())
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        self.inner.take(len)
    }

    fn finish(&self) -> Result<()> {
        self.inner.finish()
    }
}

#[cfg(all(test, feature = "ed25519"))]
mod tests;
