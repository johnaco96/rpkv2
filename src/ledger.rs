use crate::{identity::ValidatorId, validator_set::EpochSlot, wire::Cursor as WireCursor};
use anyhow::{Result, anyhow, bail};
use std::str::FromStr;

pub const LEDGER_VERSION: u8 = 1;
const BLOCK_MAGIC: &[u8; 4] = b"RPLB";
const ENTRY_MAGIC: &[u8; 4] = b"RPLE";
const BATCH_MAGIC: &[u8; 4] = b"RPLT";
const SHRED_MAGIC: &[u8; 4] = b"RPLS";
const HASH_LEN: usize = 32;
const SIGNATURE_LEN: usize = 64;
const MAX_ITEMS: usize = u16::MAX as usize;
const MAX_BLOB_LEN: usize = 16 * 1024 * 1024;

pub type LedgerHash = [u8; HASH_LEN];
pub type LedgerSignature = [u8; SIGNATURE_LEN];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionBatch {
    pub index: u32,
    pub transactions: Vec<Vec<u8>>,
    pub batch_hash: LedgerHash,
}

impl TransactionBatch {
    pub fn new(index: u32, transactions: Vec<Vec<u8>>) -> Result<Self> {
        if transactions.len() > MAX_ITEMS {
            bail!("transaction batch has too many transactions");
        }
        for transaction in &transactions {
            ensure_blob_len("transaction", transaction.len())?;
        }
        let batch_hash = hash_with_domain(
            b"rpkv2.ledger.batch.v1",
            &encode_batch_unsigned(index, &transactions)?,
        );
        Ok(Self {
            index,
            transactions,
            batch_hash,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = encode_batch_unsigned(self.index, &self.transactions)?;
        out.extend_from_slice(&self.batch_hash);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        cursor.magic(BATCH_MAGIC)?;
        cursor.version()?;
        let index = cursor.u32()?;
        let transaction_count = cursor.u16()? as usize;
        let mut transactions = Vec::with_capacity(transaction_count);
        for _ in 0..transaction_count {
            transactions.push(cursor.blob()?);
        }
        let batch_hash = cursor.hash()?;
        cursor.finish()?;

        let expected = hash_with_domain(
            b"rpkv2.ledger.batch.v1",
            &encode_batch_unsigned(index, &transactions)?,
        );
        if batch_hash != expected {
            bail!("transaction batch hash mismatch");
        }
        Ok(Self {
            index,
            transactions,
            batch_hash,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerEntry {
    pub index: u32,
    pub previous_hash: LedgerHash,
    pub batches: Vec<TransactionBatch>,
    pub entry_hash: LedgerHash,
}

impl LedgerEntry {
    pub fn new(
        index: u32,
        previous_hash: LedgerHash,
        batches: Vec<TransactionBatch>,
    ) -> Result<Self> {
        if batches.is_empty() {
            bail!("ledger entry must contain at least one transaction batch");
        }
        if batches.len() > MAX_ITEMS {
            bail!("ledger entry has too many transaction batches");
        }
        ensure_sequential_indices("transaction batch", batches.iter().map(|batch| batch.index))?;
        let entry_hash = hash_with_domain(
            b"rpkv2.ledger.entry.v1",
            &encode_entry_unsigned(index, previous_hash, &batches)?,
        );
        Ok(Self {
            index,
            previous_hash,
            batches,
            entry_hash,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = encode_entry_unsigned(self.index, self.previous_hash, &self.batches)?;
        out.extend_from_slice(&self.entry_hash);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        cursor.magic(ENTRY_MAGIC)?;
        cursor.version()?;
        let index = cursor.u32()?;
        let previous_hash = cursor.hash()?;
        let batch_count = cursor.u16()? as usize;
        let mut batches = Vec::with_capacity(batch_count);
        for _ in 0..batch_count {
            batches.push(TransactionBatch::decode(&cursor.blob()?)?);
        }
        let entry_hash = cursor.hash()?;
        cursor.finish()?;

        let entry = Self {
            index,
            previous_hash,
            batches,
            entry_hash,
        };
        entry.validate_integrity()?;
        Ok(entry)
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.batches.is_empty() {
            bail!("ledger entry must contain at least one transaction batch");
        }
        ensure_sequential_indices(
            "transaction batch",
            self.batches.iter().map(|batch| batch.index),
        )?;
        let expected = hash_with_domain(
            b"rpkv2.ledger.entry.v1",
            &encode_entry_unsigned(self.index, self.previous_hash, &self.batches)?,
        );
        if self.entry_hash != expected {
            bail!("ledger entry hash mismatch");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerBlock {
    pub slot: EpochSlot,
    pub parent_hash: LedgerHash,
    pub producer: ValidatorId,
    pub entries: Vec<LedgerEntry>,
    pub block_hash: LedgerHash,
    pub signature: LedgerSignature,
}

impl LedgerBlock {
    pub fn new(
        slot: EpochSlot,
        parent_hash: LedgerHash,
        producer: ValidatorId,
        entries: Vec<LedgerEntry>,
        signature: LedgerSignature,
    ) -> Result<Self> {
        if entries.is_empty() {
            bail!("ledger block must contain at least one entry");
        }
        if entries.len() > MAX_ITEMS {
            bail!("ledger block has too many entries");
        }
        validate_entry_chain(parent_hash, &entries)?;
        let block_hash = hash_with_domain(
            b"rpkv2.ledger.block.v1",
            &encode_block_unsigned(slot, parent_hash, &producer, &entries)?,
        );
        Ok(Self {
            slot,
            parent_hash,
            producer,
            entries,
            block_hash,
            signature,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out =
            encode_block_unsigned(self.slot, self.parent_hash, &self.producer, &self.entries)?;
        out.extend_from_slice(&self.block_hash);
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        cursor.magic(BLOCK_MAGIC)?;
        cursor.version()?;
        let slot = EpochSlot {
            epoch: cursor.u64()?,
            slot: cursor.u64()?,
        };
        let parent_hash = cursor.hash()?;
        let producer = ValidatorId::from_str(&cursor.string()?)?;
        let entry_count = cursor.u16()? as usize;
        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            entries.push(LedgerEntry::decode(&cursor.blob()?)?);
        }
        let block_hash = cursor.hash()?;
        let signature = cursor.signature()?;
        cursor.finish()?;

        let block = Self {
            slot,
            parent_hash,
            producer,
            entries,
            block_hash,
            signature,
        };
        block.validate_integrity()?;
        Ok(block)
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.entries.is_empty() {
            bail!("ledger block must contain at least one entry");
        }
        validate_entry_chain(self.parent_hash, &self.entries)?;
        let expected = hash_with_domain(
            b"rpkv2.ledger.block.v1",
            &encode_block_unsigned(self.slot, self.parent_hash, &self.producer, &self.entries)?,
        );
        if self.block_hash != expected {
            bail!("ledger block hash mismatch");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShredKind {
    Data,
    Coding,
}

impl ShredKind {
    fn as_u8(self) -> u8 {
        match self {
            Self::Data => 0,
            Self::Coding => 1,
        }
    }

    fn from_u8(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Data),
            1 => Ok(Self::Coding),
            _ => bail!("unsupported shred kind"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerShred {
    pub slot: EpochSlot,
    pub block_hash: LedgerHash,
    pub index: u32,
    pub shred_count: u32,
    pub kind: ShredKind,
    pub payload: Vec<u8>,
    pub payload_hash: LedgerHash,
    pub signature: LedgerSignature,
}

impl LedgerShred {
    pub fn from_block(block: &LedgerBlock, max_payload_len: usize) -> Result<Vec<Self>> {
        if max_payload_len == 0 {
            bail!("max shred payload length must be greater than zero");
        }
        let block_bytes = block.encode()?;
        let shred_count = block_bytes.len().div_ceil(max_payload_len);
        if shred_count == 0 || shred_count > u32::MAX as usize {
            bail!("block cannot be represented as shreds");
        }
        let mut shreds = Vec::with_capacity(shred_count);
        for (index, payload) in block_bytes.chunks(max_payload_len).enumerate() {
            shreds.push(Self::new_data(
                block.slot,
                block.block_hash,
                index as u32,
                shred_count as u32,
                payload.to_vec(),
                [0u8; SIGNATURE_LEN],
            )?);
        }
        Ok(shreds)
    }

    pub fn new_data(
        slot: EpochSlot,
        block_hash: LedgerHash,
        index: u32,
        shred_count: u32,
        payload: Vec<u8>,
        signature: LedgerSignature,
    ) -> Result<Self> {
        if shred_count == 0 {
            bail!("shred count must be greater than zero");
        }
        if index >= shred_count {
            bail!("shred index must be less than shred count");
        }
        ensure_blob_len("shred payload", payload.len())?;
        let payload_hash = hash_with_domain(b"rpkv2.ledger.shred.payload.v1", &payload);
        Ok(Self {
            slot,
            block_hash,
            index,
            shred_count,
            kind: ShredKind::Data,
            payload,
            payload_hash,
            signature,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(SHRED_MAGIC);
        out.push(LEDGER_VERSION);
        out.extend_from_slice(&self.slot.epoch.to_be_bytes());
        out.extend_from_slice(&self.slot.slot.to_be_bytes());
        out.extend_from_slice(&self.block_hash);
        out.extend_from_slice(&self.index.to_be_bytes());
        out.extend_from_slice(&self.shred_count.to_be_bytes());
        out.push(self.kind.as_u8());
        put_blob(&mut out, &self.payload)?;
        out.extend_from_slice(&self.payload_hash);
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        cursor.magic(SHRED_MAGIC)?;
        cursor.version()?;
        let slot = EpochSlot {
            epoch: cursor.u64()?,
            slot: cursor.u64()?,
        };
        let block_hash = cursor.hash()?;
        let index = cursor.u32()?;
        let shred_count = cursor.u32()?;
        let kind = ShredKind::from_u8(cursor.u8()?)?;
        let payload = cursor.blob()?;
        let payload_hash = cursor.hash()?;
        let signature = cursor.signature()?;
        cursor.finish()?;

        let shred = Self {
            slot,
            block_hash,
            index,
            shred_count,
            kind,
            payload,
            payload_hash,
            signature,
        };
        shred.validate_integrity()?;
        Ok(shred)
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.shred_count == 0 {
            bail!("shred count must be greater than zero");
        }
        if self.index >= self.shred_count {
            bail!("shred index must be less than shred count");
        }
        if self.kind != ShredKind::Data {
            bail!("coding shreds are defined but not reconstructable yet");
        }
        let expected = hash_with_domain(b"rpkv2.ledger.shred.payload.v1", &self.payload);
        if self.payload_hash != expected {
            bail!("shred payload hash mismatch");
        }
        Ok(())
    }
}

pub fn reconstruct_block_from_shreds(shreds: &[LedgerShred]) -> Result<LedgerBlock> {
    if shreds.is_empty() {
        bail!("cannot reconstruct block from empty shred set");
    }

    let mut sorted = shreds.to_vec();
    sorted.sort_by_key(|shred| shred.index);
    let first = &sorted[0];
    let expected_count = first.shred_count;
    if sorted.len() != expected_count as usize {
        bail!("missing shreds for block reconstruction");
    }

    let mut block_bytes = Vec::new();
    for (expected_index, shred) in sorted.iter().enumerate() {
        shred.validate_integrity()?;
        if shred.slot != first.slot
            || shred.block_hash != first.block_hash
            || shred.shred_count != expected_count
            || shred.index != expected_index as u32
        {
            bail!("inconsistent shred set");
        }
        block_bytes.extend_from_slice(&shred.payload);
    }

    let block = LedgerBlock::decode(&block_bytes)?;
    if block.block_hash != first.block_hash || block.slot != first.slot {
        bail!("reconstructed block does not match shred header");
    }
    Ok(block)
}

fn encode_batch_unsigned(index: u32, transactions: &[Vec<u8>]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(BATCH_MAGIC);
    out.push(LEDGER_VERSION);
    out.extend_from_slice(&index.to_be_bytes());
    put_u16_len(&mut out, transactions.len(), "transaction count")?;
    for transaction in transactions {
        put_blob(&mut out, transaction)?;
    }
    Ok(out)
}

fn encode_entry_unsigned(
    index: u32,
    previous_hash: LedgerHash,
    batches: &[TransactionBatch],
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(ENTRY_MAGIC);
    out.push(LEDGER_VERSION);
    out.extend_from_slice(&index.to_be_bytes());
    out.extend_from_slice(&previous_hash);
    put_u16_len(&mut out, batches.len(), "transaction batch count")?;
    for batch in batches {
        put_blob(&mut out, &batch.encode()?)?;
    }
    Ok(out)
}

fn encode_block_unsigned(
    slot: EpochSlot,
    parent_hash: LedgerHash,
    producer: &ValidatorId,
    entries: &[LedgerEntry],
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(BLOCK_MAGIC);
    out.push(LEDGER_VERSION);
    out.extend_from_slice(&slot.epoch.to_be_bytes());
    out.extend_from_slice(&slot.slot.to_be_bytes());
    out.extend_from_slice(&parent_hash);
    put_string(&mut out, producer.as_str())?;
    put_u16_len(&mut out, entries.len(), "entry count")?;
    for entry in entries {
        put_blob(&mut out, &entry.encode()?)?;
    }
    Ok(out)
}

fn validate_entry_chain(parent_hash: LedgerHash, entries: &[LedgerEntry]) -> Result<()> {
    ensure_sequential_indices("ledger entry", entries.iter().map(|entry| entry.index))?;
    let mut expected_previous = parent_hash;
    for entry in entries {
        entry.validate_integrity()?;
        if entry.previous_hash != expected_previous {
            bail!("ledger entry previous hash does not match chain");
        }
        expected_previous = entry.entry_hash;
    }
    Ok(())
}

fn ensure_sequential_indices(name: &str, indices: impl IntoIterator<Item = u32>) -> Result<()> {
    for (expected, actual) in indices.into_iter().enumerate() {
        if actual != expected as u32 {
            bail!("{name} index is not sequential");
        }
    }
    Ok(())
}

fn hash_with_domain(domain: &[u8], bytes: &[u8]) -> LedgerHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn put_u16_len(out: &mut Vec<u8>, len: usize, name: &str) -> Result<()> {
    let len = u16::try_from(len).map_err(|_| anyhow!("{name} exceeds u16 length"))?;
    out.extend_from_slice(&len.to_be_bytes());
    Ok(())
}

fn put_string(out: &mut Vec<u8>, value: &str) -> Result<()> {
    put_u16_len(out, value.len(), "string length")?;
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn put_blob(out: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    ensure_blob_len("blob", value.len())?;
    let len = u32::try_from(value.len()).map_err(|_| anyhow!("blob exceeds u32 length"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn ensure_blob_len(name: &str, len: usize) -> Result<()> {
    if len > MAX_BLOB_LEN {
        bail!("{name} is too large");
    }
    Ok(())
}

struct Cursor<'a> {
    inner: WireCursor<'a>,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            inner: WireCursor::new(bytes, "ledger object"),
        }
    }

    fn magic(&mut self, expected: &[u8; 4]) -> Result<()> {
        self.inner.expect(expected, "invalid ledger magic")
    }

    fn version(&mut self) -> Result<()> {
        let version = self.u8()?;
        if version != LEDGER_VERSION {
            bail!("unsupported ledger version");
        }
        Ok(())
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
        Ok(self.take(HASH_LEN)?.try_into()?)
    }

    fn signature(&mut self) -> Result<LedgerSignature> {
        Ok(self.take(SIGNATURE_LEN)?.try_into()?)
    }

    fn string(&mut self) -> Result<String> {
        let len = self.u16()? as usize;
        let bytes = self.take(len)?;
        Ok(std::str::from_utf8(bytes)?.to_string())
    }

    fn blob(&mut self) -> Result<Vec<u8>> {
        let len = self.u32()? as usize;
        ensure_blob_len("blob", len)?;
        Ok(self.take(len)?.to_vec())
    }

    fn finish(&self) -> Result<()> {
        self.inner.finish()
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        self.inner.take(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: u8) -> LedgerHash {
        [byte; HASH_LEN]
    }

    fn slot() -> EpochSlot {
        EpochSlot { epoch: 7, slot: 42 }
    }

    fn producer() -> ValidatorId {
        ValidatorId::from_str("validator-a").unwrap()
    }

    fn block_fixture() -> LedgerBlock {
        let batch = TransactionBatch::new(0, vec![b"tx-a".to_vec(), b"tx-b".to_vec()]).unwrap();
        let entry = LedgerEntry::new(0, hash(9), vec![batch]).unwrap();
        LedgerBlock::new(
            slot(),
            hash(9),
            producer(),
            vec![entry],
            [1u8; SIGNATURE_LEN],
        )
        .unwrap()
    }

    #[test]
    fn block_entry_and_batch_serialization_roundtrip() {
        let block = block_fixture();
        let encoded = block.encode().unwrap();
        let decoded = LedgerBlock::decode(&encoded).unwrap();

        assert_eq!(decoded, block);
        assert_eq!(decoded.parent_hash, hash(9));
        assert_eq!(decoded.entries[0].previous_hash, decoded.parent_hash);
    }

    #[test]
    fn shreds_reconstruct_block_from_unordered_data() {
        let block = block_fixture();
        let mut shreds = LedgerShred::from_block(&block, 32).unwrap();
        shreds.reverse();

        let reconstructed = reconstruct_block_from_shreds(&shreds).unwrap();

        assert_eq!(reconstructed, block);
        assert!(shreds.len() > 1);
    }

    #[test]
    fn corrupted_block_hash_is_detected() {
        let block = block_fixture();
        let mut encoded = block.encode().unwrap();
        let hash_offset = encoded.len() - SIGNATURE_LEN - HASH_LEN;
        encoded[hash_offset] ^= 0xff;

        assert!(LedgerBlock::decode(&encoded).is_err());
    }

    #[test]
    fn corrupted_shred_payload_is_detected() {
        let block = block_fixture();
        let mut shreds = LedgerShred::from_block(&block, 64).unwrap();
        shreds[0].payload[0] ^= 0xff;

        assert!(reconstruct_block_from_shreds(&shreds).is_err());
    }

    #[test]
    fn missing_shred_is_rejected() {
        let block = block_fixture();
        let mut shreds = LedgerShred::from_block(&block, 32).unwrap();
        shreds.pop();

        assert!(reconstruct_block_from_shreds(&shreds).is_err());
    }
}
