use crate::{
    consensus_messages::{ConsensusMessage, Vote},
    ledger::{LedgerBlock, LedgerHash, LedgerShred},
    validator_set::EpochSlot,
    wire::Cursor as WireCursor,
};
use anyhow::{Result, anyhow, bail};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::Path,
};

const LOG_FILE_NAME: &str = "blockstore.log";
const RECORD_MAGIC: &[u8; 4] = b"RPBS";
pub const BLOCKSTORE_RECORD_VERSION: u8 = 1;
const RECORD_KIND_BATCH: u8 = 1;
const RECORD_HEADER_LEN: usize = 4 + 1 + 1 + 4 + 32;
const MAX_RECORD_LEN: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredExecutionResult {
    pub slot: EpochSlot,
    pub transaction_id: LedgerHash,
    pub state_root: LedgerHash,
    pub receipt_hash: LedgerHash,
    pub success: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredStateRoot {
    pub slot: EpochSlot,
    pub block_hash: LedgerHash,
    pub state_root: LedgerHash,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlockstoreMetadata {
    pub block_count: usize,
    pub shred_count: usize,
    pub vote_count: usize,
    pub execution_result_count: usize,
    pub state_root_count: usize,
    pub latest_slot: Option<EpochSlot>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlockstoreBatch {
    shreds: Vec<LedgerShred>,
    blocks: Vec<LedgerBlock>,
    votes: Vec<Vote>,
    execution_results: Vec<StoredExecutionResult>,
    state_roots: Vec<StoredStateRoot>,
}

impl BlockstoreBatch {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put_shred(&mut self, shred: LedgerShred) {
        self.shreds.push(shred);
    }

    pub fn put_block(&mut self, block: LedgerBlock) {
        self.blocks.push(block);
    }

    pub fn put_vote(&mut self, vote: Vote) {
        self.votes.push(vote);
    }

    pub fn put_execution_result(&mut self, result: StoredExecutionResult) {
        self.execution_results.push(result);
    }

    pub fn put_state_root(&mut self, state_root: StoredStateRoot) {
        self.state_roots.push(state_root);
    }

    pub fn is_empty(&self) -> bool {
        self.shreds.is_empty()
            && self.blocks.is_empty()
            && self.votes.is_empty()
            && self.execution_results.is_empty()
            && self.state_roots.is_empty()
    }
}

#[derive(Default)]
struct BlockstoreIndexes {
    shreds: BTreeMap<ShredKey, LedgerShred>,
    blocks_by_hash: BTreeMap<LedgerHash, LedgerBlock>,
    blocks_by_slot: BTreeMap<EpochSlot, BTreeSet<LedgerHash>>,
    votes_by_block: BTreeMap<LedgerHash, Vec<Vote>>,
    execution_results: BTreeMap<(EpochSlot, LedgerHash), StoredExecutionResult>,
    state_roots: BTreeMap<(EpochSlot, LedgerHash), StoredStateRoot>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ShredKey {
    slot: EpochSlot,
    block_hash: LedgerHash,
    index: u32,
}

pub struct Blockstore {
    log: File,
    indexes: BlockstoreIndexes,
}

impl Blockstore {
    pub fn open(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;
        let log_path = dir.join(LOG_FILE_NAME);
        let indexes = if log_path.exists() {
            scan_log(&log_path)?
        } else {
            BlockstoreIndexes::default()
        };
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&log_path)?;
        Ok(Self { log, indexes })
    }

    pub fn write_batch(&mut self, batch: BlockstoreBatch) -> Result<()> {
        if batch.is_empty() {
            return Ok(());
        }
        let filtered = self.filter_idempotent_batch(batch)?;
        if filtered.is_empty() {
            return Ok(());
        }
        let payload = encode_batch(&filtered)?;
        write_record(&mut self.log, RECORD_KIND_BATCH, &payload)?;
        self.log.sync_all()?;
        apply_batch(&mut self.indexes, filtered)?;
        Ok(())
    }

    pub fn put_shred(&mut self, shred: LedgerShred) -> Result<()> {
        let mut batch = BlockstoreBatch::new();
        batch.put_shred(shred);
        self.write_batch(batch)
    }

    pub fn put_block(&mut self, block: LedgerBlock) -> Result<()> {
        let mut batch = BlockstoreBatch::new();
        batch.put_block(block);
        self.write_batch(batch)
    }

    pub fn get_shred(
        &self,
        slot: EpochSlot,
        block_hash: LedgerHash,
        index: u32,
    ) -> Option<&LedgerShred> {
        self.indexes.shreds.get(&ShredKey {
            slot,
            block_hash,
            index,
        })
    }

    pub fn get_block_by_hash(&self, block_hash: &LedgerHash) -> Option<&LedgerBlock> {
        self.indexes.blocks_by_hash.get(block_hash)
    }

    pub fn get_blocks_by_slot(&self, slot: EpochSlot) -> Vec<&LedgerBlock> {
        self.indexes
            .blocks_by_slot
            .get(&slot)
            .into_iter()
            .flat_map(|hashes| hashes.iter())
            .filter_map(|hash| self.indexes.blocks_by_hash.get(hash))
            .collect()
    }

    pub fn all_blocks(&self) -> impl Iterator<Item = &LedgerBlock> {
        self.indexes.blocks_by_hash.values()
    }

    pub fn canonical_blocks(&self) -> Result<Vec<&LedgerBlock>> {
        let mut blocks = Vec::new();
        for hashes in self.indexes.blocks_by_slot.values() {
            if hashes.len() != 1 {
                bail!("cannot replay ambiguous slot with multiple blocks");
            }
            let hash = hashes
                .iter()
                .next()
                .ok_or_else(|| anyhow!("empty block slot index"))?;
            let block = self
                .indexes
                .blocks_by_hash
                .get(hash)
                .ok_or_else(|| anyhow!("block slot index points to missing block"))?;
            blocks.push(block);
        }
        Ok(blocks)
    }

    pub fn votes_for_block(&self, block_hash: &LedgerHash) -> &[Vote] {
        self.indexes
            .votes_by_block
            .get(block_hash)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn execution_result(
        &self,
        slot: EpochSlot,
        transaction_id: &LedgerHash,
    ) -> Option<&StoredExecutionResult> {
        self.indexes.execution_results.get(&(slot, *transaction_id))
    }

    pub fn state_root(&self, slot: EpochSlot) -> Option<&StoredStateRoot> {
        let mut roots = self
            .indexes
            .state_roots
            .range((slot, [0u8; 32])..=(slot, [u8::MAX; 32]));
        let first = roots.next().map(|(_, root)| root)?;
        if roots.next().is_some() {
            return None;
        }
        Some(first)
    }

    pub fn state_root_for_block(&self, block_hash: &LedgerHash) -> Option<&StoredStateRoot> {
        self.indexes
            .state_roots
            .values()
            .find(|root| &root.block_hash == block_hash)
    }

    pub fn metadata(&self) -> BlockstoreMetadata {
        let latest_slot = self
            .indexes
            .blocks_by_slot
            .keys()
            .chain(self.indexes.state_roots.keys().map(|(slot, _)| slot))
            .copied()
            .max();
        BlockstoreMetadata {
            block_count: self.indexes.blocks_by_hash.len(),
            shred_count: self.indexes.shreds.len(),
            vote_count: self.indexes.votes_by_block.values().map(Vec::len).sum(),
            execution_result_count: self.indexes.execution_results.len(),
            state_root_count: self.indexes.state_roots.len(),
            latest_slot,
        }
    }

    fn filter_idempotent_batch(&self, batch: BlockstoreBatch) -> Result<BlockstoreBatch> {
        let mut filtered = BlockstoreBatch::new();
        for shred in batch.shreds {
            let key = shred_key(&shred);
            match self.indexes.shreds.get(&key) {
                Some(existing) if existing == &shred => {}
                Some(_) => bail!("conflicting duplicate shred"),
                None => filtered.put_shred(shred),
            }
        }
        for block in batch.blocks {
            match self.indexes.blocks_by_hash.get(&block.block_hash) {
                Some(existing) if existing == &block => {}
                Some(_) => bail!("conflicting duplicate block"),
                None => filtered.put_block(block),
            }
        }
        for vote in batch.votes {
            let duplicate = self
                .indexes
                .votes_by_block
                .get(&vote.block_hash)
                .is_some_and(|votes| votes.iter().any(|existing| existing == &vote));
            if !duplicate {
                filtered.put_vote(vote);
            }
        }
        for result in batch.execution_results {
            let key = (result.slot, result.transaction_id);
            match self.indexes.execution_results.get(&key) {
                Some(existing) if existing == &result => {}
                Some(_) => bail!("conflicting duplicate execution result"),
                None => filtered.put_execution_result(result),
            }
        }
        for state_root in batch.state_roots {
            let key = (state_root.slot, state_root.block_hash);
            match self.indexes.state_roots.get(&key) {
                Some(existing) if existing == &state_root => {}
                Some(_) => bail!("conflicting duplicate state root"),
                None => filtered.put_state_root(state_root),
            }
        }
        Ok(filtered)
    }
}

fn scan_log(path: &Path) -> Result<BlockstoreIndexes> {
    let mut file = File::open(path)?;
    let mut indexes = BlockstoreIndexes::default();
    loop {
        let mut header = [0u8; RECORD_HEADER_LEN];
        let read = read_exact_or_partial(&mut file, &mut header)?;
        if read == 0 {
            break;
        }
        if read < RECORD_HEADER_LEN {
            bail!("partial blockstore record header");
        }
        let parsed = parse_record_header(&header)?;
        let mut payload = vec![0u8; parsed.len as usize];
        let payload_read = read_exact_or_partial(&mut file, &mut payload)?;
        if payload_read < payload.len() {
            bail!("partial blockstore record payload");
        }
        let checksum = record_checksum(parsed.kind, parsed.len, &payload);
        if checksum != parsed.checksum {
            bail!("blockstore record checksum mismatch");
        }
        match parsed.kind {
            RECORD_KIND_BATCH => apply_batch(&mut indexes, decode_batch(&payload)?)?,
            _ => bail!("unsupported blockstore record kind"),
        }
    }
    Ok(indexes)
}

fn apply_batch(indexes: &mut BlockstoreIndexes, batch: BlockstoreBatch) -> Result<()> {
    for shred in batch.shreds {
        shred.validate_integrity()?;
        let key = shred_key(&shred);
        match indexes.shreds.get(&key) {
            Some(existing) if existing == &shred => {}
            Some(_) => bail!("conflicting duplicate shred"),
            None => {
                indexes.shreds.insert(key, shred);
            }
        }
    }

    for block in batch.blocks {
        block.validate_integrity()?;
        match indexes.blocks_by_hash.get(&block.block_hash) {
            Some(existing) if existing == &block => {}
            Some(_) => bail!("conflicting duplicate block"),
            None => {
                indexes
                    .blocks_by_slot
                    .entry(block.slot)
                    .or_default()
                    .insert(block.block_hash);
                indexes.blocks_by_hash.insert(block.block_hash, block);
            }
        }
    }

    for vote in batch.votes {
        let votes = indexes.votes_by_block.entry(vote.block_hash).or_default();
        if !votes.iter().any(|existing| existing == &vote) {
            votes.push(vote);
        }
    }

    for result in batch.execution_results {
        let key = (result.slot, result.transaction_id);
        match indexes.execution_results.get(&key) {
            Some(existing) if existing == &result => {}
            Some(_) => bail!("conflicting duplicate execution result"),
            None => {
                indexes.execution_results.insert(key, result);
            }
        }
    }

    for state_root in batch.state_roots {
        let key = (state_root.slot, state_root.block_hash);
        match indexes.state_roots.get(&key) {
            Some(existing) if existing == &state_root => {}
            Some(_) => bail!("conflicting duplicate state root"),
            None => {
                indexes.state_roots.insert(key, state_root);
            }
        }
    }
    Ok(())
}

fn shred_key(shred: &LedgerShred) -> ShredKey {
    ShredKey {
        slot: shred.slot,
        block_hash: shred.block_hash,
        index: shred.index,
    }
}

struct ParsedRecordHeader {
    kind: u8,
    len: u32,
    checksum: LedgerHash,
}

fn parse_record_header(header: &[u8; RECORD_HEADER_LEN]) -> Result<ParsedRecordHeader> {
    if &header[0..4] != RECORD_MAGIC {
        bail!("bad blockstore record magic");
    }
    if header[4] != BLOCKSTORE_RECORD_VERSION {
        bail!(
            "unsupported blockstore record version {}; supported {}",
            header[4],
            BLOCKSTORE_RECORD_VERSION
        );
    }
    let kind = header[5];
    let len = u32::from_be_bytes(header[6..10].try_into()?);
    if len as usize > MAX_RECORD_LEN {
        bail!("blockstore record too large");
    }
    let mut checksum = [0u8; 32];
    checksum.copy_from_slice(&header[10..42]);
    Ok(ParsedRecordHeader {
        kind,
        len,
        checksum,
    })
}

fn write_record(writer: &mut impl Write, kind: u8, payload: &[u8]) -> Result<()> {
    if payload.len() > MAX_RECORD_LEN {
        bail!("blockstore record too large");
    }
    let len = u32::try_from(payload.len()).map_err(|_| anyhow!("blockstore record too large"))?;
    let checksum = record_checksum(kind, len, payload);
    writer.write_all(RECORD_MAGIC)?;
    writer.write_all(&[BLOCKSTORE_RECORD_VERSION])?;
    writer.write_all(&[kind])?;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(&checksum)?;
    writer.write_all(payload)?;
    writer.flush()?;
    Ok(())
}

fn record_checksum(kind: u8, len: u32, payload: &[u8]) -> LedgerHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(RECORD_MAGIC);
    hasher.update(&[BLOCKSTORE_RECORD_VERSION]);
    hasher.update(&[kind]);
    hasher.update(&len.to_be_bytes());
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

fn encode_batch(batch: &BlockstoreBatch) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    put_len(&mut out, batch.shreds.len(), "shred count")?;
    for shred in &batch.shreds {
        put_blob(&mut out, &shred.encode()?)?;
    }
    put_len(&mut out, batch.blocks.len(), "block count")?;
    for block in &batch.blocks {
        put_blob(&mut out, &block.encode()?)?;
    }
    put_len(&mut out, batch.votes.len(), "vote count")?;
    for vote in &batch.votes {
        put_blob(&mut out, &vote.encode())?;
    }
    put_len(
        &mut out,
        batch.execution_results.len(),
        "execution result count",
    )?;
    for result in &batch.execution_results {
        encode_execution_result(&mut out, result);
    }
    put_len(&mut out, batch.state_roots.len(), "state root count")?;
    for state_root in &batch.state_roots {
        encode_state_root(&mut out, state_root);
    }
    Ok(out)
}

fn decode_batch(bytes: &[u8]) -> Result<BlockstoreBatch> {
    let mut cursor = Cursor::new(bytes);
    let mut batch = BlockstoreBatch::new();
    for _ in 0..cursor.u32()? {
        batch.put_shred(LedgerShred::decode(&cursor.blob()?)?);
    }
    for _ in 0..cursor.u32()? {
        batch.put_block(LedgerBlock::decode(&cursor.blob()?)?);
    }
    for _ in 0..cursor.u32()? {
        match ConsensusMessage::decode(&cursor.blob()?)? {
            ConsensusMessage::Vote(vote) => batch.put_vote(vote),
            ConsensusMessage::BlockProposal(_) => bail!("expected vote record"),
        }
    }
    for _ in 0..cursor.u32()? {
        batch.put_execution_result(decode_execution_result(&mut cursor)?);
    }
    for _ in 0..cursor.u32()? {
        batch.put_state_root(decode_state_root(&mut cursor)?);
    }
    cursor.finish()?;
    Ok(batch)
}

fn encode_execution_result(out: &mut Vec<u8>, result: &StoredExecutionResult) {
    put_slot(out, result.slot);
    out.extend_from_slice(&result.transaction_id);
    out.extend_from_slice(&result.state_root);
    out.extend_from_slice(&result.receipt_hash);
    out.push(u8::from(result.success));
}

fn decode_execution_result(cursor: &mut Cursor<'_>) -> Result<StoredExecutionResult> {
    let slot = cursor.slot()?;
    let transaction_id = cursor.hash()?;
    let state_root = cursor.hash()?;
    let receipt_hash = cursor.hash()?;
    let success = match cursor.u8()? {
        0 => false,
        1 => true,
        other => bail!("invalid execution result success flag {other}"),
    };
    Ok(StoredExecutionResult {
        slot,
        transaction_id,
        state_root,
        receipt_hash,
        success,
    })
}

fn encode_state_root(out: &mut Vec<u8>, state_root: &StoredStateRoot) {
    put_slot(out, state_root.slot);
    out.extend_from_slice(&state_root.block_hash);
    out.extend_from_slice(&state_root.state_root);
}

fn decode_state_root(cursor: &mut Cursor<'_>) -> Result<StoredStateRoot> {
    Ok(StoredStateRoot {
        slot: cursor.slot()?,
        block_hash: cursor.hash()?,
        state_root: cursor.hash()?,
    })
}

fn put_slot(out: &mut Vec<u8>, slot: EpochSlot) {
    out.extend_from_slice(&slot.epoch.to_be_bytes());
    out.extend_from_slice(&slot.slot.to_be_bytes());
}

fn put_len(out: &mut Vec<u8>, len: usize, name: &str) -> Result<()> {
    let len = u32::try_from(len).map_err(|_| anyhow!("{name} exceeds u32 length"))?;
    out.extend_from_slice(&len.to_be_bytes());
    Ok(())
}

fn put_blob(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let len = u32::try_from(bytes.len()).map_err(|_| anyhow!("blob exceeds u32 length"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn read_exact_or_partial(reader: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut read = 0;
    while read < buf.len() {
        match reader.read(&mut buf[read..])? {
            0 => break,
            n => read += n,
        }
    }
    Ok(read)
}

struct Cursor<'a> {
    inner: WireCursor<'a>,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            inner: WireCursor::new(bytes, "blockstore payload"),
        }
    }

    fn u8(&mut self) -> Result<u8> {
        self.inner.u8()
    }

    fn u32(&mut self) -> Result<u32> {
        self.inner.u32()
    }

    fn u64(&mut self) -> Result<u64> {
        self.inner.u64()
    }

    fn slot(&mut self) -> Result<EpochSlot> {
        Ok(EpochSlot::new(self.u64()?, self.u64()?))
    }

    fn hash(&mut self) -> Result<LedgerHash> {
        Ok(self.take(32)?.try_into()?)
    }

    fn blob(&mut self) -> Result<Vec<u8>> {
        let len = self.u32()? as usize;
        if len > MAX_RECORD_LEN {
            bail!("blob is too large");
        }
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
    use crate::{
        identity::ValidatorId,
        ledger::{LedgerEntry, TransactionBatch},
    };
    use std::{
        io::{Seek, SeekFrom},
        path::PathBuf,
        str::FromStr,
    };

    fn temp_dir() -> PathBuf {
        crate::test_support::temp_dir("blockstore")
    }

    fn hash(byte: u8) -> LedgerHash {
        [byte; 32]
    }

    fn slot(value: u64) -> EpochSlot {
        EpochSlot::new(0, value)
    }

    fn block_fixture() -> LedgerBlock {
        let batch = TransactionBatch::new(0, vec![b"tx-a".to_vec()]).unwrap();
        let entry = LedgerEntry::new(0, hash(7), vec![batch]).unwrap();
        LedgerBlock::new(
            slot(3),
            hash(7),
            ValidatorId::from_str("validator-a").unwrap(),
            vec![entry],
            [9u8; 64],
        )
        .unwrap()
    }

    fn vote_for(block: &LedgerBlock) -> Vote {
        Vote {
            slot: block.slot,
            voter: ValidatorId::from_str("validator-b").unwrap(),
            block_hash: block.block_hash,
            signature: [5u8; 64],
        }
    }

    #[test]
    fn write_and_read_blockstore_records() {
        let dir = temp_dir();
        let block = block_fixture();
        let shreds = LedgerShred::from_block(&block, 64).unwrap();
        let vote = vote_for(&block);
        let execution_result = StoredExecutionResult {
            slot: block.slot,
            transaction_id: hash(1),
            state_root: hash(2),
            receipt_hash: hash(3),
            success: true,
        };
        let state_root = StoredStateRoot {
            slot: block.slot,
            block_hash: block.block_hash,
            state_root: hash(2),
        };

        let mut batch = BlockstoreBatch::new();
        batch.put_block(block.clone());
        batch.put_vote(vote.clone());
        batch.put_execution_result(execution_result.clone());
        batch.put_state_root(state_root.clone());
        for shred in &shreds {
            batch.put_shred(shred.clone());
        }
        Blockstore::open(&dir).unwrap().write_batch(batch).unwrap();

        let store = Blockstore::open(&dir).unwrap();

        assert_eq!(store.get_block_by_hash(&block.block_hash), Some(&block));
        assert_eq!(store.get_blocks_by_slot(block.slot), vec![&block]);
        assert_eq!(
            store.get_shred(block.slot, block.block_hash, 0),
            Some(&shreds[0])
        );
        assert_eq!(store.votes_for_block(&block.block_hash), &[vote]);
        assert_eq!(
            store.execution_result(block.slot, &hash(1)),
            Some(&execution_result)
        );
        assert_eq!(store.state_root(block.slot), Some(&state_root));
        assert_eq!(store.metadata().block_count, 1);
    }

    #[test]
    fn committed_batch_survives_reopen_after_process_crash_simulation() {
        let dir = temp_dir();
        let block = block_fixture();
        {
            let mut store = Blockstore::open(&dir).unwrap();
            store.put_block(block.clone()).unwrap();
        }

        let recovered = Blockstore::open(&dir).unwrap();

        assert_eq!(recovered.get_block_by_hash(&block.block_hash), Some(&block));
    }

    #[test]
    fn duplicate_shred_is_idempotent() {
        let dir = temp_dir();
        let block = block_fixture();
        let shred = LedgerShred::from_block(&block, 128).unwrap().remove(0);
        let mut store = Blockstore::open(&dir).unwrap();

        store.put_shred(shred.clone()).unwrap();
        store.put_shred(shred.clone()).unwrap();

        assert_eq!(store.metadata().shred_count, 1);
        assert_eq!(
            store.get_shred(shred.slot, shred.block_hash, shred.index),
            Some(&shred)
        );
    }

    #[test]
    fn corrupted_log_record_is_detected() {
        let dir = temp_dir();
        let block = block_fixture();
        Blockstore::open(&dir).unwrap().put_block(block).unwrap();
        let path = dir.join(LOG_FILE_NAME);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.seek(SeekFrom::Start(RECORD_HEADER_LEN as u64 + 3))
            .unwrap();
        file.write_all(&[0xff]).unwrap();
        file.sync_all().unwrap();

        assert!(Blockstore::open(&dir).is_err());
    }
}
