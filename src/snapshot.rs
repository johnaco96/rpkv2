use crate::{
    consensus_messages::EquivocationEvidence,
    consensus_safety::{BlockInfo, ConsensusSafetyState, VoteRecord},
    identity::ValidatorId,
    ledger::LedgerHash,
    state::{Account, StateDb},
    validator_set::{EpochSlot, ValidatorIdentityRecord, ValidatorSet},
    wire::Cursor as WireCursor,
};
use anyhow::{Result, anyhow, bail};
use std::str::FromStr;

const SNAPSHOT_MAGIC: &[u8; 4] = b"RPSN";
pub const SNAPSHOT_VERSION: u8 = 1;
const SNAPSHOT_HASH_DOMAIN: &[u8] = b"rpkv2.snapshot.v1";
const MAX_BLOB_LEN: usize = 16 * 1024 * 1024;
const SIGNATURE_LEN: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotValidatorRecord {
    pub validator_id: ValidatorId,
    pub tls_spki_der: Vec<u8>,
    pub packet_signing_key: [u8; 32],
    pub consensus_voting_key: [u8; 32],
    pub voting_weight: u64,
    pub activation: EpochSlot,
    pub deactivation: Option<EpochSlot>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SnapshotConsensusState {
    pub blocks: Vec<BlockInfo>,
    pub votes: Vec<VoteRecord>,
    pub equivocations: Vec<EquivocationEvidence>,
}

#[derive(Clone, Debug)]
pub struct LedgerSnapshot {
    pub slot: EpochSlot,
    pub block_hash: LedgerHash,
    pub state_root: LedgerHash,
    pub state: StateDb,
    pub validators: Vec<SnapshotValidatorRecord>,
    pub consensus: SnapshotConsensusState,
    pub snapshot_hash: LedgerHash,
    pub signature: [u8; SIGNATURE_LEN],
}

impl LedgerSnapshot {
    pub fn create(
        slot: EpochSlot,
        block_hash: LedgerHash,
        state: &StateDb,
        validator_set: &ValidatorSet,
        consensus: &ConsensusSafetyState,
        signature: [u8; SIGNATURE_LEN],
    ) -> Result<Self> {
        if signature.iter().all(|byte| *byte == 0) {
            bail!("snapshot signature must not be empty");
        }
        let validators = validator_set
            .validators()
            .map(SnapshotValidatorRecord::from)
            .collect::<Vec<_>>();
        if validators.is_empty() {
            bail!("snapshot validator set must not be empty");
        }
        let consensus = SnapshotConsensusState::from(consensus);
        let mut snapshot = Self {
            slot,
            block_hash,
            state_root: state.state_hash(),
            state: state.clone(),
            validators,
            consensus,
            snapshot_hash: [0u8; 32],
            signature,
        };
        snapshot.snapshot_hash = snapshot.compute_hash()?;
        Ok(snapshot)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = self.encode_unsigned()?;
        out.extend_from_slice(&self.snapshot_hash);
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        cursor.magic(SNAPSHOT_MAGIC)?;
        cursor.version()?;
        let slot = cursor.slot()?;
        let block_hash = cursor.hash()?;
        let state_root = cursor.hash()?;

        let account_count = cursor.u32()? as usize;
        let mut state = StateDb::default();
        for _ in 0..account_count {
            state.insert(Account::new(
                cursor.hash()?,
                cursor.hash()?,
                cursor.u64()?,
                cursor.blob()?,
                cursor.u64()?,
            )?)?;
        }

        let validator_count = cursor.u32()? as usize;
        let mut validators = Vec::with_capacity(validator_count);
        for _ in 0..validator_count {
            validators.push(SnapshotValidatorRecord {
                validator_id: ValidatorId::from_str(&cursor.string()?)?,
                tls_spki_der: cursor.blob()?,
                packet_signing_key: cursor.hash()?,
                consensus_voting_key: cursor.hash()?,
                voting_weight: cursor.u64()?,
                activation: cursor.slot()?,
                deactivation: cursor.optional_slot()?,
            });
        }

        let consensus = SnapshotConsensusState {
            blocks: decode_blocks(&mut cursor)?,
            votes: decode_votes(&mut cursor)?,
            equivocations: decode_equivocations(&mut cursor)?,
        };
        let snapshot_hash = cursor.hash()?;
        let signature = cursor.signature()?;
        cursor.finish()?;

        let snapshot = Self {
            slot,
            block_hash,
            state_root,
            state,
            validators,
            consensus,
            snapshot_hash,
            signature,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn validator_set(&self) -> Result<ValidatorSet> {
        let mut set = ValidatorSet::default();
        for validator in &self.validators {
            set.insert(ValidatorIdentityRecord {
                validator_id: validator.validator_id.clone(),
                tls_spki_der: validator.tls_spki_der.clone(),
                packet_signing_key: validator.packet_signing_key,
                consensus_voting_key: validator.consensus_voting_key,
                voting_weight: validator.voting_weight,
                activation: validator.activation,
                deactivation: validator.deactivation,
            })?;
        }
        if set.is_empty() {
            bail!("snapshot validator set must not be empty");
        }
        Ok(set)
    }

    pub fn validate(&self) -> Result<()> {
        if self.signature.iter().all(|byte| *byte == 0) {
            bail!("snapshot signature must not be empty");
        }
        if self.validators.is_empty() {
            bail!("snapshot validator set must not be empty");
        }
        if self.state.state_hash() != self.state_root {
            bail!("snapshot state root mismatch");
        }
        self.validator_set()?;
        let expected = self.compute_hash()?;
        if expected != self.snapshot_hash {
            bail!("snapshot hash mismatch");
        }
        Ok(())
    }

    fn compute_hash(&self) -> Result<LedgerHash> {
        let unsigned = self.encode_unsigned()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(SNAPSHOT_HASH_DOMAIN);
        hasher.update(&unsigned);
        Ok(*hasher.finalize().as_bytes())
    }

    fn encode_unsigned(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(SNAPSHOT_MAGIC);
        out.push(SNAPSHOT_VERSION);
        put_slot(&mut out, self.slot);
        out.extend_from_slice(&self.block_hash);
        out.extend_from_slice(&self.state_root);

        put_len(&mut out, self.state.accounts().count(), "account count")?;
        for account in self.state.accounts() {
            out.extend_from_slice(&account.address);
            out.extend_from_slice(&account.owner);
            out.extend_from_slice(&account.lamports.to_be_bytes());
            put_blob(&mut out, &account.data)?;
            out.extend_from_slice(&account.nonce.to_be_bytes());
        }

        put_len(&mut out, self.validators.len(), "validator count")?;
        for validator in &self.validators {
            put_string(&mut out, validator.validator_id.as_str())?;
            put_blob(&mut out, &validator.tls_spki_der)?;
            out.extend_from_slice(&validator.packet_signing_key);
            out.extend_from_slice(&validator.consensus_voting_key);
            out.extend_from_slice(&validator.voting_weight.to_be_bytes());
            put_slot(&mut out, validator.activation);
            put_optional_slot(&mut out, validator.deactivation);
        }

        encode_blocks(&mut out, &self.consensus.blocks)?;
        encode_votes(&mut out, &self.consensus.votes)?;
        encode_equivocations(&mut out, &self.consensus.equivocations)?;
        Ok(out)
    }
}

impl From<&ValidatorIdentityRecord> for SnapshotValidatorRecord {
    fn from(value: &ValidatorIdentityRecord) -> Self {
        Self {
            validator_id: value.validator_id.clone(),
            tls_spki_der: value.tls_spki_der.clone(),
            packet_signing_key: value.packet_signing_key,
            consensus_voting_key: value.consensus_voting_key,
            voting_weight: value.voting_weight,
            activation: value.activation,
            deactivation: value.deactivation,
        }
    }
}

impl From<&ConsensusSafetyState> for SnapshotConsensusState {
    fn from(value: &ConsensusSafetyState) -> Self {
        Self {
            blocks: value.blocks().cloned().collect(),
            votes: value.votes().collect(),
            equivocations: value.equivocations().to_vec(),
        }
    }
}

fn encode_blocks(out: &mut Vec<u8>, blocks: &[BlockInfo]) -> Result<()> {
    put_len(out, blocks.len(), "consensus block count")?;
    for block in blocks {
        put_slot(out, block.slot);
        out.extend_from_slice(&block.block_hash);
        out.extend_from_slice(&block.parent_hash);
        put_string(out, block.proposer.as_str())?;
    }
    Ok(())
}

fn decode_blocks(cursor: &mut Cursor<'_>) -> Result<Vec<BlockInfo>> {
    let count = cursor.u32()? as usize;
    let mut blocks = Vec::with_capacity(count);
    for _ in 0..count {
        blocks.push(BlockInfo {
            slot: cursor.slot()?,
            block_hash: cursor.hash()?,
            parent_hash: cursor.hash()?,
            proposer: ValidatorId::from_str(&cursor.string()?)?,
        });
    }
    Ok(blocks)
}

fn encode_votes(out: &mut Vec<u8>, votes: &[VoteRecord]) -> Result<()> {
    put_len(out, votes.len(), "consensus vote count")?;
    for vote in votes {
        put_slot(out, vote.slot);
        put_string(out, vote.validator_id.as_str())?;
        out.extend_from_slice(&vote.block_hash);
    }
    Ok(())
}

fn decode_votes(cursor: &mut Cursor<'_>) -> Result<Vec<VoteRecord>> {
    let count = cursor.u32()? as usize;
    let mut votes = Vec::with_capacity(count);
    for _ in 0..count {
        votes.push(VoteRecord {
            slot: cursor.slot()?,
            validator_id: ValidatorId::from_str(&cursor.string()?)?,
            block_hash: cursor.hash()?,
        });
    }
    Ok(votes)
}

fn encode_equivocations(out: &mut Vec<u8>, evidence: &[EquivocationEvidence]) -> Result<()> {
    put_len(out, evidence.len(), "equivocation count")?;
    for item in evidence {
        put_string(out, item.validator_id.as_str())?;
        put_slot(out, item.slot);
        out.extend_from_slice(&item.first_block_hash);
        out.extend_from_slice(&item.conflicting_block_hash);
    }
    Ok(())
}

fn decode_equivocations(cursor: &mut Cursor<'_>) -> Result<Vec<EquivocationEvidence>> {
    let count = cursor.u32()? as usize;
    let mut evidence = Vec::with_capacity(count);
    for _ in 0..count {
        evidence.push(EquivocationEvidence {
            validator_id: ValidatorId::from_str(&cursor.string()?)?,
            slot: cursor.slot()?,
            first_block_hash: cursor.hash()?,
            conflicting_block_hash: cursor.hash()?,
        });
    }
    Ok(evidence)
}

fn put_slot(out: &mut Vec<u8>, slot: EpochSlot) {
    out.extend_from_slice(&slot.epoch.to_be_bytes());
    out.extend_from_slice(&slot.slot.to_be_bytes());
}

fn put_optional_slot(out: &mut Vec<u8>, slot: Option<EpochSlot>) {
    match slot {
        Some(slot) => {
            out.push(1);
            put_slot(out, slot);
        }
        None => out.push(0),
    }
}

fn put_len(out: &mut Vec<u8>, len: usize, name: &str) -> Result<()> {
    let len = u32::try_from(len).map_err(|_| anyhow!("{name} exceeds u32 length"))?;
    out.extend_from_slice(&len.to_be_bytes());
    Ok(())
}

fn put_string(out: &mut Vec<u8>, value: &str) -> Result<()> {
    put_blob(out, value.as_bytes())
}

fn put_blob(out: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    if value.len() > MAX_BLOB_LEN {
        bail!("snapshot blob too large");
    }
    let len = u32::try_from(value.len()).map_err(|_| anyhow!("snapshot blob too large"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

struct Cursor<'a> {
    inner: WireCursor<'a>,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            inner: WireCursor::new(bytes, "snapshot"),
        }
    }

    fn magic(&mut self, expected: &[u8; 4]) -> Result<()> {
        self.inner.expect(expected, "invalid snapshot magic")
    }

    fn version(&mut self) -> Result<()> {
        let version = self.u8()?;
        if version != SNAPSHOT_VERSION {
            bail!("unsupported snapshot version");
        }
        Ok(())
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

    fn hash(&mut self) -> Result<LedgerHash> {
        Ok(self.take(32)?.try_into()?)
    }

    fn signature(&mut self) -> Result<[u8; SIGNATURE_LEN]> {
        Ok(self.take(SIGNATURE_LEN)?.try_into()?)
    }

    fn slot(&mut self) -> Result<EpochSlot> {
        Ok(EpochSlot::new(self.u64()?, self.u64()?))
    }

    fn optional_slot(&mut self) -> Result<Option<EpochSlot>> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.slot()?)),
            other => bail!("invalid optional slot flag {other}"),
        }
    }

    fn string(&mut self) -> Result<String> {
        Ok(std::str::from_utf8(&self.blob()?)?.to_string())
    }

    fn blob(&mut self) -> Result<Vec<u8>> {
        let len = self.u32()? as usize;
        if len > MAX_BLOB_LEN {
            bail!("snapshot blob too large");
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
    use crate::validator_set::{ValidatorIdentityRecord, ValidatorSet};

    fn hash(byte: u8) -> LedgerHash {
        [byte; 32]
    }

    fn validator_set() -> ValidatorSet {
        let mut set = ValidatorSet::default();
        set.insert(ValidatorIdentityRecord {
            validator_id: ValidatorId::from_str("validator-a").unwrap(),
            tls_spki_der: b"spki-a".to_vec(),
            packet_signing_key: hash(2),
            consensus_voting_key: hash(3),
            voting_weight: 10,
            activation: EpochSlot::new(0, 0),
            deactivation: None,
        })
        .unwrap();
        set
    }

    fn state() -> StateDb {
        let mut state = StateDb::default();
        state
            .insert(Account::new(hash(4), hash(5), 100, b"data".to_vec(), 7).unwrap())
            .unwrap();
        state
    }

    #[test]
    fn snapshot_roundtrip_validates_integrity() {
        let snapshot = LedgerSnapshot::create(
            EpochSlot::new(0, 9),
            hash(8),
            &state(),
            &validator_set(),
            &ConsensusSafetyState::default(),
            [1u8; SIGNATURE_LEN],
        )
        .unwrap();

        let decoded = LedgerSnapshot::decode(&snapshot.encode().unwrap()).unwrap();

        assert_eq!(decoded.slot, snapshot.slot);
        assert_eq!(decoded.block_hash, snapshot.block_hash);
        assert_eq!(decoded.state_root, snapshot.state_root);
        assert_eq!(decoded.state.state_hash(), snapshot.state.state_hash());
        assert_eq!(decoded.validator_set().unwrap().len(), 1);
    }

    #[test]
    fn corrupt_snapshot_is_rejected() {
        let snapshot = LedgerSnapshot::create(
            EpochSlot::new(0, 9),
            hash(8),
            &state(),
            &validator_set(),
            &ConsensusSafetyState::default(),
            [1u8; SIGNATURE_LEN],
        )
        .unwrap();
        let mut encoded = snapshot.encode().unwrap();
        encoded[20] ^= 0xff;

        assert!(LedgerSnapshot::decode(&encoded).is_err());
    }
}
