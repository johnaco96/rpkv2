use crate::{
    consensus_messages::{
        BlockProposal, ConsensusMessageVerifier, EquivocationEvidence, Vote, VoteOutcome,
    },
    identity::ValidatorId,
    validator_set::EpochSlot,
};
use anyhow::{Result, anyhow, bail};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    str::FromStr,
};

const STATE_HEADER: &str = "rpkv2.consensus_safety.v1";
const ZERO_HASH: [u8; 32] = [0u8; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockInfo {
    pub slot: EpochSlot,
    pub block_hash: [u8; 32],
    pub parent_hash: [u8; 32],
    pub proposer: ValidatorId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoteRecord {
    pub slot: EpochSlot,
    pub validator_id: ValidatorId,
    pub block_hash: [u8; 32],
}

#[derive(Clone, Debug, Default)]
pub struct ConsensusSafetyState {
    blocks: BTreeMap<[u8; 32], BlockInfo>,
    votes: BTreeMap<(EpochSlot, ValidatorId), [u8; 32]>,
    latest_vote_by_validator: BTreeMap<ValidatorId, VoteRecord>,
    equivocations: Vec<EquivocationEvidence>,
}

impl ConsensusSafetyState {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Self::default());
        }

        let file = File::open(path)?;
        let mut lines = BufReader::new(file).lines();
        let Some(header) = lines.next() else {
            bail!("consensus safety state is empty");
        };
        if header? != STATE_HEADER {
            bail!("unsupported consensus safety state format");
        }

        let mut state = Self::default();
        for line in lines {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            state.parse_line(&line)?;
        }
        Ok(state)
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let tmp = temp_path(path)?;
        let mut file = File::create(&tmp)?;
        writeln!(file, "{STATE_HEADER}")?;
        for block in self.blocks.values() {
            writeln!(
                file,
                "block {} {} {} {} {}",
                block.slot.epoch,
                block.slot.slot,
                hex(&block.block_hash),
                hex(&block.parent_hash),
                block.proposer
            )?;
        }
        for ((slot, validator_id), block_hash) in &self.votes {
            writeln!(
                file,
                "vote {} {} {} {}",
                slot.epoch,
                slot.slot,
                validator_id,
                hex(block_hash)
            )?;
        }
        for evidence in &self.equivocations {
            writeln!(
                file,
                "equivocation {} {} {} {} {}",
                evidence.slot.epoch,
                evidence.slot.slot,
                evidence.validator_id,
                hex(&evidence.first_block_hash),
                hex(&evidence.conflicting_block_hash)
            )?;
        }
        file.sync_all()?;
        drop(file);
        fs::rename(tmp, path)?;
        Ok(())
    }

    pub fn record_proposal(
        &mut self,
        verifier: &ConsensusMessageVerifier<'_>,
        proposal: &BlockProposal,
    ) -> Result<()> {
        verifier.validate_block_proposal(proposal)?;
        if proposal.parent_hash != ZERO_HASH && !self.blocks.contains_key(&proposal.parent_hash) {
            bail!("proposal parent block is unknown");
        }
        if proposal.parent_hash == proposal.block_hash {
            bail!("proposal cannot parent itself");
        }
        self.blocks
            .entry(proposal.block_hash)
            .or_insert_with(|| BlockInfo {
                slot: proposal.slot,
                block_hash: proposal.block_hash,
                parent_hash: proposal.parent_hash,
                proposer: proposal.proposer.clone(),
            });
        Ok(())
    }

    #[cfg(feature = "ed25519")]
    pub fn create_local_vote(
        &mut self,
        local_validator_id: ValidatorId,
        block_hash: [u8; 32],
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<Vote> {
        let block = self
            .blocks
            .get(&block_hash)
            .ok_or_else(|| anyhow!("cannot vote for unknown block"))?;
        self.ensure_safe_vote(&local_validator_id, block)?;
        let vote = Vote::sign(block.slot, local_validator_id, block_hash, signing_key);
        self.record_valid_vote(&vote)?;
        Ok(vote)
    }

    pub fn accept_peer_vote(
        &mut self,
        verifier: &ConsensusMessageVerifier<'_>,
        vote: &Vote,
    ) -> Result<VoteOutcome> {
        verifier.validate_vote(vote)?;
        let block = self
            .blocks
            .get(&vote.block_hash)
            .ok_or_else(|| anyhow!("peer vote references unknown block"))?;
        if self.votes.contains_key(&(vote.slot, vote.voter.clone())) {
            return self.record_valid_vote(vote);
        }
        self.ensure_safe_vote(&vote.voter, block)?;
        self.record_valid_vote(vote)
    }

    pub fn blocks(&self) -> impl Iterator<Item = &BlockInfo> {
        self.blocks.values()
    }

    pub fn votes(&self) -> impl Iterator<Item = VoteRecord> + '_ {
        self.votes
            .iter()
            .map(|((slot, validator_id), block_hash)| VoteRecord {
                slot: *slot,
                validator_id: validator_id.clone(),
                block_hash: *block_hash,
            })
    }

    pub fn equivocations(&self) -> &[EquivocationEvidence] {
        &self.equivocations
    }

    fn ensure_safe_vote(&self, validator_id: &ValidatorId, block: &BlockInfo) -> Result<()> {
        let Some(previous) = self.latest_vote_by_validator.get(validator_id) else {
            return Ok(());
        };
        if block.slot <= previous.slot {
            bail!("vote does not advance beyond validator's latest vote");
        }
        if !self.descends_from(block.block_hash, previous.block_hash) {
            bail!("vote would switch to a fork that does not build on prior vote");
        }
        Ok(())
    }

    fn record_valid_vote(&mut self, vote: &Vote) -> Result<VoteOutcome> {
        match self.votes.get(&(vote.slot, vote.voter.clone())) {
            None => {
                self.votes
                    .insert((vote.slot, vote.voter.clone()), vote.block_hash);
                self.update_latest_vote(vote);
                Ok(VoteOutcome::Counted)
            }
            Some(existing) if existing == &vote.block_hash => Ok(VoteOutcome::Duplicate),
            Some(existing) => {
                let evidence = EquivocationEvidence {
                    validator_id: vote.voter.clone(),
                    slot: vote.slot,
                    first_block_hash: *existing,
                    conflicting_block_hash: vote.block_hash,
                };
                self.equivocations.push(evidence.clone());
                Ok(VoteOutcome::Conflicting(evidence))
            }
        }
    }

    fn update_latest_vote(&mut self, vote: &Vote) {
        let record = VoteRecord {
            slot: vote.slot,
            validator_id: vote.voter.clone(),
            block_hash: vote.block_hash,
        };
        self.latest_vote_by_validator
            .entry(vote.voter.clone())
            .and_modify(|latest| {
                if record.slot > latest.slot {
                    *latest = record.clone();
                }
            })
            .or_insert(record);
    }

    fn descends_from(&self, mut block_hash: [u8; 32], ancestor_hash: [u8; 32]) -> bool {
        while block_hash != ZERO_HASH {
            if block_hash == ancestor_hash {
                return true;
            }
            let Some(block) = self.blocks.get(&block_hash) else {
                return false;
            };
            block_hash = block.parent_hash;
        }
        false
    }

    fn parse_line(&mut self, line: &str) -> Result<()> {
        let parts: Vec<_> = line.split_whitespace().collect();
        match parts.as_slice() {
            ["block", epoch, slot, block_hash, parent_hash, proposer] => {
                let block = BlockInfo {
                    slot: EpochSlot::new(parse_u64(epoch)?, parse_u64(slot)?),
                    block_hash: parse_hash(block_hash)?,
                    parent_hash: parse_hash(parent_hash)?,
                    proposer: ValidatorId::from_str(proposer)?,
                };
                self.blocks.insert(block.block_hash, block);
            }
            ["vote", epoch, slot, validator_id, block_hash] => {
                let vote = Vote {
                    slot: EpochSlot::new(parse_u64(epoch)?, parse_u64(slot)?),
                    voter: ValidatorId::from_str(validator_id)?,
                    block_hash: parse_hash(block_hash)?,
                    signature: [0u8; 64],
                };
                self.record_valid_vote(&vote)?;
            }
            [
                "equivocation",
                epoch,
                slot,
                validator_id,
                first,
                conflicting,
            ] => {
                self.equivocations.push(EquivocationEvidence {
                    validator_id: ValidatorId::from_str(validator_id)?,
                    slot: EpochSlot::new(parse_u64(epoch)?, parse_u64(slot)?),
                    first_block_hash: parse_hash(first)?,
                    conflicting_block_hash: parse_hash(conflicting)?,
                });
            }
            _ => bail!("invalid consensus safety state line: {line}"),
        }
        Ok(())
    }
}

fn parse_u64(value: &str) -> Result<u64> {
    value
        .parse()
        .map_err(|e| anyhow!("invalid integer in consensus safety state: {e}"))
}

fn parse_hash(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64 {
        bail!("hash must be 64 hex characters");
    }
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        let start = index * 2;
        *byte = u8::from_str_radix(&value[start..start + 2], 16)
            .map_err(|_| anyhow!("hash contains non-hex characters"))?;
    }
    Ok(out)
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn temp_path(path: &Path) -> Result<PathBuf> {
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("consensus safety state path must include a file name"))?;
    Ok(path.with_file_name(format!("{}.tmp", file_name.to_string_lossy())))
}

#[cfg(all(test, feature = "ed25519"))]
mod tests {
    use super::*;
    use crate::{
        consensus_messages::ConsensusMessageVerifier,
        validator_set::{ValidatorIdentityConfig, ValidatorSet, ValidatorSetConfig},
    };
    use ed25519_dalek::SigningKey;
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir() -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "rpkv2-consensus-safety-test-{}-{suffix}-{counter}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn bytes_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn verify_key_hex(signing_key: &SigningKey) -> String {
        bytes_hex(&signing_key.verifying_key().to_bytes())
    }

    fn validator_config(
        id: &str,
        packet_seed: u8,
        consensus_key: &SigningKey,
        weight: u64,
    ) -> ValidatorIdentityConfig {
        ValidatorIdentityConfig {
            validator_id: id.to_string(),
            tls_spki_hex: bytes_hex(format!("{id}-spki").as_bytes()),
            packet_signing_key_hex: verify_key_hex(&key(packet_seed)),
            consensus_voting_key_hex: verify_key_hex(consensus_key),
            voting_weight: weight,
            activation_epoch: 0,
            activation_slot: 0,
            deactivation_epoch: None,
            deactivation_slot: None,
        }
    }

    fn fixture() -> (ValidatorSet, SigningKey, SigningKey) {
        let local_key = key(101);
        let peer_key = key(102);
        let set = ValidatorSet::from_config(ValidatorSetConfig {
            validators: vec![
                validator_config("validator-a", 1, &local_key, 1),
                validator_config("validator-b", 2, &peer_key, 1),
            ],
        })
        .unwrap();
        (set, local_key, peer_key)
    }

    fn validator_id(id: &str) -> ValidatorId {
        ValidatorId::from_str(id).unwrap()
    }

    fn hash(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn proposal(
        slot: u64,
        proposer: &str,
        parent_hash: [u8; 32],
        block_hash: [u8; 32],
        signing_key: &SigningKey,
    ) -> BlockProposal {
        BlockProposal::sign(
            EpochSlot::new(0, slot),
            validator_id(proposer),
            parent_hash,
            block_hash,
            hash(99),
            signing_key,
        )
    }

    #[test]
    fn local_node_refuses_unsafe_fork_vote() {
        let (set, local_key, peer_key) = fixture();
        let verifier = ConsensusMessageVerifier::new(&set);
        let mut safety = ConsensusSafetyState::default();
        let block_a = proposal(0, "validator-a", ZERO_HASH, hash(1), &local_key);
        let block_b = proposal(1, "validator-b", hash(1), hash(2), &peer_key);
        let fork_b = proposal(1, "validator-b", ZERO_HASH, hash(3), &peer_key);
        safety.record_proposal(&verifier, &block_a).unwrap();
        safety.record_proposal(&verifier, &block_b).unwrap();
        safety.record_proposal(&verifier, &fork_b).unwrap();

        safety
            .create_local_vote(validator_id("validator-a"), hash(1), &local_key)
            .unwrap();
        safety
            .create_local_vote(validator_id("validator-a"), hash(2), &local_key)
            .unwrap();

        let result = safety.create_local_vote(validator_id("validator-a"), hash(3), &local_key);

        assert!(result.is_err());
    }

    #[test]
    fn peer_vote_that_switches_fork_is_rejected() {
        let (set, local_key, peer_key) = fixture();
        let verifier = ConsensusMessageVerifier::new(&set);
        let mut safety = ConsensusSafetyState::default();
        let block_a = proposal(0, "validator-a", ZERO_HASH, hash(1), &local_key);
        let block_b = proposal(1, "validator-b", hash(1), hash(2), &peer_key);
        let fork_b = proposal(1, "validator-b", ZERO_HASH, hash(3), &peer_key);
        safety.record_proposal(&verifier, &block_a).unwrap();
        safety.record_proposal(&verifier, &block_b).unwrap();
        safety.record_proposal(&verifier, &fork_b).unwrap();
        let vote_a = Vote::sign(
            EpochSlot::new(0, 0),
            validator_id("validator-b"),
            hash(1),
            &peer_key,
        );
        let unsafe_vote = Vote::sign(
            EpochSlot::new(0, 1),
            validator_id("validator-b"),
            hash(3),
            &peer_key,
        );

        assert_eq!(
            safety.accept_peer_vote(&verifier, &vote_a).unwrap(),
            VoteOutcome::Counted
        );
        assert!(safety.accept_peer_vote(&verifier, &unsafe_vote).is_err());
    }

    #[test]
    fn restart_does_not_forget_local_vote_safety() {
        let (set, local_key, peer_key) = fixture();
        let verifier = ConsensusMessageVerifier::new(&set);
        let dir = temp_dir();
        let path = dir.join("consensus-safety.state");
        let mut safety = ConsensusSafetyState::default();
        let block_a = proposal(0, "validator-a", ZERO_HASH, hash(1), &local_key);
        let fork_b = proposal(1, "validator-b", ZERO_HASH, hash(3), &peer_key);
        safety.record_proposal(&verifier, &block_a).unwrap();
        safety.record_proposal(&verifier, &fork_b).unwrap();
        safety
            .create_local_vote(validator_id("validator-a"), hash(1), &local_key)
            .unwrap();
        safety.save(&path).unwrap();

        let mut restarted = ConsensusSafetyState::load(&path).unwrap();
        let result = restarted.create_local_vote(validator_id("validator-a"), hash(3), &local_key);

        assert!(result.is_err());
    }

    #[test]
    fn conflicting_vote_evidence_is_retained_after_restart() {
        let (set, local_key, peer_key) = fixture();
        let verifier = ConsensusMessageVerifier::new(&set);
        let dir = temp_dir();
        let path = dir.join("consensus-safety.state");
        let mut safety = ConsensusSafetyState::default();
        let block_a = proposal(0, "validator-a", ZERO_HASH, hash(1), &local_key);
        let fork_a = proposal(0, "validator-a", ZERO_HASH, hash(4), &local_key);
        safety.record_proposal(&verifier, &block_a).unwrap();
        safety.record_proposal(&verifier, &fork_a).unwrap();
        let vote_a = Vote::sign(
            EpochSlot::new(0, 0),
            validator_id("validator-b"),
            hash(1),
            &peer_key,
        );
        let vote_b = Vote::sign(
            EpochSlot::new(0, 0),
            validator_id("validator-b"),
            hash(4),
            &peer_key,
        );

        assert_eq!(
            safety.accept_peer_vote(&verifier, &vote_a).unwrap(),
            VoteOutcome::Counted
        );
        assert!(matches!(
            safety.accept_peer_vote(&verifier, &vote_b).unwrap(),
            VoteOutcome::Conflicting(_)
        ));
        safety.save(&path).unwrap();

        let restarted = ConsensusSafetyState::load(&path).unwrap();

        assert_eq!(restarted.equivocations().len(), 1);
        assert_eq!(restarted.equivocations()[0].first_block_hash, hash(1));
        assert_eq!(restarted.equivocations()[0].conflicting_block_hash, hash(4));
    }
}
