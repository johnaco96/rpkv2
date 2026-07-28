use crate::{
    identity::ValidatorId,
    leader_schedule::{LeaderSchedule, ProductionKind},
    validator_set::{EpochSlot, ValidatorSet},
};
use anyhow::{Result, anyhow, bail};
use std::{collections::BTreeMap, str::FromStr};

const DOMAIN: &[u8] = b"rpkv2.consensus.v1";
const WIRE_MAGIC: &[u8; 4] = b"RPKC";
pub const CONSENSUS_MESSAGE_VERSION: u8 = 1;
const KIND_BLOCK_PROPOSAL: u8 = 1;
const KIND_VOTE: u8 = 2;
const SIGNATURE_LEN: usize = 64;
const HASH_LEN: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockProposal {
    pub slot: EpochSlot,
    pub proposer: ValidatorId,
    pub parent_hash: [u8; 32],
    pub block_hash: [u8; 32],
    pub payload_hash: [u8; 32],
    pub signature: [u8; 64],
}

impl BlockProposal {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = encode_prefix(KIND_BLOCK_PROPOSAL, self.slot, &self.proposer);
        out.extend_from_slice(&self.parent_hash);
        out.extend_from_slice(&self.block_hash);
        out.extend_from_slice(&self.payload_hash);
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn signing_preimage(&self) -> Vec<u8> {
        block_proposal_preimage(
            self.slot,
            &self.proposer,
            self.parent_hash,
            self.block_hash,
            self.payload_hash,
        )
    }

    #[cfg(feature = "ed25519")]
    pub fn sign(
        slot: EpochSlot,
        proposer: ValidatorId,
        parent_hash: [u8; 32],
        block_hash: [u8; 32],
        payload_hash: [u8; 32],
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Self {
        use ed25519_dalek::Signer;

        let preimage =
            block_proposal_preimage(slot, &proposer, parent_hash, block_hash, payload_hash);
        let signature = signing_key.sign(&preimage).to_bytes();
        Self {
            slot,
            proposer,
            parent_hash,
            block_hash,
            payload_hash,
            signature,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vote {
    pub slot: EpochSlot,
    pub voter: ValidatorId,
    pub block_hash: [u8; 32],
    pub signature: [u8; 64],
}

impl Vote {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = encode_prefix(KIND_VOTE, self.slot, &self.voter);
        out.extend_from_slice(&self.block_hash);
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn signing_preimage(&self) -> Vec<u8> {
        vote_preimage(self.slot, &self.voter, self.block_hash)
    }

    #[cfg(feature = "ed25519")]
    pub fn sign(
        slot: EpochSlot,
        voter: ValidatorId,
        block_hash: [u8; 32],
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Self {
        use ed25519_dalek::Signer;

        let preimage = vote_preimage(slot, &voter, block_hash);
        let signature = signing_key.sign(&preimage).to_bytes();
        Self {
            slot,
            voter,
            block_hash,
            signature,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConsensusMessage {
    BlockProposal(BlockProposal),
    Vote(Vote),
}

impl ConsensusMessage {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::BlockProposal(proposal) => proposal.encode(),
            Self::Vote(vote) => vote.encode(),
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        cursor.expect(WIRE_MAGIC)?;
        let version = cursor.u8()?;
        if version != CONSENSUS_MESSAGE_VERSION {
            bail!("unsupported consensus message version: {version}");
        }
        let kind = cursor.u8()?;
        let slot = EpochSlot::new(cursor.u64()?, cursor.u64()?);
        let validator_id = cursor.validator_id()?;

        let message = match kind {
            KIND_BLOCK_PROPOSAL => {
                let parent_hash = cursor.hash()?;
                let block_hash = cursor.hash()?;
                let payload_hash = cursor.hash()?;
                let signature = cursor.signature()?;
                Self::BlockProposal(BlockProposal {
                    slot,
                    proposer: validator_id,
                    parent_hash,
                    block_hash,
                    payload_hash,
                    signature,
                })
            }
            KIND_VOTE => {
                let block_hash = cursor.hash()?;
                let signature = cursor.signature()?;
                Self::Vote(Vote {
                    slot,
                    voter: validator_id,
                    block_hash,
                    signature,
                })
            }
            _ => bail!("unknown consensus message kind: {kind}"),
        };
        cursor.finish()?;
        Ok(message)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EquivocationEvidence {
    pub validator_id: ValidatorId,
    pub slot: EpochSlot,
    pub first_block_hash: [u8; 32],
    pub conflicting_block_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VoteOutcome {
    Counted,
    Duplicate,
    Conflicting(EquivocationEvidence),
}

#[derive(Clone, Debug, Default)]
pub struct ConsensusReplayState {
    votes: BTreeMap<(EpochSlot, ValidatorId), [u8; 32]>,
    equivocations: Vec<EquivocationEvidence>,
}

impl ConsensusReplayState {
    pub fn record_vote(&mut self, vote: &Vote) -> VoteOutcome {
        let key = (vote.slot, vote.voter.clone());
        match self.votes.get(&key) {
            None => {
                self.votes.insert(key, vote.block_hash);
                VoteOutcome::Counted
            }
            Some(existing) if existing == &vote.block_hash => VoteOutcome::Duplicate,
            Some(existing) => {
                let evidence = EquivocationEvidence {
                    validator_id: vote.voter.clone(),
                    slot: vote.slot,
                    first_block_hash: *existing,
                    conflicting_block_hash: vote.block_hash,
                };
                self.equivocations.push(evidence.clone());
                VoteOutcome::Conflicting(evidence)
            }
        }
    }

    pub fn equivocations(&self) -> &[EquivocationEvidence] {
        &self.equivocations
    }
}

pub struct ConsensusMessageVerifier<'a> {
    validator_set: &'a ValidatorSet,
    leader_schedule: LeaderSchedule<'a>,
    replay: ConsensusReplayState,
}

impl<'a> ConsensusMessageVerifier<'a> {
    pub fn new(validator_set: &'a ValidatorSet) -> Self {
        Self {
            validator_set,
            leader_schedule: LeaderSchedule::new(validator_set),
            replay: ConsensusReplayState::default(),
        }
    }

    pub fn validate_block_proposal(&self, proposal: &BlockProposal) -> Result<()> {
        ensure_nonzero_hash("block_hash", &proposal.block_hash)?;
        ensure_nonzero_hash("payload_hash", &proposal.payload_hash)?;
        self.leader_schedule.authorize_production(
            &proposal.proposer,
            proposal.slot,
            ProductionKind::Block,
        )?;
        let validator = self
            .validator_set
            .get(&proposal.proposer)
            .ok_or_else(|| anyhow!("unknown proposal validator {}", proposal.proposer))?;
        if !validator.is_active_at(proposal.slot) {
            bail!("inactive proposal validator {}", proposal.proposer);
        }
        verify_consensus_signature(
            &validator.consensus_voting_key,
            &proposal.signing_preimage(),
            &proposal.signature,
        )
    }

    pub fn validate_vote(&self, vote: &Vote) -> Result<()> {
        ensure_nonzero_hash("block_hash", &vote.block_hash)?;
        let validator = self
            .validator_set
            .get(&vote.voter)
            .ok_or_else(|| anyhow!("unknown vote validator {}", vote.voter))?;
        if !validator.is_active_at(vote.slot) {
            bail!("inactive vote validator {}", vote.voter);
        }
        verify_consensus_signature(
            &validator.consensus_voting_key,
            &vote.signing_preimage(),
            &vote.signature,
        )
    }

    pub fn accept_vote(&mut self, vote: &Vote) -> Result<VoteOutcome> {
        self.validate_vote(vote)?;
        Ok(self.replay.record_vote(vote))
    }

    pub fn replay_state(&self) -> &ConsensusReplayState {
        &self.replay
    }
}

fn block_proposal_preimage(
    slot: EpochSlot,
    proposer: &ValidatorId,
    parent_hash: [u8; 32],
    block_hash: [u8; 32],
    payload_hash: [u8; 32],
) -> Vec<u8> {
    let mut out = signing_prefix(KIND_BLOCK_PROPOSAL, slot, proposer);
    out.extend_from_slice(&parent_hash);
    out.extend_from_slice(&block_hash);
    out.extend_from_slice(&payload_hash);
    out
}

fn vote_preimage(slot: EpochSlot, voter: &ValidatorId, block_hash: [u8; 32]) -> Vec<u8> {
    let mut out = signing_prefix(KIND_VOTE, slot, voter);
    out.extend_from_slice(&block_hash);
    out
}

fn encode_prefix(kind: u8, slot: EpochSlot, validator_id: &ValidatorId) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(WIRE_MAGIC);
    out.push(CONSENSUS_MESSAGE_VERSION);
    out.push(kind);
    encode_slot(&mut out, slot);
    encode_validator_id(&mut out, validator_id);
    out
}

fn signing_prefix(kind: u8, slot: EpochSlot, validator_id: &ValidatorId) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(DOMAIN);
    out.push(CONSENSUS_MESSAGE_VERSION);
    out.push(kind);
    encode_slot(&mut out, slot);
    encode_validator_id(&mut out, validator_id);
    out
}

fn encode_slot(out: &mut Vec<u8>, slot: EpochSlot) {
    out.extend_from_slice(&slot.epoch.to_be_bytes());
    out.extend_from_slice(&slot.slot.to_be_bytes());
}

fn encode_validator_id(out: &mut Vec<u8>, validator_id: &ValidatorId) {
    let bytes = validator_id.as_str().as_bytes();
    let len = u16::try_from(bytes.len()).expect("validator id length exceeds wire format");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

fn ensure_nonzero_hash(field: &str, hash: &[u8; 32]) -> Result<()> {
    if hash.iter().all(|byte| *byte == 0) {
        bail!("{field} must not be all zeros");
    }
    Ok(())
}

#[cfg(feature = "ed25519")]
fn verify_consensus_signature(
    consensus_voting_key: &[u8; 32],
    preimage: &[u8],
    signature: &[u8; 64],
) -> Result<()> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let key = VerifyingKey::from_bytes(consensus_voting_key)
        .map_err(|e| anyhow!("invalid consensus voting key: {e}"))?;
    let signature = Signature::from_bytes(signature);
    key.verify(preimage, &signature)
        .map_err(|e| anyhow!("invalid consensus message signature: {e}"))?;
    Ok(())
}

#[cfg(not(feature = "ed25519"))]
fn verify_consensus_signature(
    _consensus_voting_key: &[u8; 32],
    _preimage: &[u8],
    _signature: &[u8; 64],
) -> Result<()> {
    bail!("consensus message verification requires the ed25519 feature")
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn expect(&mut self, expected: &[u8]) -> Result<()> {
        let actual = self.take(expected.len())?;
        if actual != expected {
            bail!("invalid consensus message magic");
        }
        Ok(())
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u64(&mut self) -> Result<u64> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes(
            bytes.try_into().expect("cursor returned exact u64 length"),
        ))
    }

    fn validator_id(&mut self) -> Result<ValidatorId> {
        let len = usize::from(self.u16()?);
        let bytes = self.take(len)?;
        let value = std::str::from_utf8(bytes).map_err(|_| anyhow!("validator id is not UTF-8"))?;
        ValidatorId::from_str(value)
    }

    fn hash(&mut self) -> Result<[u8; 32]> {
        let bytes = self.take(HASH_LEN)?;
        Ok(bytes.try_into().expect("cursor returned exact hash length"))
    }

    fn signature(&mut self) -> Result<[u8; 64]> {
        let bytes = self.take(SIGNATURE_LEN)?;
        Ok(bytes
            .try_into()
            .expect("cursor returned exact signature length"))
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| anyhow!("consensus message length overflow"))?;
        if end > self.bytes.len() {
            bail!("truncated consensus message");
        }
        let out = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(out)
    }

    fn finish(&self) -> Result<()> {
        if self.offset != self.bytes.len() {
            bail!("consensus message has trailing bytes");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator_set::{ValidatorIdentityConfig, ValidatorSetConfig};
    use ed25519_dalek::SigningKey;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn verify_key_hex(signing_key: &SigningKey) -> String {
        hex(&signing_key.verifying_key().to_bytes())
    }

    fn validator_config(
        id: &str,
        packet_seed: u8,
        consensus_key: &SigningKey,
        weight: u64,
    ) -> ValidatorIdentityConfig {
        ValidatorIdentityConfig {
            validator_id: id.to_string(),
            tls_spki_hex: hex(format!("{id}-spki").as_bytes()),
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
        let leader_key = key(101);
        let voter_key = key(102);
        let set = ValidatorSet::from_config(ValidatorSetConfig {
            validators: vec![
                validator_config("validator-a", 1, &leader_key, 1),
                validator_config("validator-b", 2, &voter_key, 3),
            ],
        })
        .unwrap();
        (set, leader_key, voter_key)
    }

    fn validator_id(id: &str) -> ValidatorId {
        ValidatorId::from_str(id).unwrap()
    }

    fn hash(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn block_proposal_encode_decode_roundtrip() {
        let (_, leader_key, _) = fixture();
        let proposal = BlockProposal::sign(
            EpochSlot::new(0, 0),
            validator_id("validator-a"),
            hash(1),
            hash(2),
            hash(3),
            &leader_key,
        );

        let decoded = ConsensusMessage::decode(&proposal.encode()).unwrap();

        assert_eq!(decoded, ConsensusMessage::BlockProposal(proposal));
    }

    #[test]
    fn vote_encode_decode_roundtrip() {
        let (_, _, voter_key) = fixture();
        let vote = Vote::sign(
            EpochSlot::new(0, 0),
            validator_id("validator-b"),
            hash(2),
            &voter_key,
        );

        let decoded = ConsensusMessage::decode(&vote.encode()).unwrap();

        assert_eq!(decoded, ConsensusMessage::Vote(vote));
    }

    #[test]
    fn valid_leader_proposal_is_accepted() {
        let (set, leader_key, _) = fixture();
        let verifier = ConsensusMessageVerifier::new(&set);
        let proposal = BlockProposal::sign(
            EpochSlot::new(0, 0),
            validator_id("validator-a"),
            hash(1),
            hash(2),
            hash(3),
            &leader_key,
        );

        verifier.validate_block_proposal(&proposal).unwrap();
    }

    #[test]
    fn non_leader_proposal_is_rejected() {
        let (set, _, voter_key) = fixture();
        let verifier = ConsensusMessageVerifier::new(&set);
        let proposal = BlockProposal::sign(
            EpochSlot::new(0, 0),
            validator_id("validator-b"),
            hash(1),
            hash(2),
            hash(3),
            &voter_key,
        );

        assert!(verifier.validate_block_proposal(&proposal).is_err());
    }

    #[test]
    fn mutated_signature_is_rejected() {
        let (set, leader_key, _) = fixture();
        let verifier = ConsensusMessageVerifier::new(&set);
        let mut proposal = BlockProposal::sign(
            EpochSlot::new(0, 0),
            validator_id("validator-a"),
            hash(1),
            hash(2),
            hash(3),
            &leader_key,
        );
        proposal.block_hash = hash(9);

        assert!(verifier.validate_block_proposal(&proposal).is_err());
    }

    #[test]
    fn valid_vote_is_counted_once_and_duplicate_is_rejected() {
        let (set, _, voter_key) = fixture();
        let mut verifier = ConsensusMessageVerifier::new(&set);
        let vote = Vote::sign(
            EpochSlot::new(0, 0),
            validator_id("validator-b"),
            hash(2),
            &voter_key,
        );

        assert_eq!(verifier.accept_vote(&vote).unwrap(), VoteOutcome::Counted);
        assert_eq!(verifier.accept_vote(&vote).unwrap(), VoteOutcome::Duplicate);
    }

    #[test]
    fn conflicting_vote_is_detected_and_recorded() {
        let (set, _, voter_key) = fixture();
        let mut verifier = ConsensusMessageVerifier::new(&set);
        let vote_a = Vote::sign(
            EpochSlot::new(0, 0),
            validator_id("validator-b"),
            hash(2),
            &voter_key,
        );
        let vote_b = Vote::sign(
            EpochSlot::new(0, 0),
            validator_id("validator-b"),
            hash(3),
            &voter_key,
        );

        assert_eq!(verifier.accept_vote(&vote_a).unwrap(), VoteOutcome::Counted);
        let VoteOutcome::Conflicting(evidence) = verifier.accept_vote(&vote_b).unwrap() else {
            panic!("expected conflicting vote evidence");
        };

        assert_eq!(evidence.validator_id, validator_id("validator-b"));
        assert_eq!(evidence.first_block_hash, hash(2));
        assert_eq!(evidence.conflicting_block_hash, hash(3));
        assert_eq!(verifier.replay_state().equivocations().len(), 1);
    }

    #[test]
    fn vote_signed_by_wrong_key_is_rejected() {
        let (set, leader_key, _) = fixture();
        let verifier = ConsensusMessageVerifier::new(&set);
        let vote = Vote::sign(
            EpochSlot::new(0, 0),
            validator_id("validator-b"),
            hash(2),
            &leader_key,
        );

        assert!(verifier.validate_vote(&vote).is_err());
    }

    #[test]
    fn malformed_decode_is_rejected() {
        assert!(ConsensusMessage::decode(&[]).is_err());
        assert!(ConsensusMessage::decode(b"RPKC\x02").is_err());
    }
}
