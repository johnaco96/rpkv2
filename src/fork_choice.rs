use crate::{
    consensus_messages::Vote,
    fork_tree::{ForkTip, ForkTree},
    identity::ValidatorId,
    leader_schedule::{LeaderSchedule, ProductionKind},
    ledger::{LedgerBlock, LedgerHash},
    replay::GENESIS_PARENT_HASH,
    validator_set::{EpochSlot, ValidatorSet},
};
use anyhow::{Result, bail};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalityConfig {
    pub threshold_numerator: u64,
    pub threshold_denominator: u64,
}

impl Default for FinalityConfig {
    fn default() -> Self {
        Self {
            threshold_numerator: 2,
            threshold_denominator: 3,
        }
    }
}

impl FinalityConfig {
    pub fn validate(self) -> Result<()> {
        if self.threshold_denominator == 0 {
            bail!("finality threshold denominator must be greater than zero");
        }
        if self.threshold_numerator == 0 {
            bail!("finality threshold numerator must be greater than zero");
        }
        if self.threshold_numerator > self.threshold_denominator {
            bail!("finality threshold numerator cannot exceed denominator");
        }
        Ok(())
    }

    pub fn required_stake(self, total_stake: u64) -> Result<u64> {
        self.validate()?;
        if total_stake == 0 {
            bail!("cannot compute finality threshold with zero total stake");
        }
        let numerator = u128::from(total_stake)
            .checked_mul(u128::from(self.threshold_numerator))
            .ok_or_else(|| anyhow::anyhow!("finality threshold overflow"))?;
        let denominator = u128::from(self.threshold_denominator);
        let required = numerator.div_ceil(denominator);
        u64::try_from(required).map_err(|_| anyhow::anyhow!("finality threshold exceeds u64"))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalityUpdate {
    pub finalized_root: LedgerHash,
    pub finalized_slot: EpochSlot,
    pub supporting_stake: u64,
    pub required_stake: u64,
    pub pruned_blocks: Vec<LedgerHash>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForkChoiceTip {
    pub block_hash: LedgerHash,
    pub slot: EpochSlot,
    pub voted_stake: u64,
    pub latest_vote_slot: Option<EpochSlot>,
    pub cumulative_weight: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForkChoiceVoteOutcome {
    Counted,
    Duplicate,
    Stale,
    Conflicting,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LatestVote {
    slot: EpochSlot,
    block_hash: LedgerHash,
    weight: u64,
}

#[derive(Clone, Debug)]
pub struct ForkChoice {
    tree: ForkTree,
    latest_votes: BTreeMap<ValidatorId, LatestVote>,
    direct_vote_weight: BTreeMap<LedgerHash, u64>,
}

impl Default for ForkChoice {
    fn default() -> Self {
        Self::new(ForkTree::default())
    }
}

impl ForkChoice {
    pub fn new(tree: ForkTree) -> Self {
        Self {
            tree,
            latest_votes: BTreeMap::new(),
            direct_vote_weight: BTreeMap::new(),
        }
    }

    pub fn tree(&self) -> &ForkTree {
        &self.tree
    }

    pub fn insert_block(&mut self, block: &LedgerBlock, base_weight: u64) -> Result<()> {
        self.ensure_block_can_extend_finalized_root(block)?;
        self.tree.insert_block(block, base_weight)
    }

    pub fn insert_authorized_block(
        &mut self,
        block: &LedgerBlock,
        base_weight: u64,
        leader_schedule: &LeaderSchedule<'_>,
    ) -> Result<()> {
        leader_schedule.authorize_production(&block.producer, block.slot, ProductionKind::Block)?;
        self.insert_block(block, base_weight)
    }

    pub fn record_vote(
        &mut self,
        vote: &Vote,
        validator_set: &ValidatorSet,
    ) -> Result<ForkChoiceVoteOutcome> {
        let voted_block = self
            .tree
            .get(&vote.block_hash)
            .ok_or_else(|| anyhow::anyhow!("cannot count vote for unknown block"))?;
        if !voted_block.connected {
            bail!("cannot count vote for orphan block");
        }
        let finalized_root = self.tree.finalized_root();
        if finalized_root != GENESIS_PARENT_HASH
            && !self
                .tree
                .is_descendant_or_self(&vote.block_hash, &finalized_root)
        {
            bail!("cannot count vote outside finalized root");
        }
        let weight = validator_set
            .voting_weight(&vote.voter, vote.slot)
            .ok_or_else(|| {
                anyhow::anyhow!("unknown or inactive voting validator {}", vote.voter)
            })?;

        match self.latest_votes.get(&vote.voter).cloned() {
            None => {
                self.add_direct_weight(vote.block_hash, weight)?;
                self.latest_votes.insert(
                    vote.voter.clone(),
                    LatestVote {
                        slot: vote.slot,
                        block_hash: vote.block_hash,
                        weight,
                    },
                );
                Ok(ForkChoiceVoteOutcome::Counted)
            }
            Some(existing) if existing.slot > vote.slot => Ok(ForkChoiceVoteOutcome::Stale),
            Some(existing)
                if existing.slot == vote.slot && existing.block_hash == vote.block_hash =>
            {
                Ok(ForkChoiceVoteOutcome::Duplicate)
            }
            Some(existing) if existing.slot == vote.slot => Ok(ForkChoiceVoteOutcome::Conflicting),
            Some(existing) => {
                self.subtract_direct_weight(existing.block_hash, existing.weight)?;
                self.add_direct_weight(vote.block_hash, weight)?;
                self.latest_votes.insert(
                    vote.voter.clone(),
                    LatestVote {
                        slot: vote.slot,
                        block_hash: vote.block_hash,
                        weight,
                    },
                );
                Ok(ForkChoiceVoteOutcome::Counted)
            }
        }
    }

    pub fn best_fork(&self) -> Option<ForkChoiceTip> {
        self.tree
            .connected_tips()
            .into_iter()
            .map(|tip| self.score_tip(tip))
            .max_by_key(|tip| {
                (
                    tip.voted_stake,
                    tip.latest_vote_slot,
                    tip.cumulative_weight,
                    tip.slot,
                    tip.block_hash,
                )
            })
    }

    pub fn canonical_chain(&self) -> Vec<LedgerHash> {
        self.best_fork()
            .map(|tip| self.chain_to_root(tip.block_hash))
            .unwrap_or_default()
    }

    pub fn try_finalize(
        &mut self,
        validator_set: &ValidatorSet,
        config: FinalityConfig,
    ) -> Result<Option<FinalityUpdate>> {
        config.validate()?;
        let mut candidate = None;
        for block_hash in self.canonical_chain() {
            let Some(block) = self.tree.get(&block_hash) else {
                continue;
            };
            let total_stake = validator_set.total_active_weight(block.slot);
            if total_stake == 0 {
                continue;
            }
            let required_stake = config.required_stake(total_stake)?;
            let supporting_stake = self.supporting_stake(block_hash);
            if supporting_stake >= required_stake {
                candidate = Some((block, supporting_stake, required_stake));
            }
        }

        let Some((block, supporting_stake, required_stake)) = candidate else {
            return Ok(None);
        };
        if block.block_hash == self.tree.finalized_root() {
            return Ok(None);
        }

        self.tree.set_finalized_root(block.block_hash)?;
        let pruned_blocks = self.tree.prune_to_finalized_root()?;
        self.prune_votes(&pruned_blocks)?;

        Ok(Some(FinalityUpdate {
            finalized_root: block.block_hash,
            finalized_slot: block.slot,
            supporting_stake,
            required_stake,
            pruned_blocks,
        }))
    }

    fn score_tip(&self, tip: ForkTip) -> ForkChoiceTip {
        let chain = self.chain_to_root(tip.block_hash);
        let chain_set = chain.iter().copied().collect::<BTreeSet<_>>();
        let voted_stake = chain
            .iter()
            .filter_map(|hash| self.direct_vote_weight.get(hash))
            .sum();
        let latest_vote_slot = self
            .latest_votes
            .values()
            .filter(|vote| chain_set.contains(&vote.block_hash))
            .map(|vote| vote.slot)
            .max();

        ForkChoiceTip {
            block_hash: tip.block_hash,
            slot: tip.slot,
            voted_stake,
            latest_vote_slot,
            cumulative_weight: tip.cumulative_weight,
        }
    }

    fn supporting_stake(&self, block_hash: LedgerHash) -> u64 {
        self.latest_votes
            .values()
            .filter(|vote| {
                self.tree
                    .is_descendant_or_self(&vote.block_hash, &block_hash)
            })
            .map(|vote| vote.weight)
            .sum()
    }

    fn chain_to_root(&self, block_hash: LedgerHash) -> Vec<LedgerHash> {
        let mut out = Vec::new();
        let mut current = block_hash;
        while let Some(block) = self.tree.get(&current) {
            out.push(block.block_hash);
            if block.parent_hash == GENESIS_PARENT_HASH
                || block.parent_hash == self.tree.finalized_root()
            {
                break;
            }
            current = block.parent_hash;
        }
        out.reverse();
        out
    }

    fn add_direct_weight(&mut self, block_hash: LedgerHash, weight: u64) -> Result<()> {
        let current = self.direct_vote_weight.entry(block_hash).or_default();
        *current = current
            .checked_add(weight)
            .ok_or_else(|| anyhow::anyhow!("fork vote weight overflow"))?;
        Ok(())
    }

    fn subtract_direct_weight(&mut self, block_hash: LedgerHash, weight: u64) -> Result<()> {
        let current = self
            .direct_vote_weight
            .get_mut(&block_hash)
            .ok_or_else(|| anyhow::anyhow!("missing direct vote weight"))?;
        if *current < weight {
            bail!("fork vote weight underflow");
        }
        *current -= weight;
        if *current == 0 {
            self.direct_vote_weight.remove(&block_hash);
        }
        Ok(())
    }

    fn ensure_block_can_extend_finalized_root(&self, block: &LedgerBlock) -> Result<()> {
        let finalized_root = self.tree.finalized_root();
        if finalized_root == GENESIS_PARENT_HASH {
            return Ok(());
        }
        if block.block_hash == finalized_root {
            return Ok(());
        }
        if block.parent_hash == finalized_root
            || self
                .tree
                .is_descendant_or_self(&block.parent_hash, &finalized_root)
        {
            return Ok(());
        }
        bail!("cannot insert block that rolls back before finalized root");
    }

    fn prune_votes(&mut self, pruned_blocks: &[LedgerHash]) -> Result<()> {
        if pruned_blocks.is_empty() {
            return Ok(());
        }
        let pruned = pruned_blocks.iter().copied().collect::<BTreeSet<_>>();
        self.latest_votes
            .retain(|_, vote| !pruned.contains(&vote.block_hash));
        self.rebuild_direct_vote_weight()
    }

    fn rebuild_direct_vote_weight(&mut self) -> Result<()> {
        self.direct_vote_weight.clear();
        for vote in self.latest_votes.values() {
            let current = self.direct_vote_weight.entry(vote.block_hash).or_default();
            *current = current
                .checked_add(vote.weight)
                .ok_or_else(|| anyhow::anyhow!("fork vote weight overflow"))?;
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "ed25519"))]
mod tests {
    use super::*;
    use crate::{
        ledger::{LedgerEntry, TransactionBatch},
        validator_set::{ValidatorIdentityConfig, ValidatorSetConfig},
    };
    use ed25519_dalek::SigningKey;
    use std::str::FromStr;

    fn hex(bytes: &[u8]) -> String {
        crate::test_support::hex(bytes)
    }

    fn verify_key_hex(seed: u8) -> String {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        hex(&signing_key.verifying_key().to_bytes())
    }

    fn validator_config(id: &str, seed: u8, weight: u64) -> ValidatorIdentityConfig {
        ValidatorIdentityConfig {
            validator_id: id.to_string(),
            tls_spki_hex: hex(format!("{id}-spki").as_bytes()),
            packet_signing_key_hex: verify_key_hex(seed),
            consensus_voting_key_hex: verify_key_hex(seed + 100),
            voting_weight: weight,
            activation_epoch: 0,
            activation_slot: 0,
            deactivation_epoch: None,
            deactivation_slot: None,
        }
    }

    fn validator_set() -> ValidatorSet {
        ValidatorSet::from_config(ValidatorSetConfig {
            validators: vec![
                validator_config("validator-a", 1, 10),
                validator_config("validator-b", 2, 30),
                validator_config("validator-c", 3, 10),
            ],
        })
        .unwrap()
    }

    fn validator_id(id: &str) -> ValidatorId {
        ValidatorId::from_str(id).unwrap()
    }

    fn block(slot: u64, parent_hash: LedgerHash, producer: &str, payload: &[u8]) -> LedgerBlock {
        let batch = TransactionBatch::new(0, vec![payload.to_vec()]).unwrap();
        let entry = LedgerEntry::new(0, parent_hash, vec![batch]).unwrap();
        LedgerBlock::new(
            EpochSlot::new(0, slot),
            parent_hash,
            validator_id(producer),
            vec![entry],
            [7u8; 64],
        )
        .unwrap()
    }

    fn vote(slot: u64, voter: &str, block_hash: LedgerHash) -> Vote {
        Vote {
            slot: EpochSlot::new(0, slot),
            voter: validator_id(voter),
            block_hash,
            signature: [9u8; 64],
        }
    }

    #[test]
    fn fork_choice_picks_heaviest_voted_fork() {
        let validators = validator_set();
        let root_child = block(1, GENESIS_PARENT_HASH, "validator-a", b"root-child");
        let light = block(2, root_child.block_hash, "validator-b", b"light");
        let heavy = block(2, root_child.block_hash, "validator-c", b"heavy");
        let mut fork_choice = ForkChoice::default();
        fork_choice.insert_block(&root_child, 1).unwrap();
        fork_choice.insert_block(&light, 1).unwrap();
        fork_choice.insert_block(&heavy, 1).unwrap();

        fork_choice
            .record_vote(&vote(2, "validator-a", light.block_hash), &validators)
            .unwrap();
        fork_choice
            .record_vote(&vote(2, "validator-b", heavy.block_hash), &validators)
            .unwrap();

        let best = fork_choice.best_fork().unwrap();
        assert_eq!(best.block_hash, heavy.block_hash);
        assert_eq!(best.voted_stake, 30);
    }

    #[test]
    fn tie_breaker_is_deterministic_by_hash_after_equal_scores() {
        let root_child = block(1, GENESIS_PARENT_HASH, "validator-a", b"root-child");
        let first = block(2, root_child.block_hash, "validator-b", b"first");
        let second = block(2, root_child.block_hash, "validator-c", b"second");
        let mut fork_choice = ForkChoice::default();
        fork_choice.insert_block(&root_child, 1).unwrap();
        fork_choice.insert_block(&first, 1).unwrap();
        fork_choice.insert_block(&second, 1).unwrap();

        let best = fork_choice.best_fork().unwrap();
        assert_eq!(best.block_hash, first.block_hash.max(second.block_hash));
    }

    #[test]
    fn later_vote_moves_weight_and_updates_best_fork() {
        let validators = validator_set();
        let root_child = block(1, GENESIS_PARENT_HASH, "validator-a", b"root-child");
        let first = block(2, root_child.block_hash, "validator-b", b"first");
        let second = block(3, root_child.block_hash, "validator-c", b"second");
        let mut fork_choice = ForkChoice::default();
        fork_choice.insert_block(&root_child, 1).unwrap();
        fork_choice.insert_block(&first, 1).unwrap();
        fork_choice.insert_block(&second, 1).unwrap();

        assert_eq!(
            fork_choice
                .record_vote(&vote(2, "validator-b", first.block_hash), &validators)
                .unwrap(),
            ForkChoiceVoteOutcome::Counted
        );
        assert_eq!(
            fork_choice.best_fork().unwrap().block_hash,
            first.block_hash
        );

        assert_eq!(
            fork_choice
                .record_vote(&vote(3, "validator-b", second.block_hash), &validators)
                .unwrap(),
            ForkChoiceVoteOutcome::Counted
        );
        let best = fork_choice.best_fork().unwrap();
        assert_eq!(best.block_hash, second.block_hash);
        assert_eq!(best.voted_stake, 30);
    }

    #[test]
    fn duplicate_stale_and_conflicting_votes_do_not_change_choice() {
        let validators = validator_set();
        let root_child = block(1, GENESIS_PARENT_HASH, "validator-a", b"root-child");
        let first = block(2, root_child.block_hash, "validator-b", b"first");
        let second = block(2, root_child.block_hash, "validator-c", b"second");
        let mut fork_choice = ForkChoice::default();
        fork_choice.insert_block(&root_child, 1).unwrap();
        fork_choice.insert_block(&first, 1).unwrap();
        fork_choice.insert_block(&second, 1).unwrap();

        let first_vote = vote(2, "validator-a", first.block_hash);
        assert_eq!(
            fork_choice.record_vote(&first_vote, &validators).unwrap(),
            ForkChoiceVoteOutcome::Counted
        );
        assert_eq!(
            fork_choice.record_vote(&first_vote, &validators).unwrap(),
            ForkChoiceVoteOutcome::Duplicate
        );
        assert_eq!(
            fork_choice
                .record_vote(&vote(1, "validator-a", second.block_hash), &validators)
                .unwrap(),
            ForkChoiceVoteOutcome::Stale
        );
        assert_eq!(
            fork_choice
                .record_vote(&vote(2, "validator-a", second.block_hash), &validators)
                .unwrap(),
            ForkChoiceVoteOutcome::Conflicting
        );
        assert_eq!(
            fork_choice.best_fork().unwrap().block_hash,
            first.block_hash
        );
    }

    #[test]
    fn canonical_chain_exposes_replay_order() {
        let root_child = block(1, GENESIS_PARENT_HASH, "validator-a", b"root-child");
        let child = block(2, root_child.block_hash, "validator-b", b"child");
        let mut fork_choice = ForkChoice::default();
        fork_choice.insert_block(&root_child, 1).unwrap();
        fork_choice.insert_block(&child, 1).unwrap();

        assert_eq!(
            fork_choice.canonical_chain(),
            vec![root_child.block_hash, child.block_hash]
        );
    }

    #[test]
    fn finality_threshold_advances_root_and_prunes_old_forks() {
        let validators = validator_set();
        let root_child = block(1, GENESIS_PARENT_HASH, "validator-a", b"root-child");
        let canonical = block(2, root_child.block_hash, "validator-b", b"canonical");
        let old_fork = block(2, root_child.block_hash, "validator-c", b"old-fork");
        let mut fork_choice = ForkChoice::default();
        fork_choice.insert_block(&root_child, 1).unwrap();
        fork_choice.insert_block(&canonical, 1).unwrap();
        fork_choice.insert_block(&old_fork, 1).unwrap();

        fork_choice
            .record_vote(&vote(2, "validator-b", canonical.block_hash), &validators)
            .unwrap();
        fork_choice
            .record_vote(&vote(2, "validator-c", canonical.block_hash), &validators)
            .unwrap();

        let update = fork_choice
            .try_finalize(&validators, FinalityConfig::default())
            .unwrap()
            .unwrap();

        assert_eq!(update.finalized_root, canonical.block_hash);
        assert_eq!(update.supporting_stake, 40);
        assert_eq!(update.required_stake, 34);
        assert!(update.pruned_blocks.contains(&old_fork.block_hash));
        assert_eq!(fork_choice.tree().finalized_root(), canonical.block_hash);
        assert!(fork_choice.tree().get(&old_fork.block_hash).is_none());
    }

    #[test]
    fn non_final_forks_can_reorganize() {
        let validators = validator_set();
        let root_child = block(1, GENESIS_PARENT_HASH, "validator-a", b"root-child");
        let first = block(2, root_child.block_hash, "validator-b", b"first");
        let second = block(2, root_child.block_hash, "validator-c", b"second");
        let mut fork_choice = ForkChoice::default();
        fork_choice.insert_block(&root_child, 1).unwrap();
        fork_choice.insert_block(&first, 1).unwrap();
        fork_choice.insert_block(&second, 1).unwrap();

        fork_choice
            .record_vote(&vote(2, "validator-a", first.block_hash), &validators)
            .unwrap();
        assert_eq!(
            fork_choice.best_fork().unwrap().block_hash,
            first.block_hash
        );
        assert!(
            fork_choice
                .try_finalize(&validators, FinalityConfig::default())
                .unwrap()
                .is_none()
        );

        fork_choice
            .record_vote(&vote(2, "validator-b", second.block_hash), &validators)
            .unwrap();

        assert_eq!(
            fork_choice.best_fork().unwrap().block_hash,
            second.block_hash
        );
        assert_eq!(fork_choice.tree().finalized_root(), GENESIS_PARENT_HASH);
    }

    #[test]
    fn finalized_root_prevents_rollback_before_root() {
        let validators = validator_set();
        let root_child = block(1, GENESIS_PARENT_HASH, "validator-a", b"root-child");
        let canonical = block(2, root_child.block_hash, "validator-b", b"canonical");
        let rollback = block(2, GENESIS_PARENT_HASH, "validator-c", b"rollback");
        let descendant = block(3, canonical.block_hash, "validator-a", b"descendant");
        let mut fork_choice = ForkChoice::default();
        fork_choice.insert_block(&root_child, 1).unwrap();
        fork_choice.insert_block(&canonical, 1).unwrap();
        fork_choice
            .record_vote(&vote(2, "validator-b", canonical.block_hash), &validators)
            .unwrap();
        fork_choice
            .record_vote(&vote(2, "validator-c", canonical.block_hash), &validators)
            .unwrap();
        fork_choice
            .try_finalize(&validators, FinalityConfig::default())
            .unwrap()
            .unwrap();

        assert!(fork_choice.insert_block(&rollback, 1).is_err());
        fork_choice.insert_block(&descendant, 1).unwrap();
        assert_eq!(fork_choice.tree().finalized_root(), canonical.block_hash);
        assert!(fork_choice.tree().get(&descendant.block_hash).is_some());
    }
}
