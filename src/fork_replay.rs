use crate::{
    blockstore::{Blockstore, StoredStateRoot},
    execution::{
        ExecutionBatchReceipt, ExecutionPolicy, ExecutionStatus, execute_transactions_with_policy,
    },
    fork_choice::ForkChoice,
    ledger::{LedgerBlock, LedgerHash},
    replay::{GENESIS_PARENT_HASH, block_transactions},
    state::StateDb,
    validator_set::EpochSlot,
};
use anyhow::{Result, bail};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug)]
pub struct ForkExecutionState {
    pub block_hash: LedgerHash,
    pub parent_hash: LedgerHash,
    pub slot: EpochSlot,
    pub state_root: LedgerHash,
    pub state: StateDb,
    pub batch_receipt: ExecutionBatchReceipt,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPromotion {
    pub previous_tip: LedgerHash,
    pub new_tip: LedgerHash,
    pub state_root: LedgerHash,
}

#[derive(Clone, Debug)]
pub struct ForkReplay {
    root_hash: LedgerHash,
    root_state: StateDb,
    canonical_tip: LedgerHash,
    canonical_state: StateDb,
    executed: BTreeMap<LedgerHash, ForkExecutionState>,
}

impl ForkReplay {
    pub fn new(root_hash: LedgerHash, root_state: StateDb) -> Self {
        Self {
            root_hash,
            canonical_tip: root_hash,
            canonical_state: root_state.clone(),
            root_state,
            executed: BTreeMap::new(),
        }
    }

    pub fn from_genesis(state: StateDb) -> Self {
        Self::new(GENESIS_PARENT_HASH, state)
    }

    pub fn canonical_tip(&self) -> LedgerHash {
        self.canonical_tip
    }

    pub fn canonical_state(&self) -> &StateDb {
        &self.canonical_state
    }

    pub fn executed_state(&self, block_hash: &LedgerHash) -> Option<&ForkExecutionState> {
        self.executed.get(block_hash)
    }

    pub fn execute_block_from_store(
        &mut self,
        block: &LedgerBlock,
        blockstore: &Blockstore,
    ) -> Result<&ForkExecutionState> {
        let expected = blockstore
            .state_root_for_block(&block.block_hash)
            .ok_or_else(|| anyhow::anyhow!("missing state root for fork replay block"))?;
        self.execute_block(block, expected)
    }

    pub fn execute_block(
        &mut self,
        block: &LedgerBlock,
        expected: &StoredStateRoot,
    ) -> Result<&ForkExecutionState> {
        block.validate_integrity()?;
        if expected.slot != block.slot {
            bail!("state root slot does not match fork replay block");
        }
        if expected.block_hash != block.block_hash {
            bail!("state root references wrong fork replay block");
        }
        if self.executed.contains_key(&block.block_hash) {
            let executed = self
                .executed
                .get(&block.block_hash)
                .expect("contains_key checked");
            if executed.state_root != expected.state_root {
                bail!("conflicting expected state root for already executed fork block");
            }
            return Ok(executed);
        }

        let mut state = self.parent_state(block.parent_hash)?.clone();
        let transactions = block_transactions(block)?;
        let batch_receipt = execute_transactions_with_policy(
            &mut state,
            &transactions,
            block.slot.slot,
            ExecutionPolicy::Ordered,
        );
        if let Some(receipt) = batch_receipt
            .receipts
            .iter()
            .find(|receipt| !matches!(receipt.status, ExecutionStatus::Succeeded))
        {
            bail!(
                "fork replay transaction failed at slot {}:{} with status {:?}",
                block.slot.epoch,
                block.slot.slot,
                receipt.status
            );
        }

        let state_root = state.state_hash();
        if state_root != expected.state_root {
            bail!("fork replay state root mismatch");
        }

        self.executed.insert(
            block.block_hash,
            ForkExecutionState {
                block_hash: block.block_hash,
                parent_hash: block.parent_hash,
                slot: block.slot,
                state_root,
                state,
                batch_receipt,
            },
        );
        Ok(self
            .executed
            .get(&block.block_hash)
            .expect("fork execution was just inserted"))
    }

    pub fn execute_chain_from_store(
        &mut self,
        block_hashes: &[LedgerHash],
        blockstore: &Blockstore,
    ) -> Result<()> {
        let mut expected_parent = self.root_hash;
        for block_hash in block_hashes {
            let block = blockstore
                .get_block_by_hash(block_hash)
                .ok_or_else(|| anyhow::anyhow!("missing block for fork replay chain"))?;
            if block.parent_hash != expected_parent
                && !(expected_parent == GENESIS_PARENT_HASH
                    && block.parent_hash == GENESIS_PARENT_HASH)
            {
                bail!("fork replay chain is not contiguous from the replay root");
            }
            self.execute_block_from_store(block, blockstore)?;
            expected_parent = block.block_hash;
        }
        Ok(())
    }

    pub fn promote_canonical(&mut self, block_hashes: &[LedgerHash]) -> Result<CanonicalPromotion> {
        let Some(new_tip) = block_hashes.last().copied() else {
            bail!("cannot promote empty fork replay chain");
        };
        self.ensure_chain_executed(block_hashes)?;
        let executed = self
            .executed
            .get(&new_tip)
            .ok_or_else(|| anyhow::anyhow!("cannot promote unexecuted fork tip"))?;
        let previous_tip = self.canonical_tip;
        self.canonical_tip = new_tip;
        self.canonical_state = executed.state.clone();
        Ok(CanonicalPromotion {
            previous_tip,
            new_tip,
            state_root: executed.state_root,
        })
    }

    pub fn promote_from_fork_choice(
        &mut self,
        fork_choice: &ForkChoice,
    ) -> Result<CanonicalPromotion> {
        self.promote_canonical(&fork_choice.canonical_chain())
    }

    pub fn prune_non_recoverable(&mut self, retained_chain: &[LedgerHash]) {
        let retained = retained_chain.iter().copied().collect::<BTreeSet<_>>();
        self.executed
            .retain(|hash, _| retained.contains(hash) || *hash == self.canonical_tip);
    }

    fn parent_state(&self, parent_hash: LedgerHash) -> Result<&StateDb> {
        if parent_hash == self.root_hash || parent_hash == GENESIS_PARENT_HASH {
            return Ok(&self.root_state);
        }
        self.executed
            .get(&parent_hash)
            .map(|executed| &executed.state)
            .ok_or_else(|| anyhow::anyhow!("fork replay parent state is not available"))
    }

    fn ensure_chain_executed(&self, block_hashes: &[LedgerHash]) -> Result<()> {
        let mut expected_parent = self.root_hash;
        for block_hash in block_hashes {
            let executed = self
                .executed
                .get(block_hash)
                .ok_or_else(|| anyhow::anyhow!("fork replay chain contains unexecuted block"))?;
            if executed.parent_hash != expected_parent
                && !(expected_parent == GENESIS_PARENT_HASH
                    && executed.parent_hash == GENESIS_PARENT_HASH)
            {
                bail!("fork replay chain is not contiguous from the replay root");
            }
            expected_parent = *block_hash;
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "ed25519"))]
mod tests {
    use super::*;
    use crate::{
        blockstore::{BlockstoreBatch, StoredStateRoot},
        execution::{OP_TRANSFER, SYSTEM_PROGRAM_ID},
        identity::ValidatorId,
        ledger::{LedgerEntry, TransactionBatch},
        state::{Account, ProgramId},
        transaction::{Instruction, Transaction},
        validator_set::EpochSlot,
    };
    use ed25519_dalek::SigningKey;
    use std::{path::PathBuf, str::FromStr};

    fn temp_dir() -> PathBuf {
        crate::test_support::temp_dir("fork-replay")
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn pubkey(key: &SigningKey) -> [u8; 32] {
        key.verifying_key().to_bytes()
    }

    fn owner(byte: u8) -> ProgramId {
        [byte; 32]
    }

    fn state_for(sender: &SigningKey, first: &SigningKey, second: &SigningKey) -> StateDb {
        let mut state = StateDb::default();
        state
            .insert(Account::new(pubkey(sender), owner(9), 100, Vec::new(), 0).unwrap())
            .unwrap();
        state
            .insert(Account::new(pubkey(first), owner(9), 10, Vec::new(), 0).unwrap())
            .unwrap();
        state
            .insert(Account::new(pubkey(second), owner(9), 20, Vec::new(), 0).unwrap())
            .unwrap();
        state
            .insert(Account::new(SYSTEM_PROGRAM_ID, owner(9), 0, Vec::new(), 0).unwrap())
            .unwrap();
        state
    }

    fn amount_data(amount: u64) -> Vec<u8> {
        let mut data = vec![OP_TRANSFER];
        data.extend_from_slice(&amount.to_be_bytes());
        data
    }

    fn transfer_tx(
        sender: &SigningKey,
        recipient: &SigningKey,
        amount: u64,
        fee: u64,
        nonce: u64,
    ) -> Transaction {
        let mut tx = Transaction {
            account_keys: vec![pubkey(sender), pubkey(recipient), SYSTEM_PROGRAM_ID],
            required_signer_indices: vec![0],
            signatures: Vec::new(),
            recent_blockhash: [3u8; 32],
            nonce,
            fee,
            compute_limit: 100,
            expiration_slot: 10,
            instructions: vec![Instruction {
                program_id_index: 2,
                account_indices: vec![0, 1],
                data: amount_data(amount),
            }],
        };
        tx.sign_with_keys(&[(0, sender.clone())]).unwrap();
        tx
    }

    fn block_with_tx(slot: u64, parent_hash: LedgerHash, tx: &Transaction) -> LedgerBlock {
        let batch = TransactionBatch::new(0, vec![tx.encode()]).unwrap();
        let entry = LedgerEntry::new(0, parent_hash, vec![batch]).unwrap();
        LedgerBlock::new(
            EpochSlot::new(0, slot),
            parent_hash,
            ValidatorId::from_str("validator-a").unwrap(),
            vec![entry],
            [8u8; 64],
        )
        .unwrap()
    }

    fn expected_root(parent: &StateDb, block: &LedgerBlock) -> LedgerHash {
        let mut state = parent.clone();
        let transactions = block_transactions(block).unwrap();
        execute_transactions_with_policy(
            &mut state,
            &transactions,
            block.slot.slot,
            ExecutionPolicy::Ordered,
        );
        state.state_hash()
    }

    fn state_root(block: &LedgerBlock, root: LedgerHash) -> StoredStateRoot {
        StoredStateRoot {
            slot: block.slot,
            block_hash: block.block_hash,
            state_root: root,
        }
    }

    #[test]
    fn two_forks_execute_without_corrupting_canonical_state() {
        let sender = key(1);
        let first_recipient = key(2);
        let second_recipient = key(3);
        let genesis = state_for(&sender, &first_recipient, &second_recipient);
        let tx_a = transfer_tx(&sender, &first_recipient, 10, 5, 0);
        let tx_b = transfer_tx(&sender, &second_recipient, 20, 5, 0);
        let block_a = block_with_tx(1, GENESIS_PARENT_HASH, &tx_a);
        let block_b = block_with_tx(1, GENESIS_PARENT_HASH, &tx_b);
        let root_a = expected_root(&genesis, &block_a);
        let root_b = expected_root(&genesis, &block_b);
        let mut replay = ForkReplay::from_genesis(genesis.clone());

        replay
            .execute_block(&block_a, &state_root(&block_a, root_a))
            .unwrap();
        replay
            .execute_block(&block_b, &state_root(&block_b, root_b))
            .unwrap();

        assert_eq!(replay.canonical_state().state_hash(), genesis.state_hash());
        assert_ne!(
            replay
                .executed_state(&block_a.block_hash)
                .unwrap()
                .state_root,
            replay
                .executed_state(&block_b.block_hash)
                .unwrap()
                .state_root
        );
    }

    #[test]
    fn reorg_promotes_selected_fork_state_deterministically() {
        let sender = key(1);
        let first_recipient = key(2);
        let second_recipient = key(3);
        let genesis = state_for(&sender, &first_recipient, &second_recipient);
        let tx_a = transfer_tx(&sender, &first_recipient, 10, 5, 0);
        let tx_b = transfer_tx(&sender, &second_recipient, 20, 5, 0);
        let block_a = block_with_tx(1, GENESIS_PARENT_HASH, &tx_a);
        let block_b = block_with_tx(1, GENESIS_PARENT_HASH, &tx_b);
        let root_a = expected_root(&genesis, &block_a);
        let root_b = expected_root(&genesis, &block_b);
        let mut replay = ForkReplay::from_genesis(genesis);
        replay
            .execute_block(&block_a, &state_root(&block_a, root_a))
            .unwrap();
        replay
            .execute_block(&block_b, &state_root(&block_b, root_b))
            .unwrap();

        let first = replay.promote_canonical(&[block_a.block_hash]).unwrap();
        assert_eq!(first.new_tip, block_a.block_hash);
        assert_eq!(replay.canonical_state().state_hash(), root_a);

        let second = replay.promote_canonical(&[block_b.block_hash]).unwrap();
        assert_eq!(second.previous_tip, block_a.block_hash);
        assert_eq!(second.new_tip, block_b.block_hash);
        assert_eq!(replay.canonical_state().state_hash(), root_b);
    }

    #[test]
    fn invalid_state_root_rejects_fork_block() {
        let sender = key(1);
        let first_recipient = key(2);
        let second_recipient = key(3);
        let genesis = state_for(&sender, &first_recipient, &second_recipient);
        let tx = transfer_tx(&sender, &first_recipient, 10, 5, 0);
        let block = block_with_tx(1, GENESIS_PARENT_HASH, &tx);
        let mut replay = ForkReplay::from_genesis(genesis);

        assert!(
            replay
                .execute_block(&block, &state_root(&block, [99u8; 32]))
                .is_err()
        );
        assert!(replay.executed_state(&block.block_hash).is_none());
    }

    #[test]
    fn blockstore_indexes_state_roots_per_fork_block() {
        let sender = key(1);
        let first_recipient = key(2);
        let second_recipient = key(3);
        let genesis = state_for(&sender, &first_recipient, &second_recipient);
        let tx_a = transfer_tx(&sender, &first_recipient, 10, 5, 0);
        let tx_b = transfer_tx(&sender, &second_recipient, 20, 5, 0);
        let block_a = block_with_tx(1, GENESIS_PARENT_HASH, &tx_a);
        let block_b = block_with_tx(1, GENESIS_PARENT_HASH, &tx_b);
        let root_a = expected_root(&genesis, &block_a);
        let root_b = expected_root(&genesis, &block_b);
        let mut batch = BlockstoreBatch::new();
        batch.put_block(block_a.clone());
        batch.put_block(block_b.clone());
        batch.put_state_root(state_root(&block_a, root_a));
        batch.put_state_root(state_root(&block_b, root_b));
        let dir = temp_dir();
        let mut store = Blockstore::open(&dir).unwrap();
        store.write_batch(batch).unwrap();
        let mut replay = ForkReplay::from_genesis(genesis);

        replay
            .execute_chain_from_store(&[block_a.block_hash, block_b.block_hash], &store)
            .unwrap_err();
        replay.execute_block_from_store(&block_a, &store).unwrap();
        replay.execute_block_from_store(&block_b, &store).unwrap();

        assert!(store.state_root(block_a.slot).is_none());
        assert_eq!(
            store
                .state_root_for_block(&block_a.block_hash)
                .unwrap()
                .state_root,
            root_a
        );
        assert_eq!(
            store
                .state_root_for_block(&block_b.block_hash)
                .unwrap()
                .state_root,
            root_b
        );
    }
}
