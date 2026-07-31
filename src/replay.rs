use crate::{
    blockstore::Blockstore,
    execution::{ExecutionEngine, ExecutionStatus},
    ledger::{LedgerBlock, LedgerHash},
    snapshot::LedgerSnapshot,
    state::{GenesisStateConfig, StateDb},
    transaction::Transaction,
    validator_set::EpochSlot,
};
use anyhow::{Result, anyhow, bail};

pub const GENESIS_PARENT_HASH: LedgerHash = [0u8; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayProgress {
    pub blocks_replayed: usize,
    pub transactions_replayed: usize,
    pub latest_slot: Option<EpochSlot>,
    pub state_root: LedgerHash,
}

#[derive(Clone, Debug)]
pub struct ReplayReport {
    pub state: StateDb,
    pub progress: Vec<ReplayProgress>,
}

impl ReplayReport {
    pub fn final_progress(&self) -> ReplayProgress {
        self.progress
            .last()
            .cloned()
            .unwrap_or_else(|| ReplayProgress {
                blocks_replayed: 0,
                transactions_replayed: 0,
                latest_slot: None,
                state_root: self.state.state_hash(),
            })
    }
}

pub fn replay_from_genesis(
    genesis: GenesisStateConfig,
    blockstore: &Blockstore,
) -> Result<ReplayReport> {
    let state = StateDb::from_genesis(genesis)?;
    replay_from_state(state, blockstore)
}

pub fn replay_from_state(state: StateDb, blockstore: &Blockstore) -> Result<ReplayReport> {
    replay_from_checkpoint(state, blockstore, None, GENESIS_PARENT_HASH, 0)
}

pub fn replay_from_snapshot(
    snapshot: &LedgerSnapshot,
    blockstore: &Blockstore,
) -> Result<ReplayReport> {
    snapshot.validate()?;
    replay_from_checkpoint(
        snapshot.state.clone(),
        blockstore,
        Some(snapshot.slot),
        snapshot.block_hash,
        0,
    )
}

fn replay_from_checkpoint(
    mut state: StateDb,
    blockstore: &Blockstore,
    after_slot: Option<EpochSlot>,
    mut parent_hash: LedgerHash,
    initial_transactions_replayed: usize,
) -> Result<ReplayReport> {
    let mut progress = Vec::new();
    let mut engine = ExecutionEngine::new();
    let mut transactions_replayed = initial_transactions_replayed;
    let blocks = blockstore
        .canonical_blocks()?
        .into_iter()
        .filter(|block| after_slot.is_none_or(|slot| block.slot > slot))
        .collect::<Vec<_>>();

    for (block_index, block) in blocks.iter().enumerate() {
        verify_block_for_replay(block, parent_hash, blockstore)?;
        let transactions = block_transactions(block)?;
        for transaction in transactions {
            let receipt = engine.execute_transaction(&mut state, &transaction, block.slot.slot);
            if !matches!(receipt.status, ExecutionStatus::Succeeded) {
                bail!(
                    "replay transaction failed at slot {}:{} with status {:?}",
                    block.slot.epoch,
                    block.slot.slot,
                    receipt.status
                );
            }
            transactions_replayed += 1;
        }

        let actual_state_root = state.state_hash();
        let stored_state_root = blockstore
            .state_root(block.slot)
            .ok_or_else(|| anyhow!("missing state root for replayed slot"))?;
        if stored_state_root.block_hash != block.block_hash {
            bail!("stored state root references wrong block hash");
        }
        if stored_state_root.state_root != actual_state_root {
            bail!("replayed state root does not match stored state root");
        }

        progress.push(ReplayProgress {
            blocks_replayed: block_index + 1,
            transactions_replayed,
            latest_slot: Some(block.slot),
            state_root: actual_state_root,
        });
        parent_hash = block.block_hash;
    }

    if progress.is_empty() {
        progress.push(ReplayProgress {
            blocks_replayed: 0,
            transactions_replayed: 0,
            latest_slot: None,
            state_root: state.state_hash(),
        });
    }

    Ok(ReplayReport { state, progress })
}

fn verify_block_for_replay(
    block: &LedgerBlock,
    expected_parent_hash: LedgerHash,
    blockstore: &Blockstore,
) -> Result<()> {
    block.validate_integrity()?;
    if block.parent_hash != expected_parent_hash {
        bail!("block parent hash does not match canonical replay chain");
    }
    if block.signature.iter().all(|byte| *byte == 0) {
        bail!("block signature is empty");
    }
    let votes = blockstore.votes_for_block(&block.block_hash);
    if votes.is_empty() {
        bail!("block has no votes available for replay validation");
    }
    for vote in votes {
        if vote.slot != block.slot {
            bail!("vote slot does not match replayed block");
        }
        if vote.block_hash != block.block_hash {
            bail!("vote block hash does not match replayed block");
        }
        if vote.signature.iter().all(|byte| *byte == 0) {
            bail!("vote signature is empty");
        }
    }
    Ok(())
}

pub(crate) fn block_transactions(block: &LedgerBlock) -> Result<Vec<Transaction>> {
    let mut transactions = Vec::new();
    for entry in &block.entries {
        for batch in &entry.batches {
            for encoded in &batch.transactions {
                transactions.push(Transaction::decode(encoded)?);
            }
        }
    }
    Ok(transactions)
}

#[cfg(all(test, feature = "ed25519"))]
mod tests {
    use super::*;
    use crate::{
        blockstore::{BlockstoreBatch, StoredStateRoot},
        consensus_messages::Vote,
        execution::{OP_TRANSFER, SYSTEM_PROGRAM_ID},
        identity::ValidatorId,
        ledger::{LedgerEntry, TransactionBatch},
        state::GenesisAccountConfig,
        transaction::{Instruction, Transaction},
        validator_set::{ValidatorIdentityRecord, ValidatorSet},
    };
    use ed25519_dalek::SigningKey;
    use std::{path::PathBuf, str::FromStr};

    fn temp_dir() -> PathBuf {
        crate::test_support::temp_dir("replay")
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn pubkey(key: &SigningKey) -> [u8; 32] {
        key.verifying_key().to_bytes()
    }

    fn hex(bytes: &[u8]) -> String {
        crate::test_support::hex(bytes)
    }

    fn hash(byte: u8) -> LedgerHash {
        [byte; 32]
    }

    fn genesis(sender: &SigningKey, recipient: &SigningKey) -> GenesisStateConfig {
        GenesisStateConfig {
            accounts: vec![
                GenesisAccountConfig {
                    address_hex: hex(&pubkey(sender)),
                    owner_hex: hex(&hash(9)),
                    lamports: 100,
                    data_hex: String::new(),
                    nonce: 0,
                },
                GenesisAccountConfig {
                    address_hex: hex(&pubkey(recipient)),
                    owner_hex: hex(&hash(9)),
                    lamports: 10,
                    data_hex: String::new(),
                    nonce: 0,
                },
                GenesisAccountConfig {
                    address_hex: hex(&SYSTEM_PROGRAM_ID),
                    owner_hex: hex(&hash(9)),
                    lamports: 0,
                    data_hex: String::new(),
                    nonce: 0,
                },
            ],
        }
    }

    fn validator_set() -> ValidatorSet {
        let mut set = ValidatorSet::default();
        set.insert(ValidatorIdentityRecord {
            validator_id: ValidatorId::from_str("validator-a").unwrap(),
            tls_spki_der: b"validator-a-spki".to_vec(),
            packet_signing_key: hash(12),
            consensus_voting_key: hash(13),
            voting_weight: 10,
            activation: EpochSlot::new(0, 0),
            deactivation: None,
        })
        .unwrap();
        set
    }

    fn transfer_tx(
        sender: &SigningKey,
        recipient: &SigningKey,
        amount: u64,
        fee: u64,
        nonce: u64,
    ) -> Transaction {
        let mut data = vec![OP_TRANSFER];
        data.extend_from_slice(&amount.to_be_bytes());
        let mut tx = Transaction {
            account_keys: vec![pubkey(sender), pubkey(recipient), SYSTEM_PROGRAM_ID],
            required_signer_indices: vec![0],
            signatures: Vec::new(),
            recent_blockhash: hash(3),
            nonce,
            fee,
            compute_limit: 100,
            expiration_slot: 10,
            instructions: vec![Instruction {
                program_id_index: 2,
                account_indices: vec![0, 1],
                data,
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

    fn vote_for(block: &LedgerBlock) -> Vote {
        Vote {
            slot: block.slot,
            voter: ValidatorId::from_str("validator-b").unwrap(),
            block_hash: block.block_hash,
            signature: [6u8; 64],
        }
    }

    fn write_replay_fixture(
        dir: &PathBuf,
        block: LedgerBlock,
        state_root: LedgerHash,
        include_vote: bool,
    ) {
        let mut batch = BlockstoreBatch::new();
        if include_vote {
            batch.put_vote(vote_for(&block));
        }
        batch.put_state_root(StoredStateRoot {
            slot: block.slot,
            block_hash: block.block_hash,
            state_root,
        });
        batch.put_block(block);
        Blockstore::open(dir).unwrap().write_batch(batch).unwrap();
    }

    #[test]
    fn small_ledger_replay_fixture_reconstructs_state_root() {
        let sender = key(1);
        let recipient = key(2);
        let tx = transfer_tx(&sender, &recipient, 10, 5, 0);
        let block = block_with_tx(1, GENESIS_PARENT_HASH, &tx);
        let mut expected_state = StateDb::from_genesis(genesis(&sender, &recipient)).unwrap();
        ExecutionEngine::new().execute_transaction(&mut expected_state, &tx, 1);
        let expected_root = expected_state.state_hash();
        let dir = temp_dir();
        write_replay_fixture(&dir, block, expected_root, true);
        let store = Blockstore::open(&dir).unwrap();

        let report = replay_from_genesis(genesis(&sender, &recipient), &store).unwrap();

        assert_eq!(report.state.state_hash(), expected_root);
        assert_eq!(report.final_progress().blocks_replayed, 1);
        assert_eq!(report.final_progress().transactions_replayed, 1);
        assert_eq!(report.final_progress().state_root, expected_root);
    }

    #[test]
    fn corrupt_block_is_rejected() {
        let sender = key(1);
        let recipient = key(2);
        let tx = transfer_tx(&sender, &recipient, 10, 5, 0);
        let mut block = block_with_tx(1, GENESIS_PARENT_HASH, &tx);
        block.signature = [0u8; 64];
        let dir = temp_dir();
        write_replay_fixture(&dir, block, hash(4), true);
        let store = Blockstore::open(&dir).unwrap();

        assert!(replay_from_genesis(genesis(&sender, &recipient), &store).is_err());
    }

    #[test]
    fn wrong_state_root_is_rejected() {
        let sender = key(1);
        let recipient = key(2);
        let tx = transfer_tx(&sender, &recipient, 10, 5, 0);
        let block = block_with_tx(1, GENESIS_PARENT_HASH, &tx);
        let dir = temp_dir();
        write_replay_fixture(&dir, block, hash(99), true);
        let store = Blockstore::open(&dir).unwrap();

        assert!(replay_from_genesis(genesis(&sender, &recipient), &store).is_err());
    }

    #[test]
    fn missing_vote_stops_replay_safely() {
        let sender = key(1);
        let recipient = key(2);
        let tx = transfer_tx(&sender, &recipient, 10, 5, 0);
        let block = block_with_tx(1, GENESIS_PARENT_HASH, &tx);
        let dir = temp_dir();
        write_replay_fixture(&dir, block, hash(4), false);
        let store = Blockstore::open(&dir).unwrap();

        assert!(replay_from_genesis(genesis(&sender, &recipient), &store).is_err());
    }

    #[test]
    fn snapshot_replay_matches_full_replay() {
        let sender = key(1);
        let recipient = key(2);
        let tx1 = transfer_tx(&sender, &recipient, 10, 5, 0);
        let block1 = block_with_tx(1, GENESIS_PARENT_HASH, &tx1);
        let tx2 = transfer_tx(&sender, &recipient, 5, 5, 1);
        let block2 = block_with_tx(2, block1.block_hash, &tx2);
        let mut checkpoint_state = StateDb::from_genesis(genesis(&sender, &recipient)).unwrap();
        ExecutionEngine::new().execute_transaction(&mut checkpoint_state, &tx1, 1);
        let checkpoint_root = checkpoint_state.state_hash();
        let mut full_expected = checkpoint_state.clone();
        ExecutionEngine::new().execute_transaction(&mut full_expected, &tx2, 2);
        let final_root = full_expected.state_hash();
        let dir = temp_dir();
        write_replay_fixture(&dir, block1.clone(), checkpoint_root, true);
        write_replay_fixture(&dir, block2, final_root, true);
        let store = Blockstore::open(&dir).unwrap();

        let full = replay_from_genesis(genesis(&sender, &recipient), &store).unwrap();
        let snapshot = crate::snapshot::LedgerSnapshot::create(
            block1.slot,
            block1.block_hash,
            &checkpoint_state,
            &validator_set(),
            &crate::consensus_safety::ConsensusSafetyState::default(),
            [4u8; 64],
        )
        .unwrap();
        let fast = replay_from_snapshot(&snapshot, &store).unwrap();

        assert_eq!(full.state.state_hash(), final_root);
        assert_eq!(fast.state.state_hash(), final_root);
        assert_eq!(fast.final_progress().blocks_replayed, 1);
        assert_eq!(
            fast.final_progress().latest_slot,
            Some(EpochSlot::new(0, 2))
        );
    }

    #[test]
    fn restart_from_encoded_snapshot_replays_later_blocks() {
        let sender = key(1);
        let recipient = key(2);
        let tx1 = transfer_tx(&sender, &recipient, 10, 5, 0);
        let block1 = block_with_tx(1, GENESIS_PARENT_HASH, &tx1);
        let tx2 = transfer_tx(&sender, &recipient, 5, 5, 1);
        let block2 = block_with_tx(2, block1.block_hash, &tx2);
        let mut checkpoint_state = StateDb::from_genesis(genesis(&sender, &recipient)).unwrap();
        ExecutionEngine::new().execute_transaction(&mut checkpoint_state, &tx1, 1);
        let checkpoint_root = checkpoint_state.state_hash();
        let mut final_state = checkpoint_state.clone();
        ExecutionEngine::new().execute_transaction(&mut final_state, &tx2, 2);
        let final_root = final_state.state_hash();
        let dir = temp_dir();
        write_replay_fixture(&dir, block1.clone(), checkpoint_root, true);
        write_replay_fixture(&dir, block2, final_root, true);
        let store = Blockstore::open(&dir).unwrap();
        let snapshot = crate::snapshot::LedgerSnapshot::create(
            block1.slot,
            block1.block_hash,
            &checkpoint_state,
            &validator_set(),
            &crate::consensus_safety::ConsensusSafetyState::default(),
            [4u8; 64],
        )
        .unwrap();
        let restored =
            crate::snapshot::LedgerSnapshot::decode(&snapshot.encode().unwrap()).unwrap();

        let report = replay_from_snapshot(&restored, &store).unwrap();

        assert_eq!(report.state.state_hash(), final_root);
    }
}
