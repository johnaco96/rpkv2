use crate::{
    metrics,
    state::{AccountLockSet, AccountLocks, StateDb},
    transaction::{Instruction, Transaction, TransactionReplay},
};
use anyhow::{Result, anyhow, bail};
use std::collections::{BTreeMap, BTreeSet};

pub const SYSTEM_PROGRAM_ID: [u8; 32] = [1u8; 32];
pub const OP_NOOP: u8 = 0;
pub const OP_TRANSFER: u8 = 1;
const NOOP_COMPUTE_UNITS: u64 = 1;
const TRANSFER_COMPUTE_UNITS: u64 = 10;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecutionStatus {
    Succeeded,
    Failed(ExecutionError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecutionError {
    DecodeFailed,
    ValidationFailed,
    Replay,
    MissingAccount,
    NonceMismatch,
    InsufficientFunds,
    ComputeLimitExceeded,
    UnsupportedProgram,
    InvalidInstruction,
    Unauthorized,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionReceipt {
    pub transaction_id: [u8; 32],
    pub status: ExecutionStatus,
    pub fee_charged: u64,
    pub compute_used: u64,
    pub pre_state_hash: [u8; 32],
    pub post_state_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionPolicy {
    Ordered,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountConflictKind {
    ReadWrite,
    WriteWrite,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionConflict {
    pub first_index: usize,
    pub second_index: usize,
    pub account: [u8; 32],
    pub kind: AccountConflictKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionBatchReceipt {
    pub policy: ExecutionPolicy,
    pub receipts: Vec<ExecutionReceipt>,
    pub conflicts: Vec<ExecutionConflict>,
    pub pre_state_hash: [u8; 32],
    pub post_state_hash: [u8; 32],
}

#[derive(Clone, Debug, Default)]
pub struct ExecutionEngine {
    replay: TransactionReplay,
}

impl ExecutionEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn execute_encoded(
        &mut self,
        state: &mut StateDb,
        bytes: &[u8],
        current_slot: u64,
    ) -> ExecutionReceipt {
        let pre_state_hash = state.state_hash();
        match Transaction::decode(bytes) {
            Ok(transaction) => self.execute_transaction(state, &transaction, current_slot),
            Err(_) => ExecutionReceipt {
                transaction_id: *blake3::hash(bytes).as_bytes(),
                status: ExecutionStatus::Failed(ExecutionError::DecodeFailed),
                fee_charged: 0,
                compute_used: 0,
                pre_state_hash,
                post_state_hash: pre_state_hash,
            },
        }
    }

    pub fn execute_transaction(
        &mut self,
        state: &mut StateDb,
        transaction: &Transaction,
        current_slot: u64,
    ) -> ExecutionReceipt {
        let pre_state_hash = state.state_hash();
        let transaction_id = transaction.transaction_id();
        let mut receipt = ExecutionReceipt {
            transaction_id,
            status: ExecutionStatus::Succeeded,
            fee_charged: 0,
            compute_used: 0,
            pre_state_hash,
            post_state_hash: pre_state_hash,
        };

        if transaction.validate_at_slot(current_slot).is_err() {
            receipt.status = ExecutionStatus::Failed(ExecutionError::ValidationFailed);
            return receipt;
        }

        if let Err(error) = self.prepare_and_charge_fee(state, transaction, current_slot) {
            receipt.status = ExecutionStatus::Failed(error);
            receipt.post_state_hash = state.state_hash();
            return receipt;
        }
        receipt.fee_charged = transaction.fee;
        let post_fee_state = state.clone();

        match execute_instructions(state, transaction) {
            Ok(compute_used) => {
                receipt.compute_used = compute_used;
                receipt.status = ExecutionStatus::Succeeded;
            }
            Err((error, compute_used)) => {
                *state = post_fee_state;
                receipt.compute_used = compute_used;
                receipt.status = ExecutionStatus::Failed(error);
            }
        }
        receipt.post_state_hash = state.state_hash();
        receipt
    }

    fn prepare_and_charge_fee(
        &mut self,
        state: &mut StateDb,
        transaction: &Transaction,
        current_slot: u64,
    ) -> Result<(), ExecutionError> {
        ensure_all_accounts_loaded(state, transaction)
            .map_err(|_| ExecutionError::MissingAccount)?;
        let fee_payer_index = *transaction
            .required_signer_indices
            .first()
            .ok_or(ExecutionError::ValidationFailed)?;
        let fee_payer = transaction.account_keys[usize::from(fee_payer_index)];
        if self.replay.contains(transaction) {
            return Err(ExecutionError::Replay);
        }
        let payer = state
            .get(&fee_payer)
            .ok_or(ExecutionError::MissingAccount)?;
        if payer.nonce != transaction.nonce {
            return Err(ExecutionError::NonceMismatch);
        }
        if payer.lamports < transaction.fee {
            return Err(ExecutionError::InsufficientFunds);
        }

        self.replay
            .accept(transaction, current_slot)
            .map_err(|e| map_replay_or_validation(e.to_string()))?;
        state
            .update_account(&fee_payer, |account| {
                account.lamports -= transaction.fee;
                account.nonce = account
                    .nonce
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("fee payer nonce overflow"))?;
                Ok(())
            })
            .map_err(|_| ExecutionError::ValidationFailed)?;
        Ok(())
    }
}

fn execute_instructions(
    state: &mut StateDb,
    transaction: &Transaction,
) -> Result<u64, (ExecutionError, u64)> {
    let mut compute_used = 0u64;
    for instruction in &transaction.instructions {
        let cost = instruction_cost(instruction).map_err(|error| (error, compute_used))?;
        compute_used = compute_used
            .checked_add(cost)
            .ok_or((ExecutionError::ComputeLimitExceeded, compute_used))?;
        if compute_used > transaction.compute_limit {
            return Err((ExecutionError::ComputeLimitExceeded, compute_used));
        }
        execute_instruction(state, transaction, instruction)
            .map_err(|error| (error, compute_used))?;
    }
    Ok(compute_used)
}

fn instruction_cost(instruction: &Instruction) -> Result<u64, ExecutionError> {
    let opcode = instruction
        .data
        .first()
        .copied()
        .ok_or(ExecutionError::InvalidInstruction)?;
    match opcode {
        OP_NOOP => Ok(NOOP_COMPUTE_UNITS),
        OP_TRANSFER => Ok(TRANSFER_COMPUTE_UNITS),
        _ => Err(ExecutionError::InvalidInstruction),
    }
}

fn execute_instruction(
    state: &mut StateDb,
    transaction: &Transaction,
    instruction: &Instruction,
) -> Result<(), ExecutionError> {
    let program_id = transaction.account_keys[usize::from(instruction.program_id_index)];
    if program_id != SYSTEM_PROGRAM_ID {
        return Err(ExecutionError::UnsupportedProgram);
    }
    match instruction.data.first().copied() {
        Some(OP_NOOP) => execute_noop(instruction),
        Some(OP_TRANSFER) => execute_transfer(state, transaction, instruction),
        _ => Err(ExecutionError::InvalidInstruction),
    }
}

fn execute_noop(instruction: &Instruction) -> Result<(), ExecutionError> {
    if instruction.data.len() != 1 {
        return Err(ExecutionError::InvalidInstruction);
    }
    Ok(())
}

fn execute_transfer(
    state: &mut StateDb,
    transaction: &Transaction,
    instruction: &Instruction,
) -> Result<(), ExecutionError> {
    if instruction.account_indices.len() != 2 || instruction.data.len() != 9 {
        return Err(ExecutionError::InvalidInstruction);
    }
    let amount = u64::from_be_bytes(
        instruction.data[1..9]
            .try_into()
            .expect("transfer amount length checked"),
    );
    if amount == 0 {
        return Err(ExecutionError::InvalidInstruction);
    }
    let from_index = instruction.account_indices[0];
    let to_index = instruction.account_indices[1];
    if !transaction.required_signer_indices.contains(&from_index) {
        return Err(ExecutionError::Unauthorized);
    }
    let from = transaction.account_keys[usize::from(from_index)];
    let to = transaction.account_keys[usize::from(to_index)];
    let from_balance = state
        .get(&from)
        .ok_or(ExecutionError::MissingAccount)?
        .lamports;
    if from_balance < amount {
        return Err(ExecutionError::InsufficientFunds);
    }
    let to_balance = state
        .get(&to)
        .ok_or(ExecutionError::MissingAccount)?
        .lamports;
    let new_to_balance = to_balance
        .checked_add(amount)
        .ok_or(ExecutionError::InsufficientFunds)?;

    state
        .update_account(&from, |account| {
            account.lamports -= amount;
            Ok(())
        })
        .map_err(|_| ExecutionError::MissingAccount)?;
    state
        .update_account(&to, |account| {
            account.lamports = new_to_balance;
            Ok(())
        })
        .map_err(|_| ExecutionError::MissingAccount)?;
    Ok(())
}

fn ensure_all_accounts_loaded(state: &StateDb, transaction: &Transaction) -> Result<()> {
    for address in &transaction.account_keys {
        if !state.contains(address) {
            bail!("transaction references missing account");
        }
    }
    Ok(())
}

pub fn lock_set_for_transaction(transaction: &Transaction) -> Result<AccountLockSet> {
    transaction.validate_structure()?;
    let mut writable = BTreeSet::new();
    for signer_index in &transaction.required_signer_indices {
        writable.insert(transaction.account_keys[usize::from(*signer_index)]);
    }
    for instruction in &transaction.instructions {
        for account_index in &instruction.account_indices {
            writable.insert(transaction.account_keys[usize::from(*account_index)]);
        }
    }
    let mut readonly = BTreeSet::new();
    for account in &transaction.account_keys {
        if !writable.contains(account) {
            readonly.insert(*account);
        }
    }
    AccountLockSet::new(readonly, writable)
}

pub fn detect_account_conflicts(transactions: &[Transaction]) -> Vec<ExecutionConflict> {
    let mut first_readers = BTreeMap::<[u8; 32], usize>::new();
    let mut first_writers = BTreeMap::<[u8; 32], usize>::new();
    let mut conflicts = Vec::new();

    for (index, transaction) in transactions.iter().enumerate() {
        let Ok(lock_set) = lock_set_for_transaction(transaction) else {
            continue;
        };

        for account in &lock_set.writable {
            if let Some(first_index) = first_writers.get(account) {
                conflicts.push(ExecutionConflict {
                    first_index: *first_index,
                    second_index: index,
                    account: *account,
                    kind: AccountConflictKind::WriteWrite,
                });
            } else if let Some(first_index) = first_readers.get(account) {
                conflicts.push(ExecutionConflict {
                    first_index: *first_index,
                    second_index: index,
                    account: *account,
                    kind: AccountConflictKind::ReadWrite,
                });
            }
        }

        for account in &lock_set.readonly {
            if let Some(first_index) = first_writers.get(account) {
                conflicts.push(ExecutionConflict {
                    first_index: *first_index,
                    second_index: index,
                    account: *account,
                    kind: AccountConflictKind::ReadWrite,
                });
            }
        }

        for account in lock_set.readonly {
            first_readers.entry(account).or_insert(index);
        }
        for account in lock_set.writable {
            first_writers.entry(account).or_insert(index);
        }
    }

    conflicts
}

pub fn execute_ordered_transactions(
    state: &mut StateDb,
    transactions: &[Transaction],
    current_slot: u64,
) -> Vec<ExecutionReceipt> {
    execute_transactions_with_policy(state, transactions, current_slot, ExecutionPolicy::Ordered)
        .receipts
}

pub fn execute_transactions_with_policy(
    state: &mut StateDb,
    transactions: &[Transaction],
    current_slot: u64,
    policy: ExecutionPolicy,
) -> ExecutionBatchReceipt {
    let pre_state_hash = state.state_hash();
    let conflicts = detect_account_conflicts(transactions);
    metrics::global().record_execution_batch(transactions.len() as u64, conflicts.len() as u64);
    let receipts = match policy {
        ExecutionPolicy::Ordered => {
            execute_ordered_transactions_inner(state, transactions, current_slot)
        }
    };
    ExecutionBatchReceipt {
        policy,
        receipts,
        conflicts,
        pre_state_hash,
        post_state_hash: state.state_hash(),
    }
}

fn execute_ordered_transactions_inner(
    state: &mut StateDb,
    transactions: &[Transaction],
    current_slot: u64,
) -> Vec<ExecutionReceipt> {
    let mut engine = ExecutionEngine::new();
    let mut locks = AccountLocks::default();
    transactions
        .iter()
        .map(|transaction| {
            let lock_set = match lock_set_for_transaction(transaction) {
                Ok(lock_set) => lock_set,
                Err(_) => {
                    return ExecutionReceipt {
                        transaction_id: transaction.transaction_id(),
                        status: ExecutionStatus::Failed(ExecutionError::ValidationFailed),
                        fee_charged: 0,
                        compute_used: 0,
                        pre_state_hash: state.state_hash(),
                        post_state_hash: state.state_hash(),
                    };
                }
            };
            match locks.try_acquire(&lock_set) {
                Ok(guard) => {
                    let receipt = engine.execute_transaction(state, transaction, current_slot);
                    locks.release(guard);
                    receipt
                }
                Err(_) => ExecutionReceipt {
                    transaction_id: transaction.transaction_id(),
                    status: ExecutionStatus::Failed(ExecutionError::ValidationFailed),
                    fee_charged: 0,
                    compute_used: 0,
                    pre_state_hash: state.state_hash(),
                    post_state_hash: state.state_hash(),
                },
            }
        })
        .collect()
}

fn map_replay_or_validation(error: String) -> ExecutionError {
    if error.contains("replayed transaction") {
        ExecutionError::Replay
    } else {
        ExecutionError::ValidationFailed
    }
}

#[cfg(all(test, feature = "ed25519"))]
mod tests {
    use super::*;
    use crate::{
        state::{Account, ProgramId},
        transaction::Transaction,
    };
    use ed25519_dalek::SigningKey;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn pubkey(key: &SigningKey) -> [u8; 32] {
        key.verifying_key().to_bytes()
    }

    fn owner(byte: u8) -> ProgramId {
        [byte; 32]
    }

    fn amount_data(amount: u64) -> Vec<u8> {
        let mut data = vec![OP_TRANSFER];
        data.extend_from_slice(&amount.to_be_bytes());
        data
    }

    fn state_for(sender: &SigningKey, recipient: &SigningKey) -> StateDb {
        let mut state = StateDb::default();
        state
            .insert(Account::new(pubkey(sender), owner(9), 100, Vec::new(), 0).unwrap())
            .unwrap();
        state
            .insert(Account::new(pubkey(recipient), owner(9), 10, Vec::new(), 0).unwrap())
            .unwrap();
        state
            .insert(Account::new(SYSTEM_PROGRAM_ID, owner(9), 0, Vec::new(), 0).unwrap())
            .unwrap();
        state
    }

    fn transfer_tx(
        sender: &SigningKey,
        recipient: &SigningKey,
        amount: u64,
        fee: u64,
    ) -> Transaction {
        let mut tx = Transaction {
            account_keys: vec![pubkey(sender), pubkey(recipient), SYSTEM_PROGRAM_ID],
            required_signer_indices: vec![0],
            signatures: Vec::new(),
            recent_blockhash: [3u8; 32],
            nonce: 0,
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

    fn set_nonce(tx: &mut Transaction, signer: &SigningKey, nonce: u64) {
        tx.nonce = nonce;
        tx.sign_with_keys(&[(0, signer.clone())]).unwrap();
    }

    #[test]
    fn transfer_state_transition_is_deterministic() {
        let sender = key(1);
        let recipient = key(2);
        let tx = transfer_tx(&sender, &recipient, 25, 5);
        let mut first = state_for(&sender, &recipient);
        let mut second = state_for(&sender, &recipient);

        let first_receipt = ExecutionEngine::new().execute_transaction(&mut first, &tx, 1);
        let second_receipt = ExecutionEngine::new().execute_transaction(&mut second, &tx, 1);

        assert_eq!(first_receipt.status, ExecutionStatus::Succeeded);
        assert_eq!(first.state_hash(), second.state_hash());
        assert_eq!(
            first_receipt.post_state_hash,
            second_receipt.post_state_hash
        );
        assert_eq!(first.get(&pubkey(&sender)).unwrap().lamports, 70);
        assert_eq!(first.get(&pubkey(&recipient)).unwrap().lamports, 35);
        assert_eq!(first.get(&pubkey(&sender)).unwrap().nonce, 1);
    }

    #[test]
    fn failed_instruction_charges_fee_and_rolls_back_instruction_changes() {
        let sender = key(1);
        let recipient = key(2);
        let tx = transfer_tx(&sender, &recipient, 200, 5);
        let mut state = state_for(&sender, &recipient);

        let receipt = ExecutionEngine::new().execute_transaction(&mut state, &tx, 1);

        assert_eq!(
            receipt.status,
            ExecutionStatus::Failed(ExecutionError::InsufficientFunds)
        );
        assert_eq!(receipt.fee_charged, 5);
        assert_eq!(state.get(&pubkey(&sender)).unwrap().lamports, 95);
        assert_eq!(state.get(&pubkey(&recipient)).unwrap().lamports, 10);
        assert_eq!(state.get(&pubkey(&sender)).unwrap().nonce, 1);
    }

    #[test]
    fn invalid_signature_does_not_charge_fee() {
        let sender = key(1);
        let recipient = key(2);
        let mut tx = transfer_tx(&sender, &recipient, 10, 5);
        tx.fee = 6;
        let mut state = state_for(&sender, &recipient);

        let receipt = ExecutionEngine::new().execute_transaction(&mut state, &tx, 1);

        assert_eq!(
            receipt.status,
            ExecutionStatus::Failed(ExecutionError::ValidationFailed)
        );
        assert_eq!(receipt.fee_charged, 0);
        assert_eq!(state.get(&pubkey(&sender)).unwrap().lamports, 100);
    }

    #[test]
    fn compute_limit_failure_charges_fee_only() {
        let sender = key(1);
        let recipient = key(2);
        let mut tx = transfer_tx(&sender, &recipient, 10, 5);
        tx.compute_limit = 5;
        tx.sign_with_keys(&[(0, sender.clone())]).unwrap();
        let mut state = state_for(&sender, &recipient);

        let receipt = ExecutionEngine::new().execute_transaction(&mut state, &tx, 1);

        assert_eq!(
            receipt.status,
            ExecutionStatus::Failed(ExecutionError::ComputeLimitExceeded)
        );
        assert_eq!(receipt.fee_charged, 5);
        assert_eq!(state.get(&pubkey(&sender)).unwrap().lamports, 95);
        assert_eq!(state.get(&pubkey(&recipient)).unwrap().lamports, 10);
    }

    #[test]
    fn replay_transaction_is_rejected_without_second_fee() {
        let sender = key(1);
        let recipient = key(2);
        let tx = transfer_tx(&sender, &recipient, 10, 5);
        let mut state = state_for(&sender, &recipient);
        let mut engine = ExecutionEngine::new();

        let first = engine.execute_transaction(&mut state, &tx, 1);
        let second = engine.execute_transaction(&mut state, &tx, 1);

        assert_eq!(first.status, ExecutionStatus::Succeeded);
        assert_eq!(
            second.status,
            ExecutionStatus::Failed(ExecutionError::Replay)
        );
        assert_eq!(second.fee_charged, 0);
        assert_eq!(state.get(&pubkey(&sender)).unwrap().lamports, 85);
    }

    #[test]
    fn malformed_encoded_transaction_returns_receipt_without_panic() {
        let sender = key(1);
        let recipient = key(2);
        let mut state = state_for(&sender, &recipient);

        let receipt = ExecutionEngine::new().execute_encoded(&mut state, b"bad", 1);

        assert_eq!(
            receipt.status,
            ExecutionStatus::Failed(ExecutionError::DecodeFailed)
        );
        assert_eq!(receipt.pre_state_hash, receipt.post_state_hash);
    }

    #[test]
    fn ordered_transactions_produce_same_state_root() {
        let sender = key(1);
        let recipient = key(2);
        let first_tx = transfer_tx(&sender, &recipient, 10, 5);
        let mut second_tx = transfer_tx(&sender, &recipient, 5, 5);
        set_nonce(&mut second_tx, &sender, 1);
        let ordered = vec![first_tx, second_tx];
        let mut first = state_for(&sender, &recipient);
        let mut second = state_for(&sender, &recipient);

        let first_receipts = execute_ordered_transactions(&mut first, &ordered, 1);
        let second_receipts = execute_ordered_transactions(&mut second, &ordered, 1);

        assert_eq!(first_receipts, second_receipts);
        assert_eq!(first.state_hash(), second.state_hash());
        assert_eq!(first.get(&pubkey(&sender)).unwrap().lamports, 75);
        assert_eq!(first.get(&pubkey(&recipient)).unwrap().lamports, 25);
    }

    #[test]
    fn ordered_policy_reports_conflicts_and_commits_in_input_order() {
        let sender = key(1);
        let recipient = key(2);
        let first_tx = transfer_tx(&sender, &recipient, 10, 5);
        let mut second_tx = transfer_tx(&sender, &recipient, 5, 5);
        set_nonce(&mut second_tx, &sender, 1);
        let ordered = vec![first_tx, second_tx];
        let mut state = state_for(&sender, &recipient);

        let batch =
            execute_transactions_with_policy(&mut state, &ordered, 1, ExecutionPolicy::Ordered);

        assert_eq!(batch.policy, ExecutionPolicy::Ordered);
        assert_eq!(batch.receipts.len(), 2);
        assert!(batch.conflicts.iter().any(|conflict| {
            conflict.first_index == 0
                && conflict.second_index == 1
                && conflict.kind == AccountConflictKind::WriteWrite
        }));
        assert_eq!(batch.receipts[0].status, ExecutionStatus::Succeeded);
        assert_eq!(batch.receipts[1].status, ExecutionStatus::Succeeded);
        assert_eq!(state.get(&pubkey(&sender)).unwrap().lamports, 75);
        assert_eq!(state.get(&pubkey(&recipient)).unwrap().lamports, 25);
    }

    #[test]
    fn repeated_ordered_policy_fixture_is_deterministic() {
        let sender = key(1);
        let recipient = key(2);
        let first_tx = transfer_tx(&sender, &recipient, 10, 5);
        let mut second_tx = transfer_tx(&sender, &recipient, 5, 5);
        set_nonce(&mut second_tx, &sender, 1);
        let ordered = vec![first_tx, second_tx];
        let mut first = state_for(&sender, &recipient);
        let mut second = state_for(&sender, &recipient);

        let first_batch =
            execute_transactions_with_policy(&mut first, &ordered, 1, ExecutionPolicy::Ordered);
        let second_batch =
            execute_transactions_with_policy(&mut second, &ordered, 1, ExecutionPolicy::Ordered);

        assert_eq!(first_batch.receipts, second_batch.receipts);
        assert_eq!(first_batch.conflicts, second_batch.conflicts);
        assert_eq!(first_batch.post_state_hash, second_batch.post_state_hash);
        assert_eq!(first.state_hash(), second.state_hash());
    }

    #[test]
    fn malformed_lock_set_is_rejected_without_panic() {
        let sender = key(1);
        let recipient = key(2);
        let mut tx = transfer_tx(&sender, &recipient, 10, 5);
        tx.instructions[0].account_indices = vec![0, 99];
        tx.sign_with_keys(&[(0, sender.clone())]).unwrap();
        let mut state = state_for(&sender, &recipient);

        let batch =
            execute_transactions_with_policy(&mut state, &[tx], 1, ExecutionPolicy::Ordered);

        assert!(batch.conflicts.is_empty());
        assert_eq!(
            batch.receipts[0].status,
            ExecutionStatus::Failed(ExecutionError::ValidationFailed)
        );
        assert_eq!(batch.pre_state_hash, batch.post_state_hash);
    }
}
