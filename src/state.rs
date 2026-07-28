use anyhow::{Result, anyhow, bail};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

const STATE_HASH_DOMAIN: &[u8] = b"rpkv2.state.v1";
const MAX_ACCOUNT_DATA_LEN: usize = 1024 * 1024;

pub type AccountAddress = [u8; 32];
pub type ProgramId = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    pub address: AccountAddress,
    pub owner: ProgramId,
    pub lamports: u64,
    pub data: Vec<u8>,
    pub nonce: u64,
}

impl Account {
    pub fn new(
        address: AccountAddress,
        owner: ProgramId,
        lamports: u64,
        data: Vec<u8>,
        nonce: u64,
    ) -> Result<Self> {
        if address == [0u8; 32] {
            bail!("account address must not be all zeros");
        }
        if owner == [0u8; 32] {
            bail!("account owner must not be all zeros");
        }
        if data.len() > MAX_ACCOUNT_DATA_LEN {
            bail!("account data exceeds maximum length");
        }
        Ok(Self {
            address,
            owner,
            lamports,
            data,
            nonce,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct StateDb {
    accounts: BTreeMap<AccountAddress, Account>,
}

impl StateDb {
    pub fn from_genesis_toml_str(text: &str) -> Result<Self> {
        let genesis: GenesisStateConfig = toml::from_str(text)?;
        Self::from_genesis(genesis)
    }

    pub fn from_genesis(genesis: GenesisStateConfig) -> Result<Self> {
        let mut state = Self::default();
        for account in genesis.accounts {
            state.insert(Account::try_from(account)?)?;
        }
        Ok(state)
    }

    pub fn get(&self, address: &AccountAddress) -> Option<&Account> {
        self.accounts.get(address)
    }

    pub fn contains(&self, address: &AccountAddress) -> bool {
        self.accounts.contains_key(address)
    }

    pub fn insert(&mut self, account: Account) -> Result<()> {
        if self.accounts.contains_key(&account.address) {
            bail!("duplicate account address in state");
        }
        self.accounts.insert(account.address, account);
        Ok(())
    }

    pub fn write_account(&mut self, account: Account) {
        self.accounts.insert(account.address, account);
    }

    pub fn update_account(
        &mut self,
        address: &AccountAddress,
        update: impl FnOnce(&mut Account) -> Result<()>,
    ) -> Result<()> {
        let account = self
            .accounts
            .get_mut(address)
            .ok_or_else(|| anyhow!("account does not exist"))?;
        update(account)?;
        if account.data.len() > MAX_ACCOUNT_DATA_LEN {
            bail!("account data exceeds maximum length");
        }
        Ok(())
    }

    pub fn accounts(&self) -> impl Iterator<Item = &Account> {
        self.accounts.values()
    }

    pub fn snapshot(&self) -> StateSnapshot {
        StateSnapshot {
            accounts: self.accounts.values().cloned().collect(),
            state_hash: self.state_hash(),
        }
    }

    pub fn checkpoint(&self) -> StateCheckpoint {
        StateCheckpoint {
            account_count: self.accounts.len(),
            state_hash: self.state_hash(),
        }
    }

    pub fn state_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(STATE_HASH_DOMAIN);
        hasher.update(&(self.accounts.len() as u64).to_be_bytes());
        for account in self.accounts.values() {
            encode_account_for_hash(&mut hasher, account);
        }
        *hasher.finalize().as_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateSnapshot {
    pub accounts: Vec<Account>,
    pub state_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateCheckpoint {
    pub account_count: usize,
    pub state_hash: [u8; 32],
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountLockSet {
    pub readonly: BTreeSet<AccountAddress>,
    pub writable: BTreeSet<AccountAddress>,
}

impl AccountLockSet {
    pub fn new(
        readonly: impl IntoIterator<Item = AccountAddress>,
        writable: impl IntoIterator<Item = AccountAddress>,
    ) -> Result<Self> {
        let readonly: BTreeSet<_> = readonly.into_iter().collect();
        let writable: BTreeSet<_> = writable.into_iter().collect();
        if readonly.iter().any(|address| writable.contains(address)) {
            bail!("account cannot be both readonly and writable in one lock set");
        }
        Ok(Self { readonly, writable })
    }
}

#[derive(Clone, Debug, Default)]
pub struct AccountLocks {
    readonly: BTreeMap<AccountAddress, usize>,
    writable: BTreeSet<AccountAddress>,
}

impl AccountLocks {
    pub fn try_acquire(&mut self, locks: &AccountLockSet) -> Result<AccountLockGuard> {
        for address in &locks.writable {
            if self.writable.contains(address) || self.readonly.contains_key(address) {
                bail!("writable account lock conflicts with existing lock");
            }
        }
        for address in &locks.readonly {
            if self.writable.contains(address) {
                bail!("readonly account lock conflicts with existing writable lock");
            }
        }

        for address in &locks.writable {
            self.writable.insert(*address);
        }
        for address in &locks.readonly {
            *self.readonly.entry(*address).or_insert(0) += 1;
        }
        Ok(AccountLockGuard {
            locks: locks.clone(),
        })
    }

    pub fn release(&mut self, guard: AccountLockGuard) {
        for address in guard.locks.writable {
            self.writable.remove(&address);
        }
        for address in guard.locks.readonly {
            if let Some(count) = self.readonly.get_mut(&address) {
                *count -= 1;
                if *count == 0 {
                    self.readonly.remove(&address);
                }
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountLockGuard {
    locks: AccountLockSet,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisStateConfig {
    pub accounts: Vec<GenesisAccountConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisAccountConfig {
    pub address_hex: String,
    pub owner_hex: String,
    pub lamports: u64,
    #[serde(default)]
    pub data_hex: String,
    #[serde(default)]
    pub nonce: u64,
}

impl TryFrom<GenesisAccountConfig> for Account {
    type Error = anyhow::Error;

    fn try_from(value: GenesisAccountConfig) -> Result<Self> {
        Self::new(
            parse_hex_32("address_hex", &value.address_hex)?,
            parse_hex_32("owner_hex", &value.owner_hex)?,
            value.lamports,
            parse_hex_bytes("data_hex", &value.data_hex)?,
            value.nonce,
        )
    }
}

fn encode_account_for_hash(hasher: &mut blake3::Hasher, account: &Account) {
    hasher.update(&account.address);
    hasher.update(&account.owner);
    hasher.update(&account.lamports.to_be_bytes());
    hasher.update(&account.nonce.to_be_bytes());
    hasher.update(&(account.data.len() as u64).to_be_bytes());
    hasher.update(&account.data);
}

fn parse_hex_32(field: &str, value: &str) -> Result<[u8; 32]> {
    let bytes = parse_hex_bytes(field, value)?;
    if bytes.len() != 32 {
        bail!("{field} must decode to exactly 32 bytes");
    }
    Ok(bytes.try_into().expect("length checked above"))
}

fn parse_hex_bytes(field: &str, value: &str) -> Result<Vec<u8>> {
    if value.len() % 2 != 0 {
        bail!("{field} must contain an even number of hex characters");
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    for index in (0..value.len()).step_by(2) {
        out.push(
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|_| anyhow!("{field} contains non-hex characters"))?,
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(byte: u8) -> AccountAddress {
        [byte; 32]
    }

    fn owner(byte: u8) -> ProgramId {
        [byte; 32]
    }

    fn account(byte: u8, lamports: u64) -> Account {
        Account::new(address(byte), owner(200), lamports, vec![byte, byte + 1], 0).unwrap()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn account_reads_and_writes_are_deterministic() {
        let mut state = StateDb::default();
        state.insert(account(2, 20)).unwrap();
        state.insert(account(1, 10)).unwrap();

        let ordered: Vec<_> = state.accounts().map(|account| account.address[0]).collect();
        assert_eq!(ordered, vec![1, 2]);

        state
            .update_account(&address(1), |account| {
                account.lamports += 5;
                account.nonce += 1;
                Ok(())
            })
            .unwrap();

        let updated = state.get(&address(1)).unwrap();
        assert_eq!(updated.lamports, 15);
        assert_eq!(updated.nonce, 1);
    }

    #[test]
    fn state_hash_is_stable_across_insert_order() {
        let mut first = StateDb::default();
        first.insert(account(1, 10)).unwrap();
        first.insert(account(2, 20)).unwrap();

        let mut second = StateDb::default();
        second.insert(account(2, 20)).unwrap();
        second.insert(account(1, 10)).unwrap();

        assert_eq!(first.state_hash(), second.state_hash());
    }

    #[test]
    fn state_hash_changes_when_account_changes() {
        let mut state = StateDb::default();
        state.insert(account(1, 10)).unwrap();
        let before = state.state_hash();

        state
            .update_account(&address(1), |account| {
                account.lamports += 1;
                Ok(())
            })
            .unwrap();

        assert_ne!(before, state.state_hash());
    }

    #[test]
    fn genesis_loads_state() {
        let text = format!(
            r#"
[[accounts]]
address_hex = "{}"
owner_hex = "{}"
lamports = 42
data_hex = "010203"
nonce = 7
"#,
            hex(&address(1)),
            hex(&owner(2)),
        );

        let state = StateDb::from_genesis_toml_str(&text).unwrap();
        let loaded = state.get(&address(1)).unwrap();

        assert_eq!(loaded.owner, owner(2));
        assert_eq!(loaded.lamports, 42);
        assert_eq!(loaded.data, vec![1, 2, 3]);
        assert_eq!(loaded.nonce, 7);
    }

    #[test]
    fn duplicate_genesis_account_fails() {
        let text = format!(
            r#"
[[accounts]]
address_hex = "{}"
owner_hex = "{}"
lamports = 1

[[accounts]]
address_hex = "{}"
owner_hex = "{}"
lamports = 2
"#,
            hex(&address(1)),
            hex(&owner(2)),
            hex(&address(1)),
            hex(&owner(3)),
        );

        assert!(StateDb::from_genesis_toml_str(&text).is_err());
    }

    #[test]
    fn snapshot_and_checkpoint_report_state_hash() {
        let mut state = StateDb::default();
        state.insert(account(1, 10)).unwrap();

        let snapshot = state.snapshot();
        let checkpoint = state.checkpoint();

        assert_eq!(snapshot.accounts.len(), 1);
        assert_eq!(snapshot.state_hash, state.state_hash());
        assert_eq!(checkpoint.account_count, 1);
        assert_eq!(checkpoint.state_hash, state.state_hash());
    }

    #[test]
    fn account_lock_conflict_rules_are_enforced() {
        let mut locks = AccountLocks::default();
        let read = AccountLockSet::new([address(1)], []).unwrap();
        let write_same = AccountLockSet::new([], [address(1)]).unwrap();
        let read_same = AccountLockSet::new([address(1)], []).unwrap();
        let write_other = AccountLockSet::new([], [address(2)]).unwrap();

        let read_guard = locks.try_acquire(&read).unwrap();
        assert!(locks.try_acquire(&read_same).is_ok());
        assert!(locks.try_acquire(&write_same).is_err());
        assert!(locks.try_acquire(&write_other).is_ok());
        locks.release(read_guard);
    }

    #[test]
    fn account_cannot_be_readonly_and_writable_in_same_lock_set() {
        assert!(AccountLockSet::new([address(1)], [address(1)]).is_err());
    }
}
