use crate::{
    blockstore::Blockstore,
    ledger::{LedgerBlock, LedgerHash},
    replay::GENESIS_PARENT_HASH,
    validator_set::EpochSlot,
};
use anyhow::{Result, bail};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForkBlock {
    pub block_hash: LedgerHash,
    pub parent_hash: LedgerHash,
    pub slot: EpochSlot,
    pub weight: u64,
    pub cumulative_weight: u64,
    pub connected: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForkTip {
    pub block_hash: LedgerHash,
    pub slot: EpochSlot,
    pub cumulative_weight: u64,
}

#[derive(Clone, Debug)]
struct ForkNode {
    block_hash: LedgerHash,
    parent_hash: LedgerHash,
    slot: EpochSlot,
    weight: u64,
    cumulative_weight: u64,
    connected: bool,
}

#[derive(Clone, Debug)]
pub struct ForkTree {
    blocks: BTreeMap<LedgerHash, ForkNode>,
    children: BTreeMap<LedgerHash, BTreeSet<LedgerHash>>,
    missing_parent_to_children: BTreeMap<LedgerHash, BTreeSet<LedgerHash>>,
    finalized_root: LedgerHash,
}

impl Default for ForkTree {
    fn default() -> Self {
        Self::new(GENESIS_PARENT_HASH)
    }
}

impl ForkTree {
    pub fn new(finalized_root: LedgerHash) -> Self {
        Self {
            blocks: BTreeMap::new(),
            children: BTreeMap::new(),
            missing_parent_to_children: BTreeMap::new(),
            finalized_root,
        }
    }

    pub fn rebuild_from_blockstore(
        blockstore: &Blockstore,
        block_weight: impl Fn(&LedgerBlock) -> u64,
    ) -> Result<Self> {
        let mut tree = Self::default();
        let mut blocks = blockstore.all_blocks().collect::<Vec<_>>();
        blocks.sort_by_key(|block| (block.slot, block.block_hash));
        for block in blocks {
            tree.insert_block(block, block_weight(block))?;
        }
        Ok(tree)
    }

    pub fn insert_block(&mut self, block: &LedgerBlock, weight: u64) -> Result<()> {
        block.validate_integrity()?;
        if weight == 0 {
            bail!("fork block weight must be greater than zero");
        }
        if let Some(existing) = self.blocks.get(&block.block_hash) {
            if existing.parent_hash == block.parent_hash
                && existing.slot == block.slot
                && existing.weight == weight
            {
                return Ok(());
            }
            bail!("conflicting duplicate fork block");
        }
        let connected = block.parent_hash == self.finalized_root
            || block.parent_hash == GENESIS_PARENT_HASH
            || self
                .blocks
                .get(&block.parent_hash)
                .is_some_and(|parent| parent.connected);
        let parent_cumulative = if block.parent_hash == self.finalized_root
            || block.parent_hash == GENESIS_PARENT_HASH
        {
            0
        } else {
            self.blocks
                .get(&block.parent_hash)
                .filter(|parent| parent.connected)
                .map(|parent| parent.cumulative_weight)
                .unwrap_or(0)
        };
        let node = ForkNode {
            block_hash: block.block_hash,
            parent_hash: block.parent_hash,
            slot: block.slot,
            weight,
            cumulative_weight: if connected {
                parent_cumulative
                    .checked_add(weight)
                    .ok_or_else(|| anyhow::anyhow!("fork cumulative weight overflow"))?
            } else {
                weight
            },
            connected,
        };
        self.blocks.insert(block.block_hash, node);
        self.children
            .entry(block.parent_hash)
            .or_default()
            .insert(block.block_hash);
        if !connected {
            self.missing_parent_to_children
                .entry(block.parent_hash)
                .or_default()
                .insert(block.block_hash);
        }
        self.connect_waiting_descendants(block.block_hash)?;
        Ok(())
    }

    pub fn get(&self, block_hash: &LedgerHash) -> Option<ForkBlock> {
        self.blocks.get(block_hash).map(ForkBlock::from)
    }

    pub fn children(&self, block_hash: &LedgerHash) -> Vec<LedgerHash> {
        self.children
            .get(block_hash)
            .into_iter()
            .flat_map(|children| children.iter().copied())
            .collect()
    }

    pub fn descendants(&self, block_hash: &LedgerHash) -> Vec<LedgerHash> {
        let mut out = Vec::new();
        let mut stack = self.children(block_hash);
        stack.sort();
        while let Some(hash) = stack.pop() {
            out.push(hash);
            let mut children = self.children(&hash);
            children.sort();
            stack.extend(children);
        }
        out
    }

    pub fn missing_parents(&self) -> Vec<LedgerHash> {
        self.missing_parent_to_children.keys().copied().collect()
    }

    pub fn orphan_children(&self, missing_parent: &LedgerHash) -> Vec<LedgerHash> {
        self.missing_parent_to_children
            .get(missing_parent)
            .into_iter()
            .flat_map(|children| children.iter().copied())
            .collect()
    }

    pub fn best_known_fork(&self) -> Option<ForkTip> {
        self.connected_tips()
            .into_iter()
            .max_by_key(|tip| (tip.cumulative_weight, tip.slot, tip.block_hash))
    }

    pub fn connected_tips(&self) -> Vec<ForkTip> {
        self.blocks
            .values()
            .filter(|node| node.connected)
            .filter(|node| {
                self.children
                    .get(&node.block_hash)
                    .is_none_or(|children| children.is_empty())
            })
            .map(ForkTip::from)
            .collect()
    }

    pub fn finalized_root(&self) -> LedgerHash {
        self.finalized_root
    }

    pub fn set_finalized_root(&mut self, block_hash: LedgerHash) -> Result<()> {
        if block_hash != GENESIS_PARENT_HASH && !self.blocks.contains_key(&block_hash) {
            bail!("cannot finalize unknown block");
        }
        self.finalized_root = block_hash;
        Ok(())
    }

    pub fn is_descendant_or_self(
        &self,
        block_hash: &LedgerHash,
        ancestor_hash: &LedgerHash,
    ) -> bool {
        if block_hash == ancestor_hash {
            return true;
        }
        let mut current = *block_hash;
        while let Some(block) = self.blocks.get(&current) {
            if &block.parent_hash == ancestor_hash {
                return true;
            }
            if block.parent_hash == GENESIS_PARENT_HASH {
                return ancestor_hash == &GENESIS_PARENT_HASH;
            }
            current = block.parent_hash;
        }
        false
    }

    pub fn prune_to_finalized_root(&mut self) -> Result<Vec<LedgerHash>> {
        if self.finalized_root == GENESIS_PARENT_HASH {
            return Ok(Vec::new());
        }

        let mut retained = BTreeSet::new();
        retained.insert(self.finalized_root);
        for hash in self.blocks.keys() {
            if self.is_descendant_or_self(hash, &self.finalized_root) {
                retained.insert(*hash);
            }
        }

        let removed = self
            .blocks
            .keys()
            .filter(|hash| !retained.contains(*hash))
            .copied()
            .collect::<Vec<_>>();
        self.blocks.retain(|hash, _| retained.contains(hash));
        self.children.clear();
        self.missing_parent_to_children.clear();

        let mut hashes = self.blocks.keys().copied().collect::<Vec<_>>();
        hashes.sort_by_key(|hash| {
            self.blocks
                .get(hash)
                .map(|block| (block.slot, block.block_hash))
                .expect("hash was collected from blocks")
        });

        for hash in &hashes {
            if let Some(block) = self.blocks.get_mut(hash) {
                block.connected = false;
                block.cumulative_weight = block.weight;
            }
        }

        for hash in hashes {
            let Some(parent_hash) = self.blocks.get(&hash).map(|block| block.parent_hash) else {
                continue;
            };
            self.children.entry(parent_hash).or_default().insert(hash);

            let (connected, parent_cumulative) =
                if hash == self.finalized_root || parent_hash == self.finalized_root {
                    (true, 0)
                } else {
                    self.blocks
                        .get(&parent_hash)
                        .filter(|parent| parent.connected)
                        .map(|parent| (true, parent.cumulative_weight))
                        .unwrap_or((false, 0))
                };

            let Some(block) = self.blocks.get_mut(&hash) else {
                continue;
            };
            block.connected = connected;
            block.cumulative_weight = parent_cumulative
                .checked_add(if hash == self.finalized_root {
                    0
                } else {
                    block.weight
                })
                .ok_or_else(|| anyhow::anyhow!("fork cumulative weight overflow"))?;
            if !connected {
                self.missing_parent_to_children
                    .entry(block.parent_hash)
                    .or_default()
                    .insert(hash);
            }
        }

        Ok(removed)
    }

    fn connect_waiting_descendants(&mut self, parent_hash: LedgerHash) -> Result<()> {
        let Some(waiting) = self.missing_parent_to_children.remove(&parent_hash) else {
            return Ok(());
        };
        let mut stack = waiting.into_iter().collect::<Vec<_>>();
        while let Some(hash) = stack.pop() {
            let Some(node_parent_hash) = self.blocks.get(&hash).map(|node| node.parent_hash) else {
                continue;
            };
            let Some(parent) = self.blocks.get(&node_parent_hash).cloned() else {
                continue;
            };
            let connected_hash = {
                let Some(node) = self.blocks.get_mut(&hash) else {
                    continue;
                };
                if node.parent_hash != parent.block_hash || !parent.connected {
                    continue;
                }
                node.connected = true;
                node.cumulative_weight = parent
                    .cumulative_weight
                    .checked_add(node.weight)
                    .ok_or_else(|| anyhow::anyhow!("fork cumulative weight overflow"))?;
                node.block_hash
            };
            if let Some(children) = self.children.get(&hash) {
                stack.extend(children.iter().copied());
            }
            self.missing_parent_to_children.remove(&connected_hash);
        }
        Ok(())
    }
}

impl From<&ForkNode> for ForkBlock {
    fn from(node: &ForkNode) -> Self {
        Self {
            block_hash: node.block_hash,
            parent_hash: node.parent_hash,
            slot: node.slot,
            weight: node.weight,
            cumulative_weight: node.cumulative_weight,
            connected: node.connected,
        }
    }
}

impl From<&ForkNode> for ForkTip {
    fn from(node: &ForkNode) -> Self {
        Self {
            block_hash: node.block_hash,
            slot: node.slot,
            cumulative_weight: node.cumulative_weight,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        blockstore::{Blockstore, BlockstoreBatch},
        identity::ValidatorId,
        ledger::{LedgerEntry, TransactionBatch},
    };
    use std::{path::PathBuf, str::FromStr};

    fn temp_dir() -> PathBuf {
        crate::test_support::temp_dir("fork-tree")
    }

    fn block(slot: u64, parent_hash: LedgerHash, payload: &[u8]) -> LedgerBlock {
        let batch = TransactionBatch::new(0, vec![payload.to_vec()]).unwrap();
        let entry = LedgerEntry::new(0, parent_hash, vec![batch]).unwrap();
        LedgerBlock::new(
            EpochSlot::new(0, slot),
            parent_hash,
            ValidatorId::from_str("validator-a").unwrap(),
            vec![entry],
            [7u8; 64],
        )
        .unwrap()
    }

    #[test]
    fn linear_chain_tracks_descendants_and_best_tip() {
        let first = block(1, GENESIS_PARENT_HASH, b"a");
        let second = block(2, first.block_hash, b"b");
        let mut tree = ForkTree::default();

        tree.insert_block(&first, 10).unwrap();
        tree.insert_block(&second, 20).unwrap();

        assert_eq!(tree.children(&first.block_hash), vec![second.block_hash]);
        assert_eq!(
            tree.descendants(&GENESIS_PARENT_HASH),
            vec![first.block_hash, second.block_hash]
        );
        let tip = tree.best_known_fork().unwrap();
        assert_eq!(tip.block_hash, second.block_hash);
        assert_eq!(tip.cumulative_weight, 30);
    }

    #[test]
    fn two_forks_pick_heaviest_connected_tip() {
        let root_child = block(1, GENESIS_PARENT_HASH, b"root-child");
        let light = block(2, root_child.block_hash, b"light");
        let heavy = block(2, root_child.block_hash, b"heavy");
        let mut tree = ForkTree::default();

        tree.insert_block(&root_child, 10).unwrap();
        tree.insert_block(&light, 5).unwrap();
        tree.insert_block(&heavy, 50).unwrap();

        let children = tree.children(&root_child.block_hash);
        assert_eq!(children.len(), 2);
        let tip = tree.best_known_fork().unwrap();
        assert_eq!(tip.block_hash, heavy.block_hash);
        assert_eq!(tip.cumulative_weight, 60);
    }

    #[test]
    fn missing_parent_blocks_are_orphans_until_parent_arrives() {
        let parent = block(1, GENESIS_PARENT_HASH, b"parent");
        let child = block(2, parent.block_hash, b"child");
        let mut tree = ForkTree::default();

        tree.insert_block(&child, 10).unwrap();

        assert_eq!(tree.missing_parents(), vec![parent.block_hash]);
        assert_eq!(
            tree.orphan_children(&parent.block_hash),
            vec![child.block_hash]
        );
        assert!(!tree.get(&child.block_hash).unwrap().connected);

        tree.insert_block(&parent, 5).unwrap();

        assert!(tree.missing_parents().is_empty());
        assert!(tree.get(&child.block_hash).unwrap().connected);
        assert_eq!(tree.get(&child.block_hash).unwrap().cumulative_weight, 15);
    }

    #[test]
    fn rebuild_from_blockstore_survives_restart() {
        let first = block(1, GENESIS_PARENT_HASH, b"a");
        let second = block(2, first.block_hash, b"b");
        let dir = temp_dir();
        let mut batch = BlockstoreBatch::new();
        batch.put_block(second.clone());
        batch.put_block(first.clone());
        Blockstore::open(&dir).unwrap().write_batch(batch).unwrap();
        let store = Blockstore::open(&dir).unwrap();

        let tree = ForkTree::rebuild_from_blockstore(&store, |_| 1).unwrap();

        let tip = tree.best_known_fork().unwrap();
        assert_eq!(tip.block_hash, second.block_hash);
        assert_eq!(tip.cumulative_weight, 2);
        assert!(tree.missing_parents().is_empty());
    }
}
