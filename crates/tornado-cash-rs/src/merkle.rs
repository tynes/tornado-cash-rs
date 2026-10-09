//! The Tornado Cash Classic Merkle tree: height 20, MiMCSponge node hash,
//! empty leaves equal to `keccak256("tornado") mod p`.

use crate::error::{Error, Result};
use crate::hash::{fr_from_be_bytes, fr_to_bytes32, hash_left_right};
use alloy::primitives::{keccak256, B256};
use ark_bn254::Fr;

pub const TREE_HEIGHT: usize = 20;

pub fn zero_value() -> Fr {
    fr_from_be_bytes(keccak256(b"tornado").as_slice())
}

/// Authentication path for one leaf.
#[derive(Clone, Debug)]
pub struct MerkleProof {
    pub root: Fr,
    pub path_elements: Vec<Fr>,
    /// `true` when the current node is a right child at that level.
    pub path_indices: Vec<bool>,
}

impl MerkleProof {
    pub fn root_bytes(&self) -> B256 {
        B256::from(fr_to_bytes32(&self.root))
    }
}

/// A fully materialised tree over the deposited leaves.
pub struct MerkleTree {
    /// layers[0] are leaves; layers[TREE_HEIGHT] is `[root]`.
    layers: Vec<Vec<Fr>>,
    zeros: Vec<Fr>,
}

impl MerkleTree {
    pub fn new(leaves: Vec<Fr>) -> Result<Self> {
        if leaves.len() > 1 << TREE_HEIGHT {
            return Err(Error::Merkle("tree is full".into()));
        }
        let mut zeros = vec![zero_value()];
        for i in 0..TREE_HEIGHT {
            zeros.push(hash_left_right(zeros[i], zeros[i]));
        }
        let mut layers = vec![leaves];
        for level in 0..TREE_HEIGHT {
            let prev = &layers[level];
            let next: Vec<Fr> = (0..prev.len().div_ceil(2))
                .map(|i| {
                    let l = prev[2 * i];
                    let r = prev.get(2 * i + 1).copied().unwrap_or(zeros[level]);
                    hash_left_right(l, r)
                })
                .collect();
            layers.push(next);
        }
        Ok(MerkleTree { layers, zeros })
    }

    pub fn len(&self) -> usize {
        self.layers[0].len()
    }

    pub fn is_empty(&self) -> bool {
        self.layers[0].is_empty()
    }

    pub fn root(&self) -> Fr {
        self.layers[TREE_HEIGHT]
            .first()
            .copied()
            .unwrap_or(self.zeros[TREE_HEIGHT])
    }

    pub fn index_of(&self, leaf: &Fr) -> Option<usize> {
        self.layers[0].iter().position(|l| l == leaf)
    }

    pub fn proof(&self, index: usize) -> Result<MerkleProof> {
        if index >= self.len() {
            return Err(Error::Merkle(format!("leaf {index} is not in the tree")));
        }
        let mut path_elements = Vec::with_capacity(TREE_HEIGHT);
        let mut path_indices = Vec::with_capacity(TREE_HEIGHT);
        let mut idx = index;
        for level in 0..TREE_HEIGHT {
            let sibling = idx ^ 1;
            path_elements.push(
                self.layers[level]
                    .get(sibling)
                    .copied()
                    .unwrap_or(self.zeros[level]),
            );
            path_indices.push(idx & 1 == 1);
            idx >>= 1;
        }
        Ok(MerkleProof {
            root: self.root(),
            path_elements,
            path_indices,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_root_matches_contract() {
        // MerkleTreeWithHistory.zeros(20), the root of an empty height-20 tree.
        let t = MerkleTree::new(vec![]).unwrap();
        let mut z = zero_value();
        for _ in 0..TREE_HEIGHT {
            z = hash_left_right(z, z);
        }
        assert_eq!(t.root(), z);
    }

    #[test]
    fn proof_recomputes_root() {
        let leaves: Vec<Fr> = (1..=5u64).map(Fr::from).collect();
        let t = MerkleTree::new(leaves).unwrap();
        for i in 0..5 {
            let p = t.proof(i).unwrap();
            let mut cur = Fr::from(i as u64 + 1);
            for (e, right) in p.path_elements.iter().zip(&p.path_indices) {
                cur = if *right {
                    hash_left_right(*e, cur)
                } else {
                    hash_left_right(cur, *e)
                };
            }
            assert_eq!(cur, t.root());
        }
    }
}
