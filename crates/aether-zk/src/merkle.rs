use crate::field::{fr_to_bytes, poseidon_parent};
use aether_types::Hash256;
use ark_bn254::Fr;

pub const TREE_DEPTH: usize = 8; // 256 leaves

#[derive(Clone, Debug)]
pub struct NoteTree {
    pub leaves: Vec<Option<Fr>>,
    pub next_index: usize,
}

impl Default for NoteTree {
    fn default() -> Self {
        Self::new()
    }
}

impl NoteTree {
    pub fn new() -> Self {
        Self {
            leaves: vec![None; 1 << TREE_DEPTH],
            next_index: 0,
        }
    }

    pub fn root(&self) -> Fr {
        let mut layer: Vec<Fr> = self
            .leaves
            .iter()
            .map(|l| l.unwrap_or_else(empty_leaf))
            .collect();
        for _ in 0..TREE_DEPTH {
            layer = next_level(&layer);
        }
        layer[0]
    }

    pub fn root_hash(&self) -> Hash256 {
        fr_to_bytes(&self.root())
    }

    pub fn append(&mut self, cm: Fr) -> Result<usize, String> {
        if self.next_index >= self.leaves.len() {
            return Err("note tree full".into());
        }
        let idx = self.next_index;
        self.leaves[idx] = Some(cm);
        self.next_index += 1;
        Ok(idx)
    }

    pub fn authentication_path(&self, leaf_index: usize) -> Result<Vec<(Fr, bool)>, String> {
        if leaf_index >= self.leaves.len() || self.leaves[leaf_index].is_none() {
            return Err("missing leaf".into());
        }
        let mut path = Vec::with_capacity(TREE_DEPTH);
        let mut idx = leaf_index;
        let mut layer: Vec<Fr> = self
            .leaves
            .iter()
            .map(|l| l.unwrap_or_else(empty_leaf))
            .collect();
        for _ in 0..TREE_DEPTH {
            let is_right = idx % 2 == 1;
            let sibling_idx = if is_right { idx - 1 } else { idx + 1 };
            let sibling = layer.get(sibling_idx).copied().unwrap_or_else(empty_leaf);
            path.push((sibling, is_right));
            layer = next_level(&layer);
            idx /= 2;
        }
        Ok(path)
    }
}

fn empty_leaf() -> Fr {
    Fr::from(0u64)
}

fn next_level(layer: &[Fr]) -> Vec<Fr> {
    layer
        .chunks(2)
        .map(|c| {
            let l = c[0];
            let r = if c.len() > 1 { c[1] } else { empty_leaf() };
            poseidon_parent(&l, &r)
        })
        .collect()
}

pub fn empty_root_hash() -> Hash256 {
    NoteTree::new().root_hash()
}

pub fn verify_path(leaf: &Fr, leaf_index: usize, path: &[(Fr, bool)], root: &Fr) -> bool {
    if path.len() != TREE_DEPTH {
        return false;
    }
    let mut cur = *leaf;
    let mut idx = leaf_index;
    for (sibling, is_right) in path {
        let expect_right = idx % 2 == 1;
        if *is_right != expect_right {
            return false;
        }
        let (l, r) = if *is_right {
            (*sibling, cur)
        } else {
            (cur, *sibling)
        };
        cur = poseidon_parent(&l, &r);
        idx /= 2;
    }
    cur == *root
}
