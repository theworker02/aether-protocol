//! Pluggable extension points for adapting Aether without forking consensus.

use aether_types::{Hash256, Transaction};

/// Custom transaction pre-validation (compliance filters, allowlists, fee floors).
pub trait TxFilter: Send + Sync {
    fn allow(&self, tx: &Transaction) -> Result<(), String>;
}

/// Default: allow everything.
pub struct AllowAll;

impl TxFilter for AllowAll {
    fn allow(&self, _tx: &Transaction) -> Result<(), String> {
        Ok(())
    }
}

/// Hook after a block is committed (indexers, bridges, webhooks).
pub trait BlockHook: Send + Sync {
    fn on_commit(&self, height: u64, hash: Hash256);
}

pub struct NoopHook;

impl BlockHook for NoopHook {
    fn on_commit(&self, _height: u64, _hash: Hash256) {}
}

/// Register a custom rollup verifier scheme id (≥ 0x10 recommended for vendors).
pub trait RollupVerifierAdapter: Send + Sync {
    fn scheme_id(&self) -> u8;
    fn verify(
        &self,
        proof: &[u8],
        prev: &Hash256,
        post: &Hash256,
        da: &Hash256,
        batch_index: u64,
    ) -> Result<(), String>;
}
