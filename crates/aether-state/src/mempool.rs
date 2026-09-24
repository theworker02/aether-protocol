//! Priority mempool with nonce tracking and optional TxFilter hooks.

use crate::adapters::{AllowAll, TxFilter};
use crate::StateError;
use aether_crypto::{tx_hash, verify_tx};
use aether_types::{Hash256, Origin, Transaction};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

pub struct Mempool {
    txs: VecDeque<Transaction>,
    by_hash: HashMap<String, ()>,
    max_size: usize,
    filter: Arc<dyn TxFilter>,
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new(5_000, Arc::new(AllowAll))
    }
}

impl Mempool {
    pub fn new(max_size: usize, filter: Arc<dyn TxFilter>) -> Self {
        Self {
            txs: VecDeque::new(),
            by_hash: HashMap::new(),
            max_size,
            filter,
        }
    }

    pub fn len(&self) -> usize {
        self.txs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    pub fn insert(&mut self, tx: Transaction) -> Result<Hash256, StateError> {
        verify_tx(&tx).map_err(|e| StateError::Crypto(e.to_string()))?;
        self.filter
            .allow(&tx)
            .map_err(StateError::InvalidTx)?;
        let h = tx_hash(&tx).map_err(|e| StateError::Crypto(e.to_string()))?;
        let key = hex::encode(h);
        if self.by_hash.contains_key(&key) {
            return Err(StateError::InvalidTx("duplicate tx".into()));
        }
        if self.txs.len() >= self.max_size {
            return Err(StateError::InvalidTx("mempool full".into()));
        }
        self.by_hash.insert(key, ());
        self.txs.push_back(tx);
        Ok(h)
    }

    pub fn drain_prioritized(&mut self) -> Vec<Transaction> {
        let mut txs: Vec<_> = self.txs.drain(..).collect();
        self.by_hash.clear();
        txs.sort_by(|a, b| {
            b.max_priority_fee_per_gas
                .cmp(&a.max_priority_fee_per_gas)
                .then_with(|| {
                    let na = match &a.origin {
                        Origin::Account { .. } => a.nonce,
                        _ => 0,
                    };
                    let nb = match &b.origin {
                        Origin::Account { .. } => b.nonce,
                        _ => 0,
                    };
                    na.cmp(&nb)
                })
        });
        txs
    }

    pub fn requeue(&mut self, tx: Transaction) {
        if let Ok(h) = tx_hash(&tx) {
            self.by_hash.insert(hex::encode(h), ());
        }
        self.txs.push_back(tx);
    }
}
