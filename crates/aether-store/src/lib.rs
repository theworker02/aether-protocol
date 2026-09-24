//! Sled-backed persistence for chain state, blocks, and epoch snapshots.

use aether_crypto::hash_bytes;
use aether_state::ChainState;
use aether_types::{Block, Hash256};
use serde::{Deserialize, Serialize};
use sled::Db;
use std::path::Path;
use thiserror::Error;
use tracing::info;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("sled: {0}")]
    Sled(#[from] sled::Error),
    #[error("serde: {0}")]
    Serde(String),
    #[error("missing key {0}")]
    Missing(String),
    #[error("snapshot: {0}")]
    Snapshot(String),
}

/// Versioned epoch snapshot envelope (docs/SYNC.md).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochSnapshot {
    pub version: u32,
    pub chain_id: String,
    pub height: u64,
    pub epoch: u64,
    pub state_root: Hash256,
    pub state: ChainState,
    pub checksum: Hash256,
}

impl EpochSnapshot {
    pub const VERSION: u32 = 1;

    pub fn from_state(state: &ChainState, state_root: Hash256) -> Result<Self, StoreError> {
        let mut snap = Self {
            version: Self::VERSION,
            chain_id: state.params.chain_id.clone(),
            height: state.height,
            epoch: state.epoch,
            state_root,
            state: state.clone(),
            checksum: [0u8; 32],
        };
        snap.checksum = snap.compute_checksum()?;
        Ok(snap)
    }

    pub fn compute_checksum(&self) -> Result<Hash256, StoreError> {
        let mut body = self.clone();
        body.checksum = [0u8; 32];
        let bytes = serde_json::to_vec(&body).map_err(|e| StoreError::Serde(e.to_string()))?;
        Ok(hash_bytes(&bytes))
    }

    pub fn verify(&self) -> Result<(), StoreError> {
        if self.version != Self::VERSION {
            return Err(StoreError::Snapshot(format!(
                "unsupported version {}",
                self.version
            )));
        }
        let expect = self.compute_checksum()?;
        if expect != self.checksum {
            return Err(StoreError::Snapshot("checksum mismatch".into()));
        }
        if self.state.height != self.height {
            return Err(StoreError::Snapshot("height mismatch".into()));
        }
        if self.state.params.chain_id != self.chain_id {
            return Err(StoreError::Snapshot("chain_id mismatch".into()));
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, StoreError> {
        serde_json::to_vec(self).map_err(|e| StoreError::Serde(e.to_string()))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        let snap: Self =
            serde_json::from_slice(bytes).map_err(|e| StoreError::Serde(e.to_string()))?;
        snap.verify()?;
        Ok(snap)
    }
}

pub struct ChainStore {
    db: Db,
}

impl ChainStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let db = sled::open(path)?;
        info!("opened chain store");
        Ok(Self { db })
    }

    pub fn put_state(&self, state: &ChainState) -> Result<(), StoreError> {
        let bytes = serde_json::to_vec(state).map_err(|e| StoreError::Serde(e.to_string()))?;
        self.db.insert(b"state/latest", bytes)?;
        self.db.flush()?;
        Ok(())
    }

    pub fn get_state(&self) -> Result<Option<ChainState>, StoreError> {
        match self.db.get(b"state/latest")? {
            Some(bytes) => {
                let s = serde_json::from_slice(&bytes)
                    .map_err(|e| StoreError::Serde(e.to_string()))?;
                Ok(Some(s))
            }
            None => Ok(None),
        }
    }

    pub fn put_block(&self, block: &Block) -> Result<(), StoreError> {
        let key = format!("block/{}", block.header.height);
        let bytes = serde_json::to_vec(block).map_err(|e| StoreError::Serde(e.to_string()))?;
        self.db.insert(key.as_bytes(), bytes)?;
        self.db
            .insert(b"meta/height", &block.header.height.to_le_bytes())?;
        Ok(())
    }

    pub fn get_block(&self, height: u64) -> Result<Option<Block>, StoreError> {
        let key = format!("block/{height}");
        match self.db.get(key.as_bytes())? {
            Some(bytes) => Ok(Some(
                serde_json::from_slice(&bytes).map_err(|e| StoreError::Serde(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    pub fn tip_height(&self) -> Result<u64, StoreError> {
        match self.db.get(b"meta/height")? {
            Some(bytes) if bytes.len() == 8 => {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&bytes);
                Ok(u64::from_le_bytes(arr))
            }
            _ => Ok(0),
        }
    }

    pub fn put_receipt(&self, receipt: &aether_types::Receipt) -> Result<(), StoreError> {
        let key = format!("receipt/{}", hex::encode(receipt.tx_hash));
        let bytes = serde_json::to_vec(receipt).map_err(|e| StoreError::Serde(e.to_string()))?;
        self.db.insert(key.as_bytes(), bytes)?;
        Ok(())
    }

    pub fn put_commit(&self, height: u64, blob: &[u8]) -> Result<(), StoreError> {
        let key = format!("commit/{height}");
        self.db.insert(key.as_bytes(), blob)?;
        Ok(())
    }

    pub fn create_epoch_snapshot(&self, state_root: Hash256) -> Result<EpochSnapshot, StoreError> {
        let state = self
            .get_state()?
            .ok_or_else(|| StoreError::Missing("state".into()))?;
        let snap = EpochSnapshot::from_state(&state, state_root)?;
        let key = format!("snap/{}", snap.height);
        self.db.insert(key.as_bytes(), snap.to_bytes()?)?;
        self.db
            .insert(b"snap/latest", snap.height.to_le_bytes().as_slice())?;
        Ok(snap)
    }

    pub fn get_epoch_snapshot(&self, height: Option<u64>) -> Result<Option<EpochSnapshot>, StoreError> {
        let h = match height {
            Some(h) => h,
            None => match self.db.get(b"snap/latest")? {
                Some(bytes) if bytes.len() == 8 => {
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(&bytes);
                    u64::from_le_bytes(arr)
                }
                _ => return Ok(None),
            },
        };
        let key = format!("snap/{h}");
        match self.db.get(key.as_bytes())? {
            Some(bytes) => Ok(Some(EpochSnapshot::from_bytes(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn export_snapshot_bytes(&self) -> Result<Vec<u8>, StoreError> {
        let state = self
            .get_state()?
            .ok_or_else(|| StoreError::Missing("state".into()))?;
        let root = state.compute_state_root();
        EpochSnapshot::from_state(&state, root)?.to_bytes()
    }

    pub fn import_snapshot_bytes(&self, bytes: &[u8]) -> Result<ChainState, StoreError> {
        // Accept either full EpochSnapshot or raw ChainState for back-compat.
        if let Ok(snap) = EpochSnapshot::from_bytes(bytes) {
            self.put_state(&snap.state)?;
            let key = format!("snap/{}", snap.height);
            self.db.insert(key.as_bytes(), bytes)?;
            self.db
                .insert(b"snap/latest", snap.height.to_le_bytes().as_slice())?;
            return Ok(snap.state);
        }
        let state: ChainState =
            serde_json::from_slice(bytes).map_err(|e| StoreError::Serde(e.to_string()))?;
        self.put_state(&state)?;
        Ok(state)
    }

    pub fn write_snapshot_file(&self, path: impl AsRef<Path>, state_root: Hash256) -> Result<EpochSnapshot, StoreError> {
        let snap = {
            let state = self
                .get_state()?
                .ok_or_else(|| StoreError::Missing("state".into()))?;
            EpochSnapshot::from_state(&state, state_root)?
        };
        let bytes = snap.to_bytes()?;
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent).map_err(|e| StoreError::Serde(e.to_string()))?;
        }
        std::fs::write(path.as_ref(), &bytes).map_err(|e| StoreError::Serde(e.to_string()))?;
        let key = format!("snap/{}", snap.height);
        self.db.insert(key.as_bytes(), bytes)?;
        self.db
            .insert(b"snap/latest", snap.height.to_le_bytes().as_slice())?;
        Ok(snap)
    }

    pub fn load_snapshot_file(&self, path: impl AsRef<Path>) -> Result<ChainState, StoreError> {
        let bytes = std::fs::read(path.as_ref()).map_err(|e| StoreError::Serde(e.to_string()))?;
        self.import_snapshot_bytes(&bytes)
    }
}

pub fn hash_blob(data: &[u8]) -> Hash256 {
    hash_bytes(data)
}
