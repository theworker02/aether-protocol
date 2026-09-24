use crate::rollup::setup_rollup_keys;
use crate::shielded::setup_shielded_keys;
use crate::ZkError;
use ark_bn254::Bn254;
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use parking_lot::RwLock;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub struct ShieldedProvingKey {
    pub transfer: ProvingKey<Bn254>,
    pub shield: ProvingKey<Bn254>,
    pub unshield: ProvingKey<Bn254>,
}

pub struct ShieldedVerifyingKey {
    pub transfer: VerifyingKey<Bn254>,
    pub shield: VerifyingKey<Bn254>,
    pub unshield: VerifyingKey<Bn254>,
}

pub struct RollupProvingKey {
    pub groth16: ProvingKey<Bn254>,
}

pub struct RollupVerifyingKey {
    pub groth16: VerifyingKey<Bn254>,
}

pub struct ZkKeychain {
    pub shielded_pk: ShieldedProvingKey,
    pub shielded_vk: ShieldedVerifyingKey,
    pub rollup_pk: RollupProvingKey,
    pub rollup_vk: RollupVerifyingKey,
}

fn ser_pk(pk: &ProvingKey<Bn254>) -> Result<Vec<u8>, ZkError> {
    let mut v = Vec::new();
    pk.serialize_compressed(&mut v)
        .map_err(|e| ZkError::Serde(e.to_string()))?;
    Ok(v)
}

fn ser_vk(vk: &VerifyingKey<Bn254>) -> Result<Vec<u8>, ZkError> {
    let mut v = Vec::new();
    vk.serialize_compressed(&mut v)
        .map_err(|e| ZkError::Serde(e.to_string()))?;
    Ok(v)
}

fn de_pk(bytes: &[u8]) -> Result<ProvingKey<Bn254>, ZkError> {
    ProvingKey::deserialize_compressed(&mut &bytes[..]).map_err(|e| ZkError::Serde(e.to_string()))
}

fn de_vk(bytes: &[u8]) -> Result<VerifyingKey<Bn254>, ZkError> {
    VerifyingKey::deserialize_compressed(&mut &bytes[..])
        .map_err(|e| ZkError::Serde(e.to_string()))
}

/// Bumped when shielded circuit algebra changes (Poseidon CRH = 2).
const KEY_SCHEMA: u32 = 2;

#[derive(serde::Serialize, serde::Deserialize)]
struct KeyBlob {
    #[serde(default)]
    schema: u32,
    transfer_pk: Vec<u8>,
    transfer_vk: Vec<u8>,
    shield_pk: Vec<u8>,
    shield_vk: Vec<u8>,
    unshield_pk: Vec<u8>,
    unshield_vk: Vec<u8>,
    rollup_pk: Vec<u8>,
    rollup_vk: Vec<u8>,
}

impl ZkKeychain {
    pub fn setup() -> Result<Self, ZkError> {
        let (shielded_pk, shielded_vk) = setup_shielded_keys()?;
        let (rollup_pk, rollup_vk) = setup_rollup_keys()?;
        Ok(Self {
            shielded_pk,
            shielded_vk,
            rollup_pk,
            rollup_vk,
        })
    }

    pub fn save(&self, path: &Path) -> Result<(), ZkError> {
        let blob = KeyBlob {
            schema: KEY_SCHEMA,
            transfer_pk: ser_pk(&self.shielded_pk.transfer)?,
            transfer_vk: ser_vk(&self.shielded_vk.transfer)?,
            shield_pk: ser_pk(&self.shielded_pk.shield)?,
            shield_vk: ser_vk(&self.shielded_vk.shield)?,
            unshield_pk: ser_pk(&self.shielded_pk.unshield)?,
            unshield_vk: ser_vk(&self.shielded_vk.unshield)?,
            rollup_pk: ser_pk(&self.rollup_pk.groth16)?,
            rollup_vk: ser_vk(&self.rollup_vk.groth16)?,
        };
        let json = serde_json::to_vec(&blob).map_err(|e| ZkError::Serde(e.to_string()))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| ZkError::Serde(e.to_string()))?;
        }
        std::fs::write(path, json).map_err(|e| ZkError::Serde(e.to_string()))?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self, ZkError> {
        let json = std::fs::read(path).map_err(|e| ZkError::Serde(e.to_string()))?;
        let blob: KeyBlob =
            serde_json::from_slice(&json).map_err(|e| ZkError::Serde(e.to_string()))?;
        if blob.schema != KEY_SCHEMA {
            return Err(ZkError::Serde(format!(
                "zk key schema {} != {}; regenerate keys",
                blob.schema, KEY_SCHEMA
            )));
        }
        Ok(Self {
            shielded_pk: ShieldedProvingKey {
                transfer: de_pk(&blob.transfer_pk)?,
                shield: de_pk(&blob.shield_pk)?,
                unshield: de_pk(&blob.unshield_pk)?,
            },
            shielded_vk: ShieldedVerifyingKey {
                transfer: de_vk(&blob.transfer_vk)?,
                shield: de_vk(&blob.shield_vk)?,
                unshield: de_vk(&blob.unshield_vk)?,
            },
            rollup_pk: RollupProvingKey {
                groth16: de_pk(&blob.rollup_pk)?,
            },
            rollup_vk: RollupVerifyingKey {
                groth16: de_vk(&blob.rollup_vk)?,
            },
        })
    }

    pub fn serialize_rollup_vk(&self) -> Result<Vec<u8>, ZkError> {
        ser_vk(&self.rollup_vk.groth16)
    }
}

static GLOBAL: RwLock<Option<Arc<ZkKeychain>>> = RwLock::new(None);

pub fn load_or_setup_keys(path: Option<PathBuf>) -> Result<Arc<ZkKeychain>, ZkError> {
    if let Some(existing) = GLOBAL.read().clone() {
        return Ok(existing);
    }
    let path = path.unwrap_or_else(|| PathBuf::from("data/zk_keys.json"));
    let keys = if path.exists() {
        match ZkKeychain::load(&path) {
            Ok(k) => k,
            Err(_) => {
                let k = ZkKeychain::setup()?;
                k.save(&path)?;
                k
            }
        }
    } else {
        let k = ZkKeychain::setup()?;
        k.save(&path)?;
        k
    };
    let arc = Arc::new(keys);
    *GLOBAL.write() = Some(arc.clone());
    Ok(arc)
}

pub fn global_keys() -> Option<Arc<ZkKeychain>> {
    GLOBAL.read().clone()
}

pub fn set_global_keys(keys: Arc<ZkKeychain>) {
    *GLOBAL.write() = Some(keys);
}
