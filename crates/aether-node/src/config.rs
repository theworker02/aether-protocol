//! Node + genesis configuration loading for adaptable deployments.

use aether_types::*;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
pub struct NodeToml {
    pub chain_id: Option<String>,
    pub rpc: Option<String>,
    pub hybrid: Option<String>,
    pub block_time_ms: Option<u64>,
    pub faucet_aeth: Option<u64>,
    pub genesis: Option<PathBuf>,
    pub zk_keys: Option<PathBuf>,
    pub key_file: Option<PathBuf>,
    pub p2p_listen: Option<String>,
    pub bootnodes: Option<Vec<String>>,
    pub limits: Option<LimitsToml>,
    pub features: Option<FeaturesToml>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LimitsToml {
    pub mempool_max_txs: Option<usize>,
    pub rpc_max_body_bytes: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FeaturesToml {
    pub enable_shielded: Option<bool>,
    pub enable_rollups: Option<bool>,
    pub allow_noop_rollup: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub chain_id: String,
    pub rpc: String,
    pub hybrid: String,
    pub block_time_ms: u64,
    pub faucet_aeth: u64,
    pub genesis_path: Option<PathBuf>,
    pub zk_keys: PathBuf,
    pub key_file: Option<PathBuf>,
    pub mempool_max_txs: usize,
    pub enable_shielded: bool,
    pub enable_rollups: bool,
    pub allow_noop_rollup: bool,
    pub p2p_listen: Option<String>,
    pub bootnodes: Vec<String>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            chain_id: "aether-devnet-1".into(),
            rpc: "127.0.0.1:8545".into(),
            hybrid: "public".into(),
            block_time_ms: 1000,
            faucet_aeth: 1_000_000,
            genesis_path: Some(PathBuf::from("config/genesis.public.json")),
            zk_keys: PathBuf::from("data/zk_keys.json"),
            key_file: None,
            mempool_max_txs: 5000,
            enable_shielded: true,
            enable_rollups: true,
            allow_noop_rollup: false,
            p2p_listen: Some("127.0.0.1:9000".into()),
            bootnodes: Vec::new(),
        }
    }
}

impl NodeConfig {
    pub fn load_file(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("read config {}", path.display()))?;
        let t: NodeToml = toml::from_str(&raw).context("parse node.toml")?;
        let mut cfg = Self::default();
        if let Some(v) = t.chain_id {
            cfg.chain_id = v;
        }
        if let Some(v) = t.rpc {
            cfg.rpc = v;
        }
        if let Some(v) = t.hybrid {
            cfg.hybrid = v;
        }
        if let Some(v) = t.block_time_ms {
            cfg.block_time_ms = v;
        }
        if let Some(v) = t.faucet_aeth {
            cfg.faucet_aeth = v;
        }
        if let Some(v) = t.genesis {
            cfg.genesis_path = Some(v);
        }
        if let Some(v) = t.zk_keys {
            cfg.zk_keys = v;
        }
        if let Some(v) = t.key_file {
            cfg.key_file = Some(v);
        }
        if let Some(v) = t.p2p_listen {
            cfg.p2p_listen = Some(v);
        }
        if let Some(v) = t.bootnodes {
            cfg.bootnodes = v;
        }
        if let Some(l) = t.limits {
            if let Some(v) = l.mempool_max_txs {
                cfg.mempool_max_txs = v;
            }
        }
        if let Some(f) = t.features {
            if let Some(v) = f.enable_shielded {
                cfg.enable_shielded = v;
            }
            if let Some(v) = f.enable_rollups {
                cfg.enable_rollups = v;
            }
            if let Some(v) = f.allow_noop_rollup {
                cfg.allow_noop_rollup = v;
            }
        }
        Ok(cfg)
    }
}

#[derive(Debug, Deserialize)]
struct GenesisFile {
    chain_id: String,
    #[serde(default)]
    timestamp: u64,
    params: ParamsFile,
    #[serde(default)]
    alloc: Vec<AllocFile>,
    #[serde(default)]
    validators: Vec<ValFile>,
}

#[derive(Debug, Deserialize)]
struct ParamsFile {
    chain_id: Option<String>,
    epoch_length: Option<u64>,
    #[serde(default)]
    min_validator_stake: serde_json::Value,
    max_validators: Option<usize>,
    unbonding_period: Option<u64>,
    gas_limit: Option<u64>,
    hybrid_mode: Option<String>,
    block_time_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct AllocFile {
    address: String,
    balance: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct ValFile {
    address: String,
    public_key: String,
    power: serde_json::Value,
}

fn parse_u128(v: &serde_json::Value) -> Result<u128> {
    match v {
        serde_json::Value::String(s) => s.parse().context("parse u128 string"),
        serde_json::Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                Ok(u as u128)
            } else {
                n.to_string().parse().context("parse u128 number")
            }
        }
        _ => anyhow::bail!("expected string or number for u128"),
    }
}

fn parse_hybrid(s: &str) -> HybridMode {
    match s {
        "allowlist" => HybridMode::Allowlist,
        "mixed" => HybridMode::Mixed,
        _ => HybridMode::Public,
    }
}

/// Load a genesis JSON file. Empty alloc/validators are OK — node will inject faucet/validator.
pub fn load_genesis(path: &Path) -> Result<Genesis> {
    let raw = fs::read_to_string(path).with_context(|| format!("read genesis {}", path.display()))?;
    let g: GenesisFile = serde_json::from_str(&raw).context("parse genesis json")?;
    let mut params = ChainParams::default();
    params.chain_id = g
        .params
        .chain_id
        .unwrap_or_else(|| g.chain_id.clone());
    if let Some(v) = g.params.epoch_length {
        params.epoch_length = v;
    }
    if !g.params.min_validator_stake.is_null() {
        params.min_validator_stake = parse_u128(&g.params.min_validator_stake)?;
    }
    if let Some(v) = g.params.max_validators {
        params.max_validators = v;
    }
    if let Some(v) = g.params.unbonding_period {
        params.unbonding_period = v;
    }
    if let Some(v) = g.params.gas_limit {
        params.gas_limit = v;
    }
    if let Some(v) = g.params.hybrid_mode {
        params.hybrid_mode = parse_hybrid(&v);
    }
    if let Some(v) = g.params.block_time_ms {
        params.block_time_ms = v;
    }

    let mut alloc = Vec::new();
    for a in g.alloc {
        let address = parse_addr(&a.address).map_err(|e| anyhow::anyhow!(e))?;
        let balance = parse_u128(&a.balance)?;
        alloc.push(GenesisAlloc { address, balance });
    }
    let mut validators = Vec::new();
    for v in g.validators {
        let address = parse_addr(&v.address).map_err(|e| anyhow::anyhow!(e))?;
        let public_key = hex::decode(v.public_key.strip_prefix("0x").unwrap_or(&v.public_key))?;
        let power = parse_u128(&v.power)?;
        validators.push(GenesisValidator {
            address,
            public_key,
            power,
        });
    }

    Ok(Genesis {
        chain_id: g.chain_id,
        alloc,
        validators,
        params,
        timestamp: g.timestamp,
    })
}
