use aether_crypto::{block_hash, tx_hash};
use aether_state::NodeLedger;
use aether_store::{ChainStore, EpochSnapshot};
use aether_types::*;
use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};

#[derive(Clone)]
pub struct RpcState {
    pub ledger: Arc<NodeLedger>,
    pub faucet_log: Arc<RwLock<VecDeque<String>>>,
    pub store: Option<Arc<ChainStore>>,
    /// Optional peer score snapshot from NetworkHub.
    pub peer_scores: Arc<RwLock<std::collections::HashMap<String, (u64, u64)>>>,
}

#[derive(Debug, Deserialize)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub id: Value,
    pub method: String,
    pub params: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct RpcResponse {
    pub jsonrpc: &'static str,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

#[derive(Debug, Serialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

pub fn router(state: RpcState) -> Router {
    Router::new()
        .route("/", post(rpc_handler))
        .route("/health", get(|| async { "ok" }))
        .route("/metrics", get(metrics_handler))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .with_state(state)
}

async fn metrics_handler(State(state): State<RpcState>) -> String {
    let s = state.ledger.state.read();
    let peers = state.peer_scores.read().len();
    format!(
        "# HELP aether_block_height Tip height\n\
         # TYPE aether_block_height gauge\n\
         aether_block_height {}\n\
         # HELP aether_epoch Current epoch\n\
         # TYPE aether_epoch gauge\n\
         aether_epoch {}\n\
         # HELP aether_validators Active validators\n\
         # TYPE aether_validators gauge\n\
         aether_validators {}\n\
         # HELP aether_mempool_txs Mempool size\n\
         # TYPE aether_mempool_txs gauge\n\
         aether_mempool_txs {}\n\
         # HELP aether_peers Scored peers\n\
         # TYPE aether_peers gauge\n\
         aether_peers {}\n\
         # HELP aether_community_pool_wei Community pool\n\
         # TYPE aether_community_pool_wei gauge\n\
         aether_community_pool_wei {}\n\
         # HELP aether_base_fee Base fee\n\
         # TYPE aether_base_fee gauge\n\
         aether_base_fee {}\n\
         # HELP aether_bridges Open bridge channels\n\
         # TYPE aether_bridges gauge\n\
         aether_bridges {}\n",
        s.height,
        s.epoch,
        s.validators.len(),
        state.ledger.mempool.read().len(),
        peers,
        s.community_pool,
        s.base_fee,
        s.bridges.len(),
    )
}

pub async fn serve(state: RpcState, addr: SocketAddr) -> anyhow::Result<()> {
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("RPC listening on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn rpc_handler(State(state): State<RpcState>, Json(req): Json<RpcRequest>) -> Json<RpcResponse> {
    let result = match req.method.as_str() {
        "aeth_chainId" => Ok(json!(state.ledger.state.read().params.chain_id)),
        "aeth_blockNumber" => Ok(json!(state.ledger.state.read().height)),
        "aeth_protocolInfo" => Ok(protocol_info(&state)),
        "aeth_getBalance" => get_balance(&state, req.params.as_ref()),
        "aeth_getBlockByNumber" => get_block_by_number(&state, req.params.as_ref()),
        "aeth_getBlockByHash" => get_block_by_hash(&state, req.params.as_ref()),
        "aeth_getTransaction" => get_transaction(&state, req.params.as_ref()),
        "aeth_getValidators" => Ok(get_validators(&state)),
        "aeth_getAccount" => get_account(&state, req.params.as_ref()),
        "aeth_sendRawTransaction" => send_raw_tx(&state, req.params.as_ref()),
        "aeth_getMempool" => Ok(json!(state.ledger.mempool.read().len())),
        "aeth_getProposals" => Ok(serde_json::to_value(state.ledger.state.read().proposals.clone()).unwrap()),
        "aeth_getAccountProof" => get_account_proof(&state, req.params.as_ref()),
        "aeth_verifySupply" => match state.ledger.state.read().verify_supply_invariant() {
            Ok(()) => Ok(json!({"ok": true, "accounted": state.ledger.state.read().accounted_supply().to_string()})),
            Err(e) => Ok(json!({"ok": false, "error": e.to_string()})),
        },
        "aeth_getUtxoSetSize" => Ok(json!(state.ledger.state.read().utxos.len())),
        "aeth_getRollups" => Ok(serde_json::to_value(state.ledger.state.read().rollups.clone()).unwrap()),
        "aeth_syncing" => Ok(json!(false)),
        "aeth_createSnapshot" => create_snapshot(&state, req.params.as_ref()),
        "aeth_loadSnapshot" => load_snapshot(&state, req.params.as_ref()),
        "aeth_getSnapshot" => get_snapshot(&state, req.params.as_ref()),
        "aeth_exportSnapshot" => export_snapshot(&state),
        "aeth_getLightHeader" => get_light_header(&state, req.params.as_ref()),
        "aeth_getCommit" => get_commit(&state, req.params.as_ref()),
        "aeth_getDelegations" => get_delegations(&state, req.params.as_ref()),
        "aeth_getUnbonding" => Ok(serde_json::to_value(state.ledger.state.read().unbonding.clone()).unwrap()),
        "aeth_netPeers" => Ok(json!(state.peer_scores.read().clone())),
        "aeth_getBridges" => Ok(serde_json::to_value(state.ledger.state.read().bridges.clone()).unwrap()),
        "aeth_getBridgePackets" => Ok(serde_json::to_value(state.ledger.state.read().bridge_packets.clone()).unwrap()),
        "aeth_getSlashLog" => Ok(serde_json::to_value(state.ledger.state.read().slash_log.clone()).unwrap()),
        "aeth_getCommunityPool" => Ok(json!(state.ledger.state.read().community_pool.to_string())),
        "aeth_version" => Ok(json!({
            "protocol": PROTOCOL_VERSION,
            "wire": WIRE_VERSION,
            "impl": env!("CARGO_PKG_VERSION"),
        })),
        _ => Err((-32601, format!("method not found: {}", req.method))),
    };

    match result {
        Ok(v) => Json(RpcResponse {
            jsonrpc: "2.0",
            id: req.id,
            result: Some(v),
            error: None,
        }),
        Err((code, message)) => Json(RpcResponse {
            jsonrpc: "2.0",
            id: req.id,
            result: None,
            error: Some(RpcError { code, message }),
        }),
    }
}

fn protocol_info(state: &RpcState) -> Value {
    let s = state.ledger.state.read();
    json!({
        "name": "Aether Protocol",
        "version": PROTOCOL_VERSION,
        "wire_version": WIRE_VERSION,
        "chain_id": s.params.chain_id,
        "hybrid_mode": s.params.hybrid_mode,
        "height": s.height,
        "epoch": s.epoch,
        "base_fee": s.base_fee,
        "validators": s.validators.len(),
        "total_supply": s.total_supply.to_string(),
        "genesis_supply": s.genesis_supply.to_string(),
        "accounted_supply": s.accounted_supply().to_string(),
        "fee_burned": s.fee_burned.to_string(),
        "notes": s.notes.len(),
        "nullifiers": s.nullifiers.len(),
        "utxos": s.utxos.len(),
        "rollups": s.rollups.len(),
        "shielded_value": s.shielded_value.to_string(),
        "notes_root": hex_hash(&s.notes_root()),
        "pending_rollups": s.pending_rollups.len(),
        "proposals": s.proposals.len(),
        "delegations": s.delegations.len(),
        "unbonding_entries": s.unbonding.len(),
        "community_pool": s.community_pool.to_string(),
        "bridges": s.bridges.len(),
        "slash_events": s.slash_log.len(),
        "features": {
            "shielded": true,
            "poseidon_notes": true,
            "rollups": true,
            "liquid_staking": true,
            "snapshots": true,
            "governance": true,
            "p2p_mesh": true,
            "peer_bans": true,
            "bridges": true,
            "slashing": true,
            "tip_to_proposer": true,
            "metrics": true,
        },
        "zk": {
            "shielded": "groth16-bn254",
            "note_crh": "poseidon-bn254-fr",
            "rollup_schemes": ["0x01-groth16", "0x02-plonk-lite", "0x03-fraud", "0xFF-noop-gated"],
        },
        "ip": {
            "license": "Apache-2.0",
            "docs": ["docs/IP.md", "docs/ACQUISITION.md", "docs/PATENT_PLEDGE.md"],
        },
    })
}

fn get_light_header(state: &RpcState, params: Option<&Value>) -> Result<Value, (i32, String)> {
    let n = params
        .and_then(|p| p.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_u64())
        .ok_or((-32602, "height required".into()))?;
    let blocks = state.ledger.blocks.read();
    let block = blocks
        .iter()
        .find(|b| b.header.height == n)
        .ok_or((-32000, "block not found".into()))?;
    let vals: Vec<_> = state.ledger.state.read().validators.values().cloned().collect();
    let vh = aether_consensus::validators_hash(&vals);
    let lh = aether_consensus::light_header_from_block(block, vh)
        .map_err(|e| (-32000, e))?;
    Ok(serde_json::to_value(lh).unwrap())
}

fn get_commit(state: &RpcState, params: Option<&Value>) -> Result<Value, (i32, String)> {
    let n = params
        .and_then(|p| p.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_u64())
        .ok_or((-32602, "height required".into()))?;
    let commits = state.ledger.commits.read();
    let bytes = commits
        .get(&n)
        .ok_or((-32000, "commit not found".into()))?;
    let v: Value = serde_json::from_slice(bytes).unwrap_or(json!(hex::encode(bytes)));
    Ok(v)
}

fn get_delegations(state: &RpcState, params: Option<&Value>) -> Result<Value, (i32, String)> {
    let s = state.ledger.state.read();
    if let Ok(addr) = param_addr(params, 0) {
        let prefix = hex::encode(addr);
        let list: Vec<_> = s
            .delegations
            .values()
            .filter(|d| hex::encode(d.delegator) == prefix)
            .cloned()
            .collect();
        return Ok(serde_json::to_value(list).unwrap());
    }
    Ok(serde_json::to_value(s.delegations.values().cloned().collect::<Vec<_>>()).unwrap())
}

fn require_store(state: &RpcState) -> Result<&Arc<ChainStore>, (i32, String)> {
    state
        .store
        .as_ref()
        .ok_or((-32001, "store not configured".into()))
}

/// `aeth_createSnapshot` — optional path param; writes epoch snapshot file + sled index.
fn create_snapshot(state: &RpcState, params: Option<&Value>) -> Result<Value, (i32, String)> {
    let store = require_store(state)?;
    let st = state.ledger.state.read();
    let root = st.compute_state_root();
    store
        .put_state(&st)
        .map_err(|e| (-32000, e.to_string()))?;
    drop(st);

    let path = params
        .and_then(|p| p.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .map(PathBuf::from);

    let snap = if let Some(path) = path {
        store
            .write_snapshot_file(&path, root)
            .map_err(|e| (-32000, e.to_string()))?
    } else {
        store
            .create_epoch_snapshot(root)
            .map_err(|e| (-32000, e.to_string()))?
    };

    Ok(json!({
        "version": snap.version,
        "chain_id": snap.chain_id,
        "height": snap.height,
        "epoch": snap.epoch,
        "state_root": hex_hash(&snap.state_root),
        "checksum": hex_hash(&snap.checksum),
        "bytes_len": snap.to_bytes().map(|b| b.len()).unwrap_or(0),
    }))
}

/// `aeth_loadSnapshot` — path or hex/base64 blob; replaces in-memory ledger state.
fn load_snapshot(state: &RpcState, params: Option<&Value>) -> Result<Value, (i32, String)> {
    let store = require_store(state)?;
    let p0 = params
        .and_then(|p| p.as_array())
        .and_then(|a| a.first())
        .ok_or((-32602, "path or hex bytes required".into()))?;

    let chain_state = if let Some(s) = p0.as_str() {
        let looks_like_path = !s.starts_with("0x")
            && (s.contains('/') || s.contains('\\') || s.ends_with(".json") || s.ends_with(".snap"));
        if looks_like_path {
            store
                .load_snapshot_file(s)
                .map_err(|e| (-32000, e.to_string()))?
        } else {
            let raw = s.strip_prefix("0x").unwrap_or(s);
            let bytes = hex::decode(raw).map_err(|e| (-32602, format!("hex: {e}")))?;
            store
                .import_snapshot_bytes(&bytes)
                .map_err(|e| (-32000, e.to_string()))?
        }
    } else {
        return Err((-32602, "path or hex bytes required".into()));
    };

    let height = chain_state.height;
    let root = chain_state.compute_state_root();
    *state.ledger.state.write() = chain_state;

    Ok(json!({
        "ok": true,
        "height": height,
        "state_root": hex_hash(&root),
    }))
}

fn get_snapshot(state: &RpcState, params: Option<&Value>) -> Result<Value, (i32, String)> {
    let store = require_store(state)?;
    let height = params
        .and_then(|p| p.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_u64());
    let snap = store
        .get_epoch_snapshot(height)
        .map_err(|e| (-32000, e.to_string()))?
        .ok_or((-32000, "snapshot not found".into()))?;
    Ok(snapshot_json(&snap))
}

fn export_snapshot(state: &RpcState) -> Result<Value, (i32, String)> {
    let store = require_store(state)?;
    {
        let st = state.ledger.state.read();
        store
            .put_state(&st)
            .map_err(|e| (-32000, e.to_string()))?;
    }
    let bytes = store
        .export_snapshot_bytes()
        .map_err(|e| (-32000, e.to_string()))?;
    let snap = EpochSnapshot::from_bytes(&bytes).map_err(|e| (-32000, e.to_string()))?;
    Ok(json!({
        "meta": snapshot_json(&snap),
        "hex": hex::encode(bytes),
    }))
}

fn snapshot_json(snap: &EpochSnapshot) -> Value {
    json!({
        "version": snap.version,
        "chain_id": snap.chain_id,
        "height": snap.height,
        "epoch": snap.epoch,
        "state_root": hex_hash(&snap.state_root),
        "checksum": hex_hash(&snap.checksum),
    })
}

fn get_account_proof(state: &RpcState, params: Option<&Value>) -> Result<Value, (i32, String)> {
    let addr = param_addr(params, 0)?;
    let proof = state.ledger.state.read().light_account_proof(&addr);
    Ok(serde_json::to_value(proof).unwrap())
}

fn get_balance(state: &RpcState, params: Option<&Value>) -> Result<Value, (i32, String)> {
    let addr = param_addr(params, 0)?;
    Ok(json!(state.ledger.state.read().get_balance(&addr).to_string()))
}

fn get_account(state: &RpcState, params: Option<&Value>) -> Result<Value, (i32, String)> {
    let addr = param_addr(params, 0)?;
    let acct = state.ledger.state.read().get_account(&addr);
    Ok(json!({
        "address": hex_addr(&addr),
        "nonce": acct.nonce,
        "balance": acct.balance.to_string(),
        "bonded": acct.bonded.to_string(),
        "code_hash": acct.code_hash.map(|h| hex_hash(&h)),
    }))
}

fn get_validators(state: &RpcState) -> Value {
    let s = state.ledger.state.read();
    let list: Vec<_> = s.validators.values().cloned().collect();
    serde_json::to_value(list).unwrap_or(json!([]))
}

fn get_block_by_number(state: &RpcState, params: Option<&Value>) -> Result<Value, (i32, String)> {
    let n = params
        .and_then(|p| p.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_u64())
        .ok_or((-32602, "height required".into()))?;
    let blocks = state.ledger.blocks.read();
    let block = blocks
        .iter()
        .find(|b| b.header.height == n)
        .ok_or((-32000, "block not found".into()))?;
    Ok(serialize_block(block))
}

fn get_block_by_hash(state: &RpcState, params: Option<&Value>) -> Result<Value, (i32, String)> {
    let h = param_hash(params, 0)?;
    let blocks = state.ledger.blocks.read();
    for b in blocks.iter() {
        let bh = block_hash(&b.header).map_err(|e| (-32000, e.to_string()))?;
        if bh == h {
            return Ok(serialize_block(b));
        }
    }
    Err((-32000, "block not found".into()))
}

fn get_transaction(state: &RpcState, params: Option<&Value>) -> Result<Value, (i32, String)> {
    let h = param_hash(params, 0)?;
    let key = hex::encode(h);
    if let Some(r) = state.ledger.receipts.read().get(&key) {
        return Ok(json!({
            "hash": hex_hash(&h),
            "receipt": r,
        }));
    }
    for b in state.ledger.blocks.read().iter() {
        for tx in &b.transactions {
            let th = tx_hash(tx).map_err(|e| (-32000, e.to_string()))?;
            if th == h {
                return Ok(json!({
                    "hash": hex_hash(&h),
                    "tx": tx,
                    "block_height": b.header.height,
                }));
            }
        }
    }
    Err((-32000, "tx not found".into()))
}

fn send_raw_tx(state: &RpcState, params: Option<&Value>) -> Result<Value, (i32, String)> {
    let raw = params
        .and_then(|p| p.as_array())
        .and_then(|a| a.first())
        .ok_or((-32602, "tx required".into()))?;
    let tx: Transaction = serde_json::from_value(raw.clone())
        .map_err(|e| (-32602, format!("invalid tx: {e}")))?;
    let h = state
        .ledger
        .submit_tx(tx)
        .map_err(|e| (-32000, e.to_string()))?;
    Ok(json!(hex_hash(&h)))
}

fn serialize_block(block: &Block) -> Value {
    let hash = block_hash(&block.header)
        .map(|h| hex_hash(&h))
        .unwrap_or_default();
    json!({
        "hash": hash,
        "header": {
            "version": block.header.version,
            "chain_id": block.header.chain_id,
            "height": block.header.height,
            "time_unix_ms": block.header.time_unix_ms,
            "prev_hash": hex_hash(&block.header.prev_hash),
            "tx_root": hex_hash(&block.header.tx_root),
            "state_root": hex_hash(&block.header.state_root),
            "receipts_root": hex_hash(&block.header.receipts_root),
            "proposer": hex_addr(&block.header.proposer),
            "round": block.header.round,
            "epoch": block.header.epoch,
            "gas_used": block.header.gas_used,
            "gas_limit": block.header.gas_limit,
            "base_fee": block.header.base_fee,
        },
        "transactions": block.transactions,
        "tx_count": block.transactions.len(),
    })
}

fn param_addr(params: Option<&Value>, idx: usize) -> Result<Address, (i32, String)> {
    let s = params
        .and_then(|p| p.as_array())
        .and_then(|a| a.get(idx))
        .and_then(|v| v.as_str())
        .ok_or((-32602, "address required".into()))?;
    parse_addr(s).map_err(|e| (-32602, e))
}

fn param_hash(params: Option<&Value>, idx: usize) -> Result<Hash256, (i32, String)> {
    let s = params
        .and_then(|p| p.as_array())
        .and_then(|a| a.get(idx))
        .and_then(|v| v.as_str())
        .ok_or((-32602, "hash required".into()))?;
    parse_hash(s).map_err(|e| (-32602, e))
}
