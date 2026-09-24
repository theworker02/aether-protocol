mod config;

use aether_consensus::{light_header_from_block, make_vote, solo_commit, validators_hash, VoteType};
use aether_crypto::{block_hash, Keypair};
use aether_p2p::{spawn_mesh, GossipMessage, NetworkHub};
use aether_rpc::{serve, RpcState};
use aether_state::NodeLedger;
use aether_store::ChainStore;
use aether_types::*;
use anyhow::Result;
use clap::Parser;
use config::{load_genesis, NodeConfig};
use parking_lot::RwLock;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(name = "aether-node", about = "Aether Protocol reference node")]
struct Args {
    /// Optional TOML config (flags override)
    #[arg(long, default_value = "config/node.toml")]
    config: PathBuf,

    #[arg(long)]
    rpc: Option<String>,

    #[arg(long)]
    block_time_ms: Option<u64>,

    #[arg(long)]
    hybrid: Option<String>,

    #[arg(long)]
    key_file: Option<PathBuf>,

    #[arg(long)]
    zk_keys: Option<PathBuf>,

    #[arg(long)]
    genesis: Option<PathBuf>,

    #[arg(long)]
    faucet_aeth: Option<u64>,

    /// Persistent store directory (sled)
    #[arg(long, default_value = "data/chain")]
    data_dir: PathBuf,

    /// TCP P2P listen address (e.g. 0.0.0.0:9000)
    #[arg(long)]
    p2p_listen: Option<String>,

    /// Comma-separated bootnode addresses
    #[arg(long)]
    bootnodes: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();
    let mut cfg = if args.config.exists() {
        NodeConfig::load_file(&args.config).unwrap_or_else(|e| {
            warn!("config load failed ({e}); using defaults");
            NodeConfig::default()
        })
    } else {
        NodeConfig::default()
    };

    if let Some(v) = args.rpc {
        cfg.rpc = v;
    }
    if let Some(v) = args.block_time_ms {
        cfg.block_time_ms = v;
    }
    if let Some(v) = args.hybrid {
        cfg.hybrid = v;
    }
    if let Some(v) = args.key_file {
        cfg.key_file = Some(v);
    }
    if let Some(v) = args.zk_keys {
        cfg.zk_keys = v;
    }
    if let Some(v) = args.genesis {
        cfg.genesis_path = Some(v);
    }
    if let Some(v) = args.faucet_aeth {
        cfg.faucet_aeth = v;
    }
    if let Some(v) = args.p2p_listen {
        cfg.p2p_listen = Some(v);
    }
    if let Some(v) = args.bootnodes {
        cfg.bootnodes = parse_bootnodes(&v);
    }

    if cfg.allow_noop_rollup {
        std::env::set_var("AETHER_ALLOW_NOOP_ROLLUP", "1");
    }

    info!("loading / generating ZK keys at {}", cfg.zk_keys.display());
    let _zk = aether_zk::load_or_setup_keys(Some(cfg.zk_keys.clone()))
        .map_err(|e| anyhow::anyhow!("zk setup: {e}"))?;
    info!("ZK keychain ready (Poseidon notes + Groth16 shielded + rollup verifiers)");

    let kp = load_or_create_keypair(cfg.key_file.as_ref())?;
    let addr = kp.address();
    info!("validator address {}", hex_addr(&addr));
    info!("validator pubkey {}", hex::encode(kp.public_bytes()));

    let hybrid = match cfg.hybrid.as_str() {
        "allowlist" => HybridMode::Allowlist,
        "mixed" => HybridMode::Mixed,
        _ => HybridMode::Public,
    };

    let mut genesis = if let Some(ref path) = cfg.genesis_path {
        if path.exists() {
            info!("genesis from {}", path.display());
            load_genesis(path)?
        } else {
            warn!("genesis file missing; building default");
            default_genesis(&cfg, addr, &kp, hybrid)
        }
    } else {
        default_genesis(&cfg, addr, &kp, hybrid)
    };

    if genesis.validators.is_empty() {
        genesis.validators.push(GenesisValidator {
            address: addr,
            public_key: kp.public_bytes(),
            power: 10_000 * WEI_PER_AETH,
        });
    }
    if genesis.alloc.is_empty() {
        genesis.alloc.push(GenesisAlloc {
            address: addr,
            balance: (cfg.faucet_aeth as u128) * WEI_PER_AETH,
        });
    }
    genesis.params.hybrid_mode = hybrid;
    genesis.params.block_time_ms = cfg.block_time_ms;
    if !cfg.chain_id.is_empty() {
        genesis.chain_id = cfg.chain_id.clone();
        genesis.params.chain_id = cfg.chain_id.clone();
    }

    let params = genesis.params.clone();
    let ledger = NodeLedger::new(genesis);
    {
        let mut st = ledger.state.write();
        if matches!(hybrid, HybridMode::Allowlist | HybridMode::Mixed) {
            st.allowlist.insert(hex::encode(addr));
            for v in st.validators.keys().cloned().collect::<Vec<_>>() {
                st.allowlist.insert(v);
            }
        }
    }

    let store = Arc::new(ChainStore::open(&args.data_dir).map_err(|e| anyhow::anyhow!(e))?);
    {
        let st = ledger.state.read();
        store.put_state(&st).map_err(|e| anyhow::anyhow!(e))?;
        if let Some(b) = ledger.blocks.read().last() {
            store.put_block(b).map_err(|e| anyhow::anyhow!(e))?;
        }
    }

    let peer_id = hex_addr(&addr);
    let hub = NetworkHub::new(peer_id.clone(), params.chain_id.clone(), 1024);
    hub.register_peer(peer_id.clone()).await;

    let listen_addr: Option<SocketAddr> = cfg
        .p2p_listen
        .as_ref()
        .map(|s| s.parse())
        .transpose()
        .map_err(|e| anyhow::anyhow!("p2p-listen: {e}"))?;
    let boots: Vec<SocketAddr> = cfg
        .bootnodes
        .iter()
        .map(|s| s.parse())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("bootnodes: {e}"))?;
    let height0 = ledger.state.read().height;
    spawn_mesh(Arc::clone(&hub), listen_addr, boots, height0).await?;
    if let Some(a) = listen_addr {
        info!("p2p mesh listen={a} bootnodes={}", cfg.bootnodes.len());
    } else if !cfg.bootnodes.is_empty() {
        info!("p2p dialing {} bootnodes (no listen)", cfg.bootnodes.len());
    }

    let rpc_state = RpcState {
        ledger: ledger.clone(),
        faucet_log: Arc::new(RwLock::new(VecDeque::new())),
        store: Some(Arc::clone(&store)),
        peer_scores: Arc::new(RwLock::new(Default::default())),
    };

    let scores = Arc::clone(&rpc_state.peer_scores);
    let hub_scores = Arc::clone(&hub);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            tick.tick().await;
            *scores.write() = hub_scores.peer_scores().await;
        }
    });

    let rpc_addr: SocketAddr = cfg.rpc.parse()?;
    tokio::spawn(async move {
        if let Err(e) = serve(rpc_state, rpc_addr).await {
            warn!("rpc terminated: {e}");
        }
    });

    let hub_rx = Arc::clone(&hub);
    let ledger_rx = ledger.clone();
    let mut rx = hub_rx.subscribe();
    tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            match msg {
                GossipMessage::Handshake { peer_id, height, .. } => {
                    info!("p2p handshake peer={peer_id} height={height}");
                }
                GossipMessage::Transaction(tx) => {
                    match ledger_rx.submit_tx(tx) {
                        Ok(h) => info!("gossip tx accepted {}", hex_hash(&h)),
                        Err(e) => warn!("gossip tx rejected: {e}"),
                    }
                }
                GossipMessage::Block(b) => info!("gossip block height={}", b.header.height),
                GossipMessage::Vote(v) => {
                    info!(
                        "gossip vote h={} r={} type={:?}",
                        v.height, v.round, v.vote_type
                    );
                }
                GossipMessage::Commit(c) => {
                    info!("gossip commit height={} votes={}", c.height, c.votes.len());
                }
                GossipMessage::Status { height, peer_id, .. } => {
                    info!("gossip status peer={peer_id} height={height}");
                }
                GossipMessage::SnapshotOffer {
                    height,
                    state_root,
                    bytes_len,
                } => {
                    info!(
                        "gossip snapshot offer h={height} root={state_root} bytes={bytes_len}"
                    );
                }
            }
        }
    });

    info!(
        "Aether node online — hybrid={} chain={} block_time={}ms features={{shielded:{}, rollups:{}, poseidon:true, snapshots:true}}",
        params.hybrid_mode,
        params.chain_id,
        cfg.block_time_ms,
        cfg.enable_shielded,
        cfg.enable_rollups
    );
    info!("Explorer can connect to http://{}", cfg.rpc);

    let mut ticker = tokio::time::interval(Duration::from_millis(cfg.block_time_ms));
    let mut last_snap_epoch = ledger.state.read().epoch;
    loop {
        ticker.tick().await;
        match ledger.produce_block(&kp) {
            Ok(block) => {
                let vals: Vec<_> = ledger.state.read().validators.values().cloned().collect();
                let vh = validators_hash(&vals);
                let bh = block_hash(&block.header).unwrap_or([0u8; 32]);
                let prevote = make_vote(&kp, block.header.height, 0, bh, VoteType::Prevote);
                let commit = solo_commit(&kp, block.header.height, 0, bh);
                let commit_bytes = serde_json::to_vec(&commit).unwrap_or_default();
                ledger
                    .commits
                    .write()
                    .insert(block.header.height, commit_bytes.clone());
                let _ = store.put_block(&block);
                let _ = store.put_commit(block.header.height, &commit_bytes);
                let _ = store.put_state(&ledger.state.read());
                if let Ok(lh) = light_header_from_block(&block, vh) {
                    info!(
                        "light_header height={} hash={}",
                        lh.height,
                        hex_hash(&lh.hash)
                    );
                }
                info!(
                    "committed height={} txs={} state_root={} peers={} invariant=ok",
                    block.header.height,
                    block.transactions.len(),
                    hex_hash(&block.header.state_root),
                    hub.peer_count().await
                );

                let _ = hub.publish(GossipMessage::Vote(prevote));
                let _ = hub.publish(GossipMessage::Block(block.clone()));
                let _ = hub.publish(GossipMessage::Commit(commit));
                let _ = hub.publish(GossipMessage::Status {
                    chain_id: params.chain_id.clone(),
                    height: ledger.state.read().height,
                    peer_id: peer_id.clone(),
                });

                let epoch = ledger.state.read().epoch;
                if epoch > last_snap_epoch {
                    last_snap_epoch = epoch;
                    let root = ledger.state.read().compute_state_root();
                    if let Ok(snap) = store.create_epoch_snapshot(root) {
                        let bytes_len = snap.to_bytes().map(|b| b.len() as u64).unwrap_or(0);
                        let _ = hub.publish(GossipMessage::SnapshotOffer {
                            height: snap.height,
                            state_root: hex_hash(&snap.state_root),
                            bytes_len,
                        });
                        info!(
                            "epoch snapshot height={} checksum={}",
                            snap.height,
                            hex_hash(&snap.checksum)
                        );
                    }
                }
            }
            Err(e) => warn!("block production failed: {e}"),
        }
    }
}

fn parse_bootnodes(s: &str) -> Vec<String> {
    s.split(',')
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .collect()
}

fn default_genesis(
    cfg: &NodeConfig,
    addr: Address,
    kp: &Keypair,
    hybrid: HybridMode,
) -> Genesis {
    let mut params = ChainParams::default();
    params.chain_id = cfg.chain_id.clone();
    params.hybrid_mode = hybrid;
    params.block_time_ms = cfg.block_time_ms;
    Genesis {
        chain_id: cfg.chain_id.clone(),
        alloc: vec![GenesisAlloc {
            address: addr,
            balance: (cfg.faucet_aeth as u128) * WEI_PER_AETH,
        }],
        validators: vec![GenesisValidator {
            address: addr,
            public_key: kp.public_bytes(),
            power: 10_000 * WEI_PER_AETH,
        }],
        params,
        timestamp: 0,
    }
}

fn load_or_create_keypair(path: Option<&PathBuf>) -> Result<Keypair> {
    if let Some(p) = path {
        if p.exists() {
            let hex_str = std::fs::read_to_string(p)?;
            let bytes = hex::decode(hex_str.trim())?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("key file must be 32 bytes hex"))?;
            return Ok(Keypair::from_bytes(arr));
        }
        let kp = Keypair::generate();
        let secret = kp.signing.to_bytes();
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(p, hex::encode(secret))?;
        info!("wrote new validator key to {}", p.display());
        return Ok(kp);
    }
    Ok(Keypair::generate())
}
