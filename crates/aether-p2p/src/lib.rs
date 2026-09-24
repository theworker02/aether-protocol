//! Multi-validator gossip fabric: length-prefixed JSON frames over TCP.
//! Messages: handshake, txs, blocks, votes, commits (docs/NETWORKING.md).

use aether_consensus::{CommitCertificate, Vote};
use aether_types::{Block, Transaction};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{debug, info, warn};

const MAX_FRAME: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GossipMessage {
    Handshake {
        chain_id: String,
        height: u64,
        peer_id: String,
        listen: String,
    },
    Transaction(Transaction),
    Block(Block),
    Vote(Vote),
    Commit(CommitCertificate),
    Status {
        chain_id: String,
        height: u64,
        peer_id: String,
    },
    SnapshotOffer {
        height: u64,
        state_root: String,
        bytes_len: u64,
    },
}

#[derive(Clone, Debug, Default)]
struct PeerScore {
    useful: u64,
    invalid: u64,
}

pub struct NetworkHub {
    peer_id: String,
    chain_id: String,
    local_tx: broadcast::Sender<GossipMessage>,
    peers: RwLock<HashSet<String>>,
    scores: RwLock<HashMap<String, PeerScore>>,
    bans: RwLock<HashSet<String>>,
    outbound: RwLock<Vec<mpsc::UnboundedSender<Vec<u8>>>>,
}

impl NetworkHub {
    pub fn new(peer_id: String, chain_id: String, capacity: usize) -> Arc<Self> {
        let (local_tx, _) = broadcast::channel(capacity);
        Arc::new(Self {
            peer_id,
            chain_id,
            local_tx,
            peers: RwLock::new(HashSet::new()),
            scores: RwLock::new(HashMap::new()),
            bans: RwLock::new(HashSet::new()),
            outbound: RwLock::new(Vec::new()),
        })
    }

    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }

    pub fn subscribe(&self) -> broadcast::Receiver<GossipMessage> {
        self.local_tx.subscribe()
    }

    pub async fn register_peer(&self, id: String) {
        if self.bans.read().await.contains(&id) {
            warn!("ignoring banned peer {id}");
            return;
        }
        self.peers.write().await.insert(id.clone());
        self.scores.write().await.entry(id).or_default();
    }

    pub async fn ban_peer(&self, id: &str) {
        self.bans.write().await.insert(id.to_string());
        self.peers.write().await.remove(id);
        info!("banned peer {id}");
    }

    pub async fn is_banned(&self, id: &str) -> bool {
        self.bans.read().await.contains(id)
    }

    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    pub async fn peer_scores(&self) -> HashMap<String, (u64, u64)> {
        self.scores
            .read()
            .await
            .iter()
            .map(|(k, v)| (k.clone(), (v.useful, v.invalid)))
            .collect()
    }

    pub fn publish(&self, msg: GossipMessage) -> Result<()> {
        debug!("gossip {:?}", std::mem::discriminant(&msg));
        let _ = self.local_tx.send(msg.clone());
        if let Ok(bytes) = encode_frame(&msg) {
            if let Ok(guard) = self.outbound.try_read() {
                for tx in guard.iter() {
                    let _ = tx.send(bytes.clone());
                }
            }
        }
        Ok(())
    }

    pub async fn bump_useful(&self, peer: &str) {
        if let Some(s) = self.scores.write().await.get_mut(peer) {
            s.useful += 1;
        }
    }

    pub async fn bump_invalid(&self, peer: &str) {
        let mut scores = self.scores.write().await;
        let s = scores.entry(peer.to_string()).or_default();
        s.invalid += 1;
        if s.invalid >= 32 && s.invalid > s.useful.saturating_mul(2) {
            drop(scores);
            self.ban_peer(peer).await;
        }
    }
}

pub async fn spawn_mesh(
    hub: Arc<NetworkHub>,
    listen: Option<SocketAddr>,
    boots: Vec<SocketAddr>,
    height: u64,
) -> Result<()> {
    if let Some(addr) = listen {
        let hub_a = Arc::clone(&hub);
        tokio::spawn(async move {
            let listener = match TcpListener::bind(addr).await {
                Ok(l) => l,
                Err(e) => {
                    warn!("p2p bind {addr}: {e}");
                    return;
                }
            };
            info!("p2p listening on {addr}");
            loop {
                match listener.accept().await {
                    Ok((stream, remote)) => {
                        let h = Arc::clone(&hub_a);
                        tokio::spawn(async move {
                            if let Err(e) = run_peer(h, stream, remote.to_string(), height).await {
                                debug!("peer session ended: {e}");
                            }
                        });
                    }
                    Err(e) => warn!("accept error: {e}"),
                }
            }
        });
    }
    for boot in boots {
        let hub_d = Arc::clone(&hub);
        tokio::spawn(async move {
            match TcpStream::connect(boot).await {
                Ok(stream) => {
                    if let Err(e) = run_peer(hub_d, stream, boot.to_string(), height).await {
                        warn!("boot session {boot}: {e}");
                    }
                }
                Err(e) => warn!("boot dial {boot}: {e}"),
            }
        });
    }
    Ok(())
}

async fn run_peer(
    hub: Arc<NetworkHub>,
    stream: TcpStream,
    remote: String,
    height: u64,
) -> Result<()> {
    let (mut rd, mut wr) = tokio::io::split(stream);
    let (tx_out, mut rx_out) = mpsc::unbounded_channel::<Vec<u8>>();
    hub.outbound.write().await.push(tx_out);

    let hs = GossipMessage::Handshake {
        chain_id: hub.chain_id.clone(),
        height,
        peer_id: hub.peer_id.clone(),
        listen: String::new(),
    };
    write_raw(&mut wr, &encode_frame(&hs)?).await?;

    let writer = tokio::spawn(async move {
        while let Some(frame) = rx_out.recv().await {
            if write_raw(&mut wr, &frame).await.is_err() {
                break;
            }
        }
    });

    loop {
        let body = match read_frame(&mut rd).await {
            Ok(b) => b,
            Err(_) => break,
        };
        match decode_frame(&body) {
            Ok(msg) => {
                match &msg {
                    GossipMessage::Handshake {
                        peer_id, chain_id, ..
                    } => {
                        if hub.is_banned(peer_id).await {
                            warn!("reject banned peer {peer_id}");
                            break;
                        }
                        if chain_id != &hub.chain_id {
                            warn!("reject peer chain_id={chain_id}");
                            hub.bump_invalid(peer_id).await;
                            break;
                        }
                        hub.register_peer(peer_id.clone()).await;
                        info!("p2p peer online {peer_id} ({remote})");
                    }
                    _ => {
                        hub.bump_useful(&remote).await;
                    }
                }
                let _ = hub.local_tx.send(msg);
            }
            Err(e) => {
                warn!("decode from {remote}: {e}");
                hub.bump_invalid(&remote).await;
            }
        }
    }
    writer.abort();
    Ok(())
}

fn encode_frame(msg: &GossipMessage) -> Result<Vec<u8>> {
    let body = serde_json::to_vec(msg)?;
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

fn decode_frame(frame: &[u8]) -> Result<GossipMessage> {
    Ok(serde_json::from_slice(frame)?)
}

async fn write_raw<W: AsyncWriteExt + Unpin>(w: &mut W, frame: &[u8]) -> Result<()> {
    w.write_all(frame).await?;
    w.flush().await?;
    Ok(())
}

async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 || len > MAX_FRAME {
        anyhow::bail!("invalid frame len {len}");
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    Ok(body)
}
