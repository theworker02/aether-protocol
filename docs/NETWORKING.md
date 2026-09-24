# Networking Specification

**Companion to:** `PROTOCOL.md`

---

## 1. Identity

Each node generates a long-term Ed25519 **node key** distinct from validator consensus keys (recommended). Peer ID = `blake3("AETH/PEER" || node_pk)[0..20]`.

---

## 2. Transports

| Environment | Transport |
|-------------|-----------|
| Production target | QUIC + TCP fallback, Noise XX handshake (libp2p) |
| Reference (v0.2) | TCP mesh, length-prefixed JSON frames (`aether-p2p`) |

Node flags: `--p2p-listen 0.0.0.0:9000` and `--bootnodes a:9001,b:9002` (also `p2p_listen` / `bootnodes` in `config/node.toml`).

Gossip frames carry: `handshake`, `transaction`, `block`, `vote`, `commit`, `status`, `snapshot_offer`.

Frame:

```
u32_le length || utf8_json_payload
```

Max frame: 4 MiB (blobs may be chunked).

---

## 3. Gossip Topics

| Topic | Message | Validation |
|-------|---------|------------|
| `/aether/tx/1` | Transaction | Sig, nonce/UTXO, intrinsic gas |
| `/aether/block/1` | Block + Commit | Commit quorum, header link |
| `/aether/vote/1` | Vote | Sig, set membership |
| `/aether/blob/1` | Rollup DA chunk | Rollup registration, size |
| `/aether/snap/1` | Epoch snapshot offer | Height/epoch match |

Duplicate message IDs (hash of payload) are suppressed via seen-cache (LRU 65_536).

---

## 4. Sync Protocol

1. **Handshake:** exchange `Status { chain_id, height, hash, genesis_hash, hybrid_mode }`.
2. **Header sync:** request headers `(from, to]` in batches of 64.
3. **Block bodies:** download missing bodies; verify commits.
4. **State:** if lag > `snapshot_threshold`, fetch epoch snapshot + verify against header `state_root`.
5. Tip-follow via gossip.

Fork choice: **highest finalized height**; never reorg finalized blocks. Unfinalized speculative prefixes may be replaced by a conflicting round’s commit (rare; only if local view was incomplete).

---

## 5. Mempool

- Priority = `effective_tip_per_gas`.
- Nonce gaps: park subsequent account txs.
- UTXO conflicts: first-seen wins; replace-by-fee if tip ≥ 110% and same inputs.
- Size cap: 5_000 txs or 32 MiB.

---

## 6. Peer Scoring

Score decreases on: invalid messages, timeouts, excessive bans.  
Score increases on: useful blocks/txs, low latency.  
Validators preferentially dial other validators (stake-weighted).

---

## 7. Rate Limits

Per-peer: 100 msgs/s sustained, burst 500. Blob topic: 8 MiB/s.
