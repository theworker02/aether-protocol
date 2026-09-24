# State Sync & Snapshots

**Companion to:** `NETWORKING.md` · `LIGHT_CLIENT.md`

---

## 1. Sync modes

| Mode | When | Method |
|------|------|--------|
| Genesis | Fresh node | Download headers → bodies → exec |
| Fast | Lag > `snapshot_threshold` | Epoch snapshot + replay tip |
| Light | Mobile / bridge | Headers + commits only |

Default `snapshot_threshold = 1000` blocks.

---

## 2. Snapshot format

```text
Snapshot {
  version: u32,                 // = 1
  chain_id: String,
  height: u64,                  // epoch-aligned
  header_hash: Hash256,
  state_root: Hash256,
  chunks: Vec<SnapshotChunk>,
}

SnapshotChunk {
  index: u32,
  kind: Accounts | Utxos | Code | Notes | Nullifiers | Rollups | Validators,
  payload: Bytes,               // zstd optional
  checksum: Hash256,            // blake3(kind || payload)
}
```

Nodes advertise snapshot offers on `/aether/snap/1`. Downloaders verify:

1. Header at `height` finalizes with valid commit  
2. Reassembled state root matches header  
3. Chunk checksums  

---

## 3. Tip follow

After snapshot install, request blocks `(height, tip]` in batches of 64, verify commits, execute.

---

## 4. Reference implementation

v0.2 persists chain state via `aether-store` (sled). Snapshot export/import RPC:

| Method | Params | Result |
|--------|--------|--------|
| `aeth_createSnapshot` | optional `[path]` | metadata (`height`, `state_root`, `checksum`) |
| `aeth_loadSnapshot` | `[path\|hex]` | installs state into ledger + store |
| `aeth_getSnapshot` | optional `[height]` | metadata for indexed snapshot |
| `aeth_exportSnapshot` | — | metadata + hex blob |

Epoch boundaries auto-persist a snapshot and gossip `SnapshotOffer` on `/aether/snap/1`.

Production should gate load/create behind auth.

