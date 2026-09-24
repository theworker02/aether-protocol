# Adapting Aether for your product / consortium / L2

**Version:** 1.2.0  

This guide is for teams that want to **fork, white-label, or embed** Aether rather than run the reference chain as-is. For commercial acquisition / IP diligence, start with [`ACQUISITION.md`](ACQUISITION.md) and [`IP.md`](IP.md).

## 1. Choose a deployment mode

| Goal | Genesis | Hybrid flag | Notes |
|------|---------|-------------|-------|
| Public L1 research | `config/genesis.public.json` | `public` | Open bonding |
| Consortium / bank chain | `config/genesis.federated.json` | `allowlist` | Validator allowlist |
| Shared security + apps | `public` or `mixed` | `mixed` | Core proposers allowlisted |
| App-specific rollup host | any | any | Register schemes `0x01`–`0x03` |

## 2. Minimum fork checklist

1. **Rename chain** — set `chain_id` in `config/node.toml` + genesis; never reuse another network’s id.
2. **Replace genesis alloc** — treasury, team, ecosystem, faucet.
3. **Validator keys** — generate offline; set `--key-file`; back up securely.
4. **Economics** — edit `docs/ECONOMICS.md` params in genesis (`gas_limit`, `epoch_length`, stake floors).
5. **Brand** — swap `assets/brand/*`, explorer CSS variables, README badges URL.
6. **ZK keys** — run a fresh `--zk-keys` setup per network (do not reuse another net’s SRS).
7. **Security review** — treat Groth16 local setup as **dev**; plan MPC ceremony before mainnet value.
8. **License** — Apache-2.0; preserve copyright notices.

## 3. Configuration surfaces

```toml
# config/node.toml
chain_id = "my-chain-1"
rpc = "0.0.0.0:8545"
hybrid = "allowlist"
genesis = "config/genesis.federated.json"
zk_keys = "data/zk_keys.json"
```

CLI flags override TOML. Feature flags:

- `enable_shielded` / `enable_rollups` (config)
- `allow_noop_rollup` → sets `AETHER_ALLOW_NOOP_ROLLUP` (never in production)

## 4. Extension points (no consensus fork)

See `aether_state::adapters`:

| Trait | Use |
|-------|-----|
| `TxFilter` | Compliance, geo, transparent-only policy |
| `BlockHook` | Indexers, webhooks, bridge relayers |
| `RollupVerifierAdapter` | Vendor proof systems (scheme id ≥ `0x10`) |

Example sketch: `examples/adapters/transparent_only.rs`.

Wire filters in your operator binary before mempool admission.

## 5. Protocol modules you can swap

| Module | Crate | Swap guidance |
|--------|-------|---------------|
| Hash / notes | `aether-zk` | Swap Poseidon parameters; keep public input layout |
| VM | `aether-vm` | Drop in Wasmtime behind same host ABI (`docs/VM.md`) |
| P2P | `aether-p2p` | Replace hub with libp2p; keep gossip topics |
| Storage | `aether-state` | Add RocksDB/MDBX behind `ChainState` |
| Consensus pacing | `aether-consensus` | Multi-validator networking already sketched |

## 6. Recommended production roadmap

1. Persistent storage + snapshots  
2. Multi-validator AetherBFT over real transports  
3. Audited Poseidon parameters + MPC Groth16/Halo2 ceremony  
4. Light client + IBC-like bridge  
5. Formal verification of supply invariant  
6. External audit + bug bounty  

## 7. Acquisition / diligence packet

Point diligence to:

- `docs/PROTOCOL.md` — normative design  
- `docs/THREAT_MODEL.md` — residual risk  
- `docs/ZK.md` / `docs/ROLLUPS.md` — crypto posture  
- `SECURITY.md` — disclosure  
- This file — how operators adapt  

Logo / brand: `assets/brand/`.
