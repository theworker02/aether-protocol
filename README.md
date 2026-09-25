<p align="center">
  <img src="assets/brand/logo.svg" alt="Aether Protocol" width="128" height="128" />
</p>

<h1 align="center">Aether Protocol</h1>

<p align="center">
  <strong>Hybrid Layer-1 · v1.4.0</strong><br/>
  Public commons + federated finality · account + UTXO · Poseidon/Groth16 shielded notes ·
  liquid staking · slashing · IBC-lite bridges · <em>brokerless markets</em> · rollup settlement ·
  epoch snapshots · multi-validator mesh — one chain ID.
</p>

<p align="center">
  <a href="https://github.com/theworker02/aether-protocol/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/theworker02/aether-protocol/ci.yml?branch=main&style=for-the-badge&label=CI" alt="CI" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-0f6b5c?style=for-the-badge" alt="License" /></a>
  <a href="docs/PROTOCOL.md"><img src="https://img.shields.io/badge/spec-v1.4.0-c8f542?style=for-the-badge&labelColor=0b1c1a" alt="Spec" /></a>
  <a href="docs/ZK.md"><img src="https://img.shields.io/badge/zk-Poseidon%20%2B%20Groth16-0f6b5c?style=for-the-badge" alt="ZK" /></a>
  <a href="docs/ACQUISITION.md"><img src="https://img.shields.io/badge/diligence-acquisition%20pack-c8f542?style=for-the-badge&labelColor=0b1c1a" alt="Acquisition" /></a>
  <a href="docs/IP.md"><img src="https://img.shields.io/badge/IP-Apache%20%2B%20patent%20pledge-0f6b5c?style=for-the-badge" alt="IP" /></a>
  <img src="https://img.shields.io/badge/rust-1.75%2B-orange?style=for-the-badge" alt="Rust" />
</p>

<p align="center">
  <a href="#why-aether">Why</a> ·
  <a href="#whats-in-120">v1.2</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#json-rpc">RPC</a> ·
  <a href="#intellectual-property--acquisition">IP / Acquisition</a> ·
  <a href="#security">Security</a> ·
  <a href="#roadmap">Roadmap</a>
</p>

---

## Why Aether

Most chains force a single trade-off: public *or* permissioned, accounts *or* UTXO, transparent *or* private, monolith *or* rollup host. **Aether is hybrid by design** — one finality gadget, one fee market, one state root — with modes selected by genesis, governance, and per-tx kind.

| Capability | What you get in **1.2** |
|------------|-------------------------|
| **Hybrid access** | `public` · `allowlist` · `mixed` validator admission |
| **Dual ledger** | Account balances + native UTXO under one supply invariant |
| **Shielded pool** | Groth16/BN254 + **Poseidon** note CRH (native + R1CS) |
| **Liquid staking** | Bond / delegate / undelegate / redelegate / withdraw |
| **Rollup host** | `0x01` Groth16 · `0x02` Plonk-lite · `0x03` fraud · gated `0xFF` |
| **Networking** | Multi-validator TCP mesh (`--p2p-listen` / `--bootnodes`) |
| **Sync** | Epoch snapshots + `aeth_*Snapshot` RPC |
| **Contracts** | Metered AetherOps VM (Wasm ABI path documented) |
| **Operator UX** | TOML + genesis JSON, CLI, explorer, Docker Compose |
| **Diligence** | IP pack, patent pledge, acquisition data-room outline |

> **Status:** Operable reference for research, consortium pilots, white-label diligence, and acquisition review. **Not** audited for mainnet value. See [SECURITY.md](SECURITY.md).

---

## What's in 1.4.0

- **Brokerless markets** — on-chain CLOB + AMM + HTLC escrow; no central broker
- Permissionless `MarketFillOrder` (atomic delivery-vs-payment)
- `SettleBatch` multi-leg clearing; asset registry
- See [docs/MARKETS.md](docs/MARKETS.md)

### From 1.3.0

- Slashing + evidence txs, tombstones, community pool
- IBC-lite bridges (open/send/recv/ack)
- Tip → proposer; Prometheus `GET /metrics`
- Richer AetherOps ISA + `ContractCall`
- Peer bans on invalid gossip score

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Wallet · Explorer · CLI · Light clients · Indexers         │
└────────────────────────────┬────────────────────────────────┘
                             │ JSON-RPC
┌────────────────────────────▼────────────────────────────────┐
│  aether-node                                                 │
│  RPC · Mempool · Sync · Snapshots · TxFilter hooks           │
│           │                                                  │
│           ▼                                                  │
│  AetherBFT (PoS) ──► Execution                               │
│    Account | UTXO | VM | Poseidon notes | Rollups | Stake | Markets     │
│           │                                                  │
│           ▼                                                  │
│  Composite state root · Commit cert · TCP gossip mesh        │
└─────────────────────────────────────────────────────────────┘
```

| Crate | Role |
|-------|------|
| `aether-types` | Wire types, genesis, `PROTOCOL_VERSION` |
| `aether-crypto` | BLAKE3, Ed25519, Merkle |
| `aether-zk` | Poseidon + Groth16 shielded + rollup verifiers |
| `aether-consensus` | AetherBFT + light headers |
| `aether-p2p` | Multi-validator gossip mesh |
| `aether-vm` | AetherOps prototype ISA |
| `aether-state` | Ledger, staking, adapters |
| `aether-store` | sled + epoch snapshots |
| `aether-rpc` / `aether-node` / `aether-protocol-cli` | Operator surface |

---

## Quick start

```bash
git clone https://github.com/theworker02/aether-protocol.git
cd aether-protocol
cargo build -p aether-node -p aether-protocol-cli

cargo run -p aether-node -- \
  --config config/node.toml \
  --key-file ./validator.key \
  --rpc 127.0.0.1:8545 \
  --p2p-listen 127.0.0.1:9000
```

Second validator:

```bash
cargo run -p aether-node -- \
  --rpc 127.0.0.1:8546 \
  --data-dir data/chain-b \
  --p2p-listen 127.0.0.1:9001 \
  --bootnodes 127.0.0.1:9000 \
  --key-file ./validator-b.key
```

CLI:

```bash
cargo run -p aether-protocol-cli -- info
cargo run -p aether-protocol-cli -- bond --secret <hex32> --amount 10000000000000
cargo run -p aether-protocol-cli -- delegate --secret <hex32> --validator 0x... --amount 1000000000
cargo run -p aether-protocol-cli -- shield --secret <hex32> --value 1000000000 --note-out note.json
```

Explorer: `cd apps/explorer && npm i && npm run dev` → http://127.0.0.1:5173

---

## Configuration

| Key | Meaning |
|-----|---------|
| `chain_id` / `hybrid` / `genesis` | Network identity + mode |
| `p2p_listen` / `bootnodes` | Mesh listen + dial list |
| `zk_keys` | Groth16 keystore (schema v2) |
| `features.*` | Shielded / rollups / noop gate |

Genesis profiles: [`config/genesis.public.json`](config/genesis.public.json) · [`config/genesis.federated.json`](config/genesis.federated.json)

---

## JSON-RPC

| Method | Description |
|--------|-------------|
| `aeth_version` | Protocol / wire / impl versions |
| `aeth_protocolInfo` | Full feature + supply + ZK tags |
| `aeth_chainId` / `aeth_blockNumber` | Tip |
| `aeth_getBlockByNumber` / `ByHash` | Blocks |
| `aeth_getBalance` / `aeth_getAccount` | Accounts |
| `aeth_getValidators` / `aeth_getDelegations` / `aeth_getUnbonding` | Staking |
| `aeth_getLightHeader` / `aeth_getCommit` | Light client |
| `aeth_createSnapshot` / `load` / `get` / `export` | State sync |
| `aeth_netPeers` | Peer scores |
| `aeth_sendRawTransaction` | Submit tx |
| `aeth_verifySupply` | I1 check |

Health: `GET /health` → `ok`.

---

## Intellectual property & acquisition

| Doc | Purpose |
|-----|---------|
| [`docs/IP.md`](docs/IP.md) | Copyright, trademarks, diligence checklist |
| [`docs/PATENT_PLEDGE.md`](docs/PATENT_PLEDGE.md) | Defensive patent pledge |
| [`docs/ACQUISITION.md`](docs/ACQUISITION.md) | Asset inventory, data room, transfer checklist |
| [`NOTICE`](NOTICE) · [`LICENSE`](LICENSE) | Apache-2.0 attribution |
| [`CHANGELOG.md`](CHANGELOG.md) | Release history |

**Open core is free under Apache-2.0.** Acquisition value is brand, ops, ceremony, support, and team continuity — not locking public code. Commercial contact: GitHub `@theworker02` / [thanks.dev](https://thanks.dev/u/gh/theworker02).

---

## Adapting / white-label

[`docs/ADAPTING.md`](docs/ADAPTING.md) — `TxFilter`, `BlockHook`, `RollupVerifierAdapter`, brand kit under [`assets/brand/`](assets/brand/).

---

## Security

Read **[`SECURITY.md`](SECURITY.md)** before any deployment.

Reference limits remaining for mainnet: MPC ceremony, audited Poseidon params, Noise/QUIC transport, external audit.

---

## Roadmap

| Phase | Deliverable |
|-------|-------------|
| **1.3 (now)** | Slashing · bridges · metrics · peer bans · richer VM |
| **Next** | Noise/QUIC libp2p · RocksDB · MPC ceremony |
| **Then** | Wasmtime · light-client product · audited mainnet candidate |

Full table: [`docs/ROADMAP.md`](docs/ROADMAP.md)

---

## Documentation index

| Doc | Contents |
|-----|----------|
| [PROTOCOL](docs/PROTOCOL.md) | Normative core **v1.2** |
| [IP](docs/IP.md) / [ACQUISITION](docs/ACQUISITION.md) / [PATENT_PLEDGE](docs/PATENT_PLEDGE.md) | Diligence |
| [INVARIANTS](docs/INVARIANTS.md) | Supply & safety |
| [LIGHT_CLIENT](docs/LIGHT_CLIENT.md) | Headers & WSP |
| [GOVERNANCE](docs/GOVERNANCE.md) | On-chain params |
| [SYNC](docs/SYNC.md) | Snapshots |
| [ZK](docs/ZK.md) | Poseidon + Groth16 |
| [CONSENSUS](docs/CONSENSUS.md) | AetherBFT |
| [CRYPTOGRAPHY](docs/CRYPTOGRAPHY.md) | Primitives |
| [NETWORKING](docs/NETWORKING.md) | Gossip |
| [ECONOMICS](docs/ECONOMICS.md) | Fees & staking |
| [THREAT_MODEL](docs/THREAT_MODEL.md) | Adversaries |
| [VM](docs/VM.md) / [ROLLUPS](docs/ROLLUPS.md) | Execution / settlement |
| [BRIDGES](docs/BRIDGES.md) | IBC-lite packets |
| [SLASHING](docs/SLASHING.md) | Evidence & pool |
| [ROADMAP](docs/ROADMAP.md) | Phased delivery |
| [CHANGELOG](CHANGELOG.md) | Releases |

---

## Brand

<p align="center">
  <img src="assets/brand/wordmark.svg" alt="Aether wordmark" width="420" />
</p>

Colors: Ink `#0b1c1a` · Teal `#0f6b5c` · Signal `#c8f542` · Fog `#e8f2ef`

---

## License

[Apache-2.0](LICENSE) · [NOTICE](NOTICE)

## Funding

[`.github/FUNDING.yml`](.github/FUNDING.yml) · [thanks.dev/u/gh/theworker02](https://thanks.dev/u/gh/theworker02)

---

<p align="center">
  <sub>Aether Protocol 1.2 — one chain, many modes.</sub>
</p>
