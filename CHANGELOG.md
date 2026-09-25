# Changelog

All notable changes to Aether Protocol are documented here.

## [1.4.0] — 2026-09-24

### Added
- **Brokerless markets:** limit book, permissionless fills, AMM (`x*y=k`), HTLC escrow, `SettleBatch`
- Asset registry (`MarketRegisterAsset`) + secondary `asset_balances`
- RPC: `aeth_getOrders`, `aeth_getOrder`, `aeth_getPools`, `aeth_getEscrows`, `aeth_getAssets`, `aeth_getAssetBalance`, `aeth_getMarketLocked`
- CLI: `market-register`, `market-post`, `market-fill`, `market-cancel`, `markets`, `escrow-open`, `escrow-claim`
- Docs: `MARKETS.md`

### Changed
- Package + protocol SemVer **1.4.0**; wire version **3**
- Supply invariant includes `market_locked_native`
- CLI crate published as `aether-protocol-cli` (name collision on crates.io)

## [1.3.0] — 2026-09-24

### Added
- Slashing: `EvidenceDoubleSign`, `EvidenceDowntime`, tombstones, community pool
- IBC-lite bridges: open / send / recv / ack + RPC
- `ContractCall` tx kind; tip → proposer fee split
- AetherOps ISA expansion (DIV/MOD/bitwise/jumps/block context/RETURN)
- Prometheus text metrics at `GET /metrics`
- P2P peer bans on invalid-score threshold
- Docs: `BRIDGES.md`, `SLASHING.md`

### Changed
- Package SemVer **1.3.0**; protocol version string **1.3.0**
- Supply invariant includes community pool

## [1.2.0] — 2026-09-24

### Added
- Liquid staking: `StakeDelegate`, `StakeUndelegate`, `StakeRedelegate`, `StakeWithdraw`
- Unbonding queue with epoch unlock (`unbonding_period`)
- Multi-validator TCP P2P mesh (`--p2p-listen`, `--bootnodes`)
- Poseidon CRH for notes (native + R1CS) — ZK key schema v2
- Epoch snapshot envelope + RPC (`aeth_createSnapshot`, `aeth_loadSnapshot`, …)
- IP / acquisition pack: `docs/IP.md`, `docs/ACQUISITION.md`, `docs/PATENT_PLEDGE.md`, `NOTICE`
- Protocol SemVer **1.2.0**, wire version **2**

### Changed
- Specs thickened to v1.2 (PROTOCOL, ECONOMICS, NETWORKING, SYNC, ZK, ROADMAP)
- Supply invariant accounts for delegations + unbonding locks
- README acquisition-ready packaging

### Security
- Snapshot load remains operator-trust; gate in production
- Poseidon params remain reference — swap before mainnet value

## [0.2.0] — 2026-09

- Persistent sled store, governance, light headers, invariants, adapters

## [0.1.0] — 2026-09

- Initial hybrid L1 reference: dual ledger, Groth16, rollup schemes, explorer
