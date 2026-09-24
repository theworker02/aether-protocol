# Aether Protocol — Core Specification

**Version:** 1.3.0  
**Status:** Diligence-ready reference — persistence, Poseidon notes, liquid staking, slashing, IBC-lite bridges, P2P mesh, snapshots, IP pack  
**License:** Apache-2.0 (see `NOTICE`, `docs/IP.md`, `docs/ACQUISITION.md`)  
**Wire version:** `2`  
**Chain ID (devnet):** `aether-devnet-1`  
**Native denomination:** `AETH` (1 AETH = 10^9 `wei`)

---

## 0. Abstract

Aether is a **hybrid Layer-1 blockchain** that deliberately unifies several design axes usually treated as mutually exclusive:

| Axis | Mode A (public default) | Mode B (hybrid extension) |
|------|-------------------------|---------------------------|
| Access | Permissionless participation | Permissioned validator federation |
| Value model | Account balances + contract storage | Native UTXO coin set for settlement |
| Visibility | Transparent transactions | Optional shielded notes (Poseidon + Groth16) |
| Staking | Self-bond validators | Liquid delegation / undelegation |
| Execution | On-chain smart contracts | External rollups settling to L1 |
| Consensus | BFT Proof-of-Stake (AetherBFT) | Same engine, allowlisted validator set |
| Sync | Full replay | Epoch snapshots + tip follow |

The protocol does **not** fork into separate networks for these modes. A single state machine, single block production pipeline, and single networking fabric carry all modes.

**Companion documents:** `CONSENSUS.md`, `CRYPTOGRAPHY.md`, `NETWORKING.md`, `ECONOMICS.md`, `THREAT_MODEL.md`, `VM.md`, `ROLLUPS.md`, `ZK.md`, `LIGHT_CLIENT.md`, `GOVERNANCE.md`, `INVARIANTS.md`, `SYNC.md`, `ADAPTING.md`, `IP.md`, `ACQUISITION.md`, `PATENT_PLEDGE.md`, `BRIDGES.md`, `SLASHING.md`.

---

## 0.1 Release 1.3 highlights

1. Evidence-based slashing (double-sign / downtime) with community pool.  
2. IBC-lite bridge channels and ordered packets.  
3. Tip-to-proposer fee split; Prometheus metrics endpoint.  
4. Expanded AetherOps ISA and `ContractCall`.  
5. Peer ban hooks on invalid gossip score.  

### Prior 1.2 highlights

1. Poseidon CRH for note commitments, nullifiers, and Merkle parents (R1CS-matched).  
2. Multi-validator TCP gossip mesh with votes/commits/snapshot offers.  
3. Liquid staking tx surface + unbonding queue.  
4. Epoch snapshot RPC and auto-persist on epoch boundaries.  
5. Diligence packaging: IP posture, patent pledge, acquisition data room.  

---

## 1. Design Goals

### 1.1 Primary goals

1. **Hybrid without fragmentation** — one chain ID, one finality gadget, one fee market.
2. **Deterministic finality** — ≤ 2 network delays after a round of BFT commit (target ≤ 2s under healthy conditions on a well-connected validator set).
3. **Dual ledger coherence** — account and UTXO views of native value remain conservatively consistent under a single total supply invariant (including delegations and unbonding locks).
4. **Modular settlement** — rollups post data roots and state commitments; L1 verifies fraud/validity proofs per registered scheme.
5. **Selective privacy** — shielded transfers are first-class citizens but do not obscure fee payment or consensus metadata required for DoS resistance.
6. **Operational realism** — light clients, archival nodes, and consortium deployments share the same binary with configuration flags.
7. **Acquisition clarity** — open-core Apache-2.0 with explicit IP / trademark / diligence docs.

### 1.2 Explicit non-goals (1.2)

- Full EVM opcode compatibility (WASM is primary; EVM translation is future work).
- Recursive SNARK proving inside the consensus critical path (proving is async for rollups).
- Cross-shard execution (sharding reserved as a later horizontal scale path).
- On-chain order books or application-specific sequencers as protocol primitives.
- Production Noise/QUIC transport (TCP mesh is the 1.2 reference; libp2p is next).

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        Client Layer                              │
│   Wallet · Explorer · CLI · SDKs · Light Client                  │
└────────────────────────────┬────────────────────────────────────┘
                             │ JSON-RPC
┌────────────────────────────▼────────────────────────────────────┐
│                         Node Stack                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐ │
│  │   RPC    │  │   Mempool│  │ Snapshots│  │  Light Protocol  │ │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────────┬─────────┘ │
│       └─────────────┴─────────────┴─────────────────┘           │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              Consensus (AetherBFT)                        │   │
│  │   Propose → Prevote → Precommit → Commit · Epochs         │   │
│  └────────────────────────────┬─────────────────────────────┘   │
│  ┌────────────────────────────▼─────────────────────────────┐   │
│  │              Execution Engine                             │   │
│  │  Dual ledger · VM · Poseidon notes · Rollups · Staking    │   │
│  └────────────────────────────┬─────────────────────────────┘   │
│  ┌────────────────────────────▼─────────────────────────────┐   │
│  │              State & Storage (sled + snap index)          │   │
│  └────────────────────────────┬─────────────────────────────┘   │
│  ┌────────────────────────────▼─────────────────────────────┐   │
│  │              Networking (TCP mesh → libp2p target)        │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### 2.1 Node roles

| Role | Duties | Stake required |
|------|--------|----------------|
| **Validator** | Propose/vote, produce blocks | Yes (bonded) |
| **Delegator** | Liquid stake to validators | Liquid capital |
| **Full node** | Verify all txs, serve RPC, gossip | No |
| **Archival** | Retain historical state & blobs | No |
| **Light client** | Verify headers + Merkle proofs | No |
| **Sequencer (app)** | Order rollup txs off-protocol | App-defined |
| **Prover (app)** | Generate validity/fraud proofs | App-defined |

### 2.2 Hybrid operating modes

**Mode Public** (default genesis): any account may bond stake and join the active set subject to minimum stake and commission rules.

**Mode Federated**: governance (or genesis config) sets `validator_allowlist_hash`. Only identities in the allowlist may enter the active set. Bonding still applies for slashing symmetry. The chain remains publicly readable unless operators deliberately restrict RPC.

**Mode Mixed**: allowlist applies to a **core committee** that finalizes blocks; a permissionless **peripheral set** may still bond for attestation rewards without proposing. Mixed mode is activated by the `HybridCommittee` governance parameter (see §8).

---

## 3. Cryptographic Primitives

Normative choices for v0.1 reference implementation:

| Purpose | Primitive | Notes |
|---------|-----------|-------|
| Hash | BLAKE3-256 | Domain-separated; see `CRYPTOGRAPHY.md` |
| Address | `blake3(pubkey)[0..20]` | 20-byte account id |
| Signatures | Ed25519 | Consensus + tx auth |
| Merkle | Binary BLAKE3 Merkle | State roots, tx roots |
| VRF (proposer) | Ed25519-VRF (simplified in prototype) | Leader election fairness |
| Shielded notes | Commitment + nullifier (prototype uses BLAKE3; production targets Halo2/Plonk) | See §7 |
| KDF | HKDF-SHA256 | Key derivation for wallets |

**Domain separation tags** (ASCII prefixes hashed into the message):

```
AETH/BLOCK/V1
AETH/TX/V1
AETH/VOTE/V1
AETH/STATE/V1
AETH/NOTE/V1
AETH/NULLIFIER/V1
AETH/UTXO/V1
AETH/ROLLUP/V1
```

---

## 4. Data Structures

### 4.1 Block

```text
Block {
  header: Header,
  transactions: Vec<Transaction>,
  evidence: Vec<Evidence>,          // double-sign, etc.
}
```

```text
Header {
  version: u32,                     // protocol version
  chain_id: String,                 // e.g. "aether-devnet-1"
  height: u64,                      // 1-indexed
  time_unix_ms: u64,                // proposer wall clock, bounded by skew rules
  prev_hash: Hash256,
  tx_root: Hash256,                 // Merkle root of txs
  state_root: Hash256,              // post-execution composite root
  receipts_root: Hash256,
  proposer: Address,
  round: u32,                       // BFT round that committed
  epoch: u64,
  gas_used: u64,
  gas_limit: u64,
  base_fee: u64,                    // EIP-1559-style
  extra: Bytes,                     // ≤ 32 bytes
  signature: Signature,             // proposer seal
}
```

**Composite `state_root`** commits to a fixed tuple of sub-roots:

```
state_root = blake3(
  "AETH/STATE/V1" ||
  accounts_root ||
  utxo_root ||
  contracts_root ||
  notes_root ||
  nullifiers_root ||
  rollups_root ||
  validator_set_root
)
```

### 4.2 Transactions

All transactions share an envelope:

```text
Transaction {
  version: u8,
  nonce: u64,                       // per-account for AccountOrigin
  origin: Origin,
  kind: TxKind,
  gas_limit: u64,
  max_fee_per_gas: u64,
  max_priority_fee_per_gas: u64,
  tip_to: Option<Address>,          // optional tip recipient
  signature: Signature,
}

Origin =
  | AccountOrigin { from: Address }
  | UtxoOrigin { inputs: Vec<OutPoint> }
  | ShieldedOrigin { nullifiers: Vec<Nullifier>, proofs: Bytes }
```

```text
TxKind =
  | Transfer { to: Address, amount: u128, data: Bytes }
  | Deploy { code: Bytes, salt: Hash256 }
  | UtxoSpend { outputs: Vec<TxOutput> }
  | ShieldedTransfer { commitments: Vec<NoteCommitment>, ciphertext: Bytes, proof: Bytes }
  | StakeBond { amount: u128, commission_bps: u16 }
  | StakeUnbond { amount: u128 }
  | StakeRedelegate { to: Address, amount: u128 }
  | GovernanceVote { proposal_id: u64, option: u8 }
  | RollupRegister { config: RollupConfig }
  | RollupCommit { rollup_id: Hash256, batch: RollupBatch }
  | ModeSwitchHint { /* reserved; actual mode via governance */ }
```

### 4.3 Accounts

```text
Account {
  nonce: u64,
  balance: u128,                    // spendable transparent AETH
  code_hash: Option<Hash256>,
  storage_root: Hash256,
  bonded: u128,
  unbonding: Vec<UnbondingEntry>,
}
```

### 4.4 UTXO

```text
OutPoint { tx_hash: Hash256, index: u32 }

TxOutput {
  amount: u128,
  lock: LockScript,                 // usually PayToPubkey
  meta: Bytes,                      // ≤ 64 bytes
}

LockScript =
  | PayToPubkey { address: Address }
  | PayToScriptHash { hash: Hash256 }
  | Timelock { address: Address, unlock_height: u64 }
```

**Supply invariant:**

```
total_supply =
  sum(account.balance + account.bonded + unbonding) +
  sum(utxo.amount) +
  sum(shielded_note values via commitments) +
  fee_pool +
  undistributed_rewards
```

At every block end, `total_supply` MUST equal genesis supply + cumulative mint − cumulative burn (mint/burn only via explicit protocol rules).

---

## 5. Consensus — AetherBFT (summary)

Full rules in `CONSENSUS.md`. Summary:

1. Time is divided into **epochs** of `E` blocks (default 100).
2. Within an epoch, the **active validator set** is fixed (sampled/weighted from bonded stake at epoch boundary).
3. Each height has rounds. A **proposer** is selected by weighted round-robin with VRF bias correction.
4. Phases per round: **Propose → Prevote → Precommit → Commit**.
5. Quorum: `> 2/3` voting power by stake weight.
6. Finality: a block with `+2/3` precommits for the same `(height, round, block_hash)` is **final**. No probabilistic confirmation depth.
7. Locking rules follow Tendermint/HotStuff safety: once prevoting a value, locks prevent conflicting commits without unlock conditions.
8. **Federated mode** only changes how the active set is constructed (allowlist ∩ bonded), not the vote math.

### 5.1 Evidence & slashing

| Offense | Detection | Slash |
|---------|-----------|-------|
| Double-sign (conflicting votes same height/round) | Evidence tx | 5% bonded (escalating) |
| Light client attack (conflicting headers) | Fork evidence | 10% |
| Extended downtime | Missed > `D` windows | Jail + 0.01% |

Slashed stake is partially burned (50%) and partially sent to a community pool (50%).

---

## 6. Execution Model

### 6.1 Block execution pipeline

1. Verify header linkage, proposer eligibility, signature.
2. Verify tx Merkle root matches body.
3. For each tx in order:
   - Authenticate origin (sig / UTXO unlock / shielded proof).
   - Charge intrinsic gas; abort if insufficient.
   - Apply kind-specific transitions.
   - Emit receipt (status, gas, logs, state diffs digest).
4. Pay fees: `base_fee` burned; priority fee to proposer (or `tip_to`).
5. Apply consensus rewards for the block.
6. Recompute composite state root; MUST match header.
7. Persist block; gossip commit certificate.

### 6.2 Gas schedule (v0.1)

| Op | Gas |
|----|-----|
| Intrinsic tx | 21_000 |
| Per calldata byte | 16 |
| Account transfer | 9_000 |
| UTXO input | 12_000 |
| UTXO output | 8_000 |
| WASM instruction (avg) | 1–10 (metered) |
| Contract deploy per byte | 200 |
| Shielded verify (prototype stub) | 80_000 |
| Rollup commit base | 50_000 |

`gas_limit` per block default: `30_000_000`.  
`base_fee` adjusts ±12.5% targeting 50% utilization.

### 6.3 Dual ledger bridging

Moving value between account and UTXO domains:

- `Transfer` with special system address `0x00…01` (`UTXO_BRIDGE`) and data encoding outputs → mints UTXOs, burns account balance.
- `UtxoSpend` with an output locked to system address `0x00…02` (`ACCOUNT_BRIDGE`) → credits account balance.

Bridges are atomic within a single transaction; partial failure reverts entirely.

---

## 7. Shielded Pool (hybrid privacy)

Transparent metadata always visible: fee, gas, tx kind tag `ShieldedTransfer`, nullifier count.

Hidden: sender, recipient, amount (within note commitments).

**Implemented:** Groth16/BN254 circuits for shield, transfer, and unshield with mandatory on-chain verification. See `ZK.md`.

```text
Note {
  value: u64,
  recipient_pk: Fr,
  rseed: Fr,
}

commitment = value + rseed * R_GEN + pk * PK_GEN   // BN254 Fr
nullifier  = sk * SK_GEN + commitment
```

Merkle membership (depth 8, MiMC-style) is enforced inside the transfer/unshield circuits.

---

## 8. Governance & Hybrid Committee

On-chain governance parameters (subset):

| Param | Default | Description |
|-------|---------|-------------|
| `epoch_length` | 100 | Blocks per epoch |
| `min_validator_stake` | 10_000 AETH | Bond floor |
| `max_validators` | 100 | Active set cap |
| `unbonding_period` | 21 epochs | Unbond delay |
| `hybrid_committee` | Off | Off \| Allowlist \| Mixed |
| `allowlist_root` | ∅ | Merkle root of allowed validator keys |
| `privacy_enforced_fee` | true | Shielded txs must pay transparent fees |
| `rollup_max_blob_bytes` | 128 KiB | Per-batch DA cap |

Proposals: deposit → voting period → timelock → enact. Quorum and threshold defined in `ECONOMICS.md`.

---

## 9. Networking (summary)

- Transport: TCP/QUIC with Noise-like handshake (prototype: localhost TCP JSON lines).
- Gossip topics: `txs`, `blocks`, `votes`, `blobs`, `snapshots`.
- Peer scoring: latency, invalid message rate, stake-weighted preferential peering for validators.
- Sync: reverse header sync + state snapshot at epoch boundaries.

Details in `NETWORKING.md`.

---

## 10. JSON-RPC Surface (v0.1)

| Method | Description |
|--------|-------------|
| `aeth_chainId` | Chain id string |
| `aeth_blockNumber` | Latest height |
| `aeth_getBlockByNumber` | Block + txs |
| `aeth_getBlockByHash` | Block by hash |
| `aeth_getTransaction` | Tx + receipt |
| `aeth_getBalance` | Account balance |
| `aeth_getUtxo` | UTXO by outpoint |
| `aeth_getValidators` | Active set |
| `aeth_sendRawTransaction` | Submit tx |
| `aeth_estimateGas` | Gas estimate |
| `aeth_call` | Dry-run contract call |
| `aeth_getLogs` | Filter logs |
| `aeth_syncing` | Sync status |
| `aeth_protocolInfo` | Hybrid mode, params |

WebSocket: `aeth_subscribe` for `newHeads`, `logs`, `newPendingTransactions`.

---

## 11. Genesis

Genesis file fields:

```json
{
  "chain_id": "aether-devnet-1",
  "alloc": { "<address>": { "balance": "..." } },
  "validators": [ { "address": "...", "pubkey": "...", "power": "..." } ],
  "params": { "...": "..." },
  "hybrid": {
    "mode": "public",
    "allowlist": []
  },
  "timestamp": 0
}
```

Height 0 is the genesis header with empty txs; height 1 is the first proposed block.

---

## 12. Upgradeability

- **Parameter forks:** governance parameter changes (soft).
- **Consensus breaking:** coordinated binary upgrade at a flagged height (`upgrade_height`).
- **WASM precompiles:** versioned; contracts pin precompile major version.

---

## 13. Compliance & Ethics Notes

Aether’s hybrid design supports public commons and regulated consortium deployments. Operators in federated mode remain responsible for jurisdictional compliance (sanctions screening at the application/RPC layer, data retention, etc.). The protocol itself does not implement identity KYC; that is an application concern.

---

## 14. Reference Implementation Map

| Spec area | Crate / app |
|-----------|-------------|
| Types | `aether-types` |
| Crypto | `aether-crypto` |
| Consensus | `aether-consensus` |
| P2P | `aether-p2p` |
| VM | `aether-vm` |
| State | `aether-state` |
| RPC | `aether-rpc` |
| Node binary | `aether-node` |
| CLI | `aether-protocol-cli` |
| Explorer + wallet | `apps/explorer` |

---

## 15. Versioning

| Field | 1.2.0 value |
|-------|-------------|
| Spec SemVer | `1.3.0` |
| Package (`Cargo.toml`) | `1.3.0` |
| Header / wire `version` | `2` |
| ZK key schema | `2` (Poseidon circuits) |

This specification uses SemVer for the protocol document. The wire `version` field in headers is an integer monotonic with breaking changes. Devnet resets MAY wipe state between major upgrades.

IP / acquisition posture: see `IP.md`, `ACQUISITION.md`, `PATENT_PLEDGE.md`.
