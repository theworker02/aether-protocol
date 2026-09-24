# Governance Specification

**Companion to:** `PROTOCOL.md` · `ECONOMICS.md`

---

## 1. Scope

On-chain governance mutates **ChainParams** and may schedule binary upgrade heights. It does **not** rewrite history or un-finalize blocks.

---

## 2. Proposal lifecycle

```
Deposit → Voting → (Fail | Pass) → Timelock → Enact
```

| Phase | Duration (default) | Rules |
|-------|--------------------|-------|
| Deposit | until min deposit met or expiry | Min 100 AETH |
| Voting | 5 epochs (devnet: 50 blocks) | Bonded stake weighted |
| Timelock | 1 epoch | Cancelable only by new veto proposal |
| Enact | next block after timelock | Atomic param write |

### Vote options

`0 = No` · `1 = Yes` · `2 = Abstain` · `3 = NoWithVeto`

Pass if:

- Quorum: participating power ≥ 40% of bonded power at voting start  
- Threshold: `Yes / (Yes + No + NoWithVeto) > 50%`  
- Veto: if `NoWithVeto / participating > 33.4%` → fail  

---

## 3. Parameter registry

| Key | Type | Bounds | Notes |
|-----|------|--------|-------|
| `epoch_length` | u64 | [10, 10000] | |
| `min_validator_stake` | u128 | ≥ 1 AETH | |
| `max_validators` | u32 | [4, 500] | |
| `unbonding_period` | u64 | [1, 365] epochs | |
| `gas_limit` | u64 | [1e6, 1e9] | |
| `hybrid_mode` | enum | public/allowlist/mixed | |
| `allowlist_root` | Hash256 | — | |
| `base_fee_max_change` | u64 | denom 8 default | EIP-1559 elasticity |
| `upgrade_height` | u64 | > current+timelock | Binary coordination |
| `note_tree_depth` | u8 | [8, 32] | Future; v0.2 fixed 8 |

Unknown keys → proposal invalid.

---

## 4. Transactions

```text
GovernancePropose { title, description, param_key, param_value, deposit }
GovernanceVote { proposal_id, option }
GovernanceEnact { proposal_id }   // permissionless after timelock
```

Proposer recovers unused deposit if failed without veto spam rules; vetoed proposals burn 50% of deposit.

---

## 5. Emergency

No protocol-level pause key. Consortium deployments MAY filter txs via `TxFilter` adapters off-consensus. Social recovery of weak subjectivity checkpoints is off-chain.
