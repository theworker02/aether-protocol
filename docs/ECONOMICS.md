# Economics & Tokenomics

**Companion to:** `PROTOCOL.md`  
**Version:** 1.4.0  
**Unit:** 1 AETH = 1_000_000_000 wei (`10^9`).

---

## 1. Genesis Supply

Devnet default: faucet allocation from genesis `alloc` (commonly **1_000_000 AETH** to the bring-up validator).

Mainnet suggestion (non-binding): fixed genesis + optional low inflation for security budget via `inflation_per_block` (default `0`).

Supply invariant **I1** (see `INVARIANTS.md`):

```
liquid + self_bonded + delegated_shares + unbonding + utxo + shielded
  + fee_burned + gov_deposits  ==  genesis_supply
```

---

## 2. Fee Market

EIP-1559-style:

```
excess = gas_used - gas_target
base_fee' = base_fee * (1 + 1/8 * excess/gas_target)
```

- `gas_target = gas_limit / 2`
- Base fee **burned** (counted in `fee_burned`)
- Priority fee → proposer

Intrinsic gas: `21_000` + kind surcharge (bond/delegate ~40–55k, rollup register ~50k, shield path higher).

---

## 3. Block Rewards

Per committed block:

```
reward = base_reward_per_block + sum(priority_fees)
```

`base_reward_per_block` defaults to `0` on reference (fee-only).

Suggested split when inflation enabled:

- 85% proposer  
- 15% quorum voters proportional to power  

---

## 4. Staking Economics (1.2)

| Param | Default |
|-------|---------|
| Min self-bond | 10_000 AETH |
| Max commission | 100% (10000 bps) |
| Unbonding | 21 epochs |
| Max validators | 100 |
| Jail period | 2 epochs |
| Share rate | 1:1 wei (reference; upgradeable to exchange-rate shares) |

### Tx kinds

| Kind | Effect |
|------|--------|
| `StakeBond` | Self-bond → validator power + shares |
| `StakeUnbond` | Self-bond → unbonding queue |
| `StakeDelegate` | Liquid → shares on a bonded validator |
| `StakeUndelegate` | Shares → unbonding queue |
| `StakeRedelegate` | Move shares src→dst (instant in reference) |
| `StakeWithdraw` | Claim matured unbonding → liquid |

Hybrid modes still gate **who may bond** (`allowlist` / `mixed`).

---

## 5. Slashing Schedule

| Offense | Slash fraction | Jail |
|---------|----------------|------|
| Downtime | 0.01% | yes |
| Double-sign | 5% | permanent tombstone |
| Light-client attack | 10% | permanent |

50% of slash burned; 50% to community pool (pool accounting reserved for v1.3).

---

## 6. Governance Deposits

- Min deposit: 100 AETH (reference)
- Voting period: ~5 epochs (devnet shortened)
- Pass: >50% yes of participating power; quorum 40% bonded
- Timelock: 1 epoch after pass

Deposits locked in I1 until reject/enact.

---

## 7. Rollup economics

- Register fee: gas only (reference)
- Commit: gas + optional DA blob gossip cost
- Fraud challenge bond: reserved param `fraud_bond` (default 0 on reference)

---

## 9. Brokerless market fees

Market txs pay gas only in the reference (no protocol taker fee). Optional pool `fee_bps` stays inside the AMM curve. Locked AETH in orders/AMM/escrow is counted in I1 via `market_locked_native`.

See `MARKETS.md`.

---

## 10. Acquisition note

Token design here is **protocol mechanics**, not a securities offering. Commercial packaging lives in `ACQUISITION.md` / `IP.md`.
