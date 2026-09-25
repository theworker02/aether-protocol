# Protocol Invariants

**Companion to:** `PROTOCOL.md` · **Version:** 1.2.0  
These invariants MUST hold after every successful block commit. Violations are consensus-invalid.

---

## I1 — Supply conservation

```
transparent_liquid
  + self_bonded
  + delegated_shares
  + unbonding_locked
  + utxo_sum
  + shielded_value
  + fee_burned_cumulative
  + gov_deposits_locked
  + community_pool
  + market_locked_native
  == genesis_supply
```

Where `fee_burned_cumulative` tracks base-fee burns (and shielded fees). Reference node exposes `verify_supply_invariant()` / `aeth_verifySupply` and refuses to commit if broken.

---

## I2 — Nonce monotonicity

For each account address `A`, successful `AccountOrigin` txs at height `h` apply with `nonce == A.nonce` and leave `A.nonce' = A.nonce + 1`. Failed txs do not bump nonce (receipt status false still consumes intrinsic gas fee if authentication succeeded — see fee rules).

**Reference:** failed application after auth still returns a failed receipt; nonce bumps only on success (Ethereum-unlike; documented for adapters).

---

## I3 — UTXO single spend

Each `OutPoint` appears in at most one successful spend in the canonical chain. Double-spend attempts are invalid txs.

---

## I4 — Nullifier uniqueness

Each nullifier is inserted at most once. Reuse ⇒ invalid shielded tx.

---

## I5 — Finality prefix

If commit certificate `C` finalizes block hash `H` at height `h`, no conflicting certificate at `h` is ever accepted by honest nodes. Light clients rely on I5 + WSP.

---

## I6 — State root binding

`header.state_root` equals the composite root of sub-stores after applying the block’s txs in order. Mismatch ⇒ block invalid.

---

## I7 — Validator set epoch freeze

Within an epoch, `validator_set_root` in headers is constant. Changes apply at epoch boundaries only.

---

## I8 — Rollup batch sequencing

For each `rollup_id`, successful commits form a contiguous `batch_index` sequence starting at 1. Gaps are invalid.

---

## I9 — Hybrid allowlist

In `allowlist` / `mixed` modes, proposers (and bonds, per mode) intersect the allowlist Merkle set committed in params.

---

## Testing

`cargo test -p aether-state` includes invariant checks after simulated blocks. CI MUST fail on I1–I4 regressions.
