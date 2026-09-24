# AetherBFT Consensus Specification

**Companion to:** `PROTOCOL.md` · **Version:** 1.2.0  
**Inspiration:** Tendermint safety + HotStuff pacing, with hybrid validator admission.

Voting power in 1.2 = **self-bonded + delegated shares** on each validator. Unbonding and undelegation reduce power after the entry is created (immediate power drop; funds unlock after `unbonding_period` epochs).

Gossip of `Vote` / `Commit` / `Block` frames on the TCP mesh is required for multi-validator operation; solo path remains `solo_commit` for single-node bring-up.

---

## 1. Model Assumptions

- **Partial synchrony:** after GST (Global Stabilization Time), message delay ≤ Δ.
- **Stake-weighted Byzantine fault tolerance:** safety if Byzantine voting power `< 1/3` of the active set.
- **Authenticated channels:** Ed25519 identities; equivocation is attributable.
- **Crash-recovery:** validators may restart; persistent vote logs prevent equivocation on honest restart.

---

## 2. Epochs & Validator Set

### 2.1 Epoch boundary

At height `h` where `h % epoch_length == 0` (and `h > 0`), compute the next epoch’s active set from the **staking state at the end of block `h`**:

1. Collect candidates with `bonded ≥ min_validator_stake`.
2. If `hybrid_committee == Allowlist`, intersect with allowlist.
3. If `hybrid_committee == Mixed`, partition into **core** (allowlisted, may propose) and **peripheral** (may vote on attestations only—peripheral votes counted toward a secondary quorum used for light-client bonuses, not block finality in v0.1).
4. Sort by bonded stake descending; take top `max_validators`.
5. Assign voting power proportional to bonded stake (integer, floored; dust to highest).
6. Commit `validator_set_root` into the next epoch’s headers.

### 2.2 Proposer selection

For height `h`, round `r`:

```
seed = blake3("AETH/PROPOSER" || epoch || h || r || validator_set_root)
index = weighted_sample(seed, powers)
proposer = validators[index]
```

In Mixed mode, only **core** validators are sampled as proposers.

---

## 3. Messages

```text
Proposal {
  height, round, block_hash, block?, pol_round,  // proof-of-lock round
  proposer, signature
}

Vote {
  type: Prevote | Precommit,
  height, round, block_hash,  // nil hash allowed for Prevote/Precommit nil
  validator, signature
}

Commit {
  height, round, block_hash,
  signatures: Vec<Vote>,     // ≥ 2/3+ precommits
}
```

Nil hash = 32 zero bytes.

---

## 4. State Machine (per height)

Variables (validator `v`):

- `height`, `round`, `step` ∈ {NewRound, Propose, Prevote, Precommit, Commit}
- `lockedValue`, `lockedRound`
- `validValue`, `validRound`
- `decision`

### 4.1 NewRound(h, r)

1. Set `step ← NewRound`.
2. If `v` is proposer: build block from mempool (respect gas limit, priority fees); broadcast `Proposal`.
3. Else: start propose timeout `timeoutPropose(r)`.

### 4.2 On Proposal

Accept if:

- Signature valid and proposer correct for `(h,r)`.
- If `pol_round ≥ 0`, accompanying POL prevotes ≥ 2/3 for `block_hash` at `pol_round`.
- Block executes validly on local state (full nodes); light proposers may gossip without full exec but committers MUST exec.

Then: `step ← Prevote`; broadcast Prevote for `block_hash` **unless** locked on a different value with `lockedRound > pol_round`.

### 4.3 Prevote quorum

Upon `+2/3` Prevotes for `id(v)` at `(h,r)`:

- Set `lockedValue ← v`, `lockedRound ← r`, `validValue ← v`, `validRound ← r`.
- Broadcast Precommit for `id(v)`.

Upon `+2/3` Prevotes for nil: Precommit nil.

Timeout Prevote → Precommit nil.

### 4.4 Precommit quorum

Upon `+2/3` Precommits for `id(v)`:

- `decision ← v`; persist Commit certificate; execute if not already; advance to `h+1`, `round ← 0`.

Upon `+2/3` Precommits for nil or timeout: `round ← r+1`; goto NewRound.

---

## 5. Timeouts

Exponential backoff:

```
timeoutPropose(r)   = T0_propose   + r * Ti
timeoutPrevote(r)   = T0_prevote   + r * Ti
timeoutPrecommit(r) = T0_precommit + r * Ti
```

Defaults (devnet): `T0_* = 500ms`, `Ti = 250ms`.

---

## 6. Safety & Liveness Theorems (informal)

**Safety:** Two honest validators never decide different values at the same height. Proof sketch: conflicting commits require two `+2/3` Precommit sets for different hashes ⇒ intersection of voters exceeds `1/3` ⇒ some Byzantine voter double-signed ⇒ slashable, contradicting honest majority assumption.

**Liveness:** After GST, if `< 1/3` Byzantine, some round will elect a correct proposer whose proposal reaches quorum before timeouts fire, progressing the height.

**Hybrid admission does not weaken safety** because voting power weights and quorum thresholds are unchanged; only the eligible identity set is filtered.

---

## 7. Empty blocks

If mempool is empty, proposers SHOULD still propose empty blocks to advance time-dependent logic (unbonding, epoch). Empty blocks cost minimal gas accounting (header-only rewards).

---

## 8. Evidence gossip

Evidence is packaged as transactions of a privileged kind included by proposers. Invalid evidence is ignored; valid evidence triggers immediate jail in the next block’s staking transition.
