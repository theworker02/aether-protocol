# Light Clients & Weak Subjectivity

**Companion to:** `PROTOCOL.md`  
**Status:** Normative (v0.2)

---

## 1. Goals

Aether light clients verify **finality** and **account/UTXO inclusion** without executing the full state transition function. They trust:

1. A recent **trusted header** (weak subjectivity checkpoint), and  
2. The assumption that `< 1/3` of the bonded voting power at that checkpoint was Byzantine.

---

## 2. Light header

```text
LightHeader {
  height: u64,
  epoch: u64,
  hash: Hash256,              // full header hash
  prev_hash: Hash256,
  state_root: Hash256,
  validators_hash: Hash256,   // = validator_set_root
  next_validators_hash: Hash256,
  time_unix_ms: u64,
  commit: CommitCertificate,  // ≥ 2/3 precommits
}
```

Verification of a **sequential** header `H_{n+1}` given trusted `H_n`:

1. `H_{n+1}.prev_hash == H_n.hash`
2. `H_{n+1}.height == H_n.height + 1`
3. Commit signatures verify against `H_n.next_validators_hash` (or current if epoch unchanged)
4. Voting power of commit ≥ `2/3 + 1` of that set
5. Time monotonic within skew bounds (`|Δt| ≤ MAX_CLOCK_SKEW`)

---

## 3. Skipping / bisection

For large gaps, light clients use **bisection sync**:

1. Request mid-point header between trusted and target.  
2. Verify commit against the validator set committed at the last epoch boundary before the mid-point.  
3. Recurse until sequential.

Epoch boundaries MUST publish `next_validators_hash` so light clients can track set changes without full blocks.

---

## 4. Inclusion proofs

| Claim | Proof |
|-------|-------|
| Account balance | Merkle (or JSON-commitment) path under `accounts_root` component of `state_root` |
| UTXO exists | Path under `utxo_root` |
| Note commitment | Path under notes Merkle (MiMC tree) |
| Tx in block | Path under `tx_root` |
| Receipt | Path under `receipts_root` |

Composite `state_root` binding is defined in PROTOCOL §4.1 — light clients recompute the outer BLAKE3 over sub-roots.

---

## 5. Weak subjectivity period

```
WSP = unbonding_period + safety_margin_epochs
```

Default: `unbonding_period + 2` epochs. Social consensus / genesis checkpoints MUST be refreshed at least once per WSP for long-offline light clients.

---

## 6. IBC-shaped packet commitments (preview)

Aether reserves system addresses for cross-chain packets:

```
0x00…20  PACKET_COMMITMENTS
0x00…21  PACKET_ACKS
0x00…22  PACKET_RECEIPTS
```

Packet commitment = `blake3("AETH/PACKET/V1" || src || dst || sequence || data_hash)`. Full IBC semantics are out of band for v0.2 execution but light-client verifiable via storage proofs.
