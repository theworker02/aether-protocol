# Rollups & Modular Settlement

**Companion to:** `PROTOCOL.md` · **ZK:** `ZK.md`

---

## 1. Role of L1

Aether L1 provides:

1. Canonical ordering of rollup batches.
2. Data availability commitments (`da_hash`).
3. Verification hooks for fraud/validity proofs.
4. Bridge message passing (application-level).

---

## 2. Registration

```text
RollupRegister {
  rollup_id, sequencer, scheme,
  verifying_key,      // required for 0x01
  challenge_period,   // blocks; used by 0x03
}
```

| Scheme | VK required | Commit proof | Finality |
|--------|-------------|--------------|----------|
| `0x01` Groth16 | yes | Groth16 proof | immediate |
| `0x02` Plonk-lite | no | PlonkLiteProof JSON | immediate |
| `0x03` Fraud | no | empty → pending | after window / unless fraud |
| `0xFF` Noop | no | any | gated env only |

---

## 3. Batch Commit

```text
RollupCommit {
  rollup_id, batch_index,
  prev_state_root, post_state_root, da_hash,
  proof,
}
```

Validity rules:

1. Registered rollup; sequencer signature (tx auth).
2. `batch_index == last + 1` (first batch is `1`).
3. `prev_state_root` matches stored (after first).
4. Scheme verifier accepts `proof`.

### Optimistic path (`0x03`)

- Commit with empty proof → `PendingBatch`.
- `RollupFraud` with certificate during window → mark challenged (batch discarded).
- `RollupFinalize` after `submitted_height + challenge_period` if unchallenged → apply state root.

Fraud certificate:

```text
FraudCertificate {
  step, pre_state, post_state, claim_post, step_preimage
}
```

Honest step hash `H(pre||step||preimage)` must equal `post_state` and differ from `claim_post`.

---

## 4. Hybrid DA Modes

| Mode | Description |
|------|-------------|
| Hash-only | L1 stores `da_hash` (reference default) |
| Inline | Future: blob bytes in tx |
| External DA | Future: Celestia/EigenDA attestation |

---

## 5. Security

- Prefer `0x01` or `0x02` for validity rollups.
- `0x03` requires honest watchers during the challenge window.
- `0xFF` must never be enabled on networks securing value.
