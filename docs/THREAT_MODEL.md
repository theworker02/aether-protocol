# Threat Model

**Companion to:** `PROTOCOL.md`

---

## 1. Assets to Protect

1. Safety of finalized ledger (no conflicting finality).
2. Availability / liveness under partial synchrony.
3. User funds (transparent, UTXO, shielded).
4. Validator stake integrity.
5. Rollup settlement integrity per registered scheme.
6. Privacy of shielded note payloads (production proving system).

---

## 2. Adversaries

| Adversary | Capabilities |
|-----------|--------------|
| Byzantine validators `< 1/3` | Arbitrary vote/proposal behavior |
| Network adversary | Delay/reorder until GST; eclipse subset of nodes |
| Rational searchers | MEV extraction, tx reordering within block |
| Malicious rollup sequencer | Withhold data, post invalid state (scheme-dependent) |
| Cryptanalytic | Break hash/sig/zk (out of scope if primitives hold) |

---

## 3. In-Scope Attacks & Mitigations

| Attack | Mitigation |
|--------|------------|
| Double-spend | UTXO spent-set + account nonces; BFT finality |
| Long-range / weak subjectivity | Checkpointing; social genesis; unbonding period |
| Equivocation | Evidence txs + slashing |
| Eclipse | Diverse peers; validator preferential mesh |
| Fee griefing | 1559 base fee burn; mempool RBF rules |
| Shielded inflation | SNARK balance constraint (production) |
| Rollup invalid state | Fraud/validity verification; noop scheme only for dev |
| Governance capture | Quorum + timelock + deposit |
| Hybrid allowlist rug | Off-chain legal/ops controls; public auditability of params |

---

## 4. Out of Scope (v0.1)

- Side-channel attacks on signing HSMs
- Compromised user endpoints / malware
- Nation-state BGP hijacks beyond eclipse assumptions
- Quantum adversaries (migrate signatures in a future version)

---

## 5. Prototype Limitations

The reference implementation:

- Uses a **local Groth16 trusted setup** (not a multi-party ceremony).
- Uses Poseidon CRH inside circuits (reference parameters; see `ZK.md` for audited-swap guidance).
- Must not secure real value until ceremony + hash upgrade + audit.

Noop rollup scheme `0xFF` is disabled unless `AETHER_ALLOW_NOOP_ROLLUP=1`.
