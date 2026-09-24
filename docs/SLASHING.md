# Slashing & Evidence

**Companion to:** `PROTOCOL.md` · `ECONOMICS.md` · **Version:** 1.3.0

---

## 1. Offenses

| Evidence tx | Threshold | Slash bps | Jail |
|-------------|-----------|-----------|------|
| `EvidenceDoubleSign` | Two conflicting votes (same height/round/type, different `block_hash`) | 500 (5%) | Permanent tombstone |
| `EvidenceDowntime` | `missed ≥ 50` blocks in reporting window | 1 (0.01%) | 2 epochs |

Slash proceeds: **50% burned**, **50% community pool**.

---

## 2. Double-sign verification

1. Deserialize `vote_a` / `vote_b` as consensus `Vote` JSON blobs.  
2. Require same `validator`, `height`, `round`, `vote_type`.  
3. Require different `block_hash`.  
4. Evidence hash = `blake3(vote_a || vote_b)` — replay-protected in `evidence_seen`.  

Signature crypto on the embedded votes is validated by consensus helpers when the votes were produced; evidence submission trusts the encoded payload shape for the reference node.

---

## 3. Tombstones

`tombstoned = true` forever after double-sign. Bonding / re-entry rejected.

---

## 4. Community pool

- Accrues from slash halves + unassigned tips (if no proposer tip target).  
- `CommunityPoolSpend` — bonded validators may spend ≤ **1%** of pool per tx.  
- Counted in supply invariant I1.

---

## 5. RPC

- `aeth_getSlashLog`
- `aeth_getCommunityPool`
