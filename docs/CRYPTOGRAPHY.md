# Cryptography Specification

**Companion to:** `PROTOCOL.md` · **ZK details:** `ZK.md` · **Version:** 1.2.0

---

## 1. Hashing

### 1.1 Primary hash

- **Function:** BLAKE3, 256-bit output.
- **Encoding:** little-endian for integers; length-prefixed UTF-8 for strings (`u32` LE length + bytes).
- **Domain separation:** every consensus-critical hash begins with a unique ASCII tag (see PROTOCOL §3).

### 1.2 Tree hashing

Binary Merkle tree over ordered leaves for txs/receipts (BLAKE3). Shielded notes use a **Poseidon** field Merkle tree (depth 8) over BN254 Fr for SNARK friendliness.

```
H_leaf(x)  = blake3("AETH/MERKLE/LEAF" || x)
H_node(l,r)= blake3("AETH/MERKLE/NODE" || l || r)
```

Empty transparent tree root = `blake3("AETH/MERKLE/EMPTY")`.

### 1.3 Poseidon CRH (notes)

- Width-3 sponge, S-box `x⁵`, 4 full + 8 partial rounds  
- Tags: `AETH/POSEIDON/RC`, `AETH/POSEIDON/MDS`, `AETH/POSEIDON/NF`  
- Commitment: `Poseidon(value, rseed, pk)`  
- Nullifier: `Poseidon(H_NF, sk, cm)`  
- Parent: `Poseidon(0, left, right)`  

Same permutation is constrained inside Groth16 (`poseidon_gadget`). Reference parameters — swap for audited sets before mainnet value.

---

## 2. Keys & Addresses

```
sk ← random 32 bytes (CSPRNG)
pk ← Ed25519_public(sk)
address = blake3("AETH/ADDR/V1" || pk)[0..20]
```

---

## 3. Transaction Signing

Signing payload:

```
sighash = blake3("AETH/TX/V1" || encode(...))
signature = Ed25519_Sign(sk, sighash)
```

---

## 4. Block Sealing

```
header_hash = blake3("AETH/BLOCK/V1" || encode(header_without_signature))
signature = Ed25519_Sign(proposer_sk, header_hash)
```

---

## 5. Shielded Notes (implemented)

### 5.1 Algebraic commitment (R1CS)

```
cm = value + r * R_GEN + pk * PK_GEN   (over BN254 Fr)
nullifier = sk * SK_GEN + cm
```

Constants `R_GEN`, `PK_GEN`, `SK_GEN` are domain-separated `hash_to_fr` digests.

### 5.2 Groth16

- Curve: BN254
- Proving system: arkworks Groth16
- Circuits: Shield, Transfer (1-in/1-out + Merkle), Unshield
- Verification is mandatory on L1; stub proofs are rejected

### 5.3 Merkle (notes)

- Depth 8 (256 notes in reference tree; raise for mainnet)
- Parent: `left + right * X + left * right` with `X = hash_to_fr("AETH/ZK/MIMC")`

---

## 6. Rollup Proof Verification (implemented)

| Scheme ID | Verifier |
|-----------|----------|
| `0x01` | Groth16 (BN254) — state transition circuit |
| `0x02` | Plonk-lite — FS + G1 commitment opening |
| `0x03` | Fraud proof — challenge window + one-step certificate |
| `0xFF` | Devnet noop — **gated** by `AETHER_ALLOW_NOOP_ROLLUP=1` |

Transition statement (`0x01`):

```
post = prev + da*G1 + batch_index*G2 + witness_binding*G3
```

---

## 7. Randomness Beacon (optional)

At epoch end, XOR of proposers’ VRF outputs forms `epoch_randomness` for applications.
