# ZK & Production Verifiers

## Shielded pool (Groth16 / BN254)

Circuits in `aether-zk`:

| Circuit | Public inputs | Statement |
|---------|---------------|-----------|
| **Shield** | `cm`, `value` | `cm = Poseidon(value, r, pk)` |
| **Transfer** | `root`, `nullifier`, `cm_out`, `fee` | Poseidon Merkle membership of `cm_in`, `value_in = value_out + fee`, nullifier binding, output commitment |
| **Unshield** | `root`, `nullifier`, `value` | Spend note + reveal value to transparent account |

### Poseidon CRH

- Width-3 sponge over BN254 Fr, S-box `x⁵`, 4 full + 8 partial rounds
- Round constants / MDS derived from domain-separated BLAKE3 tags (`AETH/POSEIDON/RC`, `AETH/POSEIDON/MDS`)
- Note commitment: `Poseidon(value, rseed, pk)`
- Nullifier: `Poseidon(H("AETH/POSEIDON/NF"), sk, cm)`
- Merkle parent: `Poseidon(0, left, right)` (2-to-1 compression)
- Same permutation constrained inside Groth16 via `poseidon_gadget`

Note Merkle tree: depth 8, Poseidon parent hash.

Keys: `data/zk_keys.json` (schema v2; regenerated automatically when schema mismatches).

### CLI

```bash
aether shield --secret <hex> --value 1000000000 --note-out note.json
```

## Rollup schemes

| ID | Name | Behavior |
|----|------|----------|
| `0x01` | Groth16 | Immediate finality if proof verifies against registered VK |
| `0x02` | Plonk-lite | Fiat–Shamir + commitment opening check |
| `0x03` | Fraud / optimistic | Empty proof → pending; challenge with fraud cert; finalize after window |
| `0xFF` | Noop | **Disabled** unless `AETHER_ALLOW_NOOP_ROLLUP=1` |

### CLI

```bash
aether rollup-register --secret <hex> --scheme 1
aether rollup-commit --secret <hex> --rollup-id 0x... --batch-index 1 \
  --prev 0x00.. --da 0x00.. --scheme 1
```

## Security notes

- Groth16 requires a trusted setup; keys are generated locally for the reference node.
- Poseidon parameters here are **reference / domain-separated** — production should swap in an audited parameter set without changing public-input layout.
- Plonk-lite is a validity-shaped verifier API; replace with full TurboPlonk/Halo2 without changing public-input layout.
