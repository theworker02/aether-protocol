# Aether Protocol — Implementation Notes

## Crate graph

```
aether-protocol-cli ──┐
             ├── aether-types
aether-node ─┤
             ├── aether-crypto
             ├── aether-consensus
             ├── aether-p2p
             ├── aether-vm
             ├── aether-state
             └── aether-rpc
```

## Devnet behavior

1. Node generates (or loads) an Ed25519 validator key.
2. Genesis allocates faucet balance to the validator and seats it with voting power.
3. A timer produces blocks every `--block-time-ms` (default 1s).
4. Mempool txs are applied in tip-priority order; receipts indexed by hash.
5. JSON-RPC on `--rpc` serves explorer and CLI.

## Hybrid flags

| Flag | Effect |
|------|--------|
| `public` | Anyone may `StakeBond` (prototype) |
| `allowlist` | Only allowlisted addresses may bond |
| `mixed` | Allowlist populated at genesis for core set |

## Prototype gaps vs spec

- Solo proposer path is default (multi-validator BFT messaging is library-ready).
- Note tree depth 8 (256 notes) — raise for production.
- Poseidon CRH for note commitments / Merkle (native + R1CS); swap parameters without changing tx layout.
- In-memory state (no RocksDB yet).
- P2P is an in-process broadcast hub.

## Implemented (v0.2)

- Groth16 shielded shield / transfer / unshield with mandatory verify.
- Rollup schemes `0x01` (Groth16), `0x02` (Plonk-lite), `0x03` (fraud window).
- Noop `0xFF` gated behind `AETHER_ALLOW_NOOP_ROLLUP=1`.
- ZK key persistence at `data/zk_keys.json`.

See `docs/ZK.md`.