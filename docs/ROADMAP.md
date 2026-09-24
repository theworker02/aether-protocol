# Roadmap

## v1.3.0 — Protocol density (**current**)

- [x] Evidence txs + slashing / jail / tombstone
- [x] Community pool + capped spends
- [x] IBC-lite bridge channels + packets
- [x] Tip-to-proposer fee market split
- [x] AetherOps ISA expansion + `ContractCall`
- [x] Prometheus `/metrics`
- [x] Peer ban hooks on invalid score
- [x] Docs: BRIDGES, SLASHING, thickened VM

## Earlier (shipped)

- [x] v1.2 — Poseidon, P2P mesh, snapshots, liquid staking, IP/acquisition pack
- [x] v0.2 — sled, governance, light headers, invariants
- [x] v0.1 — hybrid L1 reference + ZK + rollups + explorer

## v1.3.x — Hardened networking (next)

- [ ] Noise XX + QUIC (libp2p)
- [ ] RocksDB / production KV backend
- [ ] Stake-weighted dialing + rate limits

## v1.4 — Ceremony & audit track

- [ ] MPC Groth16 (or Halo2) ceremony
- [ ] Audited Poseidon parameter swap
- [ ] Bridge light-client proofs (replace BLAKE3 stub)
- [ ] External security audit + bug bounty

## v2.0 — Mainnet-ready criteria

- [ ] Wasmtime contracts behind documented ABI
- [ ] Light client product + weak subjectivity checkpoints
- [ ] External DA adapters (Celestia / EigenDA hashes)
- [ ] Supply invariant formally checked in CI
- [ ] Documented upgrade / fork process
- [ ] SLOs for finality under documented validator sets
- [ ] Runbooks for incident response (see SECURITY.md)
