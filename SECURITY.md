# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| **1.3.x** (current) | Best-effort; diligence / pilot use; **not** for mainnet value |
| 1.2.x | Superseded; migrate to 1.3 |
| 0.x | Superseded |
| Mainnet candidates | TBD after ceremony + audit |

## Cryptographic posture (1.2)

- Ed25519 tx/consensus signatures
- BLAKE3 domain-separated hashing
- Groth16/BN254 shielded + rollup validity (`aether-zk`)
- **Poseidon** note CRH (native + R1CS); reference parameters
- Local circuit-specific trusted setup in `data/zk_keys.json` (schema v2)
- TCP multi-validator mesh (Noise/QUIC planned)

**Do not** deposit real assets until: MPC setup, audited Poseidon (or equivalent) parameters, Noise/QUIC networking, and external audit are complete.

## Reporting a vulnerability

Email security reports to the maintainers via GitHub Security Advisories on this repository (preferred) or open a **private** security advisory.

Please include:

1. Affected crate / binary / RPC method  
2. Proof of concept (non-destructive)  
3. Impact assessment (funds, finality, privacy)

We aim to acknowledge within 72 hours.

## Operator hardening

- Never enable `AETHER_ALLOW_NOOP_ROLLUP` in production  
- Restrict RPC; gate `aeth_loadSnapshot` / `aeth_createSnapshot` behind auth at the edge  
- Back up validator keys offline; use HSM/KMS when available  
- Separate node key from consensus key in production deployments  
- Treat peer scores as advisory until Noise transport lands  

## IP / disclosure

Open-source under Apache-2.0. See [`docs/IP.md`](docs/IP.md) and [`docs/ACQUISITION.md`](docs/ACQUISITION.md) for trademark and diligence boundaries — they do not weaken this security policy.
