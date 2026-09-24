# Acquisition & Commercial Diligence Pack

**Product:** Aether Protocol (hybrid L1 reference + operator stack)  
**Version:** 1.2.0  
**Repository:** https://github.com/theworker02/aether-protocol  
**Primary contact:** GitHub `@theworker02` · funding via [thanks.dev](https://thanks.dev/u/gh/theworker02)

> Informational packaging for M&A, strategic investment, and white-label licensing. **Not** an offer to sell. Terms require a definitive agreement.

---

## 1. What you are buying / licensing

| Bundle | Includes | Typical buyer |
|--------|----------|---------------|
| **A — Open Core** | Apache-2.0 code + specs as-is | Anyone (already free) |
| **B — White-label** | Brand license, support SLA, private fork sync, genesis + ceremony ops | Consortium / fintech |
| **C — Asset purchase** | Assignment of copyrights (to the extent owned), trademarks, domain, private keys custody runbook, contributor agreements | Strategic acquirer |
| **D — Talent / support** | Maintainer transition, training, 6–12 month support | Same as C |

Open Core (A) requires **no** purchase. Acquisition usually means **B + C**, optionally **D**.

---

## 2. Technical asset inventory

| Layer | Location | Maturity (1.2) |
|-------|----------|----------------|
| Normative specs | `docs/*.md` | Dense; SemVer 1.2 |
| Types / wire | `aether-types` | Stable wire v2 |
| Crypto | `aether-crypto` | BLAKE3 + Ed25519 |
| ZK | `aether-zk` | Groth16 + Poseidon CRH + rollup schemes |
| Consensus | `aether-consensus` | AetherBFT engine + light headers |
| Networking | `aether-p2p` | Multi-validator TCP mesh |
| State | `aether-state` | Dual ledger, staking, gov, rollups |
| Persistence | `aether-store` | sled + epoch snapshots |
| RPC / node / CLI | `aether-rpc`, `aether-node`, `aether-cli` | Operable |
| Explorer | `apps/explorer` | Vite UI |
| Brand | `assets/brand` | Logo + wordmark |
| CI | `.github/workflows/ci.yml` | Build + test |

---

## 3. Suggested diligence data room

1. This repository (tag `v1.2.0`)  
2. [`IP.md`](IP.md) · [`PATENT_PLEDGE.md`](PATENT_PLEDGE.md) · [`NOTICE`](../NOTICE) · [`LICENSE`](../LICENSE)  
3. [`SECURITY.md`](../SECURITY.md) · [`THREAT_MODEL.md`](THREAT_MODEL.md)  
4. [`INVARIANTS.md`](INVARIANTS.md) + CI invariant hooks  
5. Dependency SBOM: `cargo tree -d` / `cargo deny` (recommended in buyer CI)  
6. Deployment runbooks: genesis profiles, snapshot RPC, P2P flags  
7. Key ceremony status (local setup today → MPC before mainnet value)  
8. Contributor list (`git shortlog -sn`)  

---

## 4. Commercial framing (non-binding)

Indicative ranges for negotiation — **not** a quote:

| Scenario | Order of magnitude |
|----------|--------------------|
| White-label annual (B) | Mid five-figures to low six-figures USD / year, scope-dependent |
| Full assignment (C) | Negotiation on exclusivity, support, and IP completeness |
| Earn-out | Tied to mainnet launch / audit clearance / revenue |

Open-source code remains Apache-2.0; acquisition value concentrates in **brand, operators, private ops IP, and team continuity**, not in locking down public code.

---

## 5. Known gaps (honest)

- Not audited for mainnet funds  
- Groth16 setup is local (non-MPC)  
- Poseidon parameters are reference (swap for audited set)  
- P2P is TCP JSON mesh (Noise/QUIC libp2p is next)  
- Storage is sled (RocksDB / production KV optional)  

These are priced into any serious acquisition as **post-close roadmap**, not surprises.

---

## 6. Transfer checklist (closing)

- [ ] Tag + release `v1.2.0` artifacts  
- [ ] Assign / license trademarks + domains  
- [ ] Escrow validator / ceremony procedures (never mainnet secrets in git)  
- [ ] Update NOTICE / copyright headers if assignment occurs  
- [ ] Transfer GitHub org / package namespaces  
- [ ] Novate support contracts; announce maintainer transition  
- [ ] Buyer rebrands forks or obtains trademark license  

---

## 7. Contact

Open a GitHub Discussion or email via the security advisory channel for commercial inquiries. Prefer NDA before sharing private diligence materials beyond this public pack.
