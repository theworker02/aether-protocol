# Intellectual Property

**Protocol:** Aether Protocol  
**Release:** 1.2.0  
**License:** Apache License 2.0 (see [`LICENSE`](../LICENSE) and [`NOTICE`](../NOTICE))  
**Copyright:** Copyright 2024–2026 Aether Protocol Contributors / theworker02

> This document describes IP posture for diligence and acquisition. It is **not** legal advice. Engage counsel for definitive opinions in your jurisdiction.

---

## 1. Software copyright

| Asset | Ownership / license |
|-------|---------------------|
| Source code in this repository | Copyright held by contributors; licensed to the public under **Apache-2.0** |
| Specs under `docs/` | Same license unless a file header says otherwise |
| Brand assets under `assets/brand/` | © Contributors; Apache-2.0; trademark rights reserved (see §3) |
| Third-party crates (arkworks, sled, axum, …) | Their respective licenses (MIT/Apache-2.0/etc.); see Cargo.lock |

Apache-2.0 grants a **patent license** from contributors for contributions (see §3 of the LICENSE). A complementary [patent pledge](PATENT_PLEDGE.md) clarifies defensive intent.

---

## 2. What is *not* claimed as exclusive IP

- Cryptographic constructions that are public domain / academic (Groth16, Poseidon, Tendermint-style BFT patterns).
- Wire formats and protocol rules once published under Apache-2.0 — implementers may reimplement interoperably.
- Generic “hybrid L1” product category.

---

## 3. Trademarks

- **“Aether Protocol”**, the wordmark, and the logo in `assets/brand/` are **unregistered trademarks** of the project maintainers pending formal filing.
- Forks / white-labels **should** rebrand unless a written trademark license is granted (see [`ACQUISITION.md`](ACQUISITION.md)).
- Apache-2.0 does **not** grant trademark rights.

---

## 4. Trade secrets

There are **no** intentional trade secrets in the public repository. Private forks, deployment keys, MPC transcripts, and customer allowlists are out of scope and remain confidential to operators.

---

## 5. Contributions

Contributions are accepted under the [Developer Certificate of Origin](https://developercertificate.org/) (implied by PR) and Apache-2.0. Corporate contributors should confirm they have authority to grant the license.

---

## 6. Diligence checklist (IP)

- [ ] Confirm LICENSE + NOTICE present on all distributions  
- [ ] Scan for copyleft contamination (this workspace targets Apache-2.0 / MIT compatible deps)  
- [ ] Confirm no leaked customer keys / PII in git history  
- [ ] Confirm brand kit attribution if redistributing logos  
- [ ] Map any private (non-repo) IP the seller claims separately  

See also [`ACQUISITION.md`](ACQUISITION.md).
