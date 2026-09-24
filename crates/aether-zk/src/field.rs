//! Poseidon-style sponge over BN254 Fr (native + R1CS-matching).
//!
//! Parameters are domain-separated constants derived from BLAKE3 tags so the
//! same permutation is used outside circuits and inside Groth16 constraints.
//! This replaces the earlier MiMC-like parent hash for notes (docs/ZK.md).

use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, PrimeField};
use aether_crypto::tagged_hash;
use aether_types::Hash256;

pub fn fr_to_bytes(fr: &Fr) -> [u8; 32] {
    let bytes = fr.into_bigint().to_bytes_le();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

pub fn fr_from_bytes(bytes: &[u8]) -> Fr {
    let mut buf = [0u8; 32];
    let n = bytes.len().min(32);
    buf[..n].copy_from_slice(&bytes[..n]);
    Fr::from_le_bytes_mod_order(&buf)
}

pub fn hash_to_fr(tag: &str, data: &[u8]) -> Fr {
    let h = tagged_hash(tag, data);
    fr_from_bytes(&h)
}

pub fn hash256_to_fr(h: &Hash256) -> Fr {
    fr_from_bytes(h)
}

pub(crate) const FULL_ROUNDS: usize = 4;
pub(crate) const PARTIAL_ROUNDS: usize = 8;
pub(crate) const WIDTH: usize = 3; // rate 2 + capacity 1

pub(crate) fn round_constant(i: usize, j: usize) -> Fr {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(i as u64).to_le_bytes());
    buf.extend_from_slice(&(j as u64).to_le_bytes());
    hash_to_fr("AETH/POSEIDON/RC", &buf)
}

pub(crate) fn mds(i: usize, j: usize) -> Fr {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(i as u64).to_le_bytes());
    buf.extend_from_slice(&(j as u64).to_le_bytes());
    // Ensure invertible-ish diagonal dominance for toy MDS
    let mut v = hash_to_fr("AETH/POSEIDON/MDS", &buf);
    if i == j {
        v += Fr::from(2u64);
    }
    v
}

fn sbox(x: Fr) -> Fr {
    // x^5
    let x2 = x.square();
    let x4 = x2.square();
    x4 * x
}

fn apply_mds(state: &[Fr; WIDTH]) -> [Fr; WIDTH] {
    let mut out = [Fr::from(0u64); WIDTH];
    for i in 0..WIDTH {
        let mut acc = Fr::from(0u64);
        for j in 0..WIDTH {
            acc += mds(i, j) * state[j];
        }
        out[i] = acc;
    }
    out
}

/// Poseidon permutation on width-3 state.
pub fn poseidon_permute(mut state: [Fr; WIDTH]) -> [Fr; WIDTH] {
    let total = FULL_ROUNDS + PARTIAL_ROUNDS;
    for r in 0..total {
        for j in 0..WIDTH {
            state[j] += round_constant(r, j);
        }
        if r < FULL_ROUNDS / 2 || r >= FULL_ROUNDS / 2 + PARTIAL_ROUNDS {
            for j in 0..WIDTH {
                state[j] = sbox(state[j]);
            }
        } else {
            state[0] = sbox(state[0]);
        }
        state = apply_mds(&state);
    }
    state
}

/// 2-to-1 Poseidon compression (Merkle parent / commitment helper).
pub fn poseidon_hash2(left: &Fr, right: &Fr) -> Fr {
    let state = [Fr::from(0u64), *left, *right];
    poseidon_permute(state)[0]
}

/// 3-to-1 used for note commitment: H(value, r, pk)
pub fn poseidon_hash3(a: &Fr, b: &Fr, c: &Fr) -> Fr {
    let state = [*a, *b, *c];
    poseidon_permute(state)[0]
}

/// Note commitment via Poseidon.
pub fn poseidon_commit(value: u64, r: &Fr, pk: &Fr) -> Fr {
    poseidon_hash3(&Fr::from(value), r, pk)
}

pub fn poseidon_nullifier(sk: &Fr, cm: &Fr) -> Fr {
    let domain = hash_to_fr("AETH/POSEIDON/NF", &[]);
    poseidon_hash3(&domain, sk, cm)
}

/// Alias kept for Merkle module.
pub fn poseidon_parent(left: &Fr, right: &Fr) -> Fr {
    poseidon_hash2(left, right)
}

// --- Back-compat names used across zk crate ---

pub fn algebraic_commit(value: u64, r: &Fr, pk: &Fr) -> Fr {
    poseidon_commit(value, r, pk)
}

pub fn algebraic_nullifier(sk: &Fr, cm: &Fr) -> Fr {
    poseidon_nullifier(sk, cm)
}

pub fn mimc_parent(left: &Fr, right: &Fr) -> Fr {
    poseidon_parent(left, right)
}
