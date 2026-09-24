//! Poseidon R1CS gadgets matching `field::poseidon_*` (same RC/MDS/S-box).

use crate::field::{
    hash_to_fr, mds, round_constant, FULL_ROUNDS, PARTIAL_ROUNDS, WIDTH,
};
use ark_bn254::Fr;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::SynthesisError;

fn sbox(x: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    let x2 = x.square()?;
    let x4 = x2.square()?;
    Ok(&x4 * x)
}

fn zero() -> FpVar<Fr> {
    FpVar::constant(Fr::from(0u64))
}

fn permute(mut state: [FpVar<Fr>; WIDTH]) -> Result<[FpVar<Fr>; WIDTH], SynthesisError> {
    let total = FULL_ROUNDS + PARTIAL_ROUNDS;
    for r in 0..total {
        for j in 0..WIDTH {
            state[j] += FpVar::constant(round_constant(r, j));
        }
        if r < FULL_ROUNDS / 2 || r >= FULL_ROUNDS / 2 + PARTIAL_ROUNDS {
            for j in 0..WIDTH {
                state[j] = sbox(&state[j])?;
            }
        } else {
            state[0] = sbox(&state[0])?;
        }
        let mut next = [zero(), zero(), zero()];
        for i in 0..WIDTH {
            let mut acc = zero();
            for j in 0..WIDTH {
                acc += FpVar::constant(mds(i, j)) * &state[j];
            }
            next[i] = acc;
        }
        state = next;
    }
    Ok(state)
}

pub fn hash2(left: &FpVar<Fr>, right: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    let state = [zero(), left.clone(), right.clone()];
    Ok(permute(state)?[0].clone())
}

pub fn hash3(a: &FpVar<Fr>, b: &FpVar<Fr>, c: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    let state = [a.clone(), b.clone(), c.clone()];
    Ok(permute(state)?[0].clone())
}

pub fn commit(
    value: &FpVar<Fr>,
    r: &FpVar<Fr>,
    pk: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    hash3(value, r, pk)
}

pub fn nullifier(sk: &FpVar<Fr>, cm: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    let domain = FpVar::constant(hash_to_fr("AETH/POSEIDON/NF", &[]));
    hash3(&domain, sk, cm)
}
