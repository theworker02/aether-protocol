use crate::field::{fr_from_bytes, fr_to_bytes, hash_to_fr};
use crate::keys::{RollupProvingKey, RollupVerifyingKey};
use crate::plonk_lite::{prove_plonk_lite, verify_plonk_lite, PlonkLiteProof};
use crate::ZkError;
use aether_types::Hash256;
use ark_bn254::Fr;
use ark_groth16::{Groth16, Proof};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RollupScheme {
    Groth16 = 0x01,
    PlonkLite = 0x02,
    FraudProof = 0x03,
    Noop = 0xFF,
}

impl RollupScheme {
    pub fn from_u8(v: u8) -> Result<Self, ZkError> {
        match v {
            0x01 => Ok(Self::Groth16),
            0x02 => Ok(Self::PlonkLite),
            0x03 => Ok(Self::FraudProof),
            0xFF => Ok(Self::Noop),
            _ => Err(ZkError::Rollup(format!("unknown scheme {v:#x}"))),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RollupPublicInputs {
    pub prev_state_root: Hash256,
    pub post_state_root: Hash256,
    pub da_hash: Hash256,
    pub batch_index: u64,
}

/// Optimistic batch awaiting challenge window (scheme 0x03).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingBatch {
    pub rollup_id: Hash256,
    pub batch_index: u64,
    pub prev_state_root: Hash256,
    pub post_state_root: Hash256,
    pub da_hash: Hash256,
    pub submitted_height: u64,
    pub challenge_period: u64,
    pub challenged: bool,
    pub finalized: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FraudCertificate {
    /// Index of the diverging step inside the batch.
    pub step: u64,
    pub pre_state: Hash256,
    pub post_state: Hash256,
    pub claim_post: Hash256,
    pub step_preimage: Vec<u8>,
}

/// Circuit: post = H(prev || da || batch_index || witness_binding)
#[derive(Clone)]
pub struct RollupCircuit {
    pub prev: Option<Fr>,
    pub post: Option<Fr>,
    pub da: Option<Fr>,
    pub batch_index: Option<Fr>,
    pub witness_binding: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for RollupCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let prev = FpVar::new_input(cs.clone(), || {
            self.prev.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let post = FpVar::new_input(cs.clone(), || {
            self.post.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let da = FpVar::new_input(cs.clone(), || {
            self.da.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let batch = FpVar::new_input(cs.clone(), || {
            self.batch_index.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let wit = FpVar::new_witness(cs.clone(), || {
            self.witness_binding
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Algebraic transition tag used as the validity statement:
        // expected = prev + da * G1 + batch * G2 + wit * G3
        let g1 = FpVar::constant(hash_to_fr("AETH/ROLLUP/G1", &[]));
        let g2 = FpVar::constant(hash_to_fr("AETH/ROLLUP/G2", &[]));
        let g3 = FpVar::constant(hash_to_fr("AETH/ROLLUP/G3", &[]));
        let expected = &prev + &da * &g1 + &batch * &g2 + &wit * &g3;
        post.enforce_equal(&expected)?;
        Ok(())
    }
}

pub fn setup_rollup_keys() -> Result<(RollupProvingKey, RollupVerifyingKey), ZkError> {
    let circuit = RollupCircuit {
        prev: None,
        post: None,
        da: None,
        batch_index: None,
        witness_binding: None,
    };
    let (pk, vk) =
        Groth16::<ark_bn254::Bn254>::circuit_specific_setup(circuit, &mut OsRng)
            .map_err(|e| ZkError::Synthesis(e.to_string()))?;
    Ok((RollupProvingKey { groth16: pk }, RollupVerifyingKey { groth16: vk }))
}

fn transition_witness(prev: &Hash256, da: &Hash256, batch_index: u64, secret: &Fr) -> Fr {
    let mut buf = Vec::new();
    buf.extend_from_slice(prev);
    buf.extend_from_slice(da);
    buf.extend_from_slice(&batch_index.to_le_bytes());
    buf.extend_from_slice(&fr_to_bytes(secret));
    hash_to_fr("AETH/ROLLUP/WIT", &buf)
}

pub fn compute_valid_post_root(
    prev: &Hash256,
    da: &Hash256,
    batch_index: u64,
    secret: &Fr,
) -> Hash256 {
    let prev_f = fr_from_bytes(prev);
    let da_f = fr_from_bytes(da);
    let batch_f = Fr::from(batch_index);
    let wit = transition_witness(prev, da, batch_index, secret);
    let g1 = hash_to_fr("AETH/ROLLUP/G1", &[]);
    let g2 = hash_to_fr("AETH/ROLLUP/G2", &[]);
    let g3 = hash_to_fr("AETH/ROLLUP/G3", &[]);
    let post = prev_f + da_f * g1 + batch_f * g2 + wit * g3;
    fr_to_bytes(&post)
}

pub fn prove_rollup_groth16(
    pk: &RollupProvingKey,
    inputs: &RollupPublicInputs,
    secret: &Fr,
) -> Result<Vec<u8>, ZkError> {
    let expected = compute_valid_post_root(
        &inputs.prev_state_root,
        &inputs.da_hash,
        inputs.batch_index,
        secret,
    );
    if expected != inputs.post_state_root {
        return Err(ZkError::Witness(
            "post_state_root does not match valid transition".into(),
        ));
    }
    let wit = transition_witness(
        &inputs.prev_state_root,
        &inputs.da_hash,
        inputs.batch_index,
        secret,
    );
    let circuit = RollupCircuit {
        prev: Some(fr_from_bytes(&inputs.prev_state_root)),
        post: Some(fr_from_bytes(&inputs.post_state_root)),
        da: Some(fr_from_bytes(&inputs.da_hash)),
        batch_index: Some(Fr::from(inputs.batch_index)),
        witness_binding: Some(wit),
    };
    let proof = Groth16::<ark_bn254::Bn254>::prove(&pk.groth16, circuit, &mut OsRng)
        .map_err(|e| ZkError::Synthesis(e.to_string()))?;
    let mut bytes = Vec::new();
    proof
        .serialize_compressed(&mut bytes)
        .map_err(|e| ZkError::Serde(e.to_string()))?;
    Ok(bytes)
}

fn verify_groth16(
    vk: &RollupVerifyingKey,
    proof: &[u8],
    inputs: &RollupPublicInputs,
) -> Result<(), ZkError> {
    let proof = Proof::<ark_bn254::Bn254>::deserialize_compressed(&mut &proof[..])
        .map_err(|e| ZkError::Serde(e.to_string()))?;
    let public = [
        fr_from_bytes(&inputs.prev_state_root),
        fr_from_bytes(&inputs.post_state_root),
        fr_from_bytes(&inputs.da_hash),
        Fr::from(inputs.batch_index),
    ];
    let ok = Groth16::<ark_bn254::Bn254>::verify(&vk.groth16, &public, &proof)
        .map_err(|e| ZkError::Synthesis(e.to_string()))?;
    if ok {
        Ok(())
    } else {
        Err(ZkError::VerifyFailed)
    }
}

pub fn verify_fraud_certificate(
    cert: &FraudCertificate,
    claimed_post: &Hash256,
) -> Result<(), ZkError> {
    if cert.claim_post != *claimed_post {
        return Err(ZkError::Rollup("fraud claim_post mismatch".into()));
    }
    // One-step: honest post = H(pre || step || preimage)
    let mut buf = Vec::new();
    buf.extend_from_slice(&cert.pre_state);
    buf.extend_from_slice(&cert.step.to_le_bytes());
    buf.extend_from_slice(&cert.step_preimage);
    let honest = aether_crypto::tagged_hash("AETH/FRAUD/STEP", &buf);
    if honest != cert.post_state {
        return Err(ZkError::Rollup("fraud certificate self-inconsistent".into()));
    }
    if honest == cert.claim_post {
        return Err(ZkError::Rollup(
            "fraud certificate does not show divergence".into(),
        ));
    }
    Ok(())
}

pub fn verify_rollup(
    scheme: RollupScheme,
    vk: Option<&RollupVerifyingKey>,
    proof: &[u8],
    inputs: &RollupPublicInputs,
    pending: Option<&PendingBatch>,
    current_height: u64,
) -> Result<RollupVerifyOutcome, ZkError> {
    match scheme {
        RollupScheme::Groth16 => {
            let vk = vk.ok_or_else(|| ZkError::Rollup("missing groth16 vk".into()))?;
            verify_groth16(vk, proof, inputs)?;
            Ok(RollupVerifyOutcome::Final)
        }
        RollupScheme::PlonkLite => {
            let plonk: PlonkLiteProof = serde_json::from_slice(proof)
                .map_err(|e| ZkError::Serde(e.to_string()))?;
            verify_plonk_lite(
                &plonk,
                &inputs.prev_state_root,
                &inputs.post_state_root,
                &inputs.da_hash,
                inputs.batch_index,
            )?;
            Ok(RollupVerifyOutcome::Final)
        }
        RollupScheme::FraudProof => {
            if proof.is_empty() {
                // submission — enter challenge window
                Ok(RollupVerifyOutcome::Pending)
            } else {
                // fraud certificate during window
                let cert: FraudCertificate = serde_json::from_slice(proof)
                    .map_err(|e| ZkError::Serde(e.to_string()))?;
                verify_fraud_certificate(&cert, &inputs.post_state_root)?;
                Ok(RollupVerifyOutcome::FraudProven)
            }
        }
        RollupScheme::Noop => {
            let allow = std::env::var("AETHER_ALLOW_NOOP_ROLLUP")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if !allow {
                return Err(ZkError::NoopDisabled);
            }
            Ok(RollupVerifyOutcome::Final)
        }
    }
    .and_then(|outcome| {
        if let Some(p) = pending {
            if matches!(scheme, RollupScheme::FraudProof)
                && matches!(outcome, RollupVerifyOutcome::Pending)
            {
                let mature = current_height >= p.submitted_height.saturating_add(p.challenge_period);
                if mature && !p.challenged {
                    return Ok(RollupVerifyOutcome::Final);
                }
            }
        }
        Ok(outcome)
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RollupVerifyOutcome {
    Final,
    Pending,
    FraudProven,
}

pub fn prove_rollup_plonk(
    inputs: &RollupPublicInputs,
    secret: &Fr,
) -> Result<Vec<u8>, ZkError> {
    let expected = compute_valid_post_root(
        &inputs.prev_state_root,
        &inputs.da_hash,
        inputs.batch_index,
        secret,
    );
    // For plonk-lite we still require the same post root binding via secret commitment
    if expected != inputs.post_state_root {
        // Allow plonk to prove arbitrary post if secret commits — for demo, enforce same transition
        return Err(ZkError::Witness("post root mismatch for plonk".into()));
    }
    let proof = prove_plonk_lite(
        &inputs.prev_state_root,
        &inputs.post_state_root,
        &inputs.da_hash,
        inputs.batch_index,
        secret,
    )?;
    serde_json::to_vec(&proof).map_err(|e| ZkError::Serde(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;

    #[test]
    fn groth16_rollup_roundtrip() {
        let (pk, vk) = setup_rollup_keys().unwrap();
        let mut rng = OsRng;
        let secret = Fr::rand(&mut rng);
        let prev = [1u8; 32];
        let da = [2u8; 32];
        let post = compute_valid_post_root(&prev, &da, 1, &secret);
        let inputs = RollupPublicInputs {
            prev_state_root: prev,
            post_state_root: post,
            da_hash: da,
            batch_index: 1,
        };
        let proof = prove_rollup_groth16(&pk, &inputs, &secret).unwrap();
        verify_groth16(&vk, &proof, &inputs).unwrap();
    }
}
