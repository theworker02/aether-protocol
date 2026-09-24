//! Groth16 shielded circuits with Poseidon CRH (native + R1CS-matched).

use crate::field::{fr_from_bytes, fr_to_bytes};
use crate::keys::{ShieldedProvingKey, ShieldedVerifyingKey};
use crate::merkle::{verify_path, TREE_DEPTH};
use crate::notes::{note_commitment, nullifier, Note, NoteWitness};
use crate::poseidon_gadget;
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

#[derive(Clone)]
pub struct TransferCircuit {
    pub value_in: Option<u64>,
    pub value_out: Option<u64>,
    pub fee: Option<u64>,
    pub r_in: Option<Fr>,
    pub r_out: Option<Fr>,
    pub pk_in: Option<Fr>,
    pub pk_out: Option<Fr>,
    pub sk: Option<Fr>,
    pub leaf_index: Option<u64>,
    pub path: Option<Vec<(Fr, bool)>>,
    pub root: Option<Fr>,
    pub nullifier: Option<Fr>,
    pub cm_out: Option<Fr>,
    pub fee_public: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for TransferCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let value_in = FpVar::new_witness(cs.clone(), || {
            self.value_in
                .map(Fr::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let value_out = FpVar::new_witness(cs.clone(), || {
            self.value_out
                .map(Fr::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let fee_w = FpVar::new_witness(cs.clone(), || {
            self.fee
                .map(Fr::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let r_in = FpVar::new_witness(cs.clone(), || {
            self.r_in.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let r_out = FpVar::new_witness(cs.clone(), || {
            self.r_out.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let pk_in = FpVar::new_witness(cs.clone(), || {
            self.pk_in.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let pk_out = FpVar::new_witness(cs.clone(), || {
            self.pk_out.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let sk = FpVar::new_witness(cs.clone(), || {
            self.sk.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let root = FpVar::new_input(cs.clone(), || {
            self.root.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let nf_pub = FpVar::new_input(cs.clone(), || {
            self.nullifier.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let cm_out_pub = FpVar::new_input(cs.clone(), || {
            self.cm_out.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let fee_pub = FpVar::new_input(cs.clone(), || {
            self.fee_public.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let sum = &value_out + &fee_w;
        value_in.enforce_equal(&sum)?;
        fee_w.enforce_equal(&fee_pub)?;

        let cm_in = poseidon_gadget::commit(&value_in, &r_in, &pk_in)?;
        let cm_out = poseidon_gadget::commit(&value_out, &r_out, &pk_out)?;
        cm_out.enforce_equal(&cm_out_pub)?;

        let nf = poseidon_gadget::nullifier(&sk, &cm_in)?;
        nf.enforce_equal(&nf_pub)?;

        let mut cur = cm_in;
        let path = self.path.unwrap_or_default();
        let leaf_index = self.leaf_index.unwrap_or(0);
        for depth in 0..TREE_DEPTH {
            let (sib_val, _) = path
                .get(depth)
                .copied()
                .unwrap_or((Fr::from(0u64), false));
            let sibling = FpVar::new_witness(cs.clone(), || Ok(sib_val))?;
            let bit = if ((leaf_index >> depth) & 1) == 1 {
                Boolean::TRUE
            } else {
                Boolean::FALSE
            };
            let left = FpVar::conditionally_select(&bit, &sibling, &cur)?;
            let right = FpVar::conditionally_select(&bit, &cur, &sibling)?;
            cur = poseidon_gadget::hash2(&left, &right)?;
        }
        cur.enforce_equal(&root)?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct ShieldCircuit {
    pub value: Option<u64>,
    pub r: Option<Fr>,
    pub pk: Option<Fr>,
    pub cm: Option<Fr>,
    pub value_public: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for ShieldCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let value = FpVar::new_witness(cs.clone(), || {
            self.value
                .map(Fr::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let r = FpVar::new_witness(cs.clone(), || self.r.ok_or(SynthesisError::AssignmentMissing))?;
        let pk = FpVar::new_witness(cs.clone(), || {
            self.pk.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let cm_pub = FpVar::new_input(cs.clone(), || {
            self.cm.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let val_pub = FpVar::new_input(cs.clone(), || {
            self.value_public
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        value.enforce_equal(&val_pub)?;
        let cm = poseidon_gadget::commit(&value, &r, &pk)?;
        cm.enforce_equal(&cm_pub)?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct UnshieldCircuit {
    pub value: Option<u64>,
    pub r_in: Option<Fr>,
    pub pk_in: Option<Fr>,
    pub sk: Option<Fr>,
    pub leaf_index: Option<u64>,
    pub path: Option<Vec<(Fr, bool)>>,
    pub root: Option<Fr>,
    pub nullifier: Option<Fr>,
    pub value_public: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for UnshieldCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let value = FpVar::new_witness(cs.clone(), || {
            self.value
                .map(Fr::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let r_in = FpVar::new_witness(cs.clone(), || {
            self.r_in.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let pk_in = FpVar::new_witness(cs.clone(), || {
            self.pk_in.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let sk = FpVar::new_witness(cs.clone(), || {
            self.sk.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let root = FpVar::new_input(cs.clone(), || {
            self.root.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let nf_pub = FpVar::new_input(cs.clone(), || {
            self.nullifier.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let val_pub = FpVar::new_input(cs.clone(), || {
            self.value_public
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        value.enforce_equal(&val_pub)?;
        let cm_in = poseidon_gadget::commit(&value, &r_in, &pk_in)?;
        let nf = poseidon_gadget::nullifier(&sk, &cm_in)?;
        nf.enforce_equal(&nf_pub)?;

        let mut cur = cm_in;
        let path = self.path.unwrap_or_default();
        let leaf_index = self.leaf_index.unwrap_or(0);
        for depth in 0..TREE_DEPTH {
            let (sib_val, _) = path
                .get(depth)
                .copied()
                .unwrap_or((Fr::from(0u64), false));
            let sibling = FpVar::new_witness(cs.clone(), || Ok(sib_val))?;
            let bit = if ((leaf_index >> depth) & 1) == 1 {
                Boolean::TRUE
            } else {
                Boolean::FALSE
            };
            let left = FpVar::conditionally_select(&bit, &sibling, &cur)?;
            let right = FpVar::conditionally_select(&bit, &cur, &sibling)?;
            cur = poseidon_gadget::hash2(&left, &right)?;
        }
        cur.enforce_equal(&root)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransferPublicInputs {
    pub anchor: Hash256,
    pub nullifier: Hash256,
    pub cm_out: Hash256,
    pub fee: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldPublicInputs {
    pub commitment: Hash256,
    pub value: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnshieldPublicInputs {
    pub anchor: Hash256,
    pub nullifier: Hash256,
    pub value: u64,
}

fn ser_proof(proof: &Proof<ark_bn254::Bn254>) -> Result<Vec<u8>, ZkError> {
    let mut bytes = Vec::new();
    proof
        .serialize_compressed(&mut bytes)
        .map_err(|e| ZkError::Serde(e.to_string()))?;
    Ok(bytes)
}

fn de_proof(bytes: &[u8]) -> Result<Proof<ark_bn254::Bn254>, ZkError> {
    Proof::deserialize_compressed(&mut &bytes[..]).map_err(|e| ZkError::Serde(e.to_string()))
}

pub fn prove_transfer(
    pk: &ShieldedProvingKey,
    witness: &NoteWitness,
    out_note: &Note,
    fee: u64,
    root: Fr,
) -> Result<(Vec<u8>, TransferPublicInputs), ZkError> {
    if witness.note.value < out_note.value.saturating_add(fee) {
        return Err(ZkError::Witness("insufficient note value".into()));
    }
    if witness.note.value != out_note.value + fee {
        return Err(ZkError::Witness("value_in != value_out + fee".into()));
    }
    let cm_in = note_commitment(&witness.note);
    if !verify_path(&cm_in, witness.leaf_index, &witness.merkle_path, &root) {
        return Err(ZkError::Witness("bad merkle path".into()));
    }
    let nf = nullifier(&witness.sk, &cm_in);
    let cm_out = note_commitment(out_note);
    let circuit = TransferCircuit {
        value_in: Some(witness.note.value),
        value_out: Some(out_note.value),
        fee: Some(fee),
        r_in: Some(witness.note.rseed.to_fr()),
        r_out: Some(out_note.rseed.to_fr()),
        pk_in: Some(witness.note.recipient_pk.to_fr()),
        pk_out: Some(out_note.recipient_pk.to_fr()),
        sk: Some(witness.sk),
        leaf_index: Some(witness.leaf_index as u64),
        path: Some(witness.merkle_path.clone()),
        root: Some(root),
        nullifier: Some(nf),
        cm_out: Some(cm_out),
        fee_public: Some(Fr::from(fee)),
    };
    let proof = Groth16::<ark_bn254::Bn254>::prove(&pk.transfer, circuit, &mut OsRng)
        .map_err(|e| ZkError::Synthesis(e.to_string()))?;
    let publics = TransferPublicInputs {
        anchor: fr_to_bytes(&root),
        nullifier: fr_to_bytes(&nf),
        cm_out: fr_to_bytes(&cm_out),
        fee,
    };
    Ok((ser_proof(&proof)?, publics))
}

pub fn verify_transfer(
    vk: &ShieldedVerifyingKey,
    proof: &[u8],
    publics: &TransferPublicInputs,
) -> Result<(), ZkError> {
    let proof = de_proof(proof)?;
    let inputs = [
        fr_from_bytes(&publics.anchor),
        fr_from_bytes(&publics.nullifier),
        fr_from_bytes(&publics.cm_out),
        Fr::from(publics.fee),
    ];
    let ok = Groth16::<ark_bn254::Bn254>::verify(&vk.transfer, &inputs, &proof)
        .map_err(|e| ZkError::Synthesis(e.to_string()))?;
    if ok {
        Ok(())
    } else {
        Err(ZkError::VerifyFailed)
    }
}

pub fn prove_shield(
    pk: &ShieldedProvingKey,
    note: &Note,
) -> Result<(Vec<u8>, ShieldPublicInputs), ZkError> {
    let cm = note_commitment(note);
    let circuit = ShieldCircuit {
        value: Some(note.value),
        r: Some(note.rseed.to_fr()),
        pk: Some(note.recipient_pk.to_fr()),
        cm: Some(cm),
        value_public: Some(Fr::from(note.value)),
    };
    let proof = Groth16::<ark_bn254::Bn254>::prove(&pk.shield, circuit, &mut OsRng)
        .map_err(|e| ZkError::Synthesis(e.to_string()))?;
    Ok((
        ser_proof(&proof)?,
        ShieldPublicInputs {
            commitment: fr_to_bytes(&cm),
            value: note.value,
        },
    ))
}

pub fn verify_shield(
    vk: &ShieldedVerifyingKey,
    proof: &[u8],
    publics: &ShieldPublicInputs,
) -> Result<(), ZkError> {
    let proof = de_proof(proof)?;
    let inputs = [fr_from_bytes(&publics.commitment), Fr::from(publics.value)];
    let ok = Groth16::<ark_bn254::Bn254>::verify(&vk.shield, &inputs, &proof)
        .map_err(|e| ZkError::Synthesis(e.to_string()))?;
    if ok {
        Ok(())
    } else {
        Err(ZkError::VerifyFailed)
    }
}

pub fn prove_unshield(
    pk: &ShieldedProvingKey,
    witness: &NoteWitness,
    root: Fr,
) -> Result<(Vec<u8>, UnshieldPublicInputs), ZkError> {
    let cm_in = note_commitment(&witness.note);
    if !verify_path(&cm_in, witness.leaf_index, &witness.merkle_path, &root) {
        return Err(ZkError::Witness("bad merkle path".into()));
    }
    let nf = nullifier(&witness.sk, &cm_in);
    let circuit = UnshieldCircuit {
        value: Some(witness.note.value),
        r_in: Some(witness.note.rseed.to_fr()),
        pk_in: Some(witness.note.recipient_pk.to_fr()),
        sk: Some(witness.sk),
        leaf_index: Some(witness.leaf_index as u64),
        path: Some(witness.merkle_path.clone()),
        root: Some(root),
        nullifier: Some(nf),
        value_public: Some(Fr::from(witness.note.value)),
    };
    let proof = Groth16::<ark_bn254::Bn254>::prove(&pk.unshield, circuit, &mut OsRng)
        .map_err(|e| ZkError::Synthesis(e.to_string()))?;
    Ok((
        ser_proof(&proof)?,
        UnshieldPublicInputs {
            anchor: fr_to_bytes(&root),
            nullifier: fr_to_bytes(&nf),
            value: witness.note.value,
        },
    ))
}

pub fn verify_unshield(
    vk: &ShieldedVerifyingKey,
    proof: &[u8],
    publics: &UnshieldPublicInputs,
) -> Result<(), ZkError> {
    let proof = de_proof(proof)?;
    let inputs = [
        fr_from_bytes(&publics.anchor),
        fr_from_bytes(&publics.nullifier),
        Fr::from(publics.value),
    ];
    let ok = Groth16::<ark_bn254::Bn254>::verify(&vk.unshield, &inputs, &proof)
        .map_err(|e| ZkError::Synthesis(e.to_string()))?;
    if ok {
        Ok(())
    } else {
        Err(ZkError::VerifyFailed)
    }
}

pub fn setup_shielded_keys() -> Result<(ShieldedProvingKey, ShieldedVerifyingKey), ZkError> {
    let mut rng = OsRng;
    let transfer_c = TransferCircuit {
        value_in: None,
        value_out: None,
        fee: None,
        r_in: None,
        r_out: None,
        pk_in: None,
        pk_out: None,
        sk: None,
        leaf_index: None,
        path: None,
        root: None,
        nullifier: None,
        cm_out: None,
        fee_public: None,
    };
    let (tpk, tvk) = Groth16::<ark_bn254::Bn254>::circuit_specific_setup(transfer_c, &mut rng)
        .map_err(|e| ZkError::Synthesis(e.to_string()))?;

    let shield_c = ShieldCircuit {
        value: None,
        r: None,
        pk: None,
        cm: None,
        value_public: None,
    };
    let (spk, svk) = Groth16::<ark_bn254::Bn254>::circuit_specific_setup(shield_c, &mut rng)
        .map_err(|e| ZkError::Synthesis(e.to_string()))?;

    let unshield_c = UnshieldCircuit {
        value: None,
        r_in: None,
        pk_in: None,
        sk: None,
        leaf_index: None,
        path: None,
        root: None,
        nullifier: None,
        value_public: None,
    };
    let (upk, uvk) = Groth16::<ark_bn254::Bn254>::circuit_specific_setup(unshield_c, &mut rng)
        .map_err(|e| ZkError::Synthesis(e.to_string()))?;

    Ok((
        ShieldedProvingKey {
            transfer: tpk,
            shield: spk,
            unshield: upk,
        },
        ShieldedVerifyingKey {
            transfer: tvk,
            shield: svk,
            unshield: uvk,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::NoteTree;
    use crate::notes::{pk_from_address, sk_from_secret, FrBytes, Note, NoteWitness};
    use aether_types::zero_address;
    use rand::rngs::OsRng;

    #[test]
    fn shield_and_transfer_roundtrip() {
        let (pk, vk) = setup_shielded_keys().unwrap();
        let mut rng = OsRng;
        let addr = zero_address();
        let sk = sk_from_secret(&[7u8; 32]);
        let note = Note {
            value: 1_000,
            recipient_pk: FrBytes::from_fr(&pk_from_address(&addr)),
            rseed: FrBytes::random(&mut rng),
        };
        let (proof, publics) = prove_shield(&pk, &note).unwrap();
        verify_shield(&vk, &proof, &publics).unwrap();

        let mut tree = NoteTree::new();
        let cm = note_commitment(&note);
        let idx = tree.append(cm).unwrap();
        let path = tree.authentication_path(idx).unwrap();
        let root = tree.root();

        let out = Note {
            value: 900,
            recipient_pk: FrBytes::from_fr(&pk_from_address(&addr)),
            rseed: FrBytes::random(&mut rng),
        };
        let witness = NoteWitness {
            note,
            sk,
            leaf_index: idx,
            merkle_path: path,
        };
        let (tproof, tpub) = prove_transfer(&pk, &witness, &out, 100, root).unwrap();
        verify_transfer(&vk, &tproof, &tpub).unwrap();
    }
}
