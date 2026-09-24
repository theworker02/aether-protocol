use crate::field::{algebraic_commit, algebraic_nullifier, fr_from_bytes, fr_to_bytes, hash_to_fr};
use aether_crypto::tagged_hash;
use aether_types::{Address, Hash256};
use ark_bn254::Fr;
use rand::RngCore;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Note {
    pub value: u64,
    pub recipient_pk: FrBytes,
    pub rseed: FrBytes,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FrBytes(pub [u8; 32]);

impl FrBytes {
    pub fn from_fr(fr: &Fr) -> Self {
        Self(fr_to_bytes(fr))
    }
    pub fn to_fr(&self) -> Fr {
        fr_from_bytes(&self.0)
    }
    pub fn random(rng: &mut impl RngCore) -> Self {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        Self(b)
    }
}

#[derive(Clone, Debug)]
pub struct NoteWitness {
    pub note: Note,
    pub sk: Fr,
    pub leaf_index: usize,
    pub merkle_path: Vec<(Fr, bool)>, // sibling, is_right
}

pub fn note_commitment(note: &Note) -> Fr {
    algebraic_commit(note.value, &note.rseed.to_fr(), &note.recipient_pk.to_fr())
}

pub fn note_commitment_hash(note: &Note) -> Hash256 {
    fr_to_bytes(&note_commitment(note))
}

pub fn nullifier(sk: &Fr, cm: &Fr) -> Fr {
    algebraic_nullifier(sk, cm)
}

pub fn nullifier_hash(sk: &Fr, cm: &Fr) -> Hash256 {
    fr_to_bytes(&nullifier(sk, cm))
}

pub fn pk_from_address(addr: &Address) -> Fr {
    hash_to_fr("AETH/ZK/ADDR_PK", addr)
}

pub fn sk_from_secret(secret: &[u8; 32]) -> Fr {
    hash_to_fr("AETH/ZK/SK", secret)
}

/// Domain-separated BLAKE3 commitment used for explorer display / legacy bridge.
pub fn blake_note_commitment(value: u128, recipient: &Address, rseed: &Hash256) -> Hash256 {
    let mut buf = Vec::with_capacity(16 + 20 + 32);
    buf.extend_from_slice(&value.to_le_bytes());
    buf.extend_from_slice(recipient);
    buf.extend_from_slice(rseed);
    tagged_hash("AETH/NOTE/V1", &buf)
}
