//! Aether ZK: Groth16 shielded pool + production rollup proof schemes.
//!
//! Schemes:
//! - Shielded notes: Groth16/BN254 balance + commitment + nullifier circuit
//! - Rollup `0x01`: Groth16 validity proof of state transition
//! - Rollup `0x02`: Plonk-lite (KZG opening) validity proof
//! - Rollup `0x03`: Optimistic fraud-proof window + one-step fraud certificate
//! - Rollup `0xFF`: insecure noop (disabled unless `AETHER_ALLOW_NOOP_ROLLUP=1`)

pub mod field;
mod keys;
mod merkle;
mod notes;
mod plonk_lite;
mod poseidon_gadget;
mod rollup;
mod shielded;

pub use field::{
    fr_from_bytes, fr_to_bytes, hash_to_fr, poseidon_commit, poseidon_hash2, poseidon_nullifier,
    poseidon_parent,
};
pub use keys::{
    global_keys, load_or_setup_keys, set_global_keys, RollupProvingKey, RollupVerifyingKey,
    ShieldedProvingKey, ShieldedVerifyingKey, ZkKeychain,
};
pub use merkle::{NoteTree, TREE_DEPTH};
pub use notes::{
    note_commitment, nullifier, pk_from_address, sk_from_secret, FrBytes, Note, NoteWitness,
};
pub use plonk_lite::{prove_plonk_lite, verify_plonk_lite, PlonkLiteProof};
pub use rollup::{
    compute_valid_post_root, prove_rollup_groth16, prove_rollup_plonk, setup_rollup_keys,
    verify_fraud_certificate, verify_rollup, FraudCertificate, PendingBatch, RollupPublicInputs,
    RollupScheme, RollupVerifyOutcome,
};
pub use shielded::{
    prove_shield, prove_transfer, prove_unshield, verify_shield, verify_transfer,
    verify_unshield, ShieldPublicInputs, TransferPublicInputs, UnshieldPublicInputs,
};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ZkError {
    #[error("synthesis: {0}")]
    Synthesis(String),
    #[error("proof verify failed")]
    VerifyFailed,
    #[error("serialization: {0}")]
    Serde(String),
    #[error("invalid witness: {0}")]
    Witness(String),
    #[error("rollup: {0}")]
    Rollup(String),
    #[error("noop scheme disabled (set AETHER_ALLOW_NOOP_ROLLUP=1 for dev only)")]
    NoopDisabled,
}
