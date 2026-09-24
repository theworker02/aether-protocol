use aether_types::{Address, Hash256, Header, Origin, Transaction, TxKind, HASH_LEN};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("serialization error: {0}")]
    Serde(String),
}

pub struct Keypair {
    pub signing: SigningKey,
    pub verifying: VerifyingKey,
}

impl Keypair {
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();
        Self { signing, verifying }
    }

    pub fn from_bytes(secret: [u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(&secret);
        let verifying = signing.verifying_key();
        Self { signing, verifying }
    }

    pub fn public_bytes(&self) -> Vec<u8> {
        self.verifying.to_bytes().to_vec()
    }

    pub fn address(&self) -> Address {
        address_from_pubkey(&self.verifying.to_bytes())
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.signing.sign(msg).to_bytes().to_vec()
    }
}

pub fn tagged_hash(tag: &str, data: &[u8]) -> Hash256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(tag.as_bytes());
    hasher.update(&[0xff]);
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

pub fn address_from_pubkey(pk: &[u8]) -> Address {
    let h = tagged_hash("AETH/ADDR/V1", pk);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&h[..20]);
    addr
}

pub fn hash_bytes(data: &[u8]) -> Hash256 {
    tagged_hash("AETH/BLOB/V1", data)
}

pub fn merkle_root(leaves: &[Hash256]) -> Hash256 {
    if leaves.is_empty() {
        return tagged_hash("AETH/MERKLE/EMPTY", &[]);
    }
    let mut layer: Vec<Hash256> = leaves
        .iter()
        .map(|l| tagged_hash("AETH/MERKLE/LEAF", l))
        .collect();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        for chunk in layer.chunks(2) {
            if chunk.len() == 2 {
                let mut buf = [0u8; HASH_LEN * 2];
                buf[..HASH_LEN].copy_from_slice(&chunk[0]);
                buf[HASH_LEN..].copy_from_slice(&chunk[1]);
                next.push(tagged_hash("AETH/MERKLE/NODE", &buf));
            } else {
                next.push(tagged_hash("AETH/MERKLE/ODD", &chunk[0]));
            }
        }
        layer = next;
    }
    layer[0]
}

pub fn encode_json<T: Serialize>(v: &T) -> Result<Vec<u8>, CryptoError> {
    serde_json::to_vec(v).map_err(|e| CryptoError::Serde(e.to_string()))
}

#[derive(Serialize)]
struct TxSignBody<'a> {
    version: u8,
    nonce: u64,
    origin: &'a Origin,
    kind: &'a TxKind,
    gas_limit: u64,
    max_fee_per_gas: u64,
    max_priority_fee_per_gas: u64,
}

pub fn tx_sighash(tx: &Transaction) -> Result<Hash256, CryptoError> {
    let body = TxSignBody {
        version: tx.version,
        nonce: tx.nonce,
        origin: &tx.origin,
        kind: &tx.kind,
        gas_limit: tx.gas_limit,
        max_fee_per_gas: tx.max_fee_per_gas,
        max_priority_fee_per_gas: tx.max_priority_fee_per_gas,
    };
    let bytes = encode_json(&body)?;
    Ok(tagged_hash("AETH/TX/V1", &bytes))
}

pub fn sign_tx(tx: &mut Transaction, kp: &Keypair) -> Result<(), CryptoError> {
    let h = tx_sighash(tx)?;
    tx.public_key = kp.public_bytes();
    tx.signature = kp.sign(&h);
    Ok(())
}

pub fn verify_tx(tx: &Transaction) -> Result<Address, CryptoError> {
    let h = tx_sighash(tx)?;
    let pk_bytes: [u8; 32] = tx
        .public_key
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidPublicKey)?;
    let vk = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| CryptoError::InvalidPublicKey)?;
    let sig_bytes: [u8; 64] = tx
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidSignature)?;
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify(&h, &sig)
        .map_err(|_| CryptoError::InvalidSignature)?;
    Ok(address_from_pubkey(&pk_bytes))
}

pub fn header_sighash(header: &Header) -> Result<Hash256, CryptoError> {
    let mut unsigned = header.clone();
    unsigned.signature.clear();
    let bytes = encode_json(&unsigned)?;
    Ok(tagged_hash("AETH/BLOCK/V1", &bytes))
}

pub fn sign_header(header: &mut Header, kp: &Keypair) -> Result<(), CryptoError> {
    let h = header_sighash(header)?;
    header.signature = kp.sign(&h);
    Ok(())
}

pub fn block_hash(header: &Header) -> Result<Hash256, CryptoError> {
    let bytes = encode_json(header)?;
    Ok(tagged_hash("AETH/BLOCK/V1", &bytes))
}

pub fn tx_hash(tx: &Transaction) -> Result<Hash256, CryptoError> {
    let bytes = encode_json(tx)?;
    Ok(tagged_hash("AETH/TXHASH/V1", &bytes))
}

pub fn note_commitment(value: u128, recipient: &Address, rseed: &Hash256) -> Hash256 {
    let mut buf = Vec::with_capacity(8 + 20 + 32);
    buf.extend_from_slice(&value.to_le_bytes());
    buf.extend_from_slice(recipient);
    buf.extend_from_slice(rseed);
    tagged_hash("AETH/NOTE/V1", &buf)
}

pub fn nullifier(sk: &[u8], commitment: &Hash256) -> Hash256 {
    let mut buf = Vec::with_capacity(sk.len() + 32);
    buf.extend_from_slice(sk);
    buf.extend_from_slice(commitment);
    tagged_hash("AETH/NULLIFIER/V1", &buf)
}

pub fn deploy_address(sender: &Address, nonce: u64, salt: &Hash256) -> Address {
    let mut buf = Vec::with_capacity(20 + 8 + 32);
    buf.extend_from_slice(sender);
    buf.extend_from_slice(&nonce.to_le_bytes());
    buf.extend_from_slice(salt);
    let h = tagged_hash("AETH/DEPLOY", &buf);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&h[..20]);
    addr
}

pub fn composite_state_root(parts: &[&Hash256]) -> Hash256 {
    let mut buf = Vec::with_capacity(parts.len() * HASH_LEN);
    for p in parts {
        buf.extend_from_slice(*p);
    }
    tagged_hash("AETH/STATE/V1", &buf)
}
