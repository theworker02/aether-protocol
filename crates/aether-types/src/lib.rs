use serde::{Deserialize, Serialize};
use std::fmt;

pub const WEI_PER_AETH: u128 = 1_000_000_000;
pub const INTRINSIC_GAS: u64 = 21_000;
pub const DEFAULT_GAS_LIMIT: u64 = 30_000_000;
pub const DEFAULT_BASE_FEE: u64 = 1_000;
pub const EPOCH_LENGTH: u64 = 100;
pub const ADDRESS_LEN: usize = 20;
pub const HASH_LEN: usize = 32;
/// Wire + package SemVer for this release line.
pub const PROTOCOL_VERSION: &str = "1.3.0";
/// Monotonic header/tx wire version (breaking bumps only).
pub const WIRE_VERSION: u32 = 2;
/// Double-sign slash in basis points (5% = 500).
pub const SLASH_DOUBLE_SIGN_BPS: u16 = 500;
/// Downtime slash in basis points (0.01% = 1).
pub const SLASH_DOWNTIME_BPS: u16 = 1;

pub type Hash256 = [u8; HASH_LEN];
pub type Address = [u8; ADDRESS_LEN];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HybridMode {
    Public,
    Allowlist,
    Mixed,
}

impl Default for HybridMode {
    fn default() -> Self {
        Self::Public
    }
}

impl fmt::Display for HybridMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Public => write!(f, "public"),
            Self::Allowlist => write!(f, "allowlist"),
            Self::Mixed => write!(f, "mixed"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainParams {
    pub chain_id: String,
    pub epoch_length: u64,
    pub min_validator_stake: u128,
    pub max_validators: usize,
    pub unbonding_period: u64,
    pub gas_limit: u64,
    pub hybrid_mode: HybridMode,
    pub block_time_ms: u64,
}

impl Default for ChainParams {
    fn default() -> Self {
        Self {
            chain_id: "aether-devnet-1".into(),
            epoch_length: EPOCH_LENGTH,
            min_validator_stake: 10_000 * WEI_PER_AETH,
            max_validators: 100,
            unbonding_period: 21,
            gas_limit: DEFAULT_GAS_LIMIT,
            hybrid_mode: HybridMode::Public,
            block_time_ms: 1_000,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Account {
    pub nonce: u64,
    pub balance: u128,
    pub code_hash: Option<Hash256>,
    pub bonded: u128,
    pub storage: std::collections::BTreeMap<u64, u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct OutPoint {
    pub tx_hash: Hash256,
    pub index: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxOutput {
    pub amount: u128,
    pub owner: Address,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TxKind {
    Transfer {
        to: Address,
        amount: u128,
        #[serde(default)]
        data: Vec<u8>,
    },
    Deploy {
        code: Vec<u8>,
        salt: Hash256,
    },
    UtxoSpend {
        outputs: Vec<TxOutput>,
    },
    /// Transparent → shielded (Groth16 shield proof required).
    ShieldedShield {
        commitment: Hash256,
        value: u64,
        proof: Vec<u8>,
    },
    /// Shielded → shielded transfer (Groth16 transfer proof).
    ShieldedTransfer {
        anchor: Hash256,
        commitments: Vec<Hash256>,
        nullifiers: Vec<Hash256>,
        fee: u64,
        proof: Vec<u8>,
        #[serde(default)]
        ciphertext: Vec<u8>,
    },
    /// Shielded → transparent (Groth16 unshield proof).
    ShieldedUnshield {
        anchor: Hash256,
        nullifier: Hash256,
        value: u64,
        proof: Vec<u8>,
    },
    StakeBond {
        amount: u128,
        commission_bps: u16,
    },
    StakeUnbond {
        amount: u128,
    },
    /// Delegate liquid stake to a bonded validator (liquid staking).
    StakeDelegate {
        validator: Address,
        amount: u128,
    },
    /// Move delegation between validators (same epoch rules as unbond+bond).
    StakeRedelegate {
        src: Address,
        dst: Address,
        amount: u128,
    },
    /// Undelegate shares from a validator into the unbonding queue.
    StakeUndelegate {
        validator: Address,
        amount: u128,
    },
    /// Claim matured unbonding entries into liquid balance.
    StakeWithdraw {},
    RollupRegister {
        rollup_id: Hash256,
        sequencer: Address,
        scheme: u8,
        #[serde(default)]
        verifying_key: Vec<u8>,
        #[serde(default = "default_challenge_period")]
        challenge_period: u64,
    },
    RollupCommit {
        rollup_id: Hash256,
        batch_index: u64,
        prev_state_root: Hash256,
        post_state_root: Hash256,
        da_hash: Hash256,
        #[serde(default)]
        proof: Vec<u8>,
    },
    /// Finalize an optimistic batch after challenge window (scheme 0x03).
    RollupFinalize {
        rollup_id: Hash256,
        batch_index: u64,
    },
    /// Submit fraud certificate against a pending optimistic batch.
    RollupFraud {
        rollup_id: Hash256,
        batch_index: u64,
        certificate: Vec<u8>,
    },
    GovernancePropose {
        title: String,
        param_key: String,
        param_value: String,
        deposit: u128,
    },
    GovernanceVote {
        proposal_id: u64,
        option: u8,
    },
    GovernanceEnact {
        proposal_id: u64,
    },
    /// Direct contract call (same semantics as Transfer-with-data, amount optional).
    ContractCall {
        to: Address,
        amount: u128,
        data: Vec<u8>,
    },
    /// Submit double-sign evidence (two conflicting signed votes).
    EvidenceDoubleSign {
        vote_a: Vec<u8>,
        vote_b: Vec<u8>,
    },
    /// Submit downtime evidence (missed blocks threshold).
    EvidenceDowntime {
        validator: Address,
        missed: u64,
    },
    /// Open an IBC-lite channel to a counterparty chain.
    BridgeOpenChannel {
        channel_id: String,
        counterparty_chain: String,
        counterparty_channel: String,
    },
    /// Send a packet on an open channel.
    BridgeSendPacket {
        channel_id: String,
        data: Vec<u8>,
        timeout_height: u64,
    },
    /// Receive + verify a packet from a counterparty (operator / relayer).
    BridgeRecvPacket {
        channel_id: String,
        sequence: u64,
        data: Vec<u8>,
        proof: Vec<u8>,
    },
    /// Acknowledge a received packet.
    BridgeAck {
        channel_id: String,
        sequence: u64,
        acknowledgement: Vec<u8>,
    },
    /// Governance-gated community pool spend (proposer must pass deposit rules).
    CommunityPoolSpend {
        to: Address,
        amount: u128,
        memo: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Origin {
    Account { from: Address },
    Utxo { inputs: Vec<OutPoint> },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub version: u8,
    pub nonce: u64,
    pub origin: Origin,
    pub kind: TxKind,
    pub gas_limit: u64,
    pub max_fee_per_gas: u64,
    pub max_priority_fee_per_gas: u64,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Receipt {
    pub tx_hash: Hash256,
    pub status: bool,
    pub gas_used: u64,
    pub logs: Vec<Log>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Log {
    pub address: Address,
    pub topics: Vec<u64>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Header {
    pub version: u32,
    pub chain_id: String,
    pub height: u64,
    pub time_unix_ms: u64,
    pub prev_hash: Hash256,
    pub tx_root: Hash256,
    pub state_root: Hash256,
    pub receipts_root: Hash256,
    pub proposer: Address,
    pub round: u32,
    pub epoch: u64,
    pub gas_used: u64,
    pub gas_limit: u64,
    pub base_fee: u64,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub header: Header,
    pub transactions: Vec<Transaction>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub address: Address,
    pub public_key: Vec<u8>,
    pub power: u128,
    pub commission_bps: u16,
    pub jailed: bool,
    /// Shares outstanding for liquid staking (1 share ≈ 1 wei at genesis rate).
    #[serde(default)]
    pub shares: u128,
    /// Tombstoned after double-sign; permanent.
    #[serde(default)]
    pub tombstoned: bool,
    #[serde(default)]
    pub jail_until_epoch: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Delegation {
    pub delegator: Address,
    pub validator: Address,
    pub shares: u128,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnbondingEntry {
    pub id: u64,
    pub owner: Address,
    pub validator: Address,
    pub amount: u128,
    pub unlock_epoch: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgeChannel {
    pub channel_id: String,
    pub counterparty_chain: String,
    pub counterparty_channel: String,
    pub next_send_seq: u64,
    pub next_recv_seq: u64,
    pub closed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgePacket {
    pub channel_id: String,
    pub sequence: u64,
    pub data: Vec<u8>,
    pub timeout_height: u64,
    pub status: String, // sent | received | acked | timed_out
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlashEvent {
    pub height: u64,
    pub validator: Address,
    pub reason: String,
    pub slashed: u128,
    pub burned: u128,
    pub to_pool: u128,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RollupInfo {
    pub rollup_id: Hash256,
    pub sequencer: Address,
    pub scheme: u8,
    pub last_batch: u64,
    pub state_root: Hash256,
    #[serde(default)]
    pub verifying_key: Vec<u8>,
    #[serde(default)]
    pub challenge_period: u64,
}

fn default_challenge_period() -> u64 {
    10
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Genesis {
    pub chain_id: String,
    pub alloc: Vec<GenesisAlloc>,
    pub validators: Vec<GenesisValidator>,
    pub params: ChainParams,
    pub timestamp: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisAlloc {
    pub address: Address,
    pub balance: u128,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisValidator {
    pub address: Address,
    pub public_key: Vec<u8>,
    pub power: u128,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovernanceProposal {
    pub id: u64,
    pub title: String,
    pub param_key: String,
    pub param_value: String,
    pub proposer: Address,
    pub deposit: u128,
    pub yes: u128,
    pub no: u128,
    pub abstain: u128,
    pub veto: u128,
    pub voting_end_height: u64,
    pub enact_height: Option<u64>,
    pub status: String, // deposit | voting | passed | failed | enacted
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LightHeader {
    pub height: u64,
    pub epoch: u64,
    pub hash: Hash256,
    pub prev_hash: Hash256,
    pub state_root: Hash256,
    pub validators_hash: Hash256,
    pub time_unix_ms: u64,
    pub gas_used: u64,
    pub base_fee: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountProof {
    pub address: Address,
    pub account: Account,
    pub state_root: Hash256,
    pub accounts_blob_hash: Hash256,
    pub valid: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProtocolInfo {
    pub name: String,
    pub version: String,
    pub chain_id: String,
    pub hybrid_mode: HybridMode,
    pub height: u64,
    pub epoch: u64,
    pub base_fee: u64,
    pub validators: usize,
}

pub fn hex_addr(a: &Address) -> String {
    format!("0x{}", hex::encode(a))
}

pub fn hex_hash(h: &Hash256) -> String {
    format!("0x{}", hex::encode(h))
}

pub fn parse_addr(s: &str) -> Result<Address, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| e.to_string())?;
    if bytes.len() != ADDRESS_LEN {
        return Err(format!("address must be {ADDRESS_LEN} bytes"));
    }
    let mut a = [0u8; ADDRESS_LEN];
    a.copy_from_slice(&bytes);
    Ok(a)
}

pub fn parse_hash(s: &str) -> Result<Hash256, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| e.to_string())?;
    if bytes.len() != HASH_LEN {
        return Err(format!("hash must be {HASH_LEN} bytes"));
    }
    let mut h = [0u8; HASH_LEN];
    h.copy_from_slice(&bytes);
    Ok(h)
}

pub fn zero_hash() -> Hash256 {
    [0u8; HASH_LEN]
}

pub fn zero_address() -> Address {
    [0u8; ADDRESS_LEN]
}
