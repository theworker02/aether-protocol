use aether_crypto::{
    block_hash, composite_state_root, deploy_address, hash_bytes, merkle_root, tx_hash, verify_tx,
    Keypair,
};
use aether_types::{
    BridgeChannel, BridgePacket, SlashEvent, SLASH_DOUBLE_SIGN_BPS, SLASH_DOWNTIME_BPS, *,
};
use aether_vm::{execute, HostContext};
use aether_zk::{
    fr_from_bytes, global_keys, verify_fraud_certificate, verify_rollup, verify_shield,
    verify_transfer, verify_unshield, FraudCertificate, PendingBatch, RollupPublicInputs,
    RollupScheme, RollupVerifyingKey, RollupVerifyOutcome, ShieldPublicInputs, NoteTree,
    TransferPublicInputs, UnshieldPublicInputs,
};
use ark_serialize::CanonicalDeserialize;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use thiserror::Error;
use tracing::info;

pub mod adapters;
pub mod mempool;
pub use adapters::{AllowAll, BlockHook, NoopHook, RollupVerifierAdapter, TxFilter};
pub use mempool::Mempool;

#[derive(Debug, Error)]
pub enum StateError {
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("invalid tx: {0}")]
    InvalidTx(String),
    #[error("insufficient balance")]
    InsufficientBalance,
    #[error("nonce mismatch")]
    NonceMismatch,
    #[error("utxo missing")]
    UtxoMissing,
    #[error("not allowed in hybrid mode")]
    HybridDenied,
    #[error("rollup error: {0}")]
    Rollup(String),
    #[error("zk: {0}")]
    Zk(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainState {
    pub params: ChainParams,
    pub height: u64,
    pub epoch: u64,
    pub base_fee: u64,
    pub accounts: BTreeMap<String, Account>,
    pub utxos: BTreeMap<String, TxOutput>,
    pub code: BTreeMap<String, Vec<u8>>,
    /// Ordered shielded note commitments (Merkle leaves).
    pub note_leaves: Vec<Hash256>,
    pub notes: HashSet<String>,
    pub nullifiers: HashSet<String>,
    pub validators: BTreeMap<String, ValidatorInfo>,
    /// liquid staking: "delegator_hex|validator_hex" → Delegation
    #[serde(default)]
    pub delegations: BTreeMap<String, Delegation>,
    #[serde(default)]
    pub unbonding: Vec<UnbondingEntry>,
    #[serde(default)]
    pub next_unbond_id: u64,
    pub allowlist: HashSet<String>,
    pub rollups: BTreeMap<String, RollupInfo>,
    pub pending_rollups: BTreeMap<String, PendingBatch>,
    pub proposals: BTreeMap<u64, GovernanceProposal>,
    pub next_proposal_id: u64,
    pub total_supply: u128,
    pub genesis_supply: u128,
    pub fee_burned: u128,
    pub shielded_value: u128,
    /// Community pool (slash half + optional deposits).
    #[serde(default)]
    pub community_pool: u128,
    #[serde(default)]
    pub bridges: BTreeMap<String, BridgeChannel>,
    #[serde(default)]
    pub bridge_packets: BTreeMap<String, BridgePacket>,
    #[serde(default)]
    pub slash_log: Vec<SlashEvent>,
    /// Evidence hashes already processed (anti-replay).
    #[serde(default)]
    pub evidence_seen: HashSet<String>,
    /// Brokerless markets: registered assets (native AETH is implicit).
    #[serde(default)]
    pub assets: BTreeMap<String, AssetMeta>,
    /// Secondary asset balances: "addr_hex|asset_hex" → amount.
    #[serde(default)]
    pub asset_balances: BTreeMap<String, u128>,
    /// Resting limit orders (id → order).
    #[serde(default)]
    pub orders: BTreeMap<u64, LimitOrder>,
    #[serde(default)]
    pub next_order_id: u64,
    /// Constant-product AMM pools.
    #[serde(default)]
    pub pools: BTreeMap<String, AmmPool>,
    /// Hashlock escrows for P2P atomic settlement.
    #[serde(default)]
    pub escrows: BTreeMap<u64, Escrow>,
    #[serde(default)]
    pub next_escrow_id: u64,
    /// Native AETH locked in open orders + escrows + AMM reserves.
    #[serde(default)]
    pub market_locked_native: u128,
}

impl ChainState {
    pub fn from_genesis(g: &Genesis) -> Self {
        let mut accounts = BTreeMap::new();
        let mut total = 0u128;
        for a in &g.alloc {
            let key = hex::encode(a.address);
            accounts.insert(
                key,
                Account {
                    nonce: 0,
                    balance: a.balance,
                    code_hash: None,
                    bonded: 0,
                    storage: BTreeMap::new(),
                },
            );
            total += a.balance;
        }
        let mut validators = BTreeMap::new();
        for v in &g.validators {
            validators.insert(
                hex::encode(v.address),
                ValidatorInfo {
                    address: v.address,
                    public_key: v.public_key.clone(),
                    power: v.power,
                    commission_bps: 0,
                    jailed: false,
                    shares: v.power,
                    tombstoned: false,
                    jail_until_epoch: 0,
                },
            );
        }
        Self {
            params: g.params.clone(),
            height: 0,
            epoch: 0,
            base_fee: DEFAULT_BASE_FEE,
            accounts,
            utxos: BTreeMap::new(),
            code: BTreeMap::new(),
            note_leaves: Vec::new(),
            notes: HashSet::new(),
            nullifiers: HashSet::new(),
            validators,
            delegations: BTreeMap::new(),
            unbonding: Vec::new(),
            next_unbond_id: 1,
            allowlist: HashSet::new(),
            rollups: BTreeMap::new(),
            pending_rollups: BTreeMap::new(),
            proposals: BTreeMap::new(),
            next_proposal_id: 1,
            total_supply: total,
            genesis_supply: total,
            fee_burned: 0,
            shielded_value: 0,
            community_pool: 0,
            bridges: BTreeMap::new(),
            bridge_packets: BTreeMap::new(),
            slash_log: Vec::new(),
            evidence_seen: HashSet::new(),
            assets: BTreeMap::new(),
            asset_balances: BTreeMap::new(),
            orders: BTreeMap::new(),
            next_order_id: 1,
            pools: BTreeMap::new(),
            escrows: BTreeMap::new(),
            next_escrow_id: 1,
            market_locked_native: 0,
        }
    }

    fn acct_key(addr: &Address) -> String {
        hex::encode(addr)
    }

    fn outpoint_key(op: &OutPoint) -> String {
        format!("{}:{}", hex::encode(op.tx_hash), op.index)
    }

    fn pending_key(rollup_id: &Hash256, batch_index: u64) -> String {
        format!("{}:{batch_index}", hex::encode(rollup_id))
    }

    pub fn note_tree(&self) -> NoteTree {
        let mut tree = NoteTree::new();
        for leaf in &self.note_leaves {
            let _ = tree.append(fr_from_bytes(leaf));
        }
        tree
    }

    pub fn notes_root(&self) -> Hash256 {
        self.note_tree().root_hash()
    }

    pub fn get_balance(&self, addr: &Address) -> u128 {
        self.accounts
            .get(&Self::acct_key(addr))
            .map(|a| a.balance)
            .unwrap_or(0)
    }

    pub fn get_account(&self, addr: &Address) -> Account {
        self.accounts
            .get(&Self::acct_key(addr))
            .cloned()
            .unwrap_or_default()
    }

    pub fn compute_state_root(&self) -> Hash256 {
        let accounts_root = hash_bytes(&serde_json::to_vec(&self.accounts).unwrap_or_default());
        let utxo_root = hash_bytes(&serde_json::to_vec(&self.utxos).unwrap_or_default());
        let contracts_root = hash_bytes(&serde_json::to_vec(&self.code).unwrap_or_default());
        let notes_root = self.notes_root();
        let mut nulls: Vec<_> = self.nullifiers.iter().cloned().collect();
        nulls.sort();
        let nullifiers_root = hash_bytes(&serde_json::to_vec(&nulls).unwrap_or_default());
        let rollups_root = hash_bytes(&serde_json::to_vec(&self.rollups).unwrap_or_default());
        let validator_set_root =
            hash_bytes(&serde_json::to_vec(&self.validators).unwrap_or_default());
        let markets_root = hash_bytes(
            &serde_json::to_vec(&(
                &self.assets,
                &self.asset_balances,
                &self.orders,
                &self.pools,
                &self.escrows,
                self.market_locked_native,
            ))
            .unwrap_or_default(),
        );
        composite_state_root(&[
            &accounts_root,
            &utxo_root,
            &contracts_root,
            &notes_root,
            &nullifiers_root,
            &rollups_root,
            &validator_set_root,
            &markets_root,
        ])
    }

    /// I1 â€” supply conservation (docs/INVARIANTS.md).
    pub fn verify_supply_invariant(&self) -> Result<(), StateError> {
        let mut liquid = 0u128;
        let mut bonded = 0u128;
        for a in self.accounts.values() {
            liquid = liquid.saturating_add(a.balance);
            bonded = bonded.saturating_add(a.bonded);
        }
        let mut utxo_sum = 0u128;
        for u in self.utxos.values() {
            utxo_sum = utxo_sum.saturating_add(u.amount);
        }
        let mut deposits = 0u128;
        for p in self.proposals.values() {
            if p.status == "voting" || p.status == "passed" {
                deposits = deposits.saturating_add(p.deposit);
            }
        }
        let mut unbonding_locked = 0u128;
        for e in &self.unbonding {
            unbonding_locked = unbonding_locked.saturating_add(e.amount);
        }
        let mut delegated = 0u128;
        for d in self.delegations.values() {
            delegated = delegated.saturating_add(d.shares);
        }
        let lhs = liquid
            .saturating_add(bonded)
            .saturating_add(utxo_sum)
            .saturating_add(self.shielded_value)
            .saturating_add(self.fee_burned)
            .saturating_add(deposits)
            .saturating_add(unbonding_locked)
            .saturating_add(delegated)
            .saturating_add(self.community_pool)
            .saturating_add(self.market_locked_native);
        if lhs != self.genesis_supply {
            return Err(StateError::InvalidTx(format!(
                "supply invariant broken: lhs={lhs} genesis={}",
                self.genesis_supply
            )));
        }
        Ok(())
    }

    pub fn accounted_supply(&self) -> u128 {
        let mut n = 0u128;
        for a in self.accounts.values() {
            n = n.saturating_add(a.balance).saturating_add(a.bonded);
        }
        for u in self.utxos.values() {
            n = n.saturating_add(u.amount);
        }
        for d in self.delegations.values() {
            n = n.saturating_add(d.shares);
        }
        for e in &self.unbonding {
            n = n.saturating_add(e.amount);
        }
        n.saturating_add(self.shielded_value)
            .saturating_add(self.fee_burned)
            .saturating_add(self.community_pool)
            .saturating_add(self.market_locked_native)
    }

    pub fn light_account_proof(&self, addr: &Address) -> AccountProof {
        let account = self.get_account(addr);
        let accounts_blob = serde_json::to_vec(&self.accounts).unwrap_or_default();
        let accounts_blob_hash = hash_bytes(&accounts_blob);
        AccountProof {
            address: *addr,
            account,
            state_root: self.compute_state_root(),
            accounts_blob_hash,
            valid: true,
        }
    }

    pub fn apply_tx(
        &mut self,
        tx: &Transaction,
        tip_to: Option<&Address>,
    ) -> Result<Receipt, StateError> {
        let sender = verify_tx(tx).map_err(|e| StateError::Crypto(e.to_string()))?;
        let th = tx_hash(tx).map_err(|e| StateError::Crypto(e.to_string()))?;

        if tx.max_fee_per_gas < self.base_fee {
            return Err(StateError::InvalidTx("max fee below base fee".into()));
        }

        let mut gas_used = INTRINSIC_GAS;
        let mut logs = Vec::new();

        match &tx.origin {
            Origin::Account { from } => {
                if *from != sender {
                    return Err(StateError::InvalidTx("origin/pubkey mismatch".into()));
                }
                let acct = self.get_account(from);
                if acct.nonce != tx.nonce {
                    return Err(StateError::NonceMismatch);
                }
            }
            Origin::Utxo { inputs } => {
                if inputs.is_empty() {
                    return Err(StateError::InvalidTx("no utxo inputs".into()));
                }
            }
        }

        let result = match &tx.kind {
            TxKind::Transfer { to, amount, data } => {
                self.apply_transfer(&sender, to, *amount, data, tx, &mut gas_used, &mut logs)
            }
            TxKind::ContractCall { to, amount, data } => {
                self.apply_transfer(&sender, to, *amount, data, tx, &mut gas_used, &mut logs)
            }
            TxKind::Deploy { code, salt } => {
                self.apply_deploy(&sender, code, salt, tx, &mut gas_used)
            }
            TxKind::UtxoSpend { outputs } => {
                self.apply_utxo_spend(&sender, tx, outputs, &mut gas_used)
            }
            TxKind::ShieldedShield {
                commitment,
                value,
                proof,
            } => self.apply_shield_mint(&sender, commitment, *value, proof, &mut gas_used),
            TxKind::ShieldedTransfer {
                anchor,
                commitments,
                nullifiers,
                fee,
                proof,
                ..
            } => self.apply_shielded_transfer(
                anchor,
                commitments,
                nullifiers,
                *fee,
                proof,
                &mut gas_used,
            ),
            TxKind::ShieldedUnshield {
                anchor,
                nullifier,
                value,
                proof,
            } => self.apply_unshield(&sender, anchor, nullifier, *value, proof, &mut gas_used),
            TxKind::StakeBond {
                amount,
                commission_bps,
            } => self.apply_bond(&sender, *amount, *commission_bps, &mut gas_used),
            TxKind::StakeUnbond { amount } => {
                self.apply_unbond(&sender, *amount, &mut gas_used)
            }
            TxKind::StakeDelegate { validator, amount } => {
                self.apply_delegate(&sender, validator, *amount, &mut gas_used)
            }
            TxKind::StakeRedelegate { src, dst, amount } => {
                self.apply_redelegate(&sender, src, dst, *amount, &mut gas_used)
            }
            TxKind::StakeUndelegate { validator, amount } => {
                self.apply_undelegate(&sender, validator, *amount, &mut gas_used)
            }
            TxKind::StakeWithdraw {} => self.apply_withdraw(&sender, &mut gas_used),
            TxKind::RollupRegister {
                rollup_id,
                sequencer,
                scheme,
                verifying_key,
                challenge_period,
            } => self.apply_rollup_register(
                rollup_id,
                sequencer,
                *scheme,
                verifying_key,
                *challenge_period,
                &mut gas_used,
            ),
            TxKind::RollupCommit {
                rollup_id,
                batch_index,
                prev_state_root,
                post_state_root,
                da_hash,
                proof,
            } => self.apply_rollup_commit(
                &sender,
                rollup_id,
                *batch_index,
                prev_state_root,
                post_state_root,
                da_hash,
                proof,
                &mut gas_used,
            ),
            TxKind::RollupFinalize {
                rollup_id,
                batch_index,
            } => self.apply_rollup_finalize(rollup_id, *batch_index, &mut gas_used),
            TxKind::RollupFraud {
                rollup_id,
                batch_index,
                certificate,
            } => self.apply_rollup_fraud(rollup_id, *batch_index, certificate, &mut gas_used),
            TxKind::GovernancePropose {
                title,
                param_key,
                param_value,
                deposit,
            } => self.apply_gov_propose(
                &sender,
                title,
                param_key,
                param_value,
                *deposit,
                &mut gas_used,
            ),
            TxKind::GovernanceVote {
                proposal_id,
                option,
            } => self.apply_gov_vote(&sender, *proposal_id, *option, &mut gas_used),
            TxKind::GovernanceEnact { proposal_id } => {
                self.apply_gov_enact(*proposal_id, &mut gas_used)
            }
            TxKind::EvidenceDoubleSign { vote_a, vote_b } => {
                self.apply_evidence_double_sign(&sender, vote_a, vote_b, &mut gas_used)
            }
            TxKind::EvidenceDowntime { validator, missed } => {
                self.apply_evidence_downtime(&sender, validator, *missed, &mut gas_used)
            }
            TxKind::BridgeOpenChannel {
                channel_id,
                counterparty_chain,
                counterparty_channel,
            } => self.apply_bridge_open(
                &sender,
                channel_id,
                counterparty_chain,
                counterparty_channel,
                &mut gas_used,
            ),
            TxKind::BridgeSendPacket {
                channel_id,
                data,
                timeout_height,
            } => self.apply_bridge_send(&sender, channel_id, data, *timeout_height, &mut gas_used),
            TxKind::BridgeRecvPacket {
                channel_id,
                sequence,
                data,
                proof,
            } => self.apply_bridge_recv(
                &sender,
                channel_id,
                *sequence,
                data,
                proof,
                &mut gas_used,
            ),
            TxKind::BridgeAck {
                channel_id,
                sequence,
                acknowledgement,
            } => self.apply_bridge_ack(channel_id, *sequence, acknowledgement, &mut gas_used),
            TxKind::CommunityPoolSpend { to, amount, memo } => {
                self.apply_pool_spend(&sender, to, *amount, memo, &mut gas_used)
            }
            TxKind::MarketRegisterAsset {
                symbol,
                decimals,
                supply,
            } => self.apply_market_register(&sender, symbol, *decimals, *supply, &mut gas_used),
            TxKind::MarketPostOrder {
                side,
                base,
                quote,
                price_num,
                amount,
                expiry_height,
            } => self.apply_market_post(
                &sender,
                *side,
                *base,
                *quote,
                *price_num,
                *amount,
                *expiry_height,
                &mut gas_used,
            ),
            TxKind::MarketCancelOrder { order_id } => {
                self.apply_market_cancel(&sender, *order_id, &mut gas_used)
            }
            TxKind::MarketFillOrder { order_id, amount } => {
                self.apply_market_fill(&sender, *order_id, *amount, &mut gas_used)
            }
            TxKind::AmmCreatePool {
                asset_a,
                asset_b,
                amount_a,
                amount_b,
                fee_bps,
            } => self.apply_amm_create(
                &sender,
                *asset_a,
                *asset_b,
                *amount_a,
                *amount_b,
                *fee_bps,
                &mut gas_used,
            ),
            TxKind::AmmAddLiquidity {
                pool_id,
                amount_a,
                amount_b,
            } => self.apply_amm_add(&sender, *pool_id, *amount_a, *amount_b, &mut gas_used),
            TxKind::AmmRemoveLiquidity {
                pool_id,
                lp_shares,
            } => self.apply_amm_remove(&sender, *pool_id, *lp_shares, &mut gas_used),
            TxKind::AmmSwap {
                pool_id,
                asset_in,
                amount_in,
                min_out,
            } => self.apply_amm_swap(
                &sender,
                *pool_id,
                *asset_in,
                *amount_in,
                *min_out,
                &mut gas_used,
            ),
            TxKind::EscrowOpen {
                recipient,
                asset,
                amount,
                hashlock,
                timeout_height,
            } => self.apply_escrow_open(
                &sender,
                *recipient,
                *asset,
                *amount,
                *hashlock,
                *timeout_height,
                &mut gas_used,
            ),
            TxKind::EscrowClaim {
                escrow_id,
                preimage,
            } => self.apply_escrow_claim(&sender, *escrow_id, preimage, &mut gas_used),
            TxKind::EscrowRefund { escrow_id } => {
                self.apply_escrow_refund(&sender, *escrow_id, &mut gas_used)
            }
            TxKind::SettleBatch { fills } => {
                self.apply_settle_batch(&sender, fills, &mut gas_used)
            }
        };

        match result {
            Ok(()) => {
                if gas_used > tx.gas_limit {
                    return Err(StateError::InvalidTx("gas exceeds limit".into()));
                }
                let tip_cap = tx
                    .max_fee_per_gas
                    .saturating_sub(self.base_fee)
                    .min(tx.max_priority_fee_per_gas);
                let base_fee_amt = (gas_used as u128) * (self.base_fee as u128);
                let tip_amt = (gas_used as u128) * (tip_cap as u128);
                self.charge_fee_split(&sender, base_fee_amt, tip_amt, tip_to)?;
                self.bump_nonce(&sender);
                Ok(Receipt {
                    tx_hash: th,
                    status: true,
                    gas_used,
                    logs,
                    error: None,
                })
            }
            Err(e) => Ok(Receipt {
                tx_hash: th,
                status: false,
                gas_used: INTRINSIC_GAS.min(tx.gas_limit),
                logs: vec![],
                error: Some(e.to_string()),
            }),
        }
    }

    fn charge_fee_split(
        &mut self,
        from: &Address,
        burn: u128,
        tip: u128,
        tip_to: Option<&Address>,
    ) -> Result<(), StateError> {
        let total = burn.saturating_add(tip);
        let key = Self::acct_key(from);
        let acct = self.accounts.entry(key).or_default();
        if acct.balance < total {
            return Err(StateError::InsufficientBalance);
        }
        acct.balance -= total;
        self.fee_burned += burn;
        if tip > 0 {
            if let Some(to) = tip_to {
                let tk = Self::acct_key(to);
                self.accounts.entry(tk).or_default().balance += tip;
            } else {
                self.community_pool = self.community_pool.saturating_add(tip);
            }
        }
        Ok(())
    }

    fn charge_fee(&mut self, from: &Address, fee: u128) -> Result<(), StateError> {
        self.charge_fee_split(from, fee, 0, None)
    }

    fn bump_nonce(&mut self, from: &Address) {
        if let Some(acct) = self.accounts.get_mut(&Self::acct_key(from)) {
            acct.nonce += 1;
        }
    }

    fn apply_transfer(
        &mut self,
        from: &Address,
        to: &Address,
        amount: u128,
        data: &[u8],
        tx: &Transaction,
        gas_used: &mut u64,
        logs: &mut Vec<Log>,
    ) -> Result<(), StateError> {
        *gas_used += 9_000 + (data.len() as u64) * 16;
        let from_key = Self::acct_key(from);
        {
            let acct = self.accounts.entry(from_key.clone()).or_default();
            if acct.balance < amount {
                return Err(StateError::InsufficientBalance);
            }
            acct.balance -= amount;
        }
        let to_key = Self::acct_key(to);
        let has_code = self.code.contains_key(&to_key);
        {
            let dest = self.accounts.entry(to_key.clone()).or_default();
            dest.balance += amount;
        }
        if has_code && !data.is_empty() {
            let mut storage = self
                .accounts
                .get(&to_key)
                .map(|a| a.storage.clone())
                .unwrap_or_default();
            let code = self.code.get(&to_key).cloned().unwrap_or_default();
            let balances = |addr: Address| self.get_balance(&addr);
            let mut host = HostContext {
                caller: *from,
                contract: *to,
                storage: &mut storage,
                balances: &balances,
                block_height: self.height,
                block_time_ms: 0,
                call_value: amount.min(u64::MAX as u128) as u64,
            };
            let remaining = tx.gas_limit.saturating_sub(*gas_used);
            match execute(&code, &mut host, remaining) {
                Ok(vr) => {
                    *gas_used += vr.gas_used;
                    logs.extend(vr.logs);
                    if let Some(acct) = self.accounts.get_mut(&to_key) {
                        acct.storage = storage;
                    }
                    if !vr.success {
                        return Err(StateError::InvalidTx("vm failed".into()));
                    }
                }
                Err(e) => return Err(StateError::InvalidTx(e.to_string())),
            }
        }
        Ok(())
    }

    fn apply_deploy(
        &mut self,
        from: &Address,
        code: &[u8],
        salt: &Hash256,
        tx: &Transaction,
        gas_used: &mut u64,
    ) -> Result<(), StateError> {
        *gas_used += 200 * (code.len() as u64);
        let addr = deploy_address(from, tx.nonce, salt);
        let key = Self::acct_key(&addr);
        if self.code.contains_key(&key) {
            return Err(StateError::InvalidTx("contract exists".into()));
        }
        let code_hash = hash_bytes(code);
        self.code.insert(key.clone(), code.to_vec());
        let acct = self.accounts.entry(key).or_default();
        acct.code_hash = Some(code_hash);
        Ok(())
    }

    fn apply_utxo_spend(
        &mut self,
        sender: &Address,
        tx: &Transaction,
        outputs: &[TxOutput],
        gas_used: &mut u64,
    ) -> Result<(), StateError> {
        let Origin::Utxo { inputs } = &tx.origin else {
            return Err(StateError::InvalidTx("utxo origin required".into()));
        };
        *gas_used += 12_000 * (inputs.len() as u64) + 8_000 * (outputs.len() as u64);
        let mut input_sum = 0u128;
        for op in inputs {
            let key = Self::outpoint_key(op);
            let utxo = self
                .utxos
                .remove(&key)
                .ok_or(StateError::UtxoMissing)?;
            if utxo.owner != *sender {
                return Err(StateError::InvalidTx("utxo owner mismatch".into()));
            }
            input_sum += utxo.amount;
        }
        let output_sum: u128 = outputs.iter().map(|o| o.amount).sum();
        if output_sum > input_sum {
            return Err(StateError::InsufficientBalance);
        }
        // Change implicitly burned as fee extras already charged via gas; leftover returned? keep leftover as fee burn add
        let leftover = input_sum - output_sum;
        self.fee_burned += leftover;
        let th = tx_hash(tx).map_err(|e| StateError::Crypto(e.to_string()))?;
        for (i, out) in outputs.iter().enumerate() {
            let op = OutPoint {
                tx_hash: th,
                index: i as u32,
            };
            self.utxos.insert(Self::outpoint_key(&op), out.clone());
        }
        Ok(())
    }

    fn apply_shield_mint(
        &mut self,
        from: &Address,
        commitment: &Hash256,
        value: u64,
        proof: &[u8],
        gas_used: &mut u64,
    ) -> Result<(), StateError> {
        *gas_used += 100_000;
        let keys = global_keys().ok_or_else(|| StateError::Zk("zk keys not loaded".into()))?;
        let publics = ShieldPublicInputs {
            commitment: *commitment,
            value,
        };
        verify_shield(&keys.shielded_vk, proof, &publics)
            .map_err(|e| StateError::Zk(e.to_string()))?;
        let amount = value as u128;
        let acct = self.accounts.entry(Self::acct_key(from)).or_default();
        if acct.balance < amount {
            return Err(StateError::InsufficientBalance);
        }
        acct.balance -= amount;
        self.append_note(commitment)?;
        self.shielded_value += amount;
        Ok(())
    }

    fn apply_shielded_transfer(
        &mut self,
        anchor: &Hash256,
        commitments: &[Hash256],
        nullifiers: &[Hash256],
        fee: u64,
        proof: &[u8],
        gas_used: &mut u64,
    ) -> Result<(), StateError> {
        *gas_used += 250_000;
        if commitments.len() != 1 || nullifiers.len() != 1 {
            return Err(StateError::InvalidTx(
                "v0.2 transfer supports 1-in 1-out".into(),
            ));
        }
        let current_anchor = self.notes_root();
        if *anchor != current_anchor {
            return Err(StateError::InvalidTx("stale shielded anchor".into()));
        }
        let keys = global_keys().ok_or_else(|| StateError::Zk("zk keys not loaded".into()))?;
        let publics = TransferPublicInputs {
            anchor: *anchor,
            nullifier: nullifiers[0],
            cm_out: commitments[0],
            fee,
        };
        verify_transfer(&keys.shielded_vk, proof, &publics)
            .map_err(|e| StateError::Zk(e.to_string()))?;
        let nf_key = hex::encode(nullifiers[0]);
        if !self.nullifiers.insert(nf_key) {
            return Err(StateError::InvalidTx("nullifier reused".into()));
        }
        self.append_note(&commitments[0])?;
        // Fee is paid from shielded value (burned); conservation enforced by circuit.
        self.shielded_value = self
            .shielded_value
            .saturating_sub(fee as u128);
        self.fee_burned += fee as u128;
        Ok(())
    }

    fn apply_unshield(
        &mut self,
        to: &Address,
        anchor: &Hash256,
        nullifier: &Hash256,
        value: u64,
        proof: &[u8],
        gas_used: &mut u64,
    ) -> Result<(), StateError> {
        *gas_used += 200_000;
        let current_anchor = self.notes_root();
        if *anchor != current_anchor {
            return Err(StateError::InvalidTx("stale shielded anchor".into()));
        }
        let keys = global_keys().ok_or_else(|| StateError::Zk("zk keys not loaded".into()))?;
        let publics = UnshieldPublicInputs {
            anchor: *anchor,
            nullifier: *nullifier,
            value,
        };
        verify_unshield(&keys.shielded_vk, proof, &publics)
            .map_err(|e| StateError::Zk(e.to_string()))?;
        let nf_key = hex::encode(nullifier);
        if !self.nullifiers.insert(nf_key) {
            return Err(StateError::InvalidTx("nullifier reused".into()));
        }
        let amount = value as u128;
        if self.shielded_value < amount {
            return Err(StateError::InvalidTx("shielded supply underflow".into()));
        }
        self.shielded_value -= amount;
        let acct = self.accounts.entry(Self::acct_key(to)).or_default();
        acct.balance += amount;
        Ok(())
    }

    fn append_note(&mut self, commitment: &Hash256) -> Result<(), StateError> {
        let key = hex::encode(commitment);
        if !self.notes.insert(key) {
            return Err(StateError::InvalidTx("duplicate note commitment".into()));
        }
        self.note_leaves.push(*commitment);
        Ok(())
    }

    fn apply_bond(
        &mut self,
        from: &Address,
        amount: u128,
        commission_bps: u16,
        gas_used: &mut u64,
    ) -> Result<(), StateError> {
        *gas_used += 40_000;
        if amount < self.params.min_validator_stake && !self.validators.contains_key(&Self::acct_key(from)) {
            // allow top-ups below min if already validator; first bond must meet min
        }
        let key = Self::acct_key(from);
        if matches!(self.params.hybrid_mode, HybridMode::Allowlist)
            && !self.allowlist.is_empty()
            && !self.allowlist.contains(&key)
        {
            return Err(StateError::HybridDenied);
        }
        if commission_bps > 10_000 {
            return Err(StateError::InvalidTx("commission_bps > 10000".into()));
        }
        let acct = self.accounts.entry(key.clone()).or_default();
        if acct.balance < amount {
            return Err(StateError::InsufficientBalance);
        }
        let is_new = !self.validators.contains_key(&key);
        if is_new && amount < self.params.min_validator_stake {
            return Err(StateError::InvalidTx("below min_validator_stake".into()));
        }
        if is_new && self.validators.len() >= self.params.max_validators {
            return Err(StateError::InvalidTx("max validators reached".into()));
        }
        acct.balance -= amount;
        acct.bonded += amount;
        let power = acct.bonded;
        let entry = self.validators.entry(key).or_insert(ValidatorInfo {
            address: *from,
            public_key: vec![],
            power: 0,
            commission_bps,
            jailed: false,
            shares: 0,
            tombstoned: false,
            jail_until_epoch: 0,
        });
        if entry.tombstoned {
            return Err(StateError::InvalidTx("validator tombstoned".into()));
        }
        entry.power = power;
        entry.shares = entry.shares.saturating_add(amount);
        entry.commission_bps = commission_bps;
        Ok(())
    }

    fn apply_unbond(
        &mut self,
        from: &Address,
        amount: u128,
        gas_used: &mut u64,
    ) -> Result<(), StateError> {
        *gas_used += 40_000;
        let key = Self::acct_key(from);
        let acct = self.accounts.entry(key.clone()).or_default();
        if acct.bonded < amount {
            return Err(StateError::InsufficientBalance);
        }
        acct.bonded -= amount;
        if let Some(v) = self.validators.get_mut(&key) {
            v.power = acct.bonded;
            v.shares = v.shares.saturating_sub(amount);
        }
        let id = self.next_unbond_id;
        self.next_unbond_id += 1;
        self.unbonding.push(UnbondingEntry {
            id,
            owner: *from,
            validator: *from,
            amount,
            unlock_epoch: self.epoch.saturating_add(self.params.unbonding_period),
        });
        Ok(())
    }

    fn delegation_key(delegator: &Address, validator: &Address) -> String {
        format!("{}|{}", hex::encode(delegator), hex::encode(validator))
    }

    fn apply_delegate(
        &mut self,
        from: &Address,
        validator: &Address,
        amount: u128,
        gas_used: &mut u64,
    ) -> Result<(), StateError> {
        *gas_used += 45_000;
        if amount == 0 {
            return Err(StateError::InvalidTx("zero delegation".into()));
        }
        let vkey = Self::acct_key(validator);
        let val = self
            .validators
            .get(&vkey)
            .ok_or_else(|| StateError::InvalidTx("unknown validator".into()))?
            .clone();
        if val.jailed {
            return Err(StateError::InvalidTx("validator jailed".into()));
        }
        let from_key = Self::acct_key(from);
        let acct = self.accounts.entry(from_key).or_default();
        if acct.balance < amount {
            return Err(StateError::InsufficientBalance);
        }
        acct.balance -= amount;
        // Mint shares 1:1 with amount for reference exchange rate.
        let shares = amount;
        let dkey = Self::delegation_key(from, validator);
        let entry = self.delegations.entry(dkey).or_insert(Delegation {
            delegator: *from,
            validator: *validator,
            shares: 0,
        });
        entry.shares = entry.shares.saturating_add(shares);
        if let Some(v) = self.validators.get_mut(&vkey) {
            v.power = v.power.saturating_add(amount);
            v.shares = v.shares.saturating_add(shares);
        }
        Ok(())
    }

    fn apply_redelegate(
        &mut self,
        from: &Address,
        src: &Address,
        dst: &Address,
        amount: u128,
        gas_used: &mut u64,
    ) -> Result<(), StateError> {
        *gas_used += 55_000;
        if src == dst {
            return Err(StateError::InvalidTx("src == dst".into()));
        }
        if amount == 0 {
            return Err(StateError::InvalidTx("zero redelegate".into()));
        }
        let dkey = Self::delegation_key(from, src);
        {
            let d = self
                .delegations
                .get_mut(&dkey)
                .ok_or_else(|| StateError::InvalidTx("no delegation".into()))?;
            if d.shares < amount {
                return Err(StateError::InsufficientBalance);
            }
            d.shares -= amount;
        }
        if self
            .delegations
            .get(&dkey)
            .map(|d| d.shares == 0)
            .unwrap_or(true)
        {
            self.delegations.remove(&dkey);
        }
        let skey = Self::acct_key(src);
        if let Some(v) = self.validators.get_mut(&skey) {
            v.power = v.power.saturating_sub(amount);
            v.shares = v.shares.saturating_sub(amount);
        }
        let dst_key = Self::acct_key(dst);
        let dst_val = self
            .validators
            .get(&dst_key)
            .ok_or_else(|| StateError::InvalidTx("unknown dst validator".into()))?
            .clone();
        if dst_val.jailed {
            return Err(StateError::InvalidTx("dst validator jailed".into()));
        }
        let dkey_dst = Self::delegation_key(from, dst);
        let entry = self.delegations.entry(dkey_dst).or_insert(Delegation {
            delegator: *from,
            validator: *dst,
            shares: 0,
        });
        entry.shares = entry.shares.saturating_add(amount);
        if let Some(v) = self.validators.get_mut(&dst_key) {
            v.power = v.power.saturating_add(amount);
            v.shares = v.shares.saturating_add(amount);
        }
        Ok(())
    }

    fn apply_undelegate(
        &mut self,
        from: &Address,
        validator: &Address,
        amount: u128,
        gas_used: &mut u64,
    ) -> Result<(), StateError> {
        *gas_used += 45_000;
        if amount == 0 {
            return Err(StateError::InvalidTx("zero undelegate".into()));
        }
        let dkey = Self::delegation_key(from, validator);
        {
            let d = self
                .delegations
                .get_mut(&dkey)
                .ok_or_else(|| StateError::InvalidTx("no delegation".into()))?;
            if d.shares < amount {
                return Err(StateError::InsufficientBalance);
            }
            d.shares -= amount;
        }
        if self
            .delegations
            .get(&dkey)
            .map(|d| d.shares == 0)
            .unwrap_or(true)
        {
            self.delegations.remove(&dkey);
        }
        let vkey = Self::acct_key(validator);
        if let Some(v) = self.validators.get_mut(&vkey) {
            v.power = v.power.saturating_sub(amount);
            v.shares = v.shares.saturating_sub(amount);
        }
        let id = self.next_unbond_id;
        self.next_unbond_id += 1;
        self.unbonding.push(UnbondingEntry {
            id,
            owner: *from,
            validator: *validator,
            amount,
            unlock_epoch: self.epoch.saturating_add(self.params.unbonding_period),
        });
        Ok(())
    }

    fn apply_withdraw(
        &mut self,
        from: &Address,
        gas_used: &mut u64,
    ) -> Result<(), StateError> {
        *gas_used += 30_000;
        let mut claim = 0u128;
        let mut remain = Vec::new();
        for e in self.unbonding.drain(..) {
            if e.owner == *from && e.unlock_epoch <= self.epoch {
                claim = claim.saturating_add(e.amount);
            } else {
                remain.push(e);
            }
        }
        self.unbonding = remain;
        if claim == 0 {
            return Err(StateError::InvalidTx("nothing to withdraw".into()));
        }
        let key = Self::acct_key(from);
        let acct = self.accounts.entry(key).or_default();
        acct.balance = acct.balance.saturating_add(claim);
        Ok(())
    }

    fn apply_rollup_register(
        &mut self,
        rollup_id: &Hash256,
        sequencer: &Address,
        scheme: u8,
        verifying_key: &[u8],
        challenge_period: u64,
        gas_used: &mut u64,
    ) -> Result<(), StateError> {
        *gas_used += 50_000;
        let scheme = RollupScheme::from_u8(scheme).map_err(|e| StateError::Rollup(e.to_string()))?;
        if matches!(scheme, RollupScheme::Groth16) && verifying_key.is_empty() {
            return Err(StateError::Rollup(
                "groth16 rollup requires verifying_key".into(),
            ));
        }
        if matches!(scheme, RollupScheme::Noop) {
            let allow = std::env::var("AETHER_ALLOW_NOOP_ROLLUP")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if !allow {
                return Err(StateError::Rollup(
                    "noop scheme disabled; use 0x01/0x02/0x03".into(),
                ));
            }
        }
        let key = hex::encode(rollup_id);
        if self.rollups.contains_key(&key) {
            return Err(StateError::Rollup("already registered".into()));
        }
        self.rollups.insert(
            key,
            RollupInfo {
                rollup_id: *rollup_id,
                sequencer: *sequencer,
                scheme: scheme as u8,
                last_batch: 0,
                state_root: zero_hash(),
                verifying_key: verifying_key.to_vec(),
                challenge_period: if challenge_period == 0 {
                    10
                } else {
                    challenge_period
                },
            },
        );
        Ok(())
    }

    fn load_rollup_vk(bytes: &[u8]) -> Result<Option<RollupVerifyingKey>, StateError> {
        if bytes.is_empty() {
            return Ok(None);
        }
        let vk = ark_groth16::VerifyingKey::<ark_bn254::Bn254>::deserialize_compressed(
            &mut &bytes[..],
        )
        .map_err(|e| StateError::Rollup(format!("bad vk: {e}")))?;
        Ok(Some(RollupVerifyingKey { groth16: vk }))
    }

    fn apply_rollup_commit(
        &mut self,
        sender: &Address,
        rollup_id: &Hash256,
        batch_index: u64,
        prev: &Hash256,
        post: &Hash256,
        da: &Hash256,
        proof: &[u8],
        gas_used: &mut u64,
    ) -> Result<(), StateError> {
        *gas_used += 150_000;
        let key = hex::encode(rollup_id);
        let rollup = self
            .rollups
            .get(&key)
            .cloned()
            .ok_or_else(|| StateError::Rollup("unknown rollup".into()))?;
        if rollup.sequencer != *sender {
            return Err(StateError::Rollup("unauthorized sequencer".into()));
        }
        let expected = if rollup.last_batch == 0 { 1 } else { rollup.last_batch + 1 };
        if batch_index != expected {
            return Err(StateError::Rollup(format!(
                "bad batch index: got {batch_index}, expected {expected}"
            )));
        }
        if rollup.last_batch > 0 && *prev != rollup.state_root {
            return Err(StateError::Rollup("prev state mismatch".into()));
        }
        let scheme =
            RollupScheme::from_u8(rollup.scheme).map_err(|e| StateError::Rollup(e.to_string()))?;
        let inputs = RollupPublicInputs {
            prev_state_root: *prev,
            post_state_root: *post,
            da_hash: *da,
            batch_index,
        };
        let vk = Self::load_rollup_vk(&rollup.verifying_key)?;
        let vk_ref = vk.as_ref();
        // Prefer registered vk; fall back to global for matching keys
        let global = global_keys();
        let effective_vk = vk_ref.or(global.as_ref().map(|g| &g.rollup_vk));

        let outcome = verify_rollup(
            scheme,
            effective_vk,
            proof,
            &inputs,
            None,
            self.height,
        )
        .map_err(|e| StateError::Rollup(e.to_string()))?;

        match outcome {
            RollupVerifyOutcome::Final => {
                let rollup = self.rollups.get_mut(&key).unwrap();
                rollup.last_batch = batch_index;
                rollup.state_root = *post;
            }
            RollupVerifyOutcome::Pending => {
                let pk = Self::pending_key(rollup_id, batch_index);
                self.pending_rollups.insert(
                    pk,
                    PendingBatch {
                        rollup_id: *rollup_id,
                        batch_index,
                        prev_state_root: *prev,
                        post_state_root: *post,
                        da_hash: *da,
                        submitted_height: self.height,
                        challenge_period: rollup.challenge_period,
                        challenged: false,
                        finalized: false,
                    },
                );
            }
            RollupVerifyOutcome::FraudProven => {
                return Err(StateError::Rollup(
                    "fraud proof not valid on commit path".into(),
                ));
            }
        }
        Ok(())
    }

    fn apply_rollup_finalize(
        &mut self,
        rollup_id: &Hash256,
        batch_index: u64,
        gas_used: &mut u64,
    ) -> Result<(), StateError> {
        *gas_used += 30_000;
        let pk = Self::pending_key(rollup_id, batch_index);
        let pending = self
            .pending_rollups
            .get(&pk)
            .cloned()
            .ok_or_else(|| StateError::Rollup("no pending batch".into()))?;
        if pending.challenged {
            return Err(StateError::Rollup("batch was challenged".into()));
        }
        let mature = self.height
            >= pending
                .submitted_height
                .saturating_add(pending.challenge_period);
        if !mature {
            return Err(StateError::Rollup("challenge window still open".into()));
        }
        let key = hex::encode(rollup_id);
        let rollup = self
            .rollups
            .get_mut(&key)
            .ok_or_else(|| StateError::Rollup("unknown rollup".into()))?;
        rollup.last_batch = batch_index;
        rollup.state_root = pending.post_state_root;
        if let Some(p) = self.pending_rollups.get_mut(&pk) {
            p.finalized = true;
        }
        Ok(())
    }

    fn apply_rollup_fraud(
        &mut self,
        rollup_id: &Hash256,
        batch_index: u64,
        certificate: &[u8],
        gas_used: &mut u64,
    ) -> Result<(), StateError> {
        *gas_used += 80_000;
        let pk = Self::pending_key(rollup_id, batch_index);
        let pending = self
            .pending_rollups
            .get_mut(&pk)
            .ok_or_else(|| StateError::Rollup("no pending batch".into()))?;
        if pending.finalized {
            return Err(StateError::Rollup("already finalized".into()));
        }
        let mature = self.height
            >= pending
                .submitted_height
                .saturating_add(pending.challenge_period);
        if mature {
            return Err(StateError::Rollup("challenge window closed".into()));
        }
        let cert: FraudCertificate = serde_json::from_slice(certificate)
            .map_err(|e| StateError::Rollup(format!("bad fraud cert: {e}")))?;
        verify_fraud_certificate(&cert, &pending.post_state_root)
            .map_err(|e| StateError::Rollup(e.to_string()))?;
        pending.challenged = true;
        Ok(())
    }

    fn apply_gov_propose(
        &mut self,
        from: &Address,
        title: &str,
        param_key: &str,
        param_value: &str,
        deposit: u128,
        gas_used: &mut u64,
    ) -> Result<(), StateError> {
        *gas_used += 60_000;
        if deposit < 100 * WEI_PER_AETH {
            return Err(StateError::InvalidTx("min deposit 100 AETH".into()));
        }
        if !is_known_param(param_key) {
            return Err(StateError::InvalidTx(format!("unknown param {param_key}")));
        }
        let acct = self.accounts.entry(Self::acct_key(from)).or_default();
        if acct.balance < deposit {
            return Err(StateError::InsufficientBalance);
        }
        acct.balance -= deposit;
        let id = self.next_proposal_id;
        self.next_proposal_id += 1;
        let voting_end = self.height.saturating_add(50);
        self.proposals.insert(
            id,
            GovernanceProposal {
                id,
                title: title.to_string(),
                param_key: param_key.to_string(),
                param_value: param_value.to_string(),
                proposer: *from,
                deposit,
                yes: 0,
                no: 0,
                abstain: 0,
                veto: 0,
                voting_end_height: voting_end,
                enact_height: None,
                status: "voting".into(),
            },
        );
        Ok(())
    }

    fn apply_gov_vote(
        &mut self,
        from: &Address,
        proposal_id: u64,
        option: u8,
        gas_used: &mut u64,
    ) -> Result<(), StateError> {
        *gas_used += 25_000;
        let power = self
            .validators
            .get(&Self::acct_key(from))
            .map(|v| v.power)
            .unwrap_or(0);
        if power == 0 {
            return Err(StateError::InvalidTx("voter not bonded".into()));
        }
        let proposal = self
            .proposals
            .get_mut(&proposal_id)
            .ok_or_else(|| StateError::InvalidTx("unknown proposal".into()))?;
        if proposal.status != "voting" {
            return Err(StateError::InvalidTx("not in voting".into()));
        }
        if self.height > proposal.voting_end_height {
            return Err(StateError::InvalidTx("voting ended".into()));
        }
        match option {
            0 => proposal.no = proposal.no.saturating_add(power),
            1 => proposal.yes = proposal.yes.saturating_add(power),
            2 => proposal.abstain = proposal.abstain.saturating_add(power),
            3 => proposal.veto = proposal.veto.saturating_add(power),
            _ => return Err(StateError::InvalidTx("bad vote option".into())),
        }
        Ok(())
    }

    fn apply_gov_enact(&mut self, proposal_id: u64, gas_used: &mut u64) -> Result<(), StateError> {
        *gas_used += 40_000;
        let snapshot = self
            .proposals
            .get(&proposal_id)
            .cloned()
            .ok_or_else(|| StateError::InvalidTx("unknown proposal".into()))?;
        if self.height <= snapshot.voting_end_height {
            return Err(StateError::InvalidTx("voting still open".into()));
        }
        let participating = snapshot
            .yes
            .saturating_add(snapshot.no)
            .saturating_add(snapshot.abstain)
            .saturating_add(snapshot.veto);
        let decisive = snapshot
            .yes
            .saturating_add(snapshot.no)
            .saturating_add(snapshot.veto);
        let passed = participating > 0
            && decisive > 0
            && snapshot.yes * 2 > decisive
            && snapshot.veto * 3 <= participating;

        if !passed {
            let dep = snapshot.deposit;
            let proposer = snapshot.proposer;
            if let Some(p) = self.proposals.get_mut(&proposal_id) {
                p.status = "failed".into();
                p.deposit = 0;
            }
            let acct = self.accounts.entry(Self::acct_key(&proposer)).or_default();
            acct.balance = acct.balance.saturating_add(dep);
            return Ok(());
        }

        if self.height < snapshot.voting_end_height.saturating_add(1) {
            return Err(StateError::InvalidTx("timelock".into()));
        }
        self.apply_param(&snapshot.param_key, &snapshot.param_value)?;
        let dep = snapshot.deposit;
        let proposer = snapshot.proposer;
        if let Some(p) = self.proposals.get_mut(&proposal_id) {
            p.status = "enacted".into();
            p.enact_height = Some(self.height);
            p.deposit = 0;
        }
        let acct = self.accounts.entry(Self::acct_key(&proposer)).or_default();
        acct.balance = acct.balance.saturating_add(dep);
        Ok(())
    }

    fn slash_validator(
        &mut self,
        validator: &Address,
        bps: u16,
        reason: &str,
        permanent: bool,
    ) -> Result<(), StateError> {
        let key = Self::acct_key(validator);
        let val = self
            .validators
            .get_mut(&key)
            .ok_or_else(|| StateError::InvalidTx("unknown validator".into()))?;
        if val.tombstoned {
            return Err(StateError::InvalidTx("already tombstoned".into()));
        }
        let acct = self.accounts.entry(key.clone()).or_default();
        // Reference: slash is taken from self-bonded stake (delegator haircut reserved).
        let slash_amt = acct.bonded.saturating_mul(bps as u128) / 10_000;
        if slash_amt == 0 && acct.bonded == 0 {
            // Still jail even if already fully unbonded.
        } else {
            let burned = slash_amt / 2;
            let to_pool = slash_amt.saturating_sub(burned);
            acct.bonded = acct.bonded.saturating_sub(slash_amt);
            self.fee_burned = self.fee_burned.saturating_add(burned);
            self.community_pool = self.community_pool.saturating_add(to_pool);
            if let Some(v) = self.validators.get_mut(&key) {
                v.power = v.power.saturating_sub(slash_amt);
                v.shares = v.shares.saturating_sub(slash_amt);
            }
            self.slash_log.push(SlashEvent {
                height: self.height,
                validator: *validator,
                reason: reason.into(),
                slashed: slash_amt,
                burned,
                to_pool,
            });
        }
        if let Some(v) = self.validators.get_mut(&key) {
            v.jailed = true;
            v.jail_until_epoch = if permanent {
                u64::MAX
            } else {
                self.epoch.saturating_add(2)
            };
            if permanent {
                v.tombstoned = true;
            }
        }
        Ok(())
    }

    fn apply_evidence_double_sign(
        &mut self,
        _reporter: &Address,
        vote_a: &[u8],
        vote_b: &[u8],
        gas_used: &mut u64,
    ) -> Result<(), StateError> {
        *gas_used += 80_000;
        if vote_a == vote_b {
            return Err(StateError::InvalidTx("identical votes".into()));
        }
        let evid_hash = hex::encode(hash_bytes(&[vote_a, vote_b].concat()));
        if self.evidence_seen.contains(&evid_hash) {
            return Err(StateError::InvalidTx("evidence replay".into()));
        }
        let a: aether_consensus::Vote = serde_json::from_slice(vote_a)
            .map_err(|e| StateError::InvalidTx(format!("vote_a: {e}")))?;
        let b: aether_consensus::Vote = serde_json::from_slice(vote_b)
            .map_err(|e| StateError::InvalidTx(format!("vote_b: {e}")))?;
        if a.validator != b.validator {
            return Err(StateError::InvalidTx("validators differ".into()));
        }
        if a.height != b.height || a.round != b.round {
            return Err(StateError::InvalidTx("height/round mismatch".into()));
        }
        if a.block_hash == b.block_hash {
            return Err(StateError::InvalidTx("same block hash".into()));
        }
        if a.vote_type != b.vote_type {
            return Err(StateError::InvalidTx("vote type mismatch".into()));
        }
        self.slash_validator(&a.validator, SLASH_DOUBLE_SIGN_BPS, "double_sign", true)?;
        self.evidence_seen.insert(evid_hash);
        Ok(())
    }

    fn apply_evidence_downtime(
        &mut self,
        _reporter: &Address,
        validator: &Address,
        missed: u64,
        gas_used: &mut u64,
    ) -> Result<(), StateError> {
        *gas_used += 50_000;
        if missed < 50 {
            return Err(StateError::InvalidTx("missed threshold 50".into()));
        }
        let evid_hash = hex::encode(hash_bytes(
            &[
                validator.as_slice(),
                &missed.to_le_bytes(),
                &self.epoch.to_le_bytes(),
            ]
            .concat(),
        ));
        if self.evidence_seen.contains(&evid_hash) {
            return Err(StateError::InvalidTx("evidence replay".into()));
        }
        self.slash_validator(validator, SLASH_DOWNTIME_BPS, "downtime", false)?;
        self.evidence_seen.insert(evid_hash);
        Ok(())
    }

    fn apply_bridge_open(
        &mut self,
        _from: &Address,
        channel_id: &str,
        counterparty_chain: &str,
        counterparty_channel: &str,
        gas_used: &mut u64,
    ) -> Result<(), StateError> {
        *gas_used += 60_000;
        if channel_id.is_empty() || counterparty_chain.is_empty() {
            return Err(StateError::InvalidTx("empty channel fields".into()));
        }
        if self.bridges.contains_key(channel_id) {
            return Err(StateError::InvalidTx("channel exists".into()));
        }
        self.bridges.insert(
            channel_id.to_string(),
            BridgeChannel {
                channel_id: channel_id.to_string(),
                counterparty_chain: counterparty_chain.to_string(),
                counterparty_channel: counterparty_channel.to_string(),
                next_send_seq: 1,
                next_recv_seq: 1,
                closed: false,
            },
        );
        Ok(())
    }

    fn apply_bridge_send(
        &mut self,
        _from: &Address,
        channel_id: &str,
        data: &[u8],
        timeout_height: u64,
        gas_used: &mut u64,
    ) -> Result<(), StateError> {
        *gas_used += 40_000 + (data.len() as u64) * 8;
        let ch = self
            .bridges
            .get_mut(channel_id)
            .ok_or_else(|| StateError::InvalidTx("unknown channel".into()))?;
        if ch.closed {
            return Err(StateError::InvalidTx("channel closed".into()));
        }
        let seq = ch.next_send_seq;
        ch.next_send_seq += 1;
        let key = format!("{channel_id}:{seq}");
        self.bridge_packets.insert(
            key,
            BridgePacket {
                channel_id: channel_id.to_string(),
                sequence: seq,
                data: data.to_vec(),
                timeout_height,
                status: "sent".into(),
            },
        );
        Ok(())
    }

    fn apply_bridge_recv(
        &mut self,
        _from: &Address,
        channel_id: &str,
        sequence: u64,
        data: &[u8],
        proof: &[u8],
        gas_used: &mut u64,
    ) -> Result<(), StateError> {
        *gas_used += 50_000;
        let ch = self
            .bridges
            .get_mut(channel_id)
            .ok_or_else(|| StateError::InvalidTx("unknown channel".into()))?;
        if ch.closed {
            return Err(StateError::InvalidTx("channel closed".into()));
        }
        if sequence != ch.next_recv_seq {
            return Err(StateError::InvalidTx("out of order packet".into()));
        }
        // Reference: light client proof is BLAKE3 commitment of payload (relayer-trusted).
        let expect = hash_bytes(
            &[
                channel_id.as_bytes(),
                &sequence.to_le_bytes(),
                data,
            ]
            .concat(),
        );
        if proof != expect.as_slice() {
            return Err(StateError::InvalidTx("bad packet proof".into()));
        }
        ch.next_recv_seq += 1;
        let key = format!("{channel_id}:recv:{sequence}");
        self.bridge_packets.insert(
            key,
            BridgePacket {
                channel_id: channel_id.to_string(),
                sequence,
                data: data.to_vec(),
                timeout_height: 0,
                status: "received".into(),
            },
        );
        Ok(())
    }

    fn apply_bridge_ack(
        &mut self,
        channel_id: &str,
        sequence: u64,
        acknowledgement: &[u8],
        gas_used: &mut u64,
    ) -> Result<(), StateError> {
        *gas_used += 30_000;
        let key = format!("{channel_id}:{sequence}");
        let pkt = self
            .bridge_packets
            .get_mut(&key)
            .ok_or_else(|| StateError::InvalidTx("unknown packet".into()))?;
        if pkt.status != "sent" {
            return Err(StateError::InvalidTx("packet not awaiting ack".into()));
        }
        pkt.status = "acked".into();
        pkt.data = acknowledgement.to_vec();
        Ok(())
    }

    fn apply_pool_spend(
        &mut self,
        from: &Address,
        to: &Address,
        amount: u128,
        memo: &str,
        gas_used: &mut u64,
    ) -> Result<(), StateError> {
        *gas_used += 35_000;
        // Reference: any bonded validator may propose a spend ≤ 1% of pool per tx.
        let power = self
            .validators
            .get(&Self::acct_key(from))
            .map(|v| v.power)
            .unwrap_or(0);
        if power == 0 {
            return Err(StateError::InvalidTx("only validators may spend pool".into()));
        }
        if amount == 0 || memo.len() > 256 {
            return Err(StateError::InvalidTx("bad spend params".into()));
        }
        let cap = self.community_pool / 100;
        if amount > cap.max(1) {
            return Err(StateError::InvalidTx("exceeds 1% pool cap".into()));
        }
        if self.community_pool < amount {
            return Err(StateError::InsufficientBalance);
        }
        self.community_pool -= amount;
        self.accounts
            .entry(Self::acct_key(to))
            .or_default()
            .balance += amount;
        Ok(())
    }

    fn is_native(asset: &Hash256) -> bool {
        *asset == NATIVE_ASSET
    }

    fn asset_bal_key(addr: &Address, asset: &Hash256) -> String {
        format!("{}|{}", hex::encode(addr), hex::encode(asset))
    }

    fn get_asset_balance(&self, addr: &Address, asset: &Hash256) -> u128 {
        if Self::is_native(asset) {
            self.get_balance(addr)
        } else {
            self.asset_balances
                .get(&Self::asset_bal_key(addr, asset))
                .copied()
                .unwrap_or(0)
        }
    }

    fn debit_asset(
        &mut self,
        addr: &Address,
        asset: &Hash256,
        amount: u128,
    ) -> Result<(), StateError> {
        if amount == 0 {
            return Ok(());
        }
        if Self::is_native(asset) {
            let key = Self::acct_key(addr);
            let acct = self.accounts.entry(key).or_default();
            if acct.balance < amount {
                return Err(StateError::InsufficientBalance);
            }
            acct.balance -= amount;
        } else {
            let key = Self::asset_bal_key(addr, asset);
            let bal = self.asset_balances.entry(key).or_insert(0);
            if *bal < amount {
                return Err(StateError::InsufficientBalance);
            }
            *bal -= amount;
        }
        Ok(())
    }

    fn credit_asset(&mut self, addr: &Address, asset: &Hash256, amount: u128) {
        if amount == 0 {
            return;
        }
        if Self::is_native(asset) {
            self.accounts
                .entry(Self::acct_key(addr))
                .or_default()
                .balance += amount;
        } else {
            let key = Self::asset_bal_key(addr, asset);
            *self.asset_balances.entry(key).or_insert(0) += amount;
        }
    }

    fn lock_native(&mut self, amount: u128) {
        self.market_locked_native = self.market_locked_native.saturating_add(amount);
    }

    fn unlock_native(&mut self, amount: u128) {
        self.market_locked_native = self.market_locked_native.saturating_sub(amount);
    }

    fn quote_for_base(base_amount: u128, price_num: u128) -> Result<u128, StateError> {
        base_amount
            .checked_mul(price_num)
            .and_then(|v| v.checked_div(PRICE_SCALE))
            .filter(|v| *v > 0 || base_amount == 0)
            .ok_or_else(|| StateError::InvalidTx("quote overflow".into()))
    }

    fn apply_market_register(
        &mut self,
        from: &Address,
        symbol: &str,
        decimals: u8,
        supply: u128,
        gas_used: &mut u64,
    ) -> Result<(), StateError> {
        *gas_used += 50_000;
        if symbol.is_empty() || symbol.len() > 16 || !symbol.chars().all(|c| c.is_ascii_alphanumeric())
        {
            return Err(StateError::InvalidTx("bad symbol".into()));
        }
        if supply == 0 {
            return Err(StateError::InvalidTx("zero supply".into()));
        }
        let asset_id = hash_bytes(
            &[
                b"aether-asset",
                from.as_slice(),
                symbol.as_bytes(),
                &supply.to_le_bytes(),
            ]
            .concat(),
        );
        let key = hex::encode(asset_id);
        if self.assets.contains_key(&key) {
            return Err(StateError::InvalidTx("asset exists".into()));
        }
        self.assets.insert(
            key,
            AssetMeta {
                asset_id,
                symbol: symbol.to_string(),
                decimals,
                issuer: *from,
                total_supply: supply,
            },
        );
        self.credit_asset(from, &asset_id, supply);
        Ok(())
    }

    fn apply_market_post(
        &mut self,
        from: &Address,
        side: OrderSide,
        base: Hash256,
        quote: Hash256,
        price_num: u128,
        amount: u128,
        expiry_height: u64,
        gas_used: &mut u64,
    ) -> Result<(), StateError> {
        *gas_used += 55_000;
        if amount == 0 || price_num == 0 || base == quote {
            return Err(StateError::InvalidTx("bad order params".into()));
        }
        if expiry_height != 0 && expiry_height <= self.height {
            return Err(StateError::InvalidTx("already expired".into()));
        }
        let quote_amt = Self::quote_for_base(amount, price_num)?;
        let (lock_asset, lock_amt) = match side {
            OrderSide::Sell => (base, amount),
            OrderSide::Buy => (quote, quote_amt),
        };
        self.debit_asset(from, &lock_asset, lock_amt)?;
        let mut locked_native = 0u128;
        if Self::is_native(&lock_asset) {
            self.lock_native(lock_amt);
            locked_native = lock_amt;
        }
        let id = self.next_order_id;
        self.next_order_id = self.next_order_id.saturating_add(1);
        self.orders.insert(
            id,
            LimitOrder {
                id,
                maker: *from,
                side,
                base,
                quote,
                price_num,
                amount_remaining: amount,
                expiry_height,
                locked_native,
                status: "open".into(),
            },
        );
        Ok(())
    }

    fn apply_market_cancel(
        &mut self,
        from: &Address,
        order_id: u64,
        gas_used: &mut u64,
    ) -> Result<(), StateError> {
        *gas_used += 30_000;
        let order = self
            .orders
            .get(&order_id)
            .cloned()
            .ok_or_else(|| StateError::InvalidTx("order missing".into()))?;
        if order.maker != *from {
            return Err(StateError::InvalidTx("not maker".into()));
        }
        if order.status != "open" {
            return Err(StateError::InvalidTx("not open".into()));
        }
        let refund_asset = match order.side {
            OrderSide::Sell => order.base,
            OrderSide::Buy => order.quote,
        };
        let refund = match order.side {
            OrderSide::Sell => order.amount_remaining,
            OrderSide::Buy => Self::quote_for_base(order.amount_remaining, order.price_num)?,
        };
        let locked_native = order.locked_native.min(refund);
        if let Some(o) = self.orders.get_mut(&order_id) {
            o.amount_remaining = 0;
            o.locked_native = 0;
            o.status = "cancelled".into();
        }
        if Self::is_native(&refund_asset) {
            self.unlock_native(locked_native);
        }
        self.credit_asset(&order.maker, &refund_asset, refund);
        Ok(())
    }

    fn apply_market_fill(
        &mut self,
        taker: &Address,
        order_id: u64,
        amount: u128,
        gas_used: &mut u64,
    ) -> Result<(), StateError> {
        *gas_used += 70_000;
        self.fill_order(taker, order_id, amount)
    }

    fn fill_order(
        &mut self,
        taker: &Address,
        order_id: u64,
        amount: u128,
    ) -> Result<(), StateError> {
        if amount == 0 {
            return Err(StateError::InvalidTx("zero fill".into()));
        }
        let order = self
            .orders
            .get(&order_id)
            .cloned()
            .ok_or_else(|| StateError::InvalidTx("order missing".into()))?;
        if order.status != "open" {
            return Err(StateError::InvalidTx("not open".into()));
        }
        if order.expiry_height != 0 && self.height >= order.expiry_height {
            return Err(StateError::InvalidTx("expired".into()));
        }
        if amount > order.amount_remaining {
            return Err(StateError::InvalidTx("overfill".into()));
        }
        let quote_amt = Self::quote_for_base(amount, order.price_num)?;
        match order.side {
            OrderSide::Sell => {
                // Maker sold base (already locked). Taker pays quote, receives base.
                self.debit_asset(taker, &order.quote, quote_amt)?;
                self.credit_asset(taker, &order.base, amount);
                self.credit_asset(&order.maker, &order.quote, quote_amt);
                if Self::is_native(&order.base) {
                    self.unlock_native(amount);
                }
            }
            OrderSide::Buy => {
                // Maker locked quote. Taker delivers base, receives quote.
                self.debit_asset(taker, &order.base, amount)?;
                self.credit_asset(taker, &order.quote, quote_amt);
                self.credit_asset(&order.maker, &order.base, amount);
                if Self::is_native(&order.quote) {
                    self.unlock_native(quote_amt);
                }
            }
        }
        let o = self.orders.get_mut(&order_id).unwrap();
        o.amount_remaining -= amount;
        o.locked_native = o.locked_native.saturating_sub(match o.side {
            OrderSide::Sell => amount,
            OrderSide::Buy => quote_amt,
        });
        if o.amount_remaining == 0 {
            o.status = "filled".into();
        }
        Ok(())
    }

    fn apply_settle_batch(
        &mut self,
        taker: &Address,
        fills: &[SettleFill],
        gas_used: &mut u64,
    ) -> Result<(), StateError> {
        *gas_used += 40_000 + (fills.len() as u64) * 25_000;
        if fills.is_empty() || fills.len() > 64 {
            return Err(StateError::InvalidTx("bad batch size".into()));
        }
        for f in fills {
            self.fill_order(taker, f.order_id, f.amount)?;
        }
        Ok(())
    }

    fn apply_amm_create(
        &mut self,
        from: &Address,
        asset_a: Hash256,
        asset_b: Hash256,
        amount_a: u128,
        amount_b: u128,
        fee_bps: u16,
        gas_used: &mut u64,
    ) -> Result<(), StateError> {
        *gas_used += 80_000;
        if asset_a == asset_b || amount_a == 0 || amount_b == 0 || fee_bps > 10_000 {
            return Err(StateError::InvalidTx("bad pool params".into()));
        }
        let pool_id = hash_bytes(
            &[
                b"aether-amm",
                from.as_slice(),
                asset_a.as_slice(),
                asset_b.as_slice(),
                &amount_a.to_le_bytes(),
                &amount_b.to_le_bytes(),
            ]
            .concat(),
        );
        let key = hex::encode(pool_id);
        if self.pools.contains_key(&key) {
            return Err(StateError::InvalidTx("pool exists".into()));
        }
        self.debit_asset(from, &asset_a, amount_a)?;
        self.debit_asset(from, &asset_b, amount_b)?;
        if Self::is_native(&asset_a) {
            self.lock_native(amount_a);
        }
        if Self::is_native(&asset_b) {
            self.lock_native(amount_b);
        }
        let lp = integer_sqrt(amount_a.saturating_mul(amount_b)).max(1);
        let mut shares = BTreeMap::new();
        shares.insert(Self::acct_key(from), lp);
        self.pools.insert(
            key,
            AmmPool {
                pool_id,
                asset_a,
                asset_b,
                reserve_a: amount_a,
                reserve_b: amount_b,
                lp_supply: lp,
                fee_bps,
                lp_shares: shares,
            },
        );
        Ok(())
    }

    fn apply_amm_add(
        &mut self,
        from: &Address,
        pool_id: Hash256,
        amount_a: u128,
        amount_b: u128,
        gas_used: &mut u64,
    ) -> Result<(), StateError> {
        *gas_used += 60_000;
        let key = hex::encode(pool_id);
        let pool = self
            .pools
            .get(&key)
            .cloned()
            .ok_or_else(|| StateError::InvalidTx("pool missing".into()))?;
        if amount_a == 0 || amount_b == 0 {
            return Err(StateError::InvalidTx("zero liquidity".into()));
        }
        // Require proportional deposit within 1%
        let expect_b = amount_a
            .checked_mul(pool.reserve_b)
            .and_then(|v| v.checked_div(pool.reserve_a.max(1)))
            .unwrap_or(0);
        let drift = amount_b.abs_diff(expect_b);
        if expect_b > 0 && drift * 100 > expect_b {
            return Err(StateError::InvalidTx("imbalanced add".into()));
        }
        self.debit_asset(from, &pool.asset_a, amount_a)?;
        self.debit_asset(from, &pool.asset_b, amount_b)?;
        if Self::is_native(&pool.asset_a) {
            self.lock_native(amount_a);
        }
        if Self::is_native(&pool.asset_b) {
            self.lock_native(amount_b);
        }
        let minted = amount_a
            .checked_mul(pool.lp_supply)
            .and_then(|v| v.checked_div(pool.reserve_a.max(1)))
            .unwrap_or(0)
            .max(1);
        let p = self.pools.get_mut(&key).unwrap();
        p.reserve_a += amount_a;
        p.reserve_b += amount_b;
        p.lp_supply += minted;
        *p.lp_shares.entry(Self::acct_key(from)).or_insert(0) += minted;
        Ok(())
    }

    fn apply_amm_remove(
        &mut self,
        from: &Address,
        pool_id: Hash256,
        lp_shares: u128,
        gas_used: &mut u64,
    ) -> Result<(), StateError> {
        *gas_used += 55_000;
        let key = hex::encode(pool_id);
        let pool = self
            .pools
            .get(&key)
            .cloned()
            .ok_or_else(|| StateError::InvalidTx("pool missing".into()))?;
        let owned = pool
            .lp_shares
            .get(&Self::acct_key(from))
            .copied()
            .unwrap_or(0);
        if lp_shares == 0 || lp_shares > owned {
            return Err(StateError::InvalidTx("bad lp amount".into()));
        }
        let out_a = lp_shares
            .checked_mul(pool.reserve_a)
            .and_then(|v| v.checked_div(pool.lp_supply.max(1)))
            .unwrap_or(0);
        let out_b = lp_shares
            .checked_mul(pool.reserve_b)
            .and_then(|v| v.checked_div(pool.lp_supply.max(1)))
            .unwrap_or(0);
        let p = self.pools.get_mut(&key).unwrap();
        p.reserve_a -= out_a;
        p.reserve_b -= out_b;
        p.lp_supply -= lp_shares;
        let entry = p.lp_shares.entry(Self::acct_key(from)).or_insert(0);
        *entry -= lp_shares;
        if Self::is_native(&pool.asset_a) {
            self.unlock_native(out_a);
        }
        if Self::is_native(&pool.asset_b) {
            self.unlock_native(out_b);
        }
        self.credit_asset(from, &pool.asset_a, out_a);
        self.credit_asset(from, &pool.asset_b, out_b);
        Ok(())
    }

    fn apply_amm_swap(
        &mut self,
        from: &Address,
        pool_id: Hash256,
        asset_in: Hash256,
        amount_in: u128,
        min_out: u128,
        gas_used: &mut u64,
    ) -> Result<(), StateError> {
        *gas_used += 65_000;
        let key = hex::encode(pool_id);
        let pool = self
            .pools
            .get(&key)
            .cloned()
            .ok_or_else(|| StateError::InvalidTx("pool missing".into()))?;
        if amount_in == 0 {
            return Err(StateError::InvalidTx("zero swap".into()));
        }
        let (reserve_in, reserve_out, asset_out) = if asset_in == pool.asset_a {
            (pool.reserve_a, pool.reserve_b, pool.asset_b)
        } else if asset_in == pool.asset_b {
            (pool.reserve_b, pool.reserve_a, pool.asset_a)
        } else {
            return Err(StateError::InvalidTx("asset not in pool".into()));
        };
        let fee_mul = 10_000u128.saturating_sub(pool.fee_bps as u128);
        let amount_in_with_fee = amount_in
            .checked_mul(fee_mul)
            .ok_or_else(|| StateError::InvalidTx("fee overflow".into()))?
            / 10_000;
        let numerator = amount_in_with_fee
            .checked_mul(reserve_out)
            .ok_or_else(|| StateError::InvalidTx("swap overflow".into()))?;
        let denominator = reserve_in
            .checked_add(amount_in_with_fee)
            .ok_or_else(|| StateError::InvalidTx("swap overflow".into()))?;
        let amount_out = numerator / denominator;
        if amount_out < min_out {
            return Err(StateError::InvalidTx("slippage".into()));
        }
        self.debit_asset(from, &asset_in, amount_in)?;
        if Self::is_native(&asset_in) {
            self.lock_native(amount_in);
        }
        if Self::is_native(&asset_out) {
            self.unlock_native(amount_out);
        }
        self.credit_asset(from, &asset_out, amount_out);
        let p = self.pools.get_mut(&key).unwrap();
        if asset_in == p.asset_a {
            p.reserve_a += amount_in;
            p.reserve_b -= amount_out;
        } else {
            p.reserve_b += amount_in;
            p.reserve_a -= amount_out;
        }
        Ok(())
    }

    fn apply_escrow_open(
        &mut self,
        from: &Address,
        recipient: Address,
        asset: Hash256,
        amount: u128,
        hashlock: Hash256,
        timeout_height: u64,
        gas_used: &mut u64,
    ) -> Result<(), StateError> {
        *gas_used += 45_000;
        if amount == 0 || timeout_height <= self.height {
            return Err(StateError::InvalidTx("bad escrow params".into()));
        }
        if hashlock == zero_hash() {
            return Err(StateError::InvalidTx("empty hashlock".into()));
        }
        self.debit_asset(from, &asset, amount)?;
        if Self::is_native(&asset) {
            self.lock_native(amount);
        }
        let id = self.next_escrow_id;
        self.next_escrow_id = self.next_escrow_id.saturating_add(1);
        self.escrows.insert(
            id,
            Escrow {
                id,
                sender: *from,
                recipient,
                asset,
                amount,
                hashlock,
                timeout_height,
                status: "open".into(),
            },
        );
        Ok(())
    }

    fn apply_escrow_claim(
        &mut self,
        claimer: &Address,
        escrow_id: u64,
        preimage: &[u8],
        gas_used: &mut u64,
    ) -> Result<(), StateError> {
        *gas_used += 40_000;
        let esc = self
            .escrows
            .get(&escrow_id)
            .cloned()
            .ok_or_else(|| StateError::InvalidTx("escrow missing".into()))?;
        if esc.status != "open" {
            return Err(StateError::InvalidTx("not open".into()));
        }
        if *claimer != esc.recipient {
            return Err(StateError::InvalidTx("not recipient".into()));
        }
        let digest = hash_bytes(preimage);
        if digest != esc.hashlock {
            return Err(StateError::InvalidTx("bad preimage".into()));
        }
        if let Some(e) = self.escrows.get_mut(&escrow_id) {
            e.status = "claimed".into();
        }
        if Self::is_native(&esc.asset) {
            self.unlock_native(esc.amount);
        }
        self.credit_asset(&esc.recipient, &esc.asset, esc.amount);
        Ok(())
    }

    fn apply_escrow_refund(
        &mut self,
        from: &Address,
        escrow_id: u64,
        gas_used: &mut u64,
    ) -> Result<(), StateError> {
        *gas_used += 35_000;
        let esc = self
            .escrows
            .get(&escrow_id)
            .cloned()
            .ok_or_else(|| StateError::InvalidTx("escrow missing".into()))?;
        if esc.status != "open" {
            return Err(StateError::InvalidTx("not open".into()));
        }
        if *from != esc.sender {
            return Err(StateError::InvalidTx("not sender".into()));
        }
        if self.height < esc.timeout_height {
            return Err(StateError::InvalidTx("timeout not reached".into()));
        }
        if let Some(e) = self.escrows.get_mut(&escrow_id) {
            e.status = "refunded".into();
        }
        if Self::is_native(&esc.asset) {
            self.unlock_native(esc.amount);
        }
        self.credit_asset(&esc.sender, &esc.asset, esc.amount);
        Ok(())
    }

    fn apply_param(&mut self, key: &str, value: &str) -> Result<(), StateError> {
        match key {
            "epoch_length" => {
                self.params.epoch_length = value
                    .parse()
                    .map_err(|_| StateError::InvalidTx("bad epoch_length".into()))?;
            }
            "max_validators" => {
                self.params.max_validators = value
                    .parse()
                    .map_err(|_| StateError::InvalidTx("bad max_validators".into()))?;
            }
            "gas_limit" => {
                self.params.gas_limit = value
                    .parse()
                    .map_err(|_| StateError::InvalidTx("bad gas_limit".into()))?;
            }
            "unbonding_period" => {
                self.params.unbonding_period = value
                    .parse()
                    .map_err(|_| StateError::InvalidTx("bad unbonding_period".into()))?;
            }
            "hybrid_mode" => {
                self.params.hybrid_mode = match value {
                    "allowlist" => HybridMode::Allowlist,
                    "mixed" => HybridMode::Mixed,
                    "public" => HybridMode::Public,
                    _ => return Err(StateError::InvalidTx("bad hybrid_mode".into())),
                };
            }
            "block_time_ms" => {
                self.params.block_time_ms = value
                    .parse()
                    .map_err(|_| StateError::InvalidTx("bad block_time_ms".into()))?;
            }
            _ => return Err(StateError::InvalidTx("unknown param".into())),
        }
        Ok(())
    }

    pub fn adjust_base_fee(&mut self, gas_used: u64) {
        let target = self.params.gas_limit / 2;
        if target == 0 {
            return;
        }
        let base = self.base_fee as i128;
        let delta = (gas_used as i128 - target as i128) * base / (target as i128 * 8);
        let next = (base + delta).max(1) as u64;
        self.base_fee = next;
    }
}

fn is_known_param(key: &str) -> bool {
    matches!(
        key,
        "epoch_length"
            | "max_validators"
            | "gas_limit"
            | "unbonding_period"
            | "hybrid_mode"
            | "block_time_ms"
            | "min_validator_stake"
    )
}

pub struct NodeLedger {
    pub state: RwLock<ChainState>,
    pub blocks: RwLock<Vec<Block>>,
    pub receipts: RwLock<HashMap<String, Receipt>>,
    pub mempool: RwLock<Mempool>,
    pub commits: RwLock<HashMap<u64, Vec<u8>>>,
}

impl NodeLedger {
    pub fn new(genesis: Genesis) -> Arc<Self> {
        let state = ChainState::from_genesis(&genesis);
        let genesis_header = Header {
            version: WIRE_VERSION,
            chain_id: genesis.chain_id.clone(),
            height: 0,
            time_unix_ms: genesis.timestamp,
            prev_hash: zero_hash(),
            tx_root: merkle_root(&[]),
            state_root: state.compute_state_root(),
            receipts_root: merkle_root(&[]),
            proposer: zero_address(),
            round: 0,
            epoch: 0,
            gas_used: 0,
            gas_limit: genesis.params.gas_limit,
            base_fee: DEFAULT_BASE_FEE,
            signature: vec![],
        };
        Arc::new(Self {
            state: RwLock::new(state),
            blocks: RwLock::new(vec![Block {
                header: genesis_header,
                transactions: vec![],
            }]),
            receipts: RwLock::new(HashMap::new()),
            mempool: RwLock::new(Mempool::default()),
            commits: RwLock::new(HashMap::new()),
        })
    }

    pub fn with_filter(self: &Arc<Self>, filter: Arc<dyn TxFilter>) {
        let max = self.mempool.read().len().max(5_000);
        *self.mempool.write() = Mempool::new(max.max(5_000), filter);
    }

    pub fn submit_tx(&self, tx: Transaction) -> Result<Hash256, StateError> {
        self.mempool.write().insert(tx)
    }

    pub fn produce_block(&self, proposer: &Keypair) -> Result<Block, StateError> {
        let mut state = self.state.write();
        let blocks = self.blocks.read();
        let prev = blocks.last().expect("genesis");
        let prev_hash = block_hash(&prev.header).map_err(|e| StateError::Crypto(e.to_string()))?;
        let height = prev.header.height + 1;
        drop(blocks);

        let txs = self.mempool.write().drain_prioritized();

        let mut applied = Vec::new();
        let mut receipt_hashes: Vec<Hash256> = Vec::new();
        let mut gas_used_total = 0u64;

        for tx in txs {
            if gas_used_total >= state.params.gas_limit {
                self.mempool.write().requeue(tx);
                continue;
            }
            match state.apply_tx(&tx, Some(&proposer.address())) {
                Ok(receipt) => {
                    gas_used_total += receipt.gas_used;
                    let status = receipt.status;
                    receipt_hashes.push(receipt.tx_hash);
                    let h = hex::encode(receipt.tx_hash);
                    self.receipts.write().insert(h, receipt);
                    if status {
                        applied.push(tx);
                    }
                }
                Err(e) => {
                    info!("dropping tx: {e}");
                }
            }
        }

        state.adjust_base_fee(gas_used_total);
        state.height = height;
        state.epoch = height / state.params.epoch_length.max(1);
        state.verify_supply_invariant()?;

        let tx_hashes: Result<Vec<_>, _> = applied
            .iter()
            .map(|t| tx_hash(t).map_err(|e| StateError::Crypto(e.to_string())))
            .collect();
        let tx_hashes = tx_hashes?;

        let mut header = Header {
            version: WIRE_VERSION,
            chain_id: state.params.chain_id.clone(),
            height,
            time_unix_ms: chrono_now(),
            prev_hash,
            tx_root: merkle_root(&tx_hashes),
            state_root: state.compute_state_root(),
            receipts_root: merkle_root(&receipt_hashes),
            proposer: proposer.address(),
            round: 0,
            epoch: state.epoch,
            gas_used: gas_used_total,
            gas_limit: state.params.gas_limit,
            base_fee: state.base_fee,
            signature: vec![],
        };
        aether_crypto::sign_header(&mut header, proposer)
            .map_err(|e| StateError::Crypto(e.to_string()))?;

        let block = Block {
            header,
            transactions: applied,
        };
        self.blocks.write().push(block.clone());
        Ok(block)
    }
}

fn chrono_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Integer square root (Babylonian method) for initial LP shares.
fn integer_sqrt(n: u128) -> u128 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = x.saturating_add(1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

#[cfg(test)]
mod market_tests {
    use super::*;
    use aether_crypto::Keypair;

    fn funded_state(alice: &Keypair, bob: &Keypair) -> ChainState {
        let g = Genesis {
            chain_id: "aether-test".into(),
            alloc: vec![
                GenesisAlloc {
                    address: alice.address(),
                    balance: 1_000_000 * WEI_PER_AETH,
                },
                GenesisAlloc {
                    address: bob.address(),
                    balance: 1_000_000 * WEI_PER_AETH,
                },
            ],
            validators: vec![GenesisValidator {
                address: alice.address(),
                public_key: alice.public_bytes(),
                power: 10_000 * WEI_PER_AETH,
            }],
            params: ChainParams::default(),
            timestamp: 0,
        };
        ChainState::from_genesis(&g)
    }

    #[test]
    fn brokerless_sell_fill_preserves_supply() {
        let alice = Keypair::generate();
        let bob = Keypair::generate();
        let mut state = funded_state(&alice, &bob);
        state.height = 1;

        // Register quote asset for bob to hold
        let mut gas = 0u64;
        state
            .apply_market_register(&bob.address(), "USD", 6, 10_000_000, &mut gas)
            .unwrap();
        let quote = state.assets.values().next().unwrap().asset_id;

        // Alice sells 1000 wei AETH for quote at price 2 * PRICE_SCALE (2 quote per base)
        gas = 0;
        state
            .apply_market_post(
                &alice.address(),
                OrderSide::Sell,
                NATIVE_ASSET,
                quote,
                2 * PRICE_SCALE,
                1_000,
                0,
                &mut gas,
            )
            .unwrap();
        assert_eq!(state.market_locked_native, 1_000);
        state.verify_supply_invariant().unwrap();

        // Bob fills 500
        gas = 0;
        state
            .apply_market_fill(&bob.address(), 1, 500, &mut gas)
            .unwrap();
        assert_eq!(state.market_locked_native, 500);
        state.verify_supply_invariant().unwrap();
    }

    #[test]
    fn amm_swap_roundtrip_k() {
        let alice = Keypair::generate();
        let bob = Keypair::generate();
        let mut state = funded_state(&alice, &bob);
        let mut gas = 0u64;
        state
            .apply_market_register(&alice.address(), "TKN", 9, 1_000_000, &mut gas)
            .unwrap();
        let tkn = state.assets.values().next().unwrap().asset_id;
        gas = 0;
        state
            .apply_amm_create(
                &alice.address(),
                NATIVE_ASSET,
                tkn,
                10_000,
                10_000,
                30,
                &mut gas,
            )
            .unwrap();
        let pool_id = state.pools.values().next().unwrap().pool_id;
        let k_before = {
            let p = state.pools.values().next().unwrap();
            p.reserve_a * p.reserve_b
        };
        gas = 0;
        state
            .apply_amm_swap(&bob.address(), pool_id, NATIVE_ASSET, 1_000, 1, &mut gas)
            .unwrap();
        let k_after = {
            let p = state.pools.values().next().unwrap();
            p.reserve_a * p.reserve_b
        };
        assert!(k_after >= k_before);
        state.verify_supply_invariant().unwrap();
    }
}

