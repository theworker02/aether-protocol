use aether_crypto::{block_hash, tagged_hash, Keypair};
use aether_types::{
    Address, Block, Hash256, LightHeader, ValidatorInfo,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vote {
    pub height: u64,
    pub round: u32,
    pub block_hash: Hash256,
    pub validator: Address,
    pub signature: Vec<u8>,
    #[serde(default)]
    pub vote_type: VoteType,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VoteType {
    #[default]
    Prevote,
    Precommit,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitCertificate {
    pub height: u64,
    pub round: u32,
    pub block_hash: Hash256,
    pub votes: Vec<Vote>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    NewRound,
    Propose,
    Prevote,
    Precommit,
    Commit,
}

/// Per-height AetherBFT engine state (Tendermint-inspired).
#[derive(Clone, Debug)]
pub struct ConsensusEngine {
    pub height: u64,
    pub round: u32,
    pub step: Step,
    pub locked_round: i64,
    pub locked_value: Option<Hash256>,
    pub valid_round: i64,
    pub valid_value: Option<Hash256>,
    pub prevotes: HashMap<(u32, Hash256), Vec<Vote>>,
    pub precommits: HashMap<(u32, Hash256), Vec<Vote>>,
}

impl ConsensusEngine {
    pub fn new(height: u64) -> Self {
        Self {
            height,
            round: 0,
            step: Step::NewRound,
            locked_round: -1,
            locked_value: None,
            valid_round: -1,
            valid_value: None,
            prevotes: HashMap::new(),
            precommits: HashMap::new(),
        }
    }

    pub fn enter_new_round(&mut self, round: u32) {
        self.round = round;
        self.step = Step::NewRound;
    }

    pub fn record_prevote(&mut self, vote: Vote) {
        self.prevotes
            .entry((vote.round, vote.block_hash))
            .or_default()
            .push(vote);
    }

    pub fn record_precommit(&mut self, vote: Vote) {
        self.precommits
            .entry((vote.round, vote.block_hash))
            .or_default()
            .push(vote);
    }

    pub fn try_lock_on_prevote_quorum(
        &mut self,
        validators: &[ValidatorInfo],
    ) -> Option<Hash256> {
        for ((round, hash), votes) in &self.prevotes {
            if *round == self.round && has_quorum(votes, validators) {
                self.locked_round = *round as i64;
                self.locked_value = Some(*hash);
                self.valid_round = *round as i64;
                self.valid_value = Some(*hash);
                self.step = Step::Precommit;
                return Some(*hash);
            }
        }
        None
    }

    pub fn try_commit(&mut self, validators: &[ValidatorInfo]) -> Option<CommitCertificate> {
        for ((round, hash), votes) in &self.precommits {
            if *round == self.round && has_quorum(votes, validators) {
                self.step = Step::Commit;
                return Some(commit_from_votes(self.height, *round, *hash, votes.clone()));
            }
        }
        None
    }
}

pub fn select_proposer(validators: &[ValidatorInfo], height: u64, round: u32) -> Option<Address> {
    let active: Vec<_> = validators
        .iter()
        .filter(|v| !v.jailed && v.power > 0)
        .collect();
    if active.is_empty() {
        return None;
    }
    let total: u128 = active.iter().map(|v| v.power).sum();
    let seed = tagged_hash(
        "AETH/PROPOSER",
        &[
            height.to_le_bytes().as_slice(),
            &round.to_le_bytes(),
            &total.to_le_bytes(),
        ]
        .concat(),
    );
    let mut pick = u128::from_le_bytes(seed[..16].try_into().unwrap()) % total.max(1);
    for v in &active {
        if pick < v.power {
            return Some(v.address);
        }
        pick -= v.power;
    }
    Some(active[0].address)
}

pub fn has_quorum(votes: &[Vote], validators: &[ValidatorInfo]) -> bool {
    let total: u128 = validators
        .iter()
        .filter(|v| !v.jailed)
        .map(|v| v.power)
        .sum();
    if total == 0 {
        return false;
    }
    let mut seen = std::collections::HashSet::new();
    let mut power = 0u128;
    for vote in votes {
        if !seen.insert(vote.validator) {
            continue;
        }
        if let Some(v) = validators.iter().find(|x| x.address == vote.validator) {
            power = power.saturating_add(v.power);
        }
    }
    power.saturating_mul(3) > total.saturating_mul(2)
}

pub fn make_vote(
    kp: &Keypair,
    height: u64,
    round: u32,
    block_hash: Hash256,
    vote_type: VoteType,
) -> Vote {
    let mut msg = Vec::new();
    msg.extend_from_slice(&height.to_le_bytes());
    msg.extend_from_slice(&round.to_le_bytes());
    msg.extend_from_slice(&block_hash);
    msg.push(match vote_type {
        VoteType::Prevote => 0,
        VoteType::Precommit => 1,
    });
    let signature = kp.sign(&tagged_hash("AETH/VOTE/V1", &msg));
    Vote {
        height,
        round,
        block_hash,
        validator: kp.address(),
        signature,
        vote_type,
    }
}

pub fn commit_from_votes(
    height: u64,
    round: u32,
    block_hash: Hash256,
    votes: Vec<Vote>,
) -> CommitCertificate {
    CommitCertificate {
        height,
        round,
        block_hash,
        votes,
    }
}

/// Solo-validator convenience: produce a commit cert for a block hash.
pub fn solo_commit(kp: &Keypair, height: u64, round: u32, block_hash: Hash256) -> CommitCertificate {
    let vote = make_vote(kp, height, round, block_hash, VoteType::Precommit);
    commit_from_votes(height, round, block_hash, vec![vote])
}

pub fn light_header_from_block(block: &Block, validators_hash: Hash256) -> Result<LightHeader, String> {
    let hash = block_hash(&block.header).map_err(|e| e.to_string())?;
    Ok(LightHeader {
        height: block.header.height,
        epoch: block.header.epoch,
        hash,
        prev_hash: block.header.prev_hash,
        state_root: block.header.state_root,
        validators_hash,
        time_unix_ms: block.header.time_unix_ms,
        gas_used: block.header.gas_used,
        base_fee: block.header.base_fee,
    })
}

/// Verify sequential light headers (no commit crypto in v0.2 solo path — checks linkage).
pub fn verify_light_transition(prev: &LightHeader, next: &LightHeader) -> Result<(), String> {
    if next.height != prev.height + 1 {
        return Err(format!(
            "height gap: {} -> {}",
            prev.height, next.height
        ));
    }
    if next.prev_hash != prev.hash {
        return Err("prev_hash mismatch".into());
    }
    if next.time_unix_ms + 60_000 < prev.time_unix_ms {
        return Err("time went backwards beyond skew".into());
    }
    Ok(())
}

pub fn validators_hash(validators: &[ValidatorInfo]) -> Hash256 {
    let bytes = serde_json::to_vec(validators).unwrap_or_default();
    tagged_hash("AETH/VALSET/V1", &bytes)
}

pub fn timeout_propose_ms(round: u32) -> u64 {
    500 + (round as u64) * 250
}

pub fn timeout_prevote_ms(round: u32) -> u64 {
    500 + (round as u64) * 250
}

pub fn timeout_precommit_ms(round: u32) -> u64 {
    500 + (round as u64) * 250
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether_types::zero_hash;

    #[test]
    fn quorum_two_thirds() {
        let vals = vec![
            ValidatorInfo {
                address: [1u8; 20],
                public_key: vec![],
                power: 70,
                commission_bps: 0,
                jailed: false,
            },
            ValidatorInfo {
                address: [2u8; 20],
                public_key: vec![],
                power: 30,
                commission_bps: 0,
                jailed: false,
            },
        ];
        let votes = vec![Vote {
            height: 1,
            round: 0,
            block_hash: zero_hash(),
            validator: [1u8; 20],
            signature: vec![],
            vote_type: VoteType::Precommit,
        }];
        assert!(has_quorum(&votes, &vals));
    }
}
