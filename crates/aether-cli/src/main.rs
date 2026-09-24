use aether_crypto::{sign_tx, Keypair};
use aether_types::*;
use aether_zk::field::fr_to_bytes;
use aether_zk::{
    compute_valid_post_root, load_or_setup_keys, note_commitment, pk_from_address, prove_rollup_groth16,
    prove_rollup_plonk, prove_shield, sk_from_secret, FrBytes, Note, RollupPublicInputs,
};
use anyhow::{bail, Result};
use ark_bn254::Fr;
use ark_ff::UniformRand;
use clap::{Parser, Subcommand};
use rand::rngs::OsRng;
use serde_json::json;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "aether", about = "Aether Protocol CLI")]
struct Cli {
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
    #[arg(long, default_value = "data/zk_keys.json")]
    zk_keys: PathBuf,
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Keygen,
    Info,
    Account { address: String },
    Transfer {
        #[arg(long)]
        secret: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u128,
    },
    Bond {
        #[arg(long)]
        secret: String,
        #[arg(long)]
        amount: u128,
    },
    Delegate {
        #[arg(long)]
        secret: String,
        #[arg(long)]
        validator: String,
        #[arg(long)]
        amount: u128,
    },
    Undelegate {
        #[arg(long)]
        secret: String,
        #[arg(long)]
        validator: String,
        #[arg(long)]
        amount: u128,
    },
    Withdraw {
        #[arg(long)]
        secret: String,
    },
    Block {
        #[arg(long)]
        number: Option<u64>,
    },
    /// Shield transparent AETH into a note (Groth16)
    Shield {
        #[arg(long)]
        secret: String,
        #[arg(long)]
        value: u64,
        /// Optional path to write note JSON for later spend
        #[arg(long)]
        note_out: Option<PathBuf>,
    },
    /// Register a rollup with production verifier scheme
    RollupRegister {
        #[arg(long)]
        secret: String,
        #[arg(long, default_value = "1")]
        scheme: u8,
        #[arg(long, default_value_t = 10)]
        challenge_period: u64,
    },
    /// Prove + commit a rollup batch (schemes 0x01 / 0x02)
    RollupCommit {
        #[arg(long)]
        secret: String,
        #[arg(long)]
        rollup_id: String,
        #[arg(long)]
        batch_index: u64,
        #[arg(long)]
        prev: String,
        #[arg(long)]
        da: String,
        #[arg(long, default_value = "1")]
        scheme: u8,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Commands::Keygen => {
            let kp = Keypair::generate();
            println!("address: {}", hex_addr(&kp.address()));
            println!("pubkey:  {}", hex::encode(kp.public_bytes()));
            println!("secret:  {}", hex::encode(kp.signing.to_bytes()));
        }
        Commands::Info => {
            let v = rpc(&cli.rpc, "aeth_protocolInfo", json!([])).await?;
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        Commands::Account { address } => {
            let v = rpc(&cli.rpc, "aeth_getAccount", json!([address])).await?;
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        Commands::Transfer { secret, to, amount } => {
            let kp = kp_from_secret(&secret)?;
            let from = kp.address();
            let acct = rpc(&cli.rpc, "aeth_getAccount", json!([hex_addr(&from)])).await?;
            let nonce = acct["nonce"].as_u64().unwrap_or(0);
            let to_addr = parse_addr(&to).map_err(|e| anyhow::anyhow!(e))?;
            let mut tx = Transaction {
                version: 1,
                nonce,
                origin: Origin::Account { from },
                kind: TxKind::Transfer {
                    to: to_addr,
                    amount,
                    data: vec![],
                },
                gas_limit: 100_000,
                max_fee_per_gas: 10_000,
                max_priority_fee_per_gas: 1,
                signature: vec![],
                public_key: vec![],
            };
            sign_tx(&mut tx, &kp)?;
            let h = rpc(&cli.rpc, "aeth_sendRawTransaction", json!([tx])).await?;
            println!("submitted: {}", h);
        }
        Commands::Bond { secret, amount } => {
            let kp = kp_from_secret(&secret)?;
            let from = kp.address();
            let acct = rpc(&cli.rpc, "aeth_getAccount", json!([hex_addr(&from)])).await?;
            let nonce = acct["nonce"].as_u64().unwrap_or(0);
            let mut tx = Transaction {
                version: 1,
                nonce,
                origin: Origin::Account { from },
                kind: TxKind::StakeBond {
                    amount,
                    commission_bps: 500,
                },
                gas_limit: 100_000,
                max_fee_per_gas: 10_000,
                max_priority_fee_per_gas: 1,
                signature: vec![],
                public_key: vec![],
            };
            sign_tx(&mut tx, &kp)?;
            let h = rpc(&cli.rpc, "aeth_sendRawTransaction", json!([tx])).await?;
            println!("submitted: {}", h);
        }
        Commands::Delegate {
            secret,
            validator,
            amount,
        } => {
            let kp = kp_from_secret(&secret)?;
            let from = kp.address();
            let acct = rpc(&cli.rpc, "aeth_getAccount", json!([hex_addr(&from)])).await?;
            let nonce = acct["nonce"].as_u64().unwrap_or(0);
            let validator = parse_addr(&validator).map_err(|e| anyhow::anyhow!(e))?;
            let mut tx = Transaction {
                version: 1,
                nonce,
                origin: Origin::Account { from },
                kind: TxKind::StakeDelegate { validator, amount },
                gas_limit: 100_000,
                max_fee_per_gas: 10_000,
                max_priority_fee_per_gas: 1,
                signature: vec![],
                public_key: vec![],
            };
            sign_tx(&mut tx, &kp)?;
            let h = rpc(&cli.rpc, "aeth_sendRawTransaction", json!([tx])).await?;
            println!("submitted: {}", h);
        }
        Commands::Undelegate {
            secret,
            validator,
            amount,
        } => {
            let kp = kp_from_secret(&secret)?;
            let from = kp.address();
            let acct = rpc(&cli.rpc, "aeth_getAccount", json!([hex_addr(&from)])).await?;
            let nonce = acct["nonce"].as_u64().unwrap_or(0);
            let validator = parse_addr(&validator).map_err(|e| anyhow::anyhow!(e))?;
            let mut tx = Transaction {
                version: 1,
                nonce,
                origin: Origin::Account { from },
                kind: TxKind::StakeUndelegate { validator, amount },
                gas_limit: 100_000,
                max_fee_per_gas: 10_000,
                max_priority_fee_per_gas: 1,
                signature: vec![],
                public_key: vec![],
            };
            sign_tx(&mut tx, &kp)?;
            let h = rpc(&cli.rpc, "aeth_sendRawTransaction", json!([tx])).await?;
            println!("submitted: {}", h);
        }
        Commands::Withdraw { secret } => {
            let kp = kp_from_secret(&secret)?;
            let from = kp.address();
            let acct = rpc(&cli.rpc, "aeth_getAccount", json!([hex_addr(&from)])).await?;
            let nonce = acct["nonce"].as_u64().unwrap_or(0);
            let mut tx = Transaction {
                version: 1,
                nonce,
                origin: Origin::Account { from },
                kind: TxKind::StakeWithdraw {},
                gas_limit: 100_000,
                max_fee_per_gas: 10_000,
                max_priority_fee_per_gas: 1,
                signature: vec![],
                public_key: vec![],
            };
            sign_tx(&mut tx, &kp)?;
            let h = rpc(&cli.rpc, "aeth_sendRawTransaction", json!([tx])).await?;
            println!("submitted: {}", h);
        }
        Commands::Block { number } => {
            let n = match number {
                Some(n) => n,
                None => rpc(&cli.rpc, "aeth_blockNumber", json!([]))
                    .await?
                    .as_u64()
                    .unwrap_or(0),
            };
            let v = rpc(&cli.rpc, "aeth_getBlockByNumber", json!([n])).await?;
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        Commands::Shield {
            secret,
            value,
            note_out,
        } => {
            let keys = load_or_setup_keys(Some(cli.zk_keys.clone()))
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
            let kp = kp_from_secret(&secret)?;
            let from = kp.address();
            let mut rng = OsRng;
            let note = Note {
                value,
                recipient_pk: FrBytes::from_fr(&pk_from_address(&from)),
                rseed: FrBytes::random(&mut rng),
            };
            let (proof, publics) = prove_shield(&keys.shielded_pk, &note)
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
            let acct = rpc(&cli.rpc, "aeth_getAccount", json!([hex_addr(&from)])).await?;
            let nonce = acct["nonce"].as_u64().unwrap_or(0);
            let mut tx = Transaction {
                version: 1,
                nonce,
                origin: Origin::Account { from },
                kind: TxKind::ShieldedShield {
                    commitment: publics.commitment,
                    value: publics.value,
                    proof,
                },
                gas_limit: 500_000,
                max_fee_per_gas: 10_000,
                max_priority_fee_per_gas: 1,
                signature: vec![],
                public_key: vec![],
            };
            sign_tx(&mut tx, &kp)?;
            let h = rpc(&cli.rpc, "aeth_sendRawTransaction", json!([tx])).await?;
            println!("submitted: {}", h);
            println!("commitment: {}", hex_hash(&publics.commitment));
            println!("cm_fr: {}", hex::encode(fr_to_bytes(&note_commitment(&note))));
            if let Some(path) = note_out {
                let sk = sk_from_secret(&kp.signing.to_bytes());
                let blob = json!({
                    "value": note.value,
                    "recipient_pk": hex::encode(note.recipient_pk.0),
                    "rseed": hex::encode(note.rseed.0),
                    "sk": hex::encode(fr_to_bytes(&sk)),
                    "commitment": hex::encode(publics.commitment),
                });
                std::fs::write(path, serde_json::to_vec_pretty(&blob)?)?;
                println!("wrote note witness file");
            }
        }
        Commands::RollupRegister {
            secret,
            scheme,
            challenge_period,
        } => {
            let keys = load_or_setup_keys(Some(cli.zk_keys.clone()))
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
            let kp = kp_from_secret(&secret)?;
            let from = kp.address();
            let vk = if scheme == 0x01 {
                keys.serialize_rollup_vk()
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?
            } else {
                vec![]
            };
            let mut rollup_id = [0u8; 32];
            rand::RngCore::fill_bytes(&mut OsRng, &mut rollup_id);
            let acct = rpc(&cli.rpc, "aeth_getAccount", json!([hex_addr(&from)])).await?;
            let nonce = acct["nonce"].as_u64().unwrap_or(0);
            let mut tx = Transaction {
                version: 1,
                nonce,
                origin: Origin::Account { from },
                kind: TxKind::RollupRegister {
                    rollup_id,
                    sequencer: from,
                    scheme,
                    verifying_key: vk,
                    challenge_period,
                },
                gas_limit: 200_000,
                max_fee_per_gas: 10_000,
                max_priority_fee_per_gas: 1,
                signature: vec![],
                public_key: vec![],
            };
            sign_tx(&mut tx, &kp)?;
            let h = rpc(&cli.rpc, "aeth_sendRawTransaction", json!([tx])).await?;
            println!("submitted: {}", h);
            println!("rollup_id: {}", hex_hash(&rollup_id));
            println!("scheme: {scheme:#x}");
        }
        Commands::RollupCommit {
            secret,
            rollup_id,
            batch_index,
            prev,
            da,
            scheme,
        } => {
            let keys = load_or_setup_keys(Some(cli.zk_keys.clone()))
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
            let kp = kp_from_secret(&secret)?;
            let from = kp.address();
            let rid = parse_hash(&rollup_id).map_err(|e| anyhow::anyhow!(e))?;
            let prev_h = parse_hash(&prev).map_err(|e| anyhow::anyhow!(e))?;
            let da_h = parse_hash(&da).map_err(|e| anyhow::anyhow!(e))?;
            let secret_fr = Fr::rand(&mut OsRng);
            let post = compute_valid_post_root(&prev_h, &da_h, batch_index, &secret_fr);
            let inputs = RollupPublicInputs {
                prev_state_root: prev_h,
                post_state_root: post,
                da_hash: da_h,
                batch_index,
            };
            let proof = match scheme {
                0x01 => prove_rollup_groth16(&keys.rollup_pk, &inputs, &secret_fr)
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?,
                0x02 => prove_rollup_plonk(&inputs, &secret_fr)
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?,
                0x03 => vec![], // optimistic: empty proof enters challenge window
                other => bail!("unsupported commit scheme {other:#x}"),
            };
            let acct = rpc(&cli.rpc, "aeth_getAccount", json!([hex_addr(&from)])).await?;
            let nonce = acct["nonce"].as_u64().unwrap_or(0);
            let mut tx = Transaction {
                version: 1,
                nonce,
                origin: Origin::Account { from },
                kind: TxKind::RollupCommit {
                    rollup_id: rid,
                    batch_index,
                    prev_state_root: prev_h,
                    post_state_root: post,
                    da_hash: da_h,
                    proof,
                },
                gas_limit: 800_000,
                max_fee_per_gas: 10_000,
                max_priority_fee_per_gas: 1,
                signature: vec![],
                public_key: vec![],
            };
            sign_tx(&mut tx, &kp)?;
            let h = rpc(&cli.rpc, "aeth_sendRawTransaction", json!([tx])).await?;
            println!("submitted: {}", h);
            println!("post_state_root: {}", hex_hash(&post));
        }
    }
    Ok(())
}

fn kp_from_secret(secret: &str) -> Result<Keypair> {
    let s = secret.strip_prefix("0x").unwrap_or(secret);
    let bytes = hex::decode(s)?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("secret must be 32 bytes"))?;
    Ok(Keypair::from_bytes(arr))
}

async fn rpc(url: &str, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
    let client = reqwest::Client::new();
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let res: serde_json::Value = client.post(url).json(&body).send().await?.json().await?;
    if let Some(err) = res.get("error") {
        bail!("rpc error: {err}");
    }
    Ok(res.get("result").cloned().unwrap_or(serde_json::Value::Null))
}
