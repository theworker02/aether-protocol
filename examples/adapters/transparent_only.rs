//! Example: compliance TxFilter + BlockHook adapters (sync traits).

use aether_state::{BlockHook, TxFilter};
use aether_types::{Hash256, Transaction, TxKind};

pub struct TransparentOnly;

impl TxFilter for TransparentOnly {
    fn allow(&self, tx: &Transaction) -> Result<(), String> {
        match tx.kind {
            TxKind::ShieldedShield { .. }
            | TxKind::ShieldedTransfer { .. }
            | TxKind::ShieldedUnshield { .. } => {
                Err("shielded transactions disabled by policy".into())
            }
            _ => Ok(()),
        }
    }
}

pub struct PrintHook;

impl BlockHook for PrintHook {
    fn on_commit(&self, height: u64, hash: Hash256) {
        println!("committed height={height} hash=0x{}", hex::encode(hash));
    }
}

fn main() {
    println!("See docs/ADAPTING.md — wire TxFilter into NodeLedger::with_filter.");
}
