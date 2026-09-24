use aether_types::{Address, Log};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VmError {
    #[error("stack underflow")]
    StackUnderflow,
    #[error("out of gas")]
    OutOfGas,
    #[error("invalid opcode {0}")]
    InvalidOpcode(u8),
    #[error("reverted")]
    Reverted,
    #[error("bad jump")]
    BadJump,
}

#[derive(Debug, Clone)]
pub struct VmResult {
    pub gas_used: u64,
    pub storage_writes: Vec<(u64, u64)>,
    pub logs: Vec<Log>,
    pub success: bool,
    pub return_data: Vec<u8>,
}

pub struct HostContext<'a> {
    pub caller: Address,
    pub contract: Address,
    pub storage: &'a mut std::collections::BTreeMap<u64, u64>,
    pub balances: &'a dyn Fn(Address) -> u128,
    pub block_height: u64,
    pub block_time_ms: u64,
    pub call_value: u64,
}

/// Minimal stack machine used as the AetherOps prototype ISA (v1.3).
pub fn execute(
    code: &[u8],
    host: &mut HostContext<'_>,
    gas_limit: u64,
) -> Result<VmResult, VmError> {
    let mut ip = 0usize;
    let mut stack: Vec<u64> = Vec::new();
    let mut gas = gas_limit;
    let mut logs = Vec::new();
    let mut writes = Vec::new();
    let mut return_data = Vec::new();

    macro_rules! burn {
        ($n:expr) => {{
            if gas < $n {
                return Err(VmError::OutOfGas);
            }
            gas -= $n;
        }};
    }

    macro_rules! pop {
        () => {{
            stack.pop().ok_or(VmError::StackUnderflow)?
        }};
    }

    while ip < code.len() {
        let op = code[ip];
        ip += 1;
        match op {
            0x00 => {
                burn!(1);
                return Ok(VmResult {
                    gas_used: gas_limit - gas,
                    storage_writes: writes,
                    logs,
                    success: true,
                    return_data,
                });
            }
            0x01 => {
                burn!(1);
                if ip + 8 > code.len() {
                    return Err(VmError::InvalidOpcode(op));
                }
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&code[ip..ip + 8]);
                ip += 8;
                stack.push(u64::from_le_bytes(buf));
            }
            0x02 => {
                burn!(1);
                let b = pop!();
                let a = pop!();
                stack.push(a.wrapping_add(b));
            }
            0x03 => {
                burn!(1);
                let b = pop!();
                let a = pop!();
                stack.push(a.wrapping_sub(b));
            }
            0x04 => {
                burn!(1);
                let b = pop!();
                let a = pop!();
                stack.push(a.wrapping_mul(b));
            }
            0x05 => {
                // DIV
                burn!(5);
                let b = pop!();
                let a = pop!();
                stack.push(if b == 0 { 0 } else { a / b });
            }
            0x06 => {
                // MOD
                burn!(5);
                let b = pop!();
                let a = pop!();
                stack.push(if b == 0 { 0 } else { a % b });
            }
            0x07 => {
                burn!(1);
                let b = pop!();
                let a = pop!();
                stack.push(a & b);
            }
            0x08 => {
                burn!(1);
                let b = pop!();
                let a = pop!();
                stack.push(a | b);
            }
            0x09 => {
                burn!(1);
                let b = pop!();
                let a = pop!();
                stack.push(a ^ b);
            }
            0x0A => {
                // EQ
                burn!(1);
                let b = pop!();
                let a = pop!();
                stack.push(u64::from(a == b));
            }
            0x0B => {
                // LT
                burn!(1);
                let b = pop!();
                let a = pop!();
                stack.push(u64::from(a < b));
            }
            0x0C => {
                // GT
                burn!(1);
                let b = pop!();
                let a = pop!();
                stack.push(u64::from(a > b));
            }
            0x0D => {
                // NOT
                burn!(1);
                let a = pop!();
                stack.push(!a);
            }
            0x0E => {
                // DUP
                burn!(1);
                let a = *stack.last().ok_or(VmError::StackUnderflow)?;
                stack.push(a);
            }
            0x0F => {
                // SWAP
                burn!(1);
                let n = stack.len();
                if n < 2 {
                    return Err(VmError::StackUnderflow);
                }
                stack.swap(n - 1, n - 2);
            }
            0x10 => {
                burn!(800);
                let key = pop!();
                let val = host.storage.get(&key).copied().unwrap_or(0);
                stack.push(val);
            }
            0x11 => {
                burn!(5_000);
                let val = pop!();
                let key = pop!();
                host.storage.insert(key, val);
                writes.push((key, val));
            }
            0x12 => {
                // JUMP dest
                burn!(8);
                let dest = pop!() as usize;
                if dest >= code.len() {
                    return Err(VmError::BadJump);
                }
                ip = dest;
            }
            0x13 => {
                // JUMPI dest, cond
                burn!(10);
                let cond = pop!();
                let dest = pop!() as usize;
                if cond != 0 {
                    if dest >= code.len() {
                        return Err(VmError::BadJump);
                    }
                    ip = dest;
                }
            }
            0x20 => {
                burn!(375);
                let n = pop!() as usize;
                let mut topics = Vec::with_capacity(n);
                for _ in 0..n {
                    topics.push(pop!());
                }
                let data_word = pop!();
                logs.push(Log {
                    address: host.contract,
                    topics,
                    data: data_word.to_le_bytes().to_vec(),
                });
            }
            0x21 => {
                // RETURN — pop len then words (simplified: single u64 return)
                burn!(1);
                let word = pop!();
                return_data = word.to_le_bytes().to_vec();
                return Ok(VmResult {
                    gas_used: gas_limit - gas,
                    storage_writes: writes,
                    logs,
                    success: true,
                    return_data,
                });
            }
            0x30 => {
                burn!(1);
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&host.caller[..8]);
                stack.push(u64::from_le_bytes(buf));
            }
            0x31 => {
                burn!(100);
                let bal = (host.balances)(host.contract);
                stack.push(bal.min(u64::MAX as u128) as u64);
            }
            0x32 => {
                // ADDRESS (contract)
                burn!(1);
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&host.contract[..8]);
                stack.push(u64::from_le_bytes(buf));
            }
            0x33 => {
                // TIMESTAMP
                burn!(2);
                stack.push(host.block_time_ms);
            }
            0x34 => {
                // HEIGHT
                burn!(2);
                stack.push(host.block_height);
            }
            0x35 => {
                // CALLVALUE
                burn!(2);
                stack.push(host.call_value);
            }
            0xFF => {
                burn!(1);
                return Err(VmError::Reverted);
            }
            other => return Err(VmError::InvalidOpcode(other)),
        }
    }

    Ok(VmResult {
        gas_used: gas_limit - gas,
        storage_writes: writes,
        logs,
        success: true,
        return_data,
    })
}

pub fn compile_store_program(key: u64, value: u64) -> Vec<u8> {
    let mut code = Vec::new();
    code.push(0x01);
    code.extend_from_slice(&key.to_le_bytes());
    code.push(0x01);
    code.extend_from_slice(&value.to_le_bytes());
    code.push(0x11);
    code.push(0x00);
    code
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether_types::zero_address;
    use std::collections::BTreeMap;

    #[test]
    fn arith_and_jump() {
        let mut storage = BTreeMap::new();
        let balances = |_a: Address| 0u128;
        let mut host = HostContext {
            caller: zero_address(),
            contract: zero_address(),
            storage: &mut storage,
            balances: &balances,
            block_height: 7,
            block_time_ms: 1000,
            call_value: 0,
        };
        // PUSH 10, PUSH 3, DIV, PUSH 0, EQ, PUSH dest, JUMPI, STOP — simplified: PUSH 10 PUSH 2 DIV STOP
        let mut code = Vec::new();
        code.push(0x01);
        code.extend_from_slice(&10u64.to_le_bytes());
        code.push(0x01);
        code.extend_from_slice(&2u64.to_le_bytes());
        code.push(0x05); // DIV => 5
        code.push(0x21); // RETURN
        let r = execute(&code, &mut host, 100_000).unwrap();
        assert!(r.success);
        assert_eq!(r.return_data, 5u64.to_le_bytes().to_vec());
    }
}
