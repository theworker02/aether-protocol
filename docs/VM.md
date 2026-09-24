# WASM Virtual Machine

**Companion to:** `PROTOCOL.md` · **Version:** 1.3.0

---

## 1. Overview

Aether contracts are deterministic WASM modules with metered execution. Host ABI exposes storage, balance, logs, and limited cryptography.

Prototype VM executes a **minimal bytecode DSL** (`AetherOps`) so the reference node remains dependency-light. Production replaces it with Wasmtime/Wasmer under the same ABI semantics.

---

## 2. Contract Lifecycle

1. `Deploy { code, salt }` → `address = blake3("AETH/DEPLOY" || sender || nonce || salt)[0..20]`
2. Code stored under `code_hash = blake3(code)`
3. `Transfer { to: contract, data }` or `ContractCall` invokes entry

---

## 3. AetherOps ISA (1.3)

| Opcode | Hex | Effect |
|--------|-----|--------|
| `STOP` | `0x00` | Halt success |
| `PUSH` | `0x01` | Push u64 LE immediate |
| `ADD`/`SUB`/`MUL` | `0x02–04` | Stack arith |
| `DIV`/`MOD` | `0x05–06` | Div/mod (0 → 0) |
| `AND`/`OR`/`XOR`/`NOT` | `0x07–09,0x0D` | Bitwise |
| `EQ`/`LT`/`GT` | `0x0A–0C` | Compare → 0/1 |
| `DUP`/`SWAP` | `0x0E–0F` | Stack manip |
| `SLOAD`/`SSTORE` | `0x10–11` | Storage |
| `JUMP`/`JUMPI` | `0x12–13` | Control flow |
| `LOG` | `0x20` | Receipt log |
| `RETURN` | `0x21` | Halt with return word |
| `CALLER` | `0x30` | Caller address word |
| `BALANCE` | `0x31` | Contract balance (trunc) |
| `ADDRESS` | `0x32` | Contract address word |
| `TIMESTAMP` | `0x33` | Block time ms |
| `HEIGHT` | `0x34` | Block height |
| `CALLVALUE` | `0x35` | Value attached to call |
| `REVERT` | `0xFF` | Halt failure |

Gas: 1–10 per simple op; `SSTORE` 5_000; `SLOAD` 800; `LOG` 375 + data.

---

## 4. Host ABI (production WASM)

```
fn storage_read(key_ptr, key_len, out_ptr) -> i32
fn storage_write(key_ptr, key_len, val_ptr, val_len) -> i32
fn log(topics_ptr, topics_len, data_ptr, data_len) -> i32
fn get_balance(addr_ptr) -> i64
fn get_caller(out_ptr) -> i32
fn get_block_height() -> i64
fn get_block_time() -> i64
```

Reentrancy: **forbidden** (call depth 1 for external calls).

---

## 5. Precompiles

| Address | Function |
|---------|----------|
| `0x00…10` | BLAKE3 hash |
| `0x00…11` | Ed25519 verify |
| `0x00…12` | Merkle verify |

---

## 6. Determinism Rules

- No floating point.
- No wall clock; only block context (`height`, `timestamp`, `proposer`, `epoch`).
- Gas exhaustion ⇒ revert; state untouched.
