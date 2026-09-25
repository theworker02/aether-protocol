# Brokerless Markets

**Companion to:** `PROTOCOL.md`, `ECONOMICS.md`, `INVARIANTS.md`  
**Version:** 1.4.0  
**Thesis:** Replace the **broker** (match, clear, settle, custody) with a **blockchain** that does those jobs in the state machine.

---

## 1. Why no broker

A traditional broker:

1. Holds inventory or customer funds  
2. Matches buyers and sellers off-chain  
3. Clears and settles on its own books  
4. Is a single point of failure, censorship, and preferential fill  

Aether **1.4** puts those functions on-chain:

| Broker job | On-chain primitive |
|------------|--------------------|
| Custody | Locked balances in orders / AMM / HTLC escrow |
| Matching | Resting limit book + permissionless `MarketFillOrder` |
| Clearing | Atomic delivery-vs-payment in one tx; `SettleBatch` for multi-leg |
| Settlement finality | AetherBFT commit — same finality as transfers |
| Price discovery | Limit book + constant-product AMM |

No designated market-maker role is required. Anyone with keys can post, fill, LP, or escrow.

---

## 2. Assets

- **Native AETH** — asset id `NATIVE_ASSET` = `0x00…00`  
- **Registered assets** — `MarketRegisterAsset { symbol, decimals, supply }` mints `supply` to the issuer  

Secondary balances live in `asset_balances["addr|asset"]`. Native AETH stays on `Account.balance` and is tracked in `market_locked_native` when locked by markets.

---

## 3. Limit order book

```
MarketPostOrder  → lock maker funds, rest on book
MarketFillOrder  → taker fills any open order (permissionless)
MarketCancelOrder → maker unlocks remainder
SettleBatch      → atomic multi-fill clearing
```

**Price:** `quote = base * price_num / PRICE_SCALE` (`PRICE_SCALE = 10^9`).

| Side | Locked on post | On fill |
|------|----------------|---------|
| Sell | `amount` of **base** | Taker pays quote; maker receives quote; taker receives base |
| Buy  | `quote` for full size | Taker delivers base; maker receives base; taker receives locked quote |

Fills are **atomic DvP** — no broker intermediate ledger.

---

## 4. AMM (`x * y = k`)

```
AmmCreatePool → seed reserves, mint √(a·b) LP shares
AmmAddLiquidity / AmmRemoveLiquidity
AmmSwap { asset_in, amount_in, min_out }
```

Fee in basis points comes out of the input before the constant-product step. `min_out` is hard slippage protection.

---

## 5. HTLC escrow (P2P atomic swap)

```
EscrowOpen  { recipient, asset, amount, hashlock, timeout_height }
EscrowClaim { preimage }   // BLAKE3(preimage) == hashlock
EscrowRefund               // after timeout, sender only
```

Use for cross-system settlement without a trusted escrow agent: lock here, reveal preimage elsewhere (or vice versa).

---

## 6. Supply invariant (AETH)

Native AETH locked in open orders, AMM reserves, and open escrows is counted in `market_locked_native` so **I1** still holds:

```
liquid + bonded + utxo + shielded + fee_burned + gov_deposits
  + unbonding + delegated + community_pool + market_locked_native
  == genesis_supply
```

Registered assets have their own supply and are **not** part of the AETH invariant.

---

## 7. RPC

| Method | Returns |
|--------|---------|
| `aeth_getOrders` | Full order book map |
| `aeth_getOrder` | Single order by id |
| `aeth_getPools` | AMM pools |
| `aeth_getEscrows` | HTLC escrows |
| `aeth_getAssets` | Registered asset metadata |
| `aeth_getAssetBalance` | `[address, assetId]` |
| `aeth_getMarketLocked` | Native AETH locked in markets |

---

## 8. CLI examples

```bash
# Register USDC-like asset
cargo run -p aether-protocol-cli -- market-register --secret <hex> --symbol USDC --supply 1000000000000

# Sell 1 AETH for quote asset at price_num
cargo run -p aether-protocol-cli -- market-post --secret <hex> --side sell \
  --quote 0x... --price-num 1000000000 --amount 1000000000

# Anyone fills
cargo run -p aether-protocol-cli -- market-fill --secret <taker> --order-id 1 --amount 500000000

cargo run -p aether-protocol-cli -- markets
```

---

## 9. Threat notes

- Front-running / sandwiching on public mempools is expected; use `min_out`, private relays, or shielded intents in later versions.  
- Expired orders are not auto-swept in the reference — cancel or fill fails after `expiry_height`.  
- Not for mainnet value without audit.
