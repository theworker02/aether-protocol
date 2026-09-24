# Bridges (IBC-lite)

**Companion to:** `PROTOCOL.md` · **Version:** 1.3.0

---

## 1. Goals

Provide a **minimal packet transport** between Aether and counterparty chains so relayers can move arbitrary bytes with ordered sequences. This is **not** full IBC/TAO; it is an interoperable stub with the same mental model.

---

## 2. Channel lifecycle

```
BridgeOpenChannel { channel_id, counterparty_chain, counterparty_channel }
  → BridgeChannel { next_send_seq=1, next_recv_seq=1, closed=false }
```

| Tx | Effect |
|----|--------|
| `BridgeSendPacket` | Allocate `next_send_seq`, store packet `status=sent` |
| `BridgeRecvPacket` | Require `sequence == next_recv_seq`, verify proof, bump recv |
| `BridgeAck` | Mark outbound packet `acked` |

---

## 3. Packet proof (reference)

```
proof = blake3(channel_id || sequence_le || data)
```

Production must replace this with a light-client membership proof against the counterparty header. Relayers today are **operator-trusted**.

---

## 4. RPC

- `aeth_getBridges`
- `aeth_getBridgePackets`

---

## 5. Timeouts

`timeout_height` is recorded on send. Automatic timeout refunds are reserved for v1.4; until then, operators may re-open channels after manual reconciliation.
