import { useCallback, useEffect, useState, type CSSProperties, type FormEvent } from "react";
import {
  rpc,
  type AccountView,
  type BlockView,
  type ProtocolInfo,
} from "./rpc";

const WEI = 1_000_000_000n;

function short(hex: string, n = 6) {
  if (!hex) return "—";
  if (hex.length < n * 2 + 2) return hex;
  return `${hex.slice(0, n + 2)}…${hex.slice(-n)}`;
}

function formatAeth(wei: string) {
  try {
    const v = BigInt(wei);
    const whole = v / WEI;
    const frac = (v % WEI).toString().padStart(9, "0").replace(/0+$/, "");
    return frac ? `${whole}.${frac}` : whole.toString();
  } catch {
    return wei;
  }
}

export default function App() {
  const [info, setInfo] = useState<ProtocolInfo | null>(null);
  const [blocks, setBlocks] = useState<BlockView[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [lookup, setLookup] = useState("");
  const [account, setAccount] = useState<AccountView | null>(null);
  const [walletSecret, setWalletSecret] = useState("");
  const [walletTo, setWalletTo] = useState("");
  const [walletAmount, setWalletAmount] = useState("1");
  const [walletMsg, setWalletMsg] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const proto = await rpc<ProtocolInfo>("aeth_protocolInfo");
      setInfo(proto);
      const height = proto.height;
      const from = Math.max(0, height - 7);
      const next: BlockView[] = [];
      for (let h = height; h >= from; h--) {
        try {
          next.push(await rpc<BlockView>("aeth_getBlockByNumber", [h]));
        } catch {
          /* genesis-only race */
        }
      }
      setBlocks(next);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Node unreachable");
    }
  }, []);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 2000);
    return () => clearInterval(id);
  }, [refresh]);

  async function onLookup(e: FormEvent) {
    e.preventDefault();
    try {
      const acct = await rpc<AccountView>("aeth_getAccount", [lookup.trim()]);
      setAccount(acct);
      setError(null);
    } catch (err) {
      setAccount(null);
      setError(err instanceof Error ? err.message : "Lookup failed");
    }
  }

  async function onSend(e: FormEvent) {
    e.preventDefault();
    setWalletMsg("Use the `aether` CLI for signed transfers in this prototype — explorer is read-focused.");
    setWalletMsg(
      `Prepare transfer of ${walletAmount} AETH to ${short(walletTo)} (sign via CLI with your secret).`
    );
    void walletSecret;
  }

  return (
    <div style={shell}>
      <header style={hero}>
        <div style={heroGlow} aria-hidden />
        <img
          src="/logo.svg"
          alt="Aether Protocol"
          width={88}
          height={88}
          style={{ marginBottom: "1.25rem", borderRadius: 20 }}
        />
        <p style={eyebrow}>Hybrid L1 · Account + UTXO · PoS BFT · Selective privacy</p>
        <h1 style={brand}>Aether</h1>
        <p style={lede}>
          One chain for public commons and federated finality — dual ledger, modular rollups,
          shielded notes when you need them.
        </p>
        <div style={ctaRow}>
          <a href="#explore" style={ctaPrimary}>
            Explore the chain
          </a>
          <a href="#wallet" style={ctaGhost}>
            Open wallet tools
          </a>
        </div>
        <div style={signalBar} aria-hidden />
      </header>

      <main id="explore" style={main}>
        {error && <div style={banner}>{error} — is `aether-node` running on :8545?</div>}

        <section style={section}>
          <h2 style={h2}>Network pulse</h2>
          <p style={sub}>Live view of hybrid mode, finality tip, and ledger domains.</p>
          <div style={pulseGrid}>
            <Pulse label="Height" value={info ? String(info.height) : "—"} />
            <Pulse label="Epoch" value={info ? String(info.epoch) : "—"} />
            <Pulse label="Hybrid" value={info?.hybrid_mode ?? "—"} accent />
            <Pulse label="Base fee" value={info ? String(info.base_fee) : "—"} />
            <Pulse label="Validators" value={info ? String(info.validators) : "—"} />
            <Pulse label="UTXOs" value={info ? String(info.utxos) : "—"} />
            <Pulse label="Shielded notes" value={info ? String(info.notes) : "—"} />
            <Pulse
              label="Shielded AETH"
              value={info?.shielded_value ? formatAeth(info.shielded_value) : "—"}
            />
            <Pulse label="Rollups" value={info ? String(info.rollups) : "—"} />
            <Pulse
              label="Pending batches"
              value={info ? String(info.pending_rollups ?? 0) : "—"}
              accent
            />
          </div>
          {info && (
            <p style={monoLine}>
              {info.chain_id} · supply {formatAeth(info.total_supply)} AETH · burned{" "}
              {formatAeth(info.fee_burned)} AETH
              {info.zk ? ` · ZK ${info.zk.shielded}` : ""}
            </p>
          )}
          {info?.notes_root && (
            <p style={monoLine}>notes_root {short(info.notes_root, 10)}</p>
          )}
        </section>

        <section style={section}>
          <h2 style={h2}>Recent blocks</h2>
          <p style={sub}>Finalized by AetherBFT — tip refreshes every two seconds.</p>
          <div style={blockList}>
            {blocks.map((b, i) => (
              <article
                key={b.hash}
                style={{
                  ...blockRow,
                  animationDelay: `${i * 40}ms`,
                }}
              >
                <div>
                  <div style={blockHeight}>#{b.header.height}</div>
                  <div style={monoMuted}>{short(b.hash, 8)}</div>
                </div>
                <div style={blockMeta}>
                  <span>{b.tx_count} tx</span>
                  <span>gas {b.header.gas_used}</span>
                  <span>epoch {b.header.epoch}</span>
                </div>
                <div style={monoMuted}>{short(b.header.proposer)}</div>
              </article>
            ))}
            {blocks.length === 0 && <p style={sub}>Waiting for genesis…</p>}
          </div>
        </section>

        <section style={section}>
          <h2 style={h2}>Account lookup</h2>
          <p style={sub}>Inspect transparent balances, nonce, and bonded stake.</p>
          <form onSubmit={onLookup} style={formRow}>
            <input
              style={input}
              placeholder="0x address"
              value={lookup}
              onChange={(e) => setLookup(e.target.value)}
            />
            <button type="submit" style={ctaPrimary}>
              Lookup
            </button>
          </form>
          {account && (
            <div style={acctPanel}>
              <div style={monoLine}>{account.address}</div>
              <div style={pulseGrid}>
                <Pulse label="Balance" value={`${formatAeth(account.balance)} AETH`} />
                <Pulse label="Bonded" value={`${formatAeth(account.bonded)} AETH`} />
                <Pulse label="Nonce" value={String(account.nonce)} />
              </div>
            </div>
          )}
        </section>

        <section id="wallet" style={section}>
          <h2 style={h2}>Wallet</h2>
          <p style={sub}>
            Draft a transfer, then sign with the CLI:{" "}
            <code style={code}>aether transfer --secret … --to … --amount …</code>
          </p>
          <form onSubmit={onSend} style={walletForm}>
            <label style={label}>
              Secret (local only — never paste mainnet keys)
              <input
                style={input}
                type="password"
                value={walletSecret}
                onChange={(e) => setWalletSecret(e.target.value)}
                autoComplete="off"
              />
            </label>
            <label style={label}>
              Recipient
              <input
                style={input}
                value={walletTo}
                onChange={(e) => setWalletTo(e.target.value)}
                placeholder="0x…"
              />
            </label>
            <label style={label}>
              Amount (AETH)
              <input
                style={input}
                value={walletAmount}
                onChange={(e) => setWalletAmount(e.target.value)}
              />
            </label>
            <button type="submit" style={ctaPrimary}>
              Prepare transfer
            </button>
          </form>
          {walletMsg && <p style={monoLine}>{walletMsg}</p>}
        </section>
      </main>

      <footer style={footer}>
        Aether Protocol v0.1 · reference implementation · not for real value
      </footer>
    </div>
  );
}

function Pulse({
  label,
  value,
  accent,
}: {
  label: string;
  value: string;
  accent?: boolean;
}) {
  return (
    <div style={pulseItem}>
      <div style={pulseLabel}>{label}</div>
      <div style={{ ...pulseValue, color: accent ? "var(--signal)" : undefined }}>{value}</div>
    </div>
  );
}

const shell: CSSProperties = {
  position: "relative",
  zIndex: 1,
  maxWidth: 1080,
  margin: "0 auto",
  padding: "0 1.25rem 3rem",
};

const hero: CSSProperties = {
  minHeight: "100vh",
  display: "flex",
  flexDirection: "column",
  justifyContent: "center",
  padding: "4rem 0 3rem",
  position: "relative",
  animation: "rise 0.8s ease-out both",
};

const heroGlow: CSSProperties = {
  position: "absolute",
  inset: "10% -20% auto",
  height: 280,
  background:
    "radial-gradient(ellipse at center, rgba(200,245,66,0.16), transparent 70%)",
  animation: "drift 6s ease-in-out infinite alternate",
  pointerEvents: "none",
};

const eyebrow: CSSProperties = {
  fontFamily: "var(--font-mono)",
  fontSize: 13,
  letterSpacing: "0.04em",
  color: "var(--mist)",
  margin: "0 0 1rem",
};

const brand: CSSProperties = {
  fontFamily: "var(--font-display)",
  fontWeight: 800,
  fontSize: "clamp(4.5rem, 14vw, 8rem)",
  lineHeight: 0.9,
  margin: 0,
  letterSpacing: "-0.04em",
  color: "var(--fog)",
};

const lede: CSSProperties = {
  maxWidth: "34rem",
  fontSize: "1.15rem",
  lineHeight: 1.5,
  color: "var(--mist)",
  margin: "1.25rem 0 2rem",
};

const ctaRow: CSSProperties = {
  display: "flex",
  flexWrap: "wrap",
  gap: "0.75rem",
};

const ctaPrimary: CSSProperties = {
  background: "var(--signal)",
  color: "var(--ink)",
  border: "none",
  padding: "0.85rem 1.25rem",
  fontWeight: 600,
  cursor: "pointer",
  display: "inline-block",
};

const ctaGhost: CSSProperties = {
  border: "1px solid var(--line)",
  color: "var(--fog)",
  padding: "0.85rem 1.25rem",
  fontWeight: 500,
};

const signalBar: CSSProperties = {
  marginTop: "3rem",
  height: 2,
  width: "min(420px, 70%)",
  background: "linear-gradient(90deg, var(--signal), transparent)",
  transformOrigin: "left",
  animation: "pulse-line 2.8s ease-in-out infinite",
};

const main: CSSProperties = {
  display: "flex",
  flexDirection: "column",
  gap: "3.5rem",
  paddingBottom: "2rem",
};

const section: CSSProperties = {
  animation: "rise 0.7s ease-out both",
};

const h2: CSSProperties = {
  fontFamily: "var(--font-display)",
  fontSize: "1.75rem",
  margin: "0 0 0.35rem",
  letterSpacing: "-0.02em",
};

const sub: CSSProperties = {
  margin: "0 0 1.25rem",
  color: "var(--mist)",
};

const pulseGrid: CSSProperties = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fill, minmax(140px, 1fr))",
  gap: "1rem 1.25rem",
};

const pulseItem: CSSProperties = {
  borderTop: "1px solid var(--line)",
  paddingTop: "0.65rem",
};

const pulseLabel: CSSProperties = {
  fontFamily: "var(--font-mono)",
  fontSize: 12,
  color: "var(--mist)",
  textTransform: "uppercase",
  letterSpacing: "0.06em",
};

const pulseValue: CSSProperties = {
  fontFamily: "var(--font-display)",
  fontSize: "1.35rem",
  marginTop: 4,
};

const monoLine: CSSProperties = {
  fontFamily: "var(--font-mono)",
  fontSize: 13,
  color: "var(--mist)",
  marginTop: "1.25rem",
};

const monoMuted: CSSProperties = {
  fontFamily: "var(--font-mono)",
  fontSize: 12,
  color: "var(--mist)",
};

const blockList: CSSProperties = {
  display: "flex",
  flexDirection: "column",
  gap: "0.65rem",
};

const blockRow: CSSProperties = {
  display: "grid",
  gridTemplateColumns: "1.2fr 1fr 1fr",
  gap: "1rem",
  alignItems: "center",
  padding: "0.85rem 0",
  borderBottom: "1px solid var(--line)",
  animation: "rise 0.5s ease-out both",
};

const blockHeight: CSSProperties = {
  fontFamily: "var(--font-display)",
  fontSize: "1.2rem",
};

const blockMeta: CSSProperties = {
  display: "flex",
  gap: "1rem",
  fontFamily: "var(--font-mono)",
  fontSize: 12,
  color: "var(--mist)",
};

const formRow: CSSProperties = {
  display: "flex",
  flexWrap: "wrap",
  gap: "0.75rem",
};

const input: CSSProperties = {
  flex: 1,
  minWidth: 220,
  background: "rgba(0,0,0,0.35)",
  border: "1px solid var(--line)",
  color: "var(--fog)",
  padding: "0.75rem 0.9rem",
  outline: "none",
};

const acctPanel: CSSProperties = {
  marginTop: "1.25rem",
};

const walletForm: CSSProperties = {
  display: "flex",
  flexDirection: "column",
  gap: "0.85rem",
  maxWidth: 480,
};

const label: CSSProperties = {
  display: "flex",
  flexDirection: "column",
  gap: 6,
  fontSize: 14,
  color: "var(--mist)",
};

const code: CSSProperties = {
  fontFamily: "var(--font-mono)",
  fontSize: 12,
  color: "var(--signal)",
};

const banner: CSSProperties = {
  padding: "0.85rem 1rem",
  borderLeft: "3px solid var(--amber)",
  background: "rgba(232, 168, 56, 0.08)",
  color: "var(--fog)",
  fontFamily: "var(--font-mono)",
  fontSize: 13,
};

const footer: CSSProperties = {
  marginTop: "4rem",
  paddingTop: "1.5rem",
  borderTop: "1px solid var(--line)",
  fontFamily: "var(--font-mono)",
  fontSize: 12,
  color: "var(--mist)",
};
