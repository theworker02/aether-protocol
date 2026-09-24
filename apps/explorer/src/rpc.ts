const RPC = import.meta.env.VITE_RPC_URL ?? "/rpc";

export async function rpc<T = unknown>(method: string, params: unknown[] = []): Promise<T> {
  const res = await fetch(RPC, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const body = await res.json();
  if (body.error) throw new Error(body.error.message ?? "RPC error");
  return body.result as T;
}

export type ProtocolInfo = {
  name: string;
  version: string;
  chain_id: string;
  hybrid_mode: string;
  height: number;
  epoch: number;
  base_fee: number;
  validators: number;
  total_supply: string;
  fee_burned: string;
  notes: number;
  nullifiers: number;
  utxos: number;
  rollups: number;
  shielded_value?: string;
  notes_root?: string;
  pending_rollups?: number;
  zk?: {
    shielded: string;
    rollup_schemes: string[];
  };
};

export type BlockView = {
  hash: string;
  header: {
    height: number;
    time_unix_ms: number;
    prev_hash: string;
    state_root: string;
    proposer: string;
    epoch: number;
    gas_used: number;
    gas_limit: number;
    base_fee: number;
  };
  tx_count: number;
  transactions: unknown[];
};

export type AccountView = {
  address: string;
  nonce: number;
  balance: string;
  bonded: string;
  code_hash?: string;
};
