import 'dotenv/config';
import express from 'express';
import pino from 'pino';
import { createClient as createSb } from '@supabase/supabase-js';
import { createPublicClient, createWalletClient, http, parseAbi, getAddress } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { defineChain, type Chain } from 'viem';

const log = pino({
  level: process.env.LOG_LEVEL || 'info',
  transport: process.env.NODE_ENV === 'production' ? undefined : { target: 'pino-pretty' }
});

const {
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  RPC_URL,
  CHAIN_ID = '1',
  PRIVATE_KEY
} = process.env;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY || !RPC_URL || !PRIVATE_KEY) {
  log.fatal({ SUPABASE_URL: !!SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY: !!SUPABASE_SERVICE_ROLE_KEY, RPC_URL: !!RPC_URL, PRIVATE_KEY: !!PRIVATE_KEY }, 'Missing required env vars');
  process.exit(1);
}

const supabase = createSb(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });

const chain: Chain = defineChain({
  id: Number(process.env.CHAIN_ID || 1),
  name: 'ApeChain',
  nativeCurrency: { name: 'APE', symbol: 'APE', decimals: 18 },
  rpcUrls: { default: { http: [process.env.RPC_URL!] } }
});
const publicClient = createPublicClient({ transport: http(process.env.RPC_URL!), chain });
const account = privateKeyToAccount(
  process.env.PRIVATE_KEY!.startsWith('0x') ? (process.env.PRIVATE_KEY! as `0x${string}`) : (`0x${process.env.PRIVATE_KEY}` as `0x${string}`)
);
const walletClient = createWalletClient({ account, chain, transport: http(process.env.RPC_URL!) });

const presalePoolAbi = parseAbi([
  'function finalize() external',
  'function finalized() view returns (bool)'
]);

type Launch = {
  id: string;
  pool_address: `0x${string}` | null;
  status: string;
  finalized: boolean;
  finalize_attempts: number | null;
};

async function readFinalized(pool: `0x${string}`): Promise<boolean> {
  try {
    return await publicClient.readContract({ address: pool, abi: presalePoolAbi, functionName: 'finalized' }) as boolean;
  } catch {
    // if view not available, assume not finalized
    return false;
  }
}

async function callFinalize(pool: `0x${string}`): Promise<`0x${string}`> {
    const hash = await walletClient.writeContract({
        address: pool,
        abi: presalePoolAbi,
        functionName: 'finalize',
        chain,     // <-- fixes the TS error
        account    // <-- explicit is safest with viem v2 types
      });      
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status !== 'success') throw new Error(`Finalize tx failed: ${hash}`);
  return hash;
}

// Simple "claim" using a compare-and-set on (status, finalized)
async function tryClaim(id: string): Promise<boolean> {
  const { data, error } = await supabase
    .from('launches')
    .update({ /* no status change to avoid enum issues */ updated_at: new Date().toISOString() })
    .eq('id', id)
    .eq('status', 'ended')
    .eq('finalized', false)
    .select('id')
    .maybeSingle();

  if (error) {
    log.error({ err: error, id }, 'claim update failed');
    return false;
  }
  return !!data;
}

async function processOne(row: Launch) {
  if (!row.pool_address) {
    log.warn({ id: row.id }, 'no pool_address; skipping');
    return;
  }

  const id = row.id;
  const pool = getAddress(row.pool_address) as `0x${string}`;

  // attempt to claim
  const claimed = await tryClaim(id);
  if (!claimed) {
    log.debug({ id }, 'could not claim row (maybe another worker is processing or not ended)');
    return;
  }

  const attempts = (row.finalize_attempts ?? 0) + 1;

  try {
    const already = await readFinalized(pool);
    let hash: `0x${string}` | null = null;

    if (!already) {
      hash = await callFinalize(pool);
    }

    const { error } = await supabase
      .from('launches')
      .update({
        finalized: true,
        finalize_tx_hash: hash,
        finalize_attempts: attempts,
        finalize_error: null,
        updated_at: new Date().toISOString()
      })
      .eq('id', id);

    if (error) throw error;

    log.info({ id, pool, tx: hash, attempts, already }, 'finalized');
  } catch (e: any) {
    log.error({ id, pool, err: e?.message || String(e) }, 'finalize failed');
    await supabase
      .from('launches')
      .update({
        finalize_attempts: attempts,
        finalize_error: e?.message || String(e),
        updated_at: new Date().toISOString()
      })
      .eq('id', id);
    // let poller/RT retry on next cycle
  }
}

// Realtime subscription: react when a row becomes ended & not finalized
function startRealtime() {
  const ch = supabase
    .channel('launches-ended')
    .on(
      'postgres_changes',
      { event: 'UPDATE', schema: 'public', table: 'launches' },
      (payload) => {
        const next = payload.new as any;
        if (next?.status === 'ended' && next?.finalized === false) {
          const row = {
            id: next.id,
            pool_address: next.pool_address,
            status: next.status,
            finalized: next.finalized,
            finalize_attempts: next.finalize_attempts
          } as Launch;
          log.info({ id: row.id }, 'RT: ended detected → process');
          processOne(row).catch(() => {});
        }
      }
    )
    .subscribe((status, err) => {
      log.info({ status, err }, 'realtime subscription status');
    });

  return ch;
}

// Periodic poll as a safety net
async function pollOnce() {
  const { data, error } = await supabase
    .from('launches')
    .select('id, pool_address, status, finalized, finalize_attempts')
    .eq('status', 'ended')
    .eq('finalized', false)
    .limit(50);

  if (error) {
    log.error({ err: error }, 'poll query failed');
    return;
  }

  for (const r of data ?? []) {
    await processOne(r as Launch);
  }
}

function startPoller() {
  const ms = Number(process.env.POLL_INTERVAL_MS || 15000);
  log.info({ ms }, 'starting poller');
  setInterval(() => {
    pollOnce().catch(err => log.error({ err }, 'pollOnce failed'));
  }, ms);
}

// Health endpoint for Railway
function startHttp() {
  const app = express();
  app.get('/health', async (_req, res) => {
    try {
      // quick smoke test to DB
      const { error } = await supabase.from('launches').select('id').limit(1);
      if (error) throw error;
      res.json({ ok: true, time: new Date().toISOString(), address: account.address });
    } catch (e: any) {
      res.status(500).json({ ok: false, error: e?.message || String(e) });
    }
  });
  const port = Number(process.env.PORT || 8080);
  app.listen(port, () => log.info({ port, addr: account.address }, 'health server up'));
}

async function main() {
  startHttp();
  startRealtime();
  startPoller();
  log.info('worker started');
}

main().catch(err => {
  log.fatal({ err }, 'fatal');
  process.exit(1);
});
