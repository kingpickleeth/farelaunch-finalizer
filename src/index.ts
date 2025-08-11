import 'dotenv/config';
import express, { type Request, type Response } from 'express';
import pino from 'pino';
import { createClient as createSb } from '@supabase/supabase-js';
import {
  createPublicClient,
  createWalletClient,
  http,
  parseAbi,
  getAddress,
  defineChain,
  type Chain,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

const log = pino({
  level: process.env.LOG_LEVEL || 'info',
  transport: process.env.NODE_ENV === 'production' ? undefined : { target: 'pino-pretty' },
});

const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, RPC_URL, CHAIN_ID = '1', PRIVATE_KEY } =
  process.env;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY || !RPC_URL || !PRIVATE_KEY) {
  log.fatal(
    {
      SUPABASE_URL: !!SUPABASE_URL,
      SUPABASE_SERVICE_ROLE_KEY: !!SUPABASE_SERVICE_ROLE_KEY,
      RPC_URL: !!RPC_URL,
      PRIVATE_KEY: !!PRIVATE_KEY,
    },
    'Missing required env vars',
  );
  process.exit(1);
}

const supabase = createSb(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });

const chain: Chain = defineChain({
  id: Number(CHAIN_ID || 1),
  name: 'ApeChain',
  nativeCurrency: { name: 'APE', symbol: 'APE', decimals: 18 },
  rpcUrls: { default: { http: [RPC_URL!] } },
});
const publicClient = createPublicClient({ transport: http(RPC_URL!), chain });
const account = privateKeyToAccount(
  PRIVATE_KEY!.startsWith('0x') ? (PRIVATE_KEY! as `0x${string}`) : (`0x${PRIVATE_KEY}` as `0x${string}`),
);
const walletClient = createWalletClient({ account, chain, transport: http(RPC_URL!) });

const presalePoolAbi = parseAbi([
  'function finalize() external',
  'function finalized() view returns (bool)',
]);

type Launch = {
  id: string;
  pool_address: `0x${string}` | null;
  status: string;
  finalized: boolean;
  finalize_attempts: number | null;
  finalizing?: boolean | null;
};

async function readFinalized(pool: `0x${string}`): Promise<boolean> {
  try {
    return (await publicClient.readContract({
      address: pool,
      abi: presalePoolAbi,
      functionName: 'finalized',
    })) as boolean;
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
    chain,
    account,
  });
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status !== 'success') throw new Error(`Finalize tx failed: ${hash}`);
  return hash;
}

// --- in-memory processing lock to suppress duplicate concurrent runs (3A) ---
const processing = new Set<string>();
function markStart(id: string): boolean {
  if (processing.has(id)) return false;
  processing.add(id);
  return true;
}
function markDone(id: string) {
  processing.delete(id);
}

// Compare-and-set DB lock: flip finalizing=false -> true so only one worker proceeds
async function tryClaim(id: string): Promise<boolean> {
  const { data, error } = await supabase
    .from('launches')
    .update({
      finalizing: true,
      updated_at: new Date().toISOString(),
    })
    .eq('id', id)
    .eq('status', 'ended')
    .eq('finalized', false)
    .eq('finalizing', false) // lock guard
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

  if (!markStart(row.id)) {
    log.debug({ id: row.id }, 'already processing; skip');
    return;
  }

  const id = row.id;
  const pool = getAddress(row.pool_address) as `0x${string}`;

  try {
    // attempt to claim DB lock
    const claimed = await tryClaim(id);
    if (!claimed) {
      log.debug({ id }, 'could not claim row (another worker/instance or not eligible)');
      return;
    }

    const attempts = (row.finalize_attempts ?? 0) + 1;

    const already = await readFinalized(pool);
    let hash: `0x${string}` | null = null;

    if (!already) {
      hash = await callFinalize(pool);
    }

    const { error } = await supabase
      .from('launches')
      .update({
        finalized: true,
        finalizing: false,
        finalize_tx_hash: hash,
        finalize_attempts: attempts,
        finalize_error: null,
        updated_at: new Date().toISOString(),
      })
      .eq('id', id);

    if (error) throw error;

    log.info({ id, pool, tx: hash, attempts, already }, 'finalized');
  } catch (e: any) {
    log.error({ id, pool, err: e?.message || String(e) }, 'finalize failed');
    await supabase
      .from('launches')
      .update({
        finalizing: false, // release lock to allow retries
        finalize_attempts: (row.finalize_attempts ?? 0) + 1,
        finalize_error: e?.message || String(e),
        updated_at: new Date().toISOString(),
      })
      .eq('id', id);
  } finally {
    markDone(id);
  }
}

// Realtime subscription with stricter filter (3B/4)
function startRealtime() {
  const ch = supabase
    .channel('launches-ended')
    .on(
      'postgres_changes',
      { event: 'UPDATE', schema: 'public', table: 'launches' },
      (payload) => {
        // If you ran: ALTER TABLE public.launches REPLICA IDENTITY FULL;
        // then payload.old will be populated and we can check a true transition.
        const prev = (payload as any).old as Partial<Launch> | undefined;
        const next = (payload as any).new as Launch;

        // Only react if it still needs work:
        const needsWork =
          next?.status === 'ended' && next?.finalized === false && (next as any)?.finalizing === false;

        // If we have previous row, ensure this was a transition INTO 'ended'.
        const transitionedIntoEnded = prev ? prev.status !== 'ended' && next.status === 'ended' : true;

        if (needsWork && transitionedIntoEnded) {
          log.info({ id: next.id }, 'RT: ended → claim');
          processOne({
            id: next.id,
            pool_address: next.pool_address as any,
            status: next.status,
            finalized: next.finalized,
            finalize_attempts: (next as any).finalize_attempts ?? 0,
            finalizing: (next as any).finalizing ?? false,
          }).catch(() => {});
        } else {
          // Quiet debug for noisy updates
          log.debug(
            { id: next?.id, needsWork, transitionedIntoEnded, status: next?.status, finalized: next?.finalized, finalizing: (next as any)?.finalizing },
            'RT: ignore',
          );
        }
      },
    )
    .subscribe((status, err) => {
      log.info({ status, err }, 'realtime subscription status');
    });

  return ch;
}

// Safety-net poller (kept minimal logs)
async function pollOnce() {
  const { data, error } = await supabase
    .from('launches')
    .select('id, pool_address, status, finalized, finalize_attempts, finalizing')
    .eq('status', 'ended')
    .eq('finalized', false)
    .eq('finalizing', false)
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
    pollOnce().catch((err) => log.error({ err }, 'pollOnce failed'));
  }, ms);
}

// Health endpoint for Railway
function startHttp() {
  const app = express();
  app.get('/health', async (_req: Request, res: Response) => {
    try {
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

main().catch((err) => {
  log.fatal({ err }, 'fatal');
  process.exit(1);
});
