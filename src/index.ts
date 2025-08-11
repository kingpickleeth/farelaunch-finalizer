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

// ABI with preflight views + custom error
const presalePoolAbi = parseAbi([
  // tx + views
  'function finalize() external',
  'function finalized() view returns (bool)',
  'function softCap() view returns (uint256)',
  'function hardCap() view returns (uint256)',
  'function totalRaised() view returns (uint256)',
  'function endAt() view returns (uint256)',
  'function failed() view returns (bool)',
  // custom error from your contract
  'error Window()',
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
    return false;
  }
}

// --- NEW: on-chain preflight that mirrors your finalize() guards ---
async function checkFinalizeEligibility(pool: `0x${string}`) {
  const [softCap, hardCap, totalRaised, endAt, finalized, failed] = await Promise.all([
    publicClient.readContract({ address: pool, abi: presalePoolAbi, functionName: 'softCap' }) as Promise<bigint>,
    publicClient.readContract({ address: pool, abi: presalePoolAbi, functionName: 'hardCap' }) as Promise<bigint>,
    publicClient.readContract({ address: pool, abi: presalePoolAbi, functionName: 'totalRaised' }) as Promise<bigint>,
    publicClient.readContract({ address: pool, abi: presalePoolAbi, functionName: 'endAt' }) as Promise<bigint>,
    publicClient.readContract({ address: pool, abi: presalePoolAbi, functionName: 'finalized' }) as Promise<boolean>,
    publicClient.readContract({ address: pool, abi: presalePoolAbi, functionName: 'failed' }) as Promise<boolean>,
  ]);

  const block = await publicClient.getBlock();
  const now = Number(block.timestamp); // seconds

  const canFinalize =
    (!finalized && !failed) &&
    (
      (totalRaised >= softCap && now >= Number(endAt)) ||
      (totalRaised >= hardCap)
    );

  return {
    canFinalize,
    finalized,
    failed,
    now,
    softCap: softCap.toString(),
    hardCap: hardCap.toString(),
    totalRaised: totalRaised.toString(),
    endAt: endAt.toString(),
  };
}
async function callFinalize(pool: `0x${string}`): Promise<`0x${string}`> {
    // preflight; skip or mark failed based on on-chain state
    const st = await checkFinalizeEligibility(pool);
  
    // If we are after endAt and below soft cap, this sale failed.
    const afterEnd = st.now >= Number(st.endAt);
    const belowSoft = BigInt(st.totalRaised) < BigInt(st.softCap);
  
    if (!st.canFinalize && afterEnd && belowSoft && !st.finalized && !st.failed) {
      log.info({ pool, ...st }, 'preflight: mark failed (below soft cap after end)');
      // NOTE: we don't know launch id here, so processOne updates the row.
      // Return a sentinel by throwing; processOne will catch and set failed.
      const err = new Error('SALE_FAILED_BELOW_SOFTCAP');
      (err as any).__saleFailed = true;
      throw err;
    }
  
    if (!st.canFinalize) {
      log.info({ pool, reason: 'not_eligible', ...st }, 'preflight: skip finalize');
      // Throw a normal error so processOne records attempt & moves on (will retry later)
      throw new Error('Finalize not eligible yet (Window)');
    }
  
    try {
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
    } catch (e: any) {
      const data = e?.data || e?.cause?.data;
      const sel = typeof data === 'string' ? data.slice(0, 10) : undefined;
      if (sel === '0x86997fcd') {
        log.warn({ pool, selector: sel, msg: e?.shortMessage || e?.message }, 'reverted: Window()');
      } else if (sel) {
        log.warn({ pool, selector: sel, msg: e?.shortMessage || e?.message }, 'reverted: custom error');
      } else {
        log.warn({ pool, msg: e?.shortMessage || e?.message }, 'reverted');
      }
      throw e;
    }
  }  
// --- in-memory processing lock to suppress duplicate concurrent runs ---
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
    const saleFailed = e && e.__saleFailed === true;
  
    log.error({ id, pool, err: e?.message || String(e) }, 'finalize failed');
  
    const update: any = {
      finalizing: false,
      finalize_attempts: (row.finalize_attempts ?? 0) + 1,
      finalize_error: e?.message || String(e),
      updated_at: new Date().toISOString(),
    };
  
    if (saleFailed) {
      update.status = 'failed';     // <-- mark failed in DB
      update.finalized = false;
    }
  
    await supabase
      .from('launches')
      .update(update)
      .eq('id', id);
  }
   finally {
    markDone(id);
  }
}

// Realtime subscription with stricter filter
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
          next?.status === 'ended' &&
          next?.finalized === false &&
          (next as any)?.finalizing === false;

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
          log.debug(
            {
              id: next?.id,
              needsWork,
              transitionedIntoEnded,
              status: next?.status,
              finalized: next?.finalized,
              finalizing: (next as any)?.finalizing,
            },
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

// Safety-net poller
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
