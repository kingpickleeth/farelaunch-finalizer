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
  'function finalize() external',
  'function finalized() view returns (bool)',
  'function softCap() view returns (uint256)',
  'function hardCap() view returns (uint256)',
  'function totalRaised() view returns (uint256)',
  'function endAt() view returns (uint256)',
  'function failed() view returns (bool)',
  'error Window()',
]);

type Status = 'draft' | 'upcoming' | 'active' | 'ended' | 'failed' | 'finalized';

type Launch = {
  id: string;
  pool_address: `0x${string}` | null;
  status: Status;
  finalized: boolean;
  finalize_attempts: number | null;
  finalizing?: boolean | null;
  start_at?: string | null;
  end_at?: string | null;
};

type ChainSnapshot = {
  softCap: bigint;
  hardCap: bigint;
  totalRaised: bigint;
  endAt: bigint;
  finalized: boolean;
  failed: boolean;
  now: number; // seconds (block timestamp)
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

// -------- Chain snapshot & status resolution --------

async function getChainSnapshot(pool: `0x${string}`): Promise<ChainSnapshot> {
  const [softCap, hardCap, totalRaised, endAt, finalized, failed] = await Promise.all([
    publicClient.readContract({ address: pool, abi: presalePoolAbi, functionName: 'softCap' }) as Promise<bigint>,
    publicClient.readContract({ address: pool, abi: presalePoolAbi, functionName: 'hardCap' }) as Promise<bigint>,
    publicClient.readContract({ address: pool, abi: presalePoolAbi, functionName: 'totalRaised' }) as Promise<bigint>,
    publicClient.readContract({ address: pool, abi: presalePoolAbi, functionName: 'endAt' }) as Promise<bigint>,
    publicClient.readContract({ address: pool, abi: presalePoolAbi, functionName: 'finalized' }) as Promise<boolean>,
    publicClient.readContract({ address: pool, abi: presalePoolAbi, functionName: 'failed' }) as Promise<boolean>,
  ]);
  const block = await publicClient.getBlock();
  return {
    softCap,
    hardCap,
    totalRaised,
    endAt,
    finalized,
    failed,
    now: Number(block.timestamp),
  };
}

function computeNextStatus(row: Launch, chain: ChainSnapshot | null, nowMs: number): Status {
  // terminal states stick
  if (row.status === 'finalized') return 'finalized';
  if (row.status === 'failed') return 'failed';

  const start = row.start_at ? Date.parse(row.start_at) : NaN;
  const end = row.end_at ? Date.parse(row.end_at) : NaN;
  const hasWindow = Number.isFinite(start) && Number.isFinite(end);
  const afterStart = hasWindow && nowMs >= start;
  const afterEnd = hasWindow && nowMs > end;

  if (chain) {
    // contract tells us terminal states first
    if (chain.finalized) return 'finalized';
    if (chain.failed) return 'failed';

    // hard cap reached = sale effectively ended
    if (chain.hardCap > 0n && chain.totalRaised >= chain.hardCap) return 'ended';

    // end reached and < soft cap => failed
    const afterEndOnChain = chain.now >= Number(chain.endAt || 0n);
    if (afterEndOnChain && chain.totalRaised < chain.softCap) return 'failed';

    // otherwise reflect window
    if (afterStart && !afterEnd) return 'active';
    if (!afterStart) return 'upcoming';
    if (afterEnd) return 'ended';
  }

  // no chain info: fallback to time
  if (!hasWindow) return 'draft';
  if (!afterStart) return 'upcoming';
  if (!afterEnd) return 'active';
  return 'ended';
}

async function reconcileStatus(row: Launch): Promise<Status> {
  const nowMs = Date.now();

  // Only hit chain if could be active/ending
  const readChain =
    !!row.pool_address &&
    (row.status === 'upcoming' || row.status === 'active' || row.status === 'ended');

  const chain = readChain ? await getChainSnapshot(row.pool_address!) : null;
  const next = computeNextStatus(row, chain, nowMs);

  if (next !== row.status) {
    const { error } = await supabase
      .from('launches')
      .update({ status: next, updated_at: new Date().toISOString() })
      .eq('id', row.id);
    if (error) throw error;
    log.info({ id: row.id, from: row.status, to: next }, 'status reconciled');
  }

  return next;
}

// -------- Finalize preflight & call --------

async function checkFinalizeEligibility(pool: `0x${string}`) {
  const s = await getChainSnapshot(pool);
  const canFinalize =
    (!s.finalized && !s.failed) &&
    ((s.totalRaised >= s.softCap && s.now >= Number(s.endAt)) || (s.totalRaised >= s.hardCap));

  return {
    ...s,
    canFinalize,
  };
}

async function callFinalize(pool: `0x${string}`): Promise<`0x${string}`> {
  const st = await checkFinalizeEligibility(pool);

  const afterEnd = st.now >= Number(st.endAt);
  const belowSoft = st.totalRaised < st.softCap;

  if (!st.canFinalize && afterEnd && belowSoft && !st.finalized && !st.failed) {
    log.info(
      { pool, totalRaised: st.totalRaised.toString(), softCap: st.softCap.toString(), endAt: st.endAt.toString(), now: st.now },
      'preflight: mark failed (below soft cap after end)',
    );
    const err = new Error('SALE_FAILED_BELOW_SOFTCAP');
    (err as any).__saleFailed = true;
    throw err;
  }

  if (!st.canFinalize) {
    log.info(
      {
        pool,
        reason: 'not_eligible',
        totalRaised: st.totalRaised.toString(),
        softCap: st.softCap.toString(),
        hardCap: st.hardCap.toString(),
        endAt: st.endAt.toString(),
        now: st.now,
        finalized: st.finalized,
        failed: st.failed,
      },
      'preflight: skip finalize',
    );
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

// -------- Concurrency guards --------

const processing = new Set<string>();
function markStart(id: string): boolean {
  if (processing.has(id)) return false;
  processing.add(id);
  return true;
}
function markDone(id: string) {
  processing.delete(id);
}

// -------- DB lock & finalize pipeline --------

async function tryClaim(id: string): Promise<boolean> {
  const { data, error } = await supabase
    .from('launches')
    .update({ finalizing: true, updated_at: new Date().toISOString() })
    .eq('id', id)
    .eq('status', 'ended')
    .eq('finalized', false)
    .eq('finalizing', false)
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
    // Reconcile before attempting finalize (may flip to failed/finalized)
    const nextStatus = await reconcileStatus(row);
    if (nextStatus !== 'ended') {
      log.info({ id, nextStatus }, 'no finalize needed after reconcile');
      return;
    }

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
        status: 'finalized',
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
      update.status = 'failed';
      update.finalized = false;
    }

    await supabase.from('launches').update(update).eq('id', id);
  } finally {
    markDone(id);
  }
}

// -------- Realtime & Poller --------

function startRealtime() {
  const ch = supabase
    .channel('launches-status')
    .on(
      'postgres_changes',
      { event: '*', schema: 'public', table: 'launches' }, // watch all updates/inserts that might change timing
      async (payload) => {
        const next = (payload as any).new as Launch | undefined;
        if (!next) return;

        // Reconcile status for any update touching a relevant row
        try {
          const reconciled = await reconcileStatus({
            id: next.id,
            status: next.status as Status,
            start_at: (next as any).start_at,
            end_at: (next as any).end_at,
            pool_address: next.pool_address as any,
            finalized: next.finalized,
            finalizing: (next as any).finalizing ?? false,
            finalize_attempts: (next as any).finalize_attempts ?? 0,
          });

          // If now ended and needs finalize, kick pipeline
          if (
            reconciled === 'ended' &&
            next.finalized === false &&
            (next as any).finalizing === false
          ) {
            log.info({ id: next.id }, 'RT: ended → process');
            processOne({
              id: next.id,
              status: reconciled,
              pool_address: next.pool_address as any,
              finalized: next.finalized,
              finalizing: (next as any).finalizing ?? false,
              start_at: (next as any).start_at,
              end_at: (next as any).end_at,
              finalize_attempts: (next as any).finalize_attempts ?? 0,
            }).catch(() => {});
          }
        } catch (err) {
          log.error({ err, id: next.id }, 'realtime reconcile failed');
        }
      },
    )
    .subscribe((status, err) => {
      log.info({ status, err }, 'realtime subscription status');
    });

  return ch;
}

async function pollOnce() {
  // Grab candidates that might change based on time/chain and aren’t terminal or in-flight
  const { data, error } = await supabase
    .from('launches')
    .select('id, pool_address, status, finalized, finalizing, finalize_attempts, start_at, end_at')
    .in('status', ['draft', 'upcoming', 'active', 'ended'])
    .limit(100);

  if (error) {
    log.error({ err: error }, 'poll query failed');
    return;
  }

  for (const r of data ?? []) {
    const row = r as unknown as Launch;
    try {
      const next = await reconcileStatus(row);
      if (next === 'ended' && !row.finalized && !(row as any).finalizing) {
        await processOne({ ...row, status: next });
      }
    } catch (err) {
      log.error({ err, id: row.id }, 'poll reconcile/process failed');
    }
  }
}

function startPoller() {
  const ms = Number(process.env.POLL_INTERVAL_MS || 15000);
  log.info({ ms }, 'starting poller');
  setInterval(() => {
    pollOnce().catch((err) => log.error({ err }, 'pollOnce failed'));
  }, ms);
}

// -------- Health server --------

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

// -------- Main --------

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
