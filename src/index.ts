// index.ts
import 'dotenv/config';
import express, { type Request, type Response } from 'express';
import pino from 'pino';
import { createClient as createSb } from '@supabase/supabase-js';
import {
  createPublicClient,
  createWalletClient,
  http,
  parseAbi,
  parseEventLogs,
  getAddress,
  defineChain,
  type Chain,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

// ---------- Logging ----------
const log = pino({
  level: process.env.LOG_LEVEL || 'info',
  transport: process.env.NODE_ENV === 'production' ? undefined : { target: 'pino-pretty' },
});

// ---------- Env ----------
const {
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  RPC_URL,
  CHAIN_ID = '1',
  PRIVATE_KEY,
  FACTORY_ADDRESS = '0x7d8c6B58BA2d40FC6E34C25f9A488067Fe0D2dB4', // Camelot AMM v2 (ApeChain)
  PORT = '8080',
  POLL_INTERVAL_MS = '15000',
} = process.env;

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

// ---------- Supabase ----------
const supabase = createSb(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });

// ---------- Chain/Clients ----------
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

// ---------- ABIs ----------
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

// Factory & Pair (minimal)
const camelotV2FactoryAbi = parseAbi([
  'event PairCreated(address indexed token0, address indexed token1, address pair, uint256)',
  'function getPair(address,address) view returns (address)',
]);
const v2PairAbi = parseAbi([
  'function sync() external',
  'event Mint(address indexed sender, uint256 amount0, uint256 amount1)',
  'event Sync(uint112 reserve0, uint112 reserve1)',
]);

// ---------- Types ----------
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

// ---------- Helpers ----------
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
  return { softCap, hardCap, totalRaised, endAt, finalized, failed, now: Number(block.timestamp) };
}

// ---------- Status logic ----------
function computeNextStatus(row: Launch, chain: ChainSnapshot | null, nowMs: number): Status {
  if (row.status === 'finalized') return 'finalized';
  if (row.status === 'failed') return 'failed';

  const start = row.start_at ? Date.parse(row.start_at) : NaN;
  const end = row.end_at ? Date.parse(row.end_at) : NaN;
  const hasWindow = Number.isFinite(start) && Number.isFinite(end);
  const afterStart = hasWindow && nowMs >= start;
  const afterEnd = hasWindow && nowMs > end;

  if (chain) {
    if (chain.finalized) return 'finalized';
    if (chain.failed) return 'failed';

    if (chain.hardCap > 0n && chain.totalRaised >= chain.hardCap) return 'ended';

    const afterEndOnChain = chain.now >= Number(chain.endAt || 0n);
    if (afterEndOnChain && chain.totalRaised < chain.softCap) return 'failed';

    if (afterStart && !afterEnd) return 'active';
    if (!afterStart) return 'upcoming';
    if (afterEnd) return 'ended';
  }

  if (!hasWindow) return 'draft';
  if (!afterStart) return 'upcoming';
  if (!afterEnd) return 'active';
  return 'ended';
}

async function reconcileStatus(row: Launch): Promise<Status> {
  const nowMs = Date.now();
  const readChain =
    !!row.pool_address && (row.status === 'upcoming' || row.status === 'active' || row.status === 'ended');
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

// ---------- Finalize preflight & call ----------
async function checkFinalizeEligibility(pool: `0x${string}`) {
  const s = await getChainSnapshot(pool);
  const canFinalize =
    (!s.finalized && !s.failed) &&
    ((s.totalRaised >= s.softCap && s.now >= Number(s.endAt)) || (s.totalRaised >= s.hardCap));
  return { ...s, canFinalize };
}

/** Return both tx hash and receipt so we can parse logs for PairCreated/Mint/Sync */
async function callFinalize(pool: `0x${string}`): Promise<{ hash: `0x${string}`; receipt: any }> {
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
    return { hash, receipt };
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

// ---------- Post-finalize: find pairs & sync ----------
async function pairsFromFinalizeReceipt(receipt: any): Promise<`0x${string}`[]> {
  const pairs = new Set<`0x${string}`>();

  // PairCreated (preferred)
  try {
    const created = parseEventLogs({
      abi: camelotV2FactoryAbi,
      logs: receipt.logs ?? [],
      eventName: 'PairCreated',
      strict: false,
    });
    for (const ev of created) {
      const addr = (ev as any)?.args?.pair as `0x${string}` | undefined;
      const factoryAddr = (ev as any)?.address as `0x${string}` | undefined;
      if (addr) {
        if (!factoryAddr || factoryAddr.toLowerCase() === FACTORY_ADDRESS.toLowerCase()) {
          pairs.add(addr);
        }
      }
    }
  } catch {/* ignore */}

  // Mint/Sync (covers pre-existing pairs that got liquidity/sync)
  try {
    const mintsOrSyncs = parseEventLogs({
      abi: v2PairAbi,
      logs: receipt.logs ?? [],
      eventName: ['Mint', 'Sync'],
      strict: false,
    });
    for (const ev of mintsOrSyncs) {
      const addr = (ev as any)?.address as `0x${string}` | undefined; // log.address is pair
      if (addr) pairs.add(addr);
    }
  } catch {/* ignore */}

  return [...pairs];
}

async function kickScreenersWithSync(pairs: `0x${string}`[], txHash?: `0x${string}`): Promise<void> {
  const ttlMs = Number(process.env.MIN_SYNC_INTERVAL_MS || 10 * 60 * 1000); // default 10 minutes
  const nowIso = new Date().toISOString();

  for (const pair of pairs) {
    try {
      // check last sync
      const { data: row } = await supabase
        .from('pair_syncs')
        .select('last_synced')
        .eq('pair', pair)
        .maybeSingle();

      const last = row?.last_synced ? Date.parse(row.last_synced as any) : 0;
      const age = Date.now() - last;

      if (age < ttlMs) {
        log.info({ pair, ageMs: age }, 'skip sync: recently synced');
        continue;
      }

      const hash = await walletClient.writeContract({
        address: pair,
        abi: v2PairAbi,
        functionName: 'sync',
        account,
        chain,
      });
      log.info({ pair, hash }, 'sync() submitted');
      const r = await publicClient.waitForTransactionReceipt({ hash });
      log.info({ pair, block: Number(r.blockNumber) }, 'sync() confirmed');

      // upsert sync record
      await supabase
        .from('pair_syncs')
        .upsert({ pair, last_synced: nowIso, tx_hash: txHash ?? hash }, { onConflict: 'pair' });
    } catch (e: any) {
      log.warn({ pair, err: e?.message || String(e) }, 'sync() failed (continuing)');
    }
  }
}

// ---------- Concurrency guards ----------
const processing = new Set<string>();
function markStart(id: string): boolean {
  if (processing.has(id)) return false;
  processing.add(id);
  return true;
}
function markDone(id: string) {
  processing.delete(id);
}

// ---------- DB lock & finalize pipeline ----------
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
    let receipt: any | null = null;

    if (!already) {
      const result = await callFinalize(pool);
      hash = result.hash;
      receipt = result.receipt;
      const txHash = receipt.transactionHash as `0x${string}`;
      {
        const { data } = await supabase
          .from('processed_txs')
          .select('tx_hash')
          .eq('tx_hash', txHash)
          .maybeSingle();
    
        if (data) {
          log.info({ txHash }, 'receipt already processed; skipping');
        } else {
          await supabase.from('processed_txs').insert({ tx_hash: txHash });
    
          const pairs = await pairsFromFinalizeReceipt(receipt);
          if (pairs.length) {
            log.info({ pool, pairs }, 'finalize detected pairs; syncing…');
            await kickScreenersWithSync(pairs, txHash); // pass txHash down (optional)
          } else {
            log.warn({ pool, tx: txHash }, 'no PairCreated/Mint/Sync logs found in finalize receipt');
          }
        }
      }
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

// ---------- Realtime & Poller ----------
function startRealtime() {
  const ch = supabase
    .channel('launches-status')
    .on(
      'postgres_changes',
      { event: '*', schema: 'public', table: 'launches' },
      async (payload) => {
        const next = (payload as any).new as Launch | undefined;
        if (!next) return;

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

          if (reconciled === 'ended' && next.finalized === false && (next as any).finalizing === false) {
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
  const ms = Number(POLL_INTERVAL_MS || 15000);
  log.info({ ms }, 'starting poller');
  setInterval(() => {
    pollOnce().catch((err) => log.error({ err }, 'pollOnce failed'));
  }, ms);
}

// ---------- Health server ----------
function startHttp() {
  const app = express();
  app.use(express.json());

  // Health
  app.get('/health', async (_req: Request, res: Response) => {
    try {
      const { error } = await supabase.from('launches').select('id').limit(1);
      if (error) throw error;
      res.json({ ok: true, time: new Date().toISOString(), address: account.address });
    } catch (e: any) {
      res.status(500).json({ ok: false, error: e?.message || String(e) });
    }
  });

  // Manually trigger a sync() on a given pair (no swap)
  app.post('/sync-now', async (req: Request, res: Response) => {
    try {
      const pair = String(req.query.pair || '').toLowerCase() as `0x${string}`;
      if (!pair || !pair.startsWith('0x') || pair.length !== 42) {
        return res.status(400).json({ ok: false, error: 'Missing/invalid ?pair=0x...' });
      }
      await kickScreenersWithSync([pair]); // uses your walletClient/publicClient
      res.json({ ok: true, pair });
    } catch (e: any) {
      res.status(500).json({ ok: false, error: e?.message || String(e) });
    }
  });

  // Simulate post-finalize flow: parse any tx receipt, find pairs, call sync()
  app.post('/after-finalize', async (req: Request, res: Response) => {
    try {
      const tx = String(req.query.tx || '');
      if (!tx || !tx.startsWith('0x') || tx.length !== 66) {
        return res.status(400).json({ ok: false, error: 'Missing/invalid ?tx=0x...' });
      }
      const receipt = await publicClient.getTransactionReceipt({ hash: tx as `0x${string}` });
      const pairs = await pairsFromFinalizeReceipt(receipt);
      if (pairs.length) await kickScreenersWithSync(pairs);
      res.json({ ok: true, pairs });
    } catch (e: any) {
      res.status(500).json({ ok: false, error: e?.message || String(e) });
    }
  });

  // Kick the full pipeline for a DB row (by launches.id)
  app.post('/process-now', async (req: Request, res: Response) => {
    try {
      const id = String(req.query.id || '');
      if (!id) return res.status(400).json({ ok: false, error: 'Missing ?id=' });
      const { data, error } = await supabase.from('launches').select('*').eq('id', id).maybeSingle();
      if (error) throw error;
      if (!data) return res.status(404).json({ ok: false, error: 'Row not found' });
      await processOne(data as unknown as Launch);
      res.json({ ok: true });
    } catch (e: any) {
      res.status(500).json({ ok: false, error: e?.message || String(e) });
    }
  });

  const port = Number(process.env.PORT || 8080);
  app.listen(port, () => log.info({ port, addr: account.address }, 'health server up'));
}


// ---------- Main ----------
async function main() {
  startHttp();
  startRealtime();
  startPoller();
  log.info({ chainId: chain.id, factory: FACTORY_ADDRESS }, 'worker started');
}

main().catch((err) => {
  log.fatal({ err }, 'fatal');
  process.exit(1);
});
