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
  POLL_INTERVAL_MS = '3000',
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
  'function markFailed() external',       // <-- added
  'function refund() external',
  'function refundAllRemaining(uint256 maxRecipients) external',
  'function refundedAll() view returns (bool)',
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
async function sweepRefundBatch(pool: `0x${string}`) {
  const BATCH = Number(process.env.REFUND_BATCH || 200);
  // Try reading refundedAll(); if the pool is old (no function), readContract will throw.
  let isFailed = false;
  let isDone = false;
  try {
    const [failed, refundedAll] = await Promise.all([
      publicClient.readContract({ address: pool, abi: presalePoolAbi, functionName: 'failed' }) as Promise<boolean>,
      publicClient.readContract({ address: pool, abi: presalePoolAbi, functionName: 'refundedAll' }) as Promise<boolean>,
    ]);
    isFailed = failed;
    isDone = refundedAll;
  } catch {
    // Old pool impl: no refundedAll(). Just return; backend can still optionally call refund() for itself.
    return;
  }
  if (!isFailed || isDone) return;

  try {
    const hash = await walletClient.writeContract({
      address: pool,
      abi: presalePoolAbi,
      functionName: 'refundAllRemaining',
      args: [BigInt(BATCH)],
      chain,
      account,
    });
    const r = await publicClient.waitForTransactionReceipt({ hash });
    if (r.status === 'success') {
      log.info({ pool, hash, batch: BATCH }, 'refundAllRemaining batch submitted');
    }
  } catch (e: any) {
    log.warn({ pool, err: e?.shortMessage || e?.message || String(e) }, 'refundAllRemaining failed (will try later)');
  }
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

  // Fast path: pure time window flip without chain reads
  if (!row.pool_address) {
    const nextBare = computeNextStatus(row, null, nowMs);
    if (nextBare !== row.status) {
      await supabase
        .from('launches')
        .update({ status: nextBare, updated_at: new Date().toISOString() })
        .eq('id', row.id);
      log.info({ id: row.id, from: row.status, to: nextBare }, 'status reconciled (time-only)');
    }
    return nextBare;
  }

  // Only hit chain when the row is 'upcoming'/'active'/'ended'
  const needsChain = row.status === 'upcoming' || row.status === 'active' || row.status === 'ended';
  const chainSnap = needsChain ? await getChainSnapshot(row.pool_address) : null;
  const next = computeNextStatus(row, chainSnap, nowMs);

  if (next !== row.status) {
    await supabase
      .from('launches')
      .update({ status: next, updated_at: new Date().toISOString() })
      .eq('id', row.id);
    log.info({ id: row.id, from: row.status, to: next }, 'status reconciled');
  }
  return next;
}

// ---------- Finalize preflight & call ----------
async function checkFinalizeEligibility(pool: `0x${string}`) {
  const s = await getChainSnapshot(pool);
  const canFinalize =
    !s.finalized &&
    !s.failed &&
    ((s.totalRaised >= s.softCap && s.now >= Number(s.endAt)) || s.totalRaised >= s.hardCap);
  return { ...s, canFinalize };
}

async function callFinalize(pool: `0x${string}`): Promise<{ hash: `0x${string}`; receipt: any }> {
  const st = await checkFinalizeEligibility(pool);

  const afterEnd = st.now >= Number(st.endAt);
  const belowSoft = st.totalRaised < st.softCap;

  if (!st.canFinalize && afterEnd && belowSoft && !st.finalized && !st.failed) {
    log.info(
      {
        pool,
        totalRaised: st.totalRaised.toString(),
        softCap: st.softCap.toString(),
        endAt: st.endAt.toString(),
        now: st.now,
      },
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

// ---------- markFailed & Refund helpers ----------
async function callMarkFailed(pool: `0x${string}`): Promise<`0x${string}` | null> {
  const s = await getChainSnapshot(pool);
  const afterEnd = s.now >= Number(s.endAt);
  const belowSoft = s.totalRaised < s.softCap;

  if (s.failed) {
    return null; // already failed
  }
  if (!afterEnd || !belowSoft) {
    throw new Error('NotFailed window not met');
  }

  const hash = await walletClient.writeContract({
    address: pool,
    abi: presalePoolAbi,
    functionName: 'markFailed',
    chain,
    account,
  });
  const r = await publicClient.waitForTransactionReceipt({ hash });
  if (r.status !== 'success') throw new Error(`markFailed tx failed: ${hash}`);
  log.info({ pool, hash }, 'markFailed() confirmed');
  return hash;
}

async function ensureFailedOnChain(pool: `0x${string}`): Promise<boolean> {
  const s = await getChainSnapshot(pool);
  if (s.failed) return true;
  const afterEnd = s.now >= Number(s.endAt);
  const belowSoft = s.totalRaised < s.softCap;
  if (!afterEnd || !belowSoft) return false;
  await callMarkFailed(pool);
  return true;
}

async function callRefund(pool: `0x${string}`): Promise<{ hash: `0x${string}` | null; receipt: any | null }> {
  // Ensure the on-chain failed flag is set (will send markFailed if eligible)
  const ok = await ensureFailedOnChain(pool);
  if (!ok) {
    const s = await getChainSnapshot(pool);
    log.info(
      {
        pool,
        reason: 'not_failed_yet',
        totalRaised: s.totalRaised.toString(),
        softCap: s.softCap.toString(),
        endAt: s.endAt.toString(),
        now: s.now,
        finalized: s.finalized,
        failed: s.failed,
      },
      'preflight: skip refund (failed flag not set/eligible)',
    );
    throw new Error('Refund not eligible yet (Failed flag not set)');
  }

  try {
    const hash = await walletClient.writeContract({
      address: pool,
      abi: presalePoolAbi,
      functionName: 'refund',
      chain,
      account,
    });
    const receipt = await publicClient.waitForTransactionReceipt({ hash });
    if (receipt.status !== 'success') throw new Error(`Refund tx failed: ${hash}`);
    return { hash, receipt };
  } catch (e: any) {
    const msg = e?.shortMessage || e?.message || String(e);
    // Contract uses: require(amt > 0, "nothing")
    if (typeof msg === 'string' && msg.toLowerCase().includes('nothing')) {
      // Backend wallet had no contribution — treat as no-op
      (e as any).__noContribution = true;
    }
    // If still "not failed", surface clearly
    if (typeof msg === 'string' && msg.toLowerCase().includes('not failed')) {
      (e as any).__notFailed = true;
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
  } catch {
    /* ignore */
  }

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
  } catch {
    /* ignore */
  }

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

// ---------- DB lock & finalize/refund pipeline ----------
async function tryClaim(id: string, mode: 'finalize' | 'refund'): Promise<boolean> {
  let q = supabase
    .from('launches')
    .update({ finalizing: true, updated_at: new Date().toISOString() })
    .eq('id', id)
    .eq('finalized', false)
    .eq('finalizing', false);

  if (mode === 'finalize') {
    q = q.eq('status', 'ended');
  } else {
    q = q.eq('status', 'failed');
  }

  const { data, error } = await q.select('id').maybeSingle();
  if (error) {
    log.error({ err: error, id, mode }, 'claim update failed');
    return false;
  }
  return !!data;
}

async function processOne(row: Launch) {
  if (!row.pool_address) {
    log.debug({ id: row.id }, 'no pool_address; skipping'); // quieter
    return;
  }
  if (!markStart(row.id)) {
    log.debug({ id: row.id }, 'already processing; skip');
    return;
  }

  const id = row.id;
  const pool = getAddress(row.pool_address) as `0x${string}`;

  try {
    // Reconcile first
    const nextStatus = await reconcileStatus(row);

    // Refund path if sale ended below soft cap (status = 'failed')
  // Refund path if sale ended below soft cap (status = 'failed')
if (nextStatus === 'failed') {
  const claimed = await tryClaim(id, 'refund');
  if (!claimed) {
    log.debug({ id }, 'could not claim row for refund (another worker or not eligible)');
    return;
  }

  try {
    // Make sure on-chain failed flag is set (will call markFailed if eligible)
    await ensureFailedOnChain(pool);
    // Kick one sweep batch (new impl); old impl will no-op here
    await sweepRefundBatch(pool);

    // Clear lock & mark attempt; no DB status flip needed (row is already 'failed')
    const { error } = await supabase
      .from('launches')
      .update({
        finalizing: false,
        finalize_attempts: (row.finalize_attempts ?? 0) + 1,
        finalize_error: null,
        updated_at: new Date().toISOString(),
      })
      .eq('id', id);
    if (error) throw error;
    log.info({ id, pool }, 'refund sweep tick executed');
  } catch (e: any) {
    log.error({ id, pool, err: e?.message || String(e) }, 'refund sweep tick failed');
    await supabase
      .from('launches')
      .update({
        finalizing: false,
        finalize_attempts: (row.finalize_attempts ?? 0) + 1,
        finalize_error: `REFUND_SWEEP_FAILED: ${e?.message || String(e)}`,
        updated_at: new Date().toISOString(),
      })
      .eq('id', id);
  }
  return;
}

    // Finalize path
    if (nextStatus !== 'ended') {
      log.info({ id, nextStatus }, 'no finalize/refund needed after reconcile');
      return;
    }

    // attempt to claim DB lock for FINALIZE
    const claimed = await tryClaim(id, 'finalize');
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
            await kickScreenersWithSync(pairs, txHash);
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

    // If we intentionally flagged the sale as "below soft cap after end",
    // set failed on-chain, then attempt refund (may be no-op)
 // inside the `catch (e: any)` of processOne, where saleFailed === true
if (saleFailed) {
  try {
    await callMarkFailed(pool); // ok if already failed
  } catch (mfErr: any) {
    log.warn({ id, pool, err: mfErr?.message || String(mfErr) }, 'markFailed attempt failed or not needed');
  }

  try {
    // NEW: sweep refunds for contributors (new impl). No-op on old impl.
    await sweepRefundBatch(pool);
    update.status = 'failed';
    update.finalized = false;
    update.finalize_error = null;
  } catch (er: any) {
    // OPTIONAL: fallback for old impls (refund() only refunds the caller)
    try {
      const { hash: refundHash } = await callRefund(pool);
      log.info({ id, pool, tx: refundHash }, 'legacy self-refund executed after markFailed');
      update.status = 'failed';
      update.finalized = false;
      update.finalize_error = null;
    } catch (er2: any) {
      if (er2 && er2.__noContribution) {
        update.status = 'failed';
        update.finalized = false;
        update.finalize_error = null;
      } else {
        update.status = 'failed';
        update.finalized = false;
        update.finalize_error = `REFUND_FAILED: ${er2?.message || String(er2)}`;
      }
    }
  }
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
        const next = payload.new as Launch | undefined;
        if (!next) return;

        // 🔒 Ignore rows without a pool to prevent log spam / useless processing
        if (!next.pool_address) {
          log.debug({ id: next.id }, 'RT: no pool_address; ignoring');
          return;
        }

        try {
          const reconciled = await reconcileStatus({
            id: next.id,
            status: next.status as Status,
            start_at: next.start_at,
            end_at: next.end_at,
            pool_address: next.pool_address as any,
            finalized: next.finalized,
            finalizing: (next as any).finalizing ?? false,
            finalize_attempts: (next as any).finalize_attempts ?? 0,
          });

          if (
            (reconciled === 'ended' || reconciled === 'failed') &&
            next.finalized === false &&
            (next as any).finalizing === false
          ) {
            log.info({ id: next.id }, `RT: ${reconciled} → process`);
            processOne({
              id: next.id,
              status: reconciled,
              pool_address: next.pool_address as any,
              finalized: next.finalized,
              finalizing: (next as any).finalizing ?? false,
              start_at: next.start_at,
              end_at: next.end_at,
              finalize_attempts: (next as any).finalize_attempts ?? 0,
            }).catch(() => {});
          }
        } catch (err) {
          log.error({ err, id: next?.id }, 'realtime reconcile failed');
        }
      },
    )
    // NOTE: subscribe takes a single status callback in v2.x
    .subscribe((status) => {
      log.info({ status }, 'realtime subscription status');
      if (status === 'CLOSED' || status === 'TIMED_OUT') {
        log.warn({ status }, 'realtime closed, retrying in 2s');
        setTimeout(() => {
          _realtime = startRealtime();
        }, 2000);
      }
    });

  return ch;
}

async function pollOnce() {
  const { data } = await supabase
    .from('launches')
    .select('id, pool_address, status, finalized, finalizing, finalize_attempts, start_at, end_at')
    .in('status', ['upcoming', 'active', 'ended', 'failed']) // include failed so we can mark/refund
    .not('pool_address', 'is', null) // skip rows without pools
    .limit(200);

  const now = Date.now();
  const soon = (r: any) => {
    const end = r.end_at ? Date.parse(r.end_at) : Infinity;
    return end - now <= 7_000; // ending within 7s
  };

  const hot = (data ?? []).filter(soon);
  const cold = (data ?? []).filter((r) => !soon(r));

  // Do "hot" rows first & in parallel (limit concurrency if many)
  await Promise.all(hot.map((r) => reconcileStatus(r as any)));

  // Then the rest (can be sequential or limited parallel)
  for (const r of cold) {
    await reconcileStatus(r as any);
  }
}

// top-level
let _pollTimer: NodeJS.Timer | null = null;
let _realtime: ReturnType<typeof startRealtime> | null = null;

// clamp + log poll interval
function getPollMs() {
  const raw = process.env.POLL_INTERVAL_MS ?? '3000';
  const n = Number.parseInt(raw, 10);
  const ms = Number.isFinite(n) ? n : 3000;
  const clamped = Math.min(Math.max(ms, 1000), 60000);
  if (clamped !== n) log.warn({ raw, parsed: n, using: clamped }, 'POLL_INTERVAL_MS adjusted');
  return clamped;
}

function startPoller() {
  const ms = getPollMs();
  log.info({ ms }, 'starting poller');
  const t = setInterval(() => {
    pollOnce().catch((err) => log.error({ err }, 'pollOnce failed'));
  }, ms);
  return t;
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
  app.get('/', (_req, res) => res.status(200).send('ok'));
  // catch-all 200 for GET to satisfy any default probe hitting '/' or another path
  app.get('*', (_req, res) => res.status(200).send('ok'));

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

  const raw = process.env.PORT ?? '';
  const parsed = parseInt(raw, 10);
  const port = Number.isFinite(parsed) && parsed > 0 ? parsed : 8080; // 8080 for local only
  log.info({ rawEnvPort: process.env.PORT }, 'startup: PORT from env');

  app.listen(port, '0.0.0.0', () => {
    log.info({ port, addr: account.address }, 'health server up');
  });
}

process.on('unhandledRejection', (reason) => log.fatal({ reason }, 'unhandledRejection'));
process.on('uncaughtException', (err) => log.fatal({ err }, 'uncaughtException'));
process.on('exit', (code) => log.warn({ code }, 'process exit'));

// IMPORTANT: don't exit on SIGTERM
process.on('SIGTERM', () => {
  log.warn('received SIGTERM (platform stop) — not calling process.exit');
});

// ---------- Main ----------
async function main() {
  startHttp();
  _realtime = startRealtime();
  await pollOnce().catch((e) => log.error({ e }, 'initial poll failed'));
  _pollTimer = startPoller();
  log.info({ chainId: chain.id, factory: FACTORY_ADDRESS }, 'worker started');
}

main().catch((err) => {
  log.fatal({ err }, 'fatal');
  process.exit(1);
});
