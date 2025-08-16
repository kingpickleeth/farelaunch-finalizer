// index.ts
import 'dotenv/config';
import express from 'express';
import pino from 'pino';
import { createClient as createSb } from '@supabase/supabase-js';
import { createPublicClient, createWalletClient, http, parseAbi, parseEventLogs, getAddress, defineChain, } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
// ---------- Logging ----------
const log = pino({
    level: process.env.LOG_LEVEL || 'info',
    transport: process.env.NODE_ENV === 'production' ? undefined : { target: 'pino-pretty' },
});
// ---------- Env ----------
const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, RPC_URL, CHAIN_ID = '1', PRIVATE_KEY, FACTORY_ADDRESS = '0x7d8c6B58BA2d40FC6E34C25f9A488067Fe0D2dB4', // Camelot AMM v2 (ApeChain)
POLL_INTERVAL_MS = '3000', } = process.env;
if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY || !RPC_URL || !PRIVATE_KEY) {
    log.fatal({
        SUPABASE_URL: !!SUPABASE_URL,
        SUPABASE_SERVICE_ROLE_KEY: !!SUPABASE_SERVICE_ROLE_KEY,
        RPC_URL: !!RPC_URL,
        PRIVATE_KEY: !!PRIVATE_KEY,
    }, 'Missing required env vars');
    process.exit(1);
}
// ---------- Supabase ----------
const supabase = createSb(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });
// ---------- Chain/Clients ----------
const chain = defineChain({
    id: Number(CHAIN_ID || 1),
    name: 'ApeChain',
    nativeCurrency: { name: 'APE', symbol: 'APE', decimals: 18 },
    rpcUrls: { default: { http: [RPC_URL] } },
});
const publicClient = createPublicClient({ transport: http(RPC_URL), chain });
const account = privateKeyToAccount(PRIVATE_KEY.startsWith('0x') ? PRIVATE_KEY : `0x${PRIVATE_KEY}`);
const walletClient = createWalletClient({ account, chain, transport: http(RPC_URL) });
// ---------- ABIs ----------
const presalePoolAbi = parseAbi([
    'function finalize() external',
    'function markFailed() external', // <-- added
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
// ---------- Helpers ----------
async function readFinalized(pool) {
    try {
        return (await publicClient.readContract({
            address: pool,
            abi: presalePoolAbi,
            functionName: 'finalized',
        }));
    }
    catch {
        return false;
    }
}
async function getChainSnapshot(pool) {
    const [softCap, hardCap, totalRaised, endAt, finalized, failed] = await Promise.all([
        publicClient.readContract({ address: pool, abi: presalePoolAbi, functionName: 'softCap' }),
        publicClient.readContract({ address: pool, abi: presalePoolAbi, functionName: 'hardCap' }),
        publicClient.readContract({ address: pool, abi: presalePoolAbi, functionName: 'totalRaised' }),
        publicClient.readContract({ address: pool, abi: presalePoolAbi, functionName: 'endAt' }),
        publicClient.readContract({ address: pool, abi: presalePoolAbi, functionName: 'finalized' }),
        publicClient.readContract({ address: pool, abi: presalePoolAbi, functionName: 'failed' }),
    ]);
    const block = await publicClient.getBlock();
    return { softCap, hardCap, totalRaised, endAt, finalized, failed, now: Number(block.timestamp) };
}
async function sweepRefundBatch(pool) {
    const BATCH = Number(process.env.REFUND_BATCH || 200);
    // Try to read gates; old impls may not have refundedAll()
    let isFailed = false, isDone = false;
    try {
        const [failed, refundedAll] = await Promise.all([
            publicClient.readContract({ address: pool, abi: presalePoolAbi, functionName: 'failed' }),
            publicClient.readContract({ address: pool, abi: presalePoolAbi, functionName: 'refundedAll' }),
        ]);
        isFailed = failed;
        isDone = refundedAll;
    }
    catch {
        // Old pool impl: no refundedAll(). Nothing we can sweep here.
        return "noop";
    }
    if (!isFailed)
        return "noop";
    if (isDone)
        return "done";
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
            return "submitted";
        }
    }
    catch (e) {
        log.warn({ pool, err: e?.shortMessage || e?.message || String(e) }, 'refundAllRemaining failed (will try later)');
    }
    return "noop";
}
async function isRefundComplete(pool) {
    try {
        const [failed, refundedAll] = await Promise.all([
            publicClient.readContract({ address: pool, abi: presalePoolAbi, functionName: 'failed' }),
            publicClient.readContract({ address: pool, abi: presalePoolAbi, functionName: 'refundedAll' }),
        ]);
        return failed && refundedAll;
    }
    catch {
        // Old impl: no refundedAll() — we can't know it's “done”; treat as not complete
        return false;
    }
}
// ---------- Status logic ----------
function computeNextStatus(row, chain, nowMs) {
    if (row.status === 'finalized')
        return 'finalized';
    if (row.status === 'failed')
        return 'failed';
    const start = row.start_at ? Date.parse(row.start_at) : NaN;
    const end = row.end_at ? Date.parse(row.end_at) : NaN;
    const hasWindow = Number.isFinite(start) && Number.isFinite(end);
    const afterStart = hasWindow && nowMs >= start;
    const afterEnd = hasWindow && nowMs > end;
    if (chain) {
        if (chain.finalized)
            return 'finalized';
        if (chain.failed)
            return 'failed';
        if (chain.hardCap > 0n && chain.totalRaised >= chain.hardCap)
            return 'ended';
        const afterEndOnChain = chain.now >= Number(chain.endAt || 0n);
        if (afterEndOnChain && chain.totalRaised < chain.softCap)
            return 'failed';
        if (afterStart && !afterEnd)
            return 'active';
        if (!afterStart)
            return 'upcoming';
        if (afterEnd)
            return 'ended';
    }
    if (!hasWindow)
        return 'draft';
    if (!afterStart)
        return 'upcoming';
    if (!afterEnd)
        return 'active';
    return 'ended';
}
async function reconcileStatus(row) {
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
    const needsChain = !!row.pool_address; // read chain whenever there’s a pool
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
async function checkFinalizeEligibility(pool) {
    const s = await getChainSnapshot(pool);
    const canFinalize = !s.finalized &&
        !s.failed &&
        ((s.totalRaised >= s.softCap && s.now >= Number(s.endAt)) || s.totalRaised >= s.hardCap);
    return { ...s, canFinalize };
}
async function callFinalize(pool) {
    const st = await checkFinalizeEligibility(pool);
    const afterEnd = st.now >= Number(st.endAt);
    const belowSoft = st.totalRaised < st.softCap;
    if (!st.canFinalize && afterEnd && belowSoft && !st.finalized && !st.failed) {
        log.info({
            pool,
            totalRaised: st.totalRaised.toString(),
            softCap: st.softCap.toString(),
            endAt: st.endAt.toString(),
            now: st.now,
        }, 'preflight: mark failed (below soft cap after end)');
        const err = new Error('SALE_FAILED_BELOW_SOFTCAP');
        err.__saleFailed = true;
        throw err;
    }
    if (!st.canFinalize) {
        log.info({
            pool,
            reason: 'not_eligible',
            totalRaised: st.totalRaised.toString(),
            softCap: st.softCap.toString(),
            hardCap: st.hardCap.toString(),
            endAt: st.endAt.toString(),
            now: st.now,
            finalized: st.finalized,
            failed: st.failed,
        }, 'preflight: skip finalize');
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
        if (receipt.status !== 'success')
            throw new Error(`Finalize tx failed: ${hash}`);
        return { hash, receipt };
    }
    catch (e) {
        const data = e?.data || e?.cause?.data;
        const sel = typeof data === 'string' ? data.slice(0, 10) : undefined;
        if (sel === '0x86997fcd') {
            log.warn({ pool, selector: sel, msg: e?.shortMessage || e?.message }, 'reverted: Window()');
        }
        else if (sel) {
            log.warn({ pool, selector: sel, msg: e?.shortMessage || e?.message }, 'reverted: custom error');
        }
        else {
            log.warn({ pool, msg: e?.shortMessage || e?.message }, 'reverted');
        }
        throw e;
    }
}
// ---------- markFailed & Refund helpers ----------
async function callMarkFailed(pool) {
    const s = await getChainSnapshot(pool);
    const afterEnd = s.now >= Number(s.endAt);
    const belowSoft = s.totalRaised < s.softCap;
    log.debug({ pool, afterEnd, belowSoft, failed: s.failed }, 'callMarkFailed preflight');
    if (s.failed)
        return null;
    if (!afterEnd || !belowSoft)
        throw new Error('NotFailed window not met');
    try {
        const sim = await publicClient.simulateContract({
            address: pool,
            abi: presalePoolAbi,
            functionName: 'markFailed',
            account,
        });
        const hash = await walletClient.writeContract(sim.request);
        const r = await publicClient.waitForTransactionReceipt({ hash });
        if (r.status !== 'success')
            throw new Error(`markFailed tx failed: ${hash}`);
        try {
            await supabase.from('processed_txs').insert({ tx_hash: hash });
        }
        catch { }
        log.info({ pool, hash }, 'markFailed() confirmed');
        return hash;
    }
    catch (e) {
        const msg = (e?.shortMessage || e?.message || '').toLowerCase();
        const sel = e?.data ?? e?.cause?.data;
        log.error({
            pool,
            msg: e?.shortMessage || e?.message,
            selector: typeof sel === 'string' ? sel.slice(0, 10) : null,
            raw: e,
        }, 'markFailed reverted');
        if (msg.includes('function selector was not recognized') || msg.includes('no matching function'))
            e.__noMarkFailed = true;
        if (msg.includes('ownable') || msg.includes('onlyowner') || msg.includes('caller is not the owner'))
            e.__notAuthorized = true;
        throw e;
    }
}
async function ensureFailedOnChain(pool) {
    const s = await getChainSnapshot(pool);
    const afterEnd = s.now >= Number(s.endAt);
    const belowSoft = s.totalRaised < s.softCap;
    log.debug({ pool, failed: s.failed, afterEnd, belowSoft, now: s.now, endAt: Number(s.endAt) }, 'ensureFailedOnChain snapshot');
    if (s.failed)
        return true;
    if (!afterEnd || !belowSoft)
        return false;
    await callMarkFailed(pool);
    return true;
}
async function callRefund(pool) {
    // Ensure the on-chain failed flag is set (will send markFailed if eligible)
    const ok = await ensureFailedOnChain(pool);
    if (!ok) {
        const s = await getChainSnapshot(pool);
        log.info({
            pool,
            reason: 'not_failed_yet',
            totalRaised: s.totalRaised.toString(),
            softCap: s.softCap.toString(),
            endAt: s.endAt.toString(),
            now: s.now,
            finalized: s.finalized,
            failed: s.failed,
        }, 'preflight: skip refund (failed flag not set/eligible)');
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
        if (receipt.status !== 'success')
            throw new Error(`Refund tx failed: ${hash}`);
        return { hash, receipt };
    }
    catch (e) {
        const msg = e?.shortMessage || e?.message || String(e);
        // Contract uses: require(amt > 0, "nothing")
        if (typeof msg === 'string' && msg.toLowerCase().includes('nothing')) {
            // Backend wallet had no contribution — treat as no-op
            e.__noContribution = true;
        }
        // If still "not failed", surface clearly
        if (typeof msg === 'string' && msg.toLowerCase().includes('not failed')) {
            e.__notFailed = true;
        }
        throw e;
    }
}
// ---------- Post-finalize: find pairs & sync ----------
async function pairsFromFinalizeReceipt(receipt) {
    const pairs = new Set();
    // PairCreated (preferred)
    try {
        const created = parseEventLogs({
            abi: camelotV2FactoryAbi,
            logs: receipt.logs ?? [],
            eventName: 'PairCreated',
            strict: false,
        });
        for (const ev of created) {
            const addr = ev?.args?.pair;
            const factoryAddr = ev?.address;
            if (addr) {
                if (!factoryAddr || factoryAddr.toLowerCase() === FACTORY_ADDRESS.toLowerCase()) {
                    pairs.add(addr);
                }
            }
        }
    }
    catch {
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
            const addr = ev?.address; // log.address is pair
            if (addr)
                pairs.add(addr);
        }
    }
    catch {
        /* ignore */
    }
    return [...pairs];
}
async function kickScreenersWithSync(pairs, txHash) {
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
            const last = row?.last_synced ? Date.parse(row.last_synced) : 0;
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
        }
        catch (e) {
            log.warn({ pair, err: e?.message || String(e) }, 'sync() failed (continuing)');
        }
    }
}
// ---------- Concurrency guards ----------
const processing = new Set();
function markStart(id) {
    if (processing.has(id))
        return false;
    processing.add(id);
    return true;
}
function markDone(id) {
    processing.delete(id);
}
const RT_COOLDOWN_MS = Number(process.env.RT_COOLDOWN_MS || 30_000);
const _rtLast = new Map();
const REFUND_SWEEP_COOLDOWN_MS = Number(process.env.REFUND_SWEEP_COOLDOWN_MS || 60_000); // 60s default
const _lastRefundSweep = new Map();
const REFUND_DONE_CACHE_MS = Number(process.env.REFUND_DONE_CACHE_MS || 60_000);
const _refundDoneCache = new Map();
async function isRefundCompleteCached(pool) {
    const hit = _refundDoneCache.get(pool);
    const now = Date.now();
    if (hit && now - hit.t < REFUND_DONE_CACHE_MS)
        return hit.done;
    const done = await isRefundComplete(pool);
    _refundDoneCache.set(pool, { t: now, done });
    return done;
}
// ---------- DB lock & finalize/refund pipeline ----------
async function tryClaim(id, mode) {
    let q = supabase
        .from('launches')
        .update({ finalizing: true, updated_at: new Date().toISOString() })
        .eq('id', id)
        .eq('finalized', false)
        .eq('finalizing', false);
    if (mode === 'finalize') {
        q = q.eq('status', 'ended');
    }
    else {
        q = q.eq('status', 'failed');
    }
    const { data, error } = await q.select('id').maybeSingle();
    if (error) {
        log.error({ err: error, id, mode }, 'claim update failed');
        return false;
    }
    return !!data;
}
async function processOne(row) {
    if (!row.pool_address) {
        log.debug({ id: row.id }, 'no pool_address; skipping'); // quieter
        return;
    }
    if (!markStart(row.id)) {
        log.debug({ id: row.id }, 'already processing; skip');
        return;
    }
    const id = row.id;
    const pool = getAddress(row.pool_address);
    try {
        // Reconcile first
        const nextStatus = await reconcileStatus(row);
        // Refund path if sale ended below soft cap (status = 'failed')
        // Refund path if sale ended below soft cap (status = 'failed')
        if (nextStatus === 'failed') {
            // Try once pre-claim (safe)
            let eligible = false;
            try {
                eligible = await ensureFailedOnChain(pool); // true = already failed or markFailed sent+confirmed
            }
            catch (e) {
                log.warn({ id, pool, err: e?.message || String(e) }, 'pre-claim ensureFailedOnChain() threw');
            }
            // If refunds are already complete, don't claim & don't write — avoids RT/poller churn
            const doneAlready = await isRefundCompleteCached(pool);
            if (doneAlready) {
                log.debug({ id, pool }, 'refund already complete; skipping');
                return;
            }
            const claimed = await tryClaim(id, 'refund');
            if (!claimed) {
                log.debug({ id }, 'could not claim row for refund (another worker or not eligible)');
                return;
            }
            try {
                // Enforce eligibility *again* inside the lock, and branch on the boolean
                // Enforce eligibility *again* inside the lock
                eligible = await ensureFailedOnChain(pool); // ← reassign, do NOT redeclare
                if (!eligible) {
                    await supabase.from('launches').update({
                        finalizing: false,
                        finalize_attempts: row.finalize_attempts ?? 0,
                        finalize_error: 'NOT_ELIGIBLE_TO_MARK_FAILED_YET',
                        updated_at: new Date().toISOString(),
                    }).eq('id', id);
                    log.debug({ id, pool }, 'skipping sweep: failed flag not set yet');
                    return;
                }
                // Cooldown to avoid hammering the same pool
                const last = _lastRefundSweep.get(pool) || 0;
                if (Date.now() - last < REFUND_SWEEP_COOLDOWN_MS) {
                    await supabase.from('launches').update({
                        finalizing: false,
                        finalize_attempts: row.finalize_attempts ?? 0,
                        finalize_error: null,
                        updated_at: new Date().toISOString(),
                    }).eq('id', id);
                    log.debug({ id, pool }, 'refund sweep cooled down; skipping');
                    return;
                }
                // Do one sweep attempt
                const sweep = await sweepRefundBatch(pool); // returns "submitted" | "done" | "noop"
                if (sweep === 'submitted') {
                    _lastRefundSweep.set(pool, Date.now());
                    await supabase.from('launches').update({
                        finalizing: false,
                        finalize_attempts: (row.finalize_attempts ?? 0) + 1,
                        finalize_error: null,
                        updated_at: new Date().toISOString(),
                    }).eq('id', id);
                    log.info({ id, pool }, 'refund sweep tick executed');
                }
                else if (sweep === 'done') {
                    await supabase.from('launches').update({
                        finalizing: false,
                        finalize_error: null,
                        updated_at: new Date().toISOString(),
                    }).eq('id', id);
                    log.debug({ id, pool }, 'refund sweep complete'); // was info
                }
                else {
                    // "noop" — nothing to do (old impl or already attempted and not yet ready)
                    await supabase.from('launches').update({
                        finalizing: false,
                        finalize_error: null,
                        updated_at: new Date().toISOString(),
                    }).eq('id', id);
                    log.debug({ id, pool }, 'refund sweep noop');
                }
                return;
            }
            catch (e) {
                const errMsg = e?.shortMessage || e?.message || String(e);
                log.error({ id, pool, err: errMsg }, 'refund path failed');
                await supabase
                    .from('launches')
                    .update({
                    finalizing: false,
                    finalize_attempts: (row.finalize_attempts ?? 0) + 1,
                    finalize_error: (e && e.__notAuthorized)
                        ? 'MARK_FAILED_NOT_AUTHORIZED'
                        : (e && e.__noMarkFailed)
                            ? 'MARK_FAILED_NOT_AVAILABLE_ON_IMPL'
                            : `FAILED_BRANCH_ERROR: ${errMsg}`,
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
        let hash = null;
        let receipt = null;
        if (!already) {
            const result = await callFinalize(pool);
            hash = result.hash;
            receipt = result.receipt;
            const txHash = receipt.transactionHash;
            {
                const { data } = await supabase
                    .from('processed_txs')
                    .select('tx_hash')
                    .eq('tx_hash', txHash)
                    .maybeSingle();
                if (data) {
                    log.info({ txHash }, 'receipt already processed; skipping');
                }
                else {
                    await supabase.from('processed_txs').insert({ tx_hash: txHash });
                    const pairs = await pairsFromFinalizeReceipt(receipt);
                    if (pairs.length) {
                        log.info({ pool, pairs }, 'finalize detected pairs; syncing…');
                        await kickScreenersWithSync(pairs, txHash);
                    }
                    else {
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
        if (error)
            throw error;
        log.info({ id, pool, tx: hash, attempts, already }, 'finalized');
    }
    catch (e) {
        const saleFailed = e && e.__saleFailed === true;
        log.error({ id, pool, err: e?.message || String(e) }, 'finalize failed');
        const update = {
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
                await callMarkFailed(pool);
            }
            catch (mfErr) {
                if (mfErr?.__noMarkFailed) {
                    log.warn({ id, pool }, 'pool impl has no markFailed(); skipping flip');
                }
                else {
                    log.warn({ id, pool, err: mfErr?.message || String(mfErr) }, 'markFailed attempt failed or not needed');
                }
            }
            try {
                // NEW: sweep refunds for contributors (new impl). No-op on old impl.
                await sweepRefundBatch(pool);
                update.status = 'failed';
                update.finalized = false;
                update.finalize_error = null;
            }
            catch (er) {
                // OPTIONAL: fallback for old impls (refund() only refunds the caller)
                try {
                    const { hash: refundHash } = await callRefund(pool);
                    log.info({ id, pool, tx: refundHash }, 'legacy self-refund executed after markFailed');
                    update.status = 'failed';
                    update.finalized = false;
                    update.finalize_error = null;
                }
                catch (er2) {
                    if (er2 && er2.__noContribution) {
                        update.status = 'failed';
                        update.finalized = false;
                        update.finalize_error = null;
                    }
                    else {
                        update.status = 'failed';
                        update.finalized = false;
                        update.finalize_error = `REFUND_FAILED: ${er2?.message || String(er2)}`;
                    }
                }
            }
        }
        await supabase.from('launches').update(update).eq('id', id);
    }
    finally {
        markDone(id);
    }
}
// ---------- Realtime & Poller ----------
function startRealtime() {
    const ch = supabase
        .channel('launches-status')
        .on('postgres_changes', { event: '*', schema: 'public', table: 'launches' }, async (payload) => {
        const next = payload.new;
        if (!next)
            return;
        const now = Date.now();
        const last = _rtLast.get(next.id) || 0;
        if (now - last < RT_COOLDOWN_MS) {
            log.debug({ id: next.id, sinceMs: now - last }, 'RT: cooled down; skipping');
            return;
        }
        _rtLast.set(next.id, now);
        // 🔒 Ignore rows without a pool to prevent log spam / useless processing
        if (!next.pool_address) {
            log.debug({ id: next.id }, 'RT: no pool_address; ignoring');
            return;
        }
        try {
            const reconciled = await reconcileStatus({
                id: next.id,
                status: next.status,
                start_at: next.start_at,
                end_at: next.end_at,
                pool_address: next.pool_address,
                finalized: next.finalized,
                finalizing: next.finalizing ?? false,
                finalize_attempts: next.finalize_attempts ?? 0,
            });
            if ((reconciled === 'ended' || reconciled === 'failed') &&
                next.finalized === false &&
                next.finalizing === false) {
                log.info({ id: next.id }, `RT: ${reconciled} → process`);
                processOne({
                    id: next.id,
                    status: reconciled,
                    pool_address: next.pool_address,
                    finalized: next.finalized,
                    finalizing: next.finalizing ?? false,
                    start_at: next.start_at,
                    end_at: next.end_at,
                    finalize_attempts: next.finalize_attempts ?? 0,
                }).catch(() => { });
            }
        }
        catch (err) {
            log.error({ err, id: next?.id }, 'realtime reconcile failed');
        }
    })
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
        .in('status', ['upcoming', 'active', 'ended', 'failed'])
        .not('pool_address', 'is', null)
        .limit(200);
    const now = Date.now();
    const soon = (r) => {
        const end = r.end_at ? Date.parse(r.end_at) : Infinity;
        return end - now <= 7_000;
    };
    const hot = (data ?? []).filter(soon);
    const cold = (data ?? []).filter((r) => !soon(r));
    // Reconcile hot rows first (in parallel)
    const hotNexts = await Promise.all(hot.map(async (r) => ({ r, next: await reconcileStatus(r) })));
    // Then cold rows (sequential to keep RPC load low)
    const coldNexts = [];
    for (const r of cold) {
        const next = await reconcileStatus(r);
        coldNexts.push({ r, next });
    }
    // NEW: Kick processing for anything that now needs action and isn't locked/finalized
    const needsAction = [...hotNexts, ...coldNexts]
        .filter(({ r, next }) => (next === 'failed' || next === 'ended') &&
        r.finalized === false &&
        r.finalizing === false);
    // Limit concurrency a bit if you want (here: sequential)
    for (const { r } of needsAction) {
        await processOne(r).catch((err) => log.error({ id: r.id, err: err?.message || String(err) }, 'poller processOne failed'));
    }
}
// top-level
let _pollTimer = null;
let _realtime = null;
// clamp + log poll interval
function getPollMs() {
    const raw = process.env.POLL_INTERVAL_MS ?? '3000';
    const n = Number.parseInt(raw, 10);
    const ms = Number.isFinite(n) ? n : 3000;
    const clamped = Math.min(Math.max(ms, 1000), 60000);
    if (clamped !== n)
        log.warn({ raw, parsed: n, using: clamped }, 'POLL_INTERVAL_MS adjusted');
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
    app.get('/health', async (_req, res) => {
        try {
            const { error } = await supabase.from('launches').select('id').limit(1);
            if (error)
                throw error;
            res.json({ ok: true, time: new Date().toISOString(), address: account.address });
        }
        catch (e) {
            res.status(500).json({ ok: false, error: e?.message || String(e) });
        }
    });
    // --- DEBUG: quick snapshot of failure gates ---
    app.get('/debug/snapshot', async (req, res) => {
        try {
            const pool = String(req.query.pool || '');
            if (!pool || !pool.startsWith('0x') || pool.length !== 42) {
                return res.status(400).json({ ok: false, error: 'Missing/invalid ?pool=0x...' });
            }
            const s = await getChainSnapshot(pool);
            const afterEnd = s.now >= Number(s.endAt);
            const belowSoft = s.totalRaised < s.softCap;
            res.json({
                ok: true,
                pool,
                snapshot: {
                    softCap: s.softCap.toString(),
                    hardCap: s.hardCap.toString(),
                    totalRaised: s.totalRaised.toString(),
                    endAt: Number(s.endAt),
                    now: s.now,
                    finalized: s.finalized,
                    failed: s.failed,
                    gates: { afterEnd, belowSoft },
                },
            });
        }
        catch (e) {
            res.status(500).json({ ok: false, error: e?.message || String(e) });
        }
    });
    // --- DEBUG: force a markFailed attempt (safe/idempotent if already failed) ---
    app.post('/debug/mark-failed-now', async (req, res) => {
        try {
            const pool = String(req.query.pool || '');
            if (!pool || !pool.startsWith('0x') || pool.length !== 42) {
                return res.status(400).json({ ok: false, error: 'Missing/invalid ?pool=0x...' });
            }
            const hash = await callMarkFailed(pool);
            res.json({ ok: true, pool, tx: hash });
        }
        catch (e) {
            res.status(500).json({
                ok: false,
                error: e?.shortMessage || e?.message || String(e),
                cause: e?.cause?.message || e?.cause || null,
                data: e?.data || e?.cause?.data || null,
            });
        }
    });
    // --- DEBUG: run one refund sweep batch if failed ---
    app.post('/debug/refund-sweep-now', async (req, res) => {
        try {
            const pool = String(req.query.pool || '');
            if (!pool || !pool.startsWith('0x') || pool.length !== 42) {
                return res.status(400).json({ ok: false, error: 'Missing/invalid ?pool=0x...' });
            }
            await sweepRefundBatch(pool);
            res.json({ ok: true, pool });
        }
        catch (e) {
            res.status(500).json({ ok: false, error: e?.message || String(e) });
        }
    });
    // Manually trigger a sync() on a given pair (no swap)
    app.post('/sync-now', async (req, res) => {
        try {
            const pair = String(req.query.pair || '').toLowerCase();
            if (!pair || !pair.startsWith('0x') || pair.length !== 42) {
                return res.status(400).json({ ok: false, error: 'Missing/invalid ?pair=0x...' });
            }
            await kickScreenersWithSync([pair]); // uses your walletClient/publicClient
            res.json({ ok: true, pair });
        }
        catch (e) {
            res.status(500).json({ ok: false, error: e?.message || String(e) });
        }
    });
    // Simulate post-finalize flow: parse any tx receipt, find pairs, call sync()
    app.post('/after-finalize', async (req, res) => {
        try {
            const tx = String(req.query.tx || '');
            if (!tx || !tx.startsWith('0x') || tx.length !== 66) {
                return res.status(400).json({ ok: false, error: 'Missing/invalid ?tx=0x...' });
            }
            const receipt = await publicClient.getTransactionReceipt({ hash: tx });
            const pairs = await pairsFromFinalizeReceipt(receipt);
            if (pairs.length)
                await kickScreenersWithSync(pairs);
            res.json({ ok: true, pairs });
        }
        catch (e) {
            res.status(500).json({ ok: false, error: e?.message || String(e) });
        }
    });
    // Kick the full pipeline for a DB row (by launches.id)
    app.post('/process-now', async (req, res) => {
        try {
            const id = String(req.query.id || '');
            if (!id)
                return res.status(400).json({ ok: false, error: 'Missing ?id=' });
            const { data, error } = await supabase.from('launches').select('*').eq('id', id).maybeSingle();
            if (error)
                throw error;
            if (!data)
                return res.status(404).json({ ok: false, error: 'Row not found' });
            await processOne(data);
            res.json({ ok: true });
        }
        catch (e) {
            res.status(500).json({ ok: false, error: e?.message || String(e) });
        }
    });
    app.get('/', (_req, res) => res.status(200).send('ok'));
    // catch-all 200 for GET to satisfy any default probe hitting '/' or another path
    app.get('*', (_req, res) => res.status(200).send('ok'));
    const raw = process.env.PORT ?? '';
    const parsed = parseInt(raw, 10);
    const port = Number.isFinite(parsed) && parsed > 0 ? parsed : 8080; // 8080 for local only
    log.info({ rawEnvPort: process.env.PORT }, 'startup: PORT from env');
    app.listen(port, '0.0.0.0', () => {
        log.info({ port, addr: account.address }, 'health server up');
    });
    // after app.listen(...)
    const stack = app._router?.stack || [];
    const routes = stack
        .filter((l) => l.route)
        .map((l) => ({ path: l.route.path, methods: Object.keys(l.route.methods) }));
    log.info({ routes }, 'registered routes');
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
//# sourceMappingURL=index.js.map