// pool-cost-v3.mjs — price the V3 role-2 pool hook (the nullifier-set revision).
// Method: the upstream difference measurement (pinned/covenant-cost.mjs, Track 12),
// as pool-cost.mjs applies it — the op cost from the 'r2:statement' mark to the
// 'r2:slices' mark, HOOKED build minus PLAIN build, both spending the SAME proof.
// The v3 hook lives entirely inside that range (p1..p11 with the v3 changes: the
// NEW 4w walk-locking hash pins, the REMOVED fold check 7, the split check 10 —
// length + first half only), so the difference is exactly the v3 hook's cost.
// The GRAPH pin (TXINPUTCOUNT==5 + the walk-locking hash pins, v3-graph-pin.patch)
// is executed BEFORE r2:statement — OUTSIDE the measured range — so the plain
// baseline here is the v3-era PLAIN program (same graph pin, no hook), and both
// evaluations run against the FIVE-input pool shape: source outputs = tagged fuel +
// state NFT (commitment = noteRoot ‖ nullSetRoot) + the raw walk lockings; outputs
// = the honest carrier / new state (newRoot ‖ finalNullRoot) / payout — NO fold.
import { readFileSync } from 'node:fs';
import { decodeAuthenticationInstructions, encodeAuthenticationInstruction } from '@bitauth/libauth';
import { VMS, p2sh32 } from './vm.mjs';
import { buildProgram, setCovenant } from './script.mjs';
import { unlockingsFor } from './transaction.mjs';
import { FIXTURES } from '../sound-si-gls/math.mjs';
import { covenantHook, covenantParams } from './pool-hook.mjs';
import { scenarioV3, poolTransactionForV3, walkWitnesses, walkV3 } from './pool-tx-v3.mjs';
import { buildWalkScripts } from './walk-scripts.mjs';

const CATEGORY_DISPLAY = Buffer.from('2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544', 'hex');
const CATEGORY_ONCHAIN = Buffer.from(CATEGORY_DISPLAY).reverse().toString('hex');

/* the v3.1 walk scripts (P2SH32-wrapped on chain — the raw form is
   relay-nonstandard, measured 2026-11-27) + the graph pin (shared by BOTH
   builds — the pin is generator-side, the hook is the only difference) */
const { walkA, walkB, sizes } = buildWalkScripts(CATEGORY_ONCHAIN);
const { lockings: WALK_LOCKS, hashes: [walkAHash, walkBHash] } = walkV3(walkA, walkB);
process.env.POOL_NULLDATA_HASHES = JSON.stringify([walkAHash.toString('hex'), walkBHash.toString('hex')]);

/* the PLAIN v3 program first (module-level COVENANT is empty until setCovenant runs) */
const plain = buildProgram();

/* then the hooked v3 program under the same VK */
setCovenant(covenantHook(covenantParams({ categoryOnChain: CATEGORY_ONCHAIN }), 3, { walkAHash, walkBHash }));
const hooked = buildProgram();

/* fixture 0 (transfer pv=0) — the honest scenario, with its nullSet walk data */
const proofs = JSON.parse(readFileSync('/home/apecs/cov/our-v3-proofs.json', 'utf8'));
const c = proofs[0].covenant;
const leToBig = (hex) => BigInt('0x' + Buffer.from(hex, 'hex').reverse().toString('hex') || '0');
const sc = { nf0: leToBig(c.nf0), nf1: leToBig(c.nf1), cm0: leToBig(c.cm0), cm1: leToBig(c.cm1), cm2: leToBig(c.cm2), newRoot: leToBig(c.newMerkleRoot), pv: BigInt(c.publicValueAbs), sign: BigInt(c.isUnshield) };
const scenarioArgs = { sc, n0: BigInt(proofs[0].publicSignals[0]), nullSet: proofs[0].nullSet, categoryDisplay: CATEGORY_DISPLAY, balance: 1000n, outs: 3 };
const scenario = scenarioV3(scenarioArgs);
const walkW = walkWitnesses(scenarioArgs.nullSet, walkA, walkB);

/* sized witnesses: the hooked program needs pool-shaped sizing (pool-tx-v3.mjs);
   the plain program takes the same core — its unlockings carry the plain code
   pieces — at the same fills (the measured range is filler-independent) */
const Th = poolTransactionForV3(FIXTURES.fixtures[0], hooked, scenarioArgs, [walkA, walkB]);
const Tp = unlockingsFor(Th.core, plain, Th.fills);
console.log(`witnesses: hooked fills ${JSON.stringify(Th.fills)} (unlocking[2] ${Th.unlockings[2].length} B), plain fills ${JSON.stringify(Th.fills)} (unlocking[2] ${Tp.unlockings[2].length} B) · walks ${Th.walkW.map((w) => w.length).join('/')} B`);

/* the FIVE-input pool shape both evaluations run against — each build spends its
   OWN P2SH32 locking (the plain and hooked programs hash differently) */
const shape = (prog, progUnlockings) => {
    const lock = p2sh32(prog.R);
    const inputs = [...progUnlockings.map((u, n) => ({ outpointIndex: n, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array(u) })),
        ...walkW.map((w, k) => ({ outpointIndex: progUnlockings.length + k, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array(w) }))];
    const fuel = [
        { lockingBytecode: new Uint8Array(lock), valueSatoshis: 1000n, token: { category: new Uint8Array(CATEGORY_DISPLAY), amount: sc.sign === 0n ? sc.pv : 0n, nft: { capability: 'mutable', commitment: new Uint8Array(scenario.tag) } } },
        { lockingBytecode: new Uint8Array(lock), valueSatoshis: 1000n, token: { category: new Uint8Array(CATEGORY_DISPLAY), amount: 0n, nft: { capability: 'mutable', commitment: new Uint8Array(scenario.tag) } } },
    ];
    const sourceOutputs = [...fuel,
        { lockingBytecode: new Uint8Array(lock), valueSatoshis: 1000n, token: { category: new Uint8Array(CATEGORY_DISPLAY), amount: scenarioArgs.balance, nft: { capability: 'mutable', commitment: new Uint8Array(scenario.stateCommit) } } },
        { lockingBytecode: new Uint8Array(WALK_LOCKS[0]), valueSatoshis: 300n },
        { lockingBytecode: new Uint8Array(WALK_LOCKS[1]), valueSatoshis: 300n }];
    return { inputs, sourceOutputs };
};

/* rangeCost, adapted from pinned/covenant-cost.mjs: trace input 2, keep only role-2
   frames (states whose instruction list matches role2's disassembly), read the op
   cost at the marks */
const rangeCost = (prog, unlockings, mode, from, to) => {
    const { inputs, sourceOutputs } = shape(prog, unlockings);
    const outputs = poolOutputs(prog, scenario, scenarioArgs);
    const d = decodeAuthenticationInstructions(prog.funcCodes.role2);
    const offs = []; let x = 0;
    for (const t of d) { offs.push(x); x += encodeAuthenticationInstruction(t).length; }
    const m = Object.fromEntries(prog.marks.filter((q) => q.role === 2).map((q) => [q.name, q.roff]));
    let first = null, last = null;
    for (const s of VMS[mode].debug({ inputIndex: 2, sourceOutputs, transaction: { version: 2, locktime: 0, inputs, outputs } })) {
        if (s.error !== undefined) break;
        if (s.instructions?.length !== d.length) continue;
        const off = offs[s.ip] ?? Infinity;
        if (first === null && off >= m[from]) first = s.metrics.operationCost;
        if (first !== null && last === null && off >= m[to]) last = s.metrics.operationCost;
    }
    if (first === null || last === null) throw new Error(`rangeCost(${mode}): marks not both reached (first=${first}, last=${last})`);
    return { op: last - first, bytes: m[to] - m[from] };
};

/* the honest v3 outputs (carrier / new state / payout) — same for both builds */
import { poolOutputs } from './pool-tx.mjs';

console.log(`\nv3 hook price (r2:statement → r2:slices, fixture 0, same proof both builds):`);
for (const mode of ['standard', 'consensus']) {
    const t = rangeCost(hooked, Th.unlockings, mode, 'r2:statement', 'r2:slices');
    const p = rangeCost(plain, Tp.unlockings, mode, 'r2:statement', 'r2:slices');
    console.log(`  ${mode.padEnd(9)}: v3 hook costs ${t.op - p.op} op (${t.bytes - p.bytes} B of role-2 code) — range totals: hooked ${t.op}, plain ${p.op}`);
}

/* also: total input-2 cost + margin for both builds, both modes, and the walk
   inputs' own costs in the hooked build — for the record */
const evalIn = (prog, unlockings, mode, i) => {
    const { inputs, sourceOutputs } = shape(prog, unlockings);
    const outputs = poolOutputs(prog, scenario, scenarioArgs);
    const st = VMS[mode].evaluate({ inputIndex: i, sourceOutputs, transaction: { version: 2, locktime: 0, inputs, outputs } });
    const u = i < 3 ? unlockings[i] : walkW[i - 3];
    const budget = (41 + u.length) * 800;
    return { op: st.metrics.operationCost, budget, err: st.error };
};
console.log(`\ntotal input-2 cost (fixture 0):`);
for (const mode of ['standard', 'consensus']) {
    const h = evalIn(hooked, Th.unlockings, mode, 2), p = evalIn(plain, Tp.unlockings, mode, 2);
    console.log(`  ${mode.padEnd(9)}: hooked ${h.op} of ${h.budget} (${(100 * h.op / h.budget).toFixed(1)}%)${h.err ? ' ERR ' + String(h.err).slice(0, 60) : ''} · plain ${p.op} of ${p.budget} (${(100 * p.op / p.budget).toFixed(1)}%)${p.err ? ' ERR' : ''}`);
}
console.log(`\nthe walk inputs' own costs (hooked build, fixture 0):`);
for (const mode of ['standard', 'consensus']) {
    const a = evalIn(hooked, Th.unlockings, mode, 3), b = evalIn(hooked, Th.unlockings, mode, 4);
    console.log(`  ${mode.padEnd(9)}: walkA ${a.op} of ${a.budget} (${(100 * a.op / a.budget).toFixed(1)}%)${a.err ? ' ERR' : ''} · walkB ${b.op} of ${b.budget} (${(100 * b.op / b.budget).toFixed(1)}%)${b.err ? ' ERR' : ''}`);
}
