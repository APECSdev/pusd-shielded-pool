// pool-cost.mjs — price the role-2 pool hook (open item 2).
// Method: the upstream difference measurement (pinned/covenant-cost.mjs, Track 12) — the op cost
// from the 'r2:statement' mark to the 'r2:slices' mark, HOOKED build minus PLAIN build, both
// spending the SAME proof. The hook lives entirely inside that range ('r2:covenant' + p1..p11 all
// sit between statement and slices), so the difference is exactly the hook's cost.
// The hooked input-2 evaluation must run against the POOL shape or the trace dies at check 2 and
// the range is truncated — hence pool-tx's sized witness + pool-shaped evaluation here.
import { readFileSync } from 'node:fs';
import { decodeAuthenticationInstructions, encodeAuthenticationInstruction } from '@bitauth/libauth';
import { VMS, p2sh32 } from './vm.mjs';
import { buildProgram, setCovenant } from './script.mjs';
import { transactionFor } from './transaction.mjs';
import { FIXTURES } from '../sound-si-gls/math.mjs';
import { covenantHook, covenantParams, carrierOf, carrierOutput } from './pool-hook.mjs';
import { poolTransactionFor, poolScenario, poolOutputs } from './pool-tx.mjs';

const CATEGORY_DISPLAY = Buffer.from('2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544', 'hex');

/* the PLAIN program first (module-level COVENANT is empty until setCovenant runs) */
const plain = buildProgram();

/* then the hooked program under the same VK */
setCovenant(covenantHook(covenantParams({ categoryOnChain: Buffer.from(CATEGORY_DISPLAY).reverse().toString('hex') })));
const hooked = buildProgram();

/* fixture 0 (transfer pv=0) — the honest scenario */
const proofs = JSON.parse(readFileSync('/home/apecs/cov/our-proofs.json', 'utf8'));
const c = proofs[0].covenant;
const leToBig = (hex) => BigInt('0x' + Buffer.from(hex, 'hex').reverse().toString('hex') || '0');
const sc = { nf0: leToBig(c.nf0), nf1: leToBig(c.nf1), cm0: leToBig(c.cm0), cm1: leToBig(c.cm1), newRoot: leToBig(c.newMerkleRoot), pv: BigInt(c.publicValueAbs), sign: BigInt(c.isUnshield) };
const n0 = BigInt(proofs[0].publicSignals[0]);
const scenarioArgs = { sc, n0, categoryDisplay: CATEGORY_DISPLAY };

/* sized witnesses: the hooked program needs pool-shaped sizing; the plain program's stock sizer
   is correct as-is (no hook to reject the default shape) */
const Th = poolTransactionFor(FIXTURES.fixtures[0], hooked, scenarioArgs);
const Tp = transactionFor(FIXTURES.fixtures[0], plain);
console.log(`witnesses: hooked fills ${JSON.stringify(Th.fills)} (unlocking[2] ${Th.unlockings[2].length} B), plain fills ${JSON.stringify(Tp.fills)} (unlocking[2] ${Tp.unlockings[2].length} B)`);

/* rangeCost, adapted from pinned/covenant-cost.mjs: trace input 2, keep only role-2 frames
   (states whose instruction list matches role2's disassembly), read the op cost at the marks */
const rangeCost = (prog, unlockings, mode, from, to) => {
    const lock = p2sh32(prog.R);
    const scenario = prog === hooked ? Th.scenario : poolScenario(scenarioArgs);
    const inputs = unlockings.map((u, n) => ({ outpointIndex: n, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array(u) }));
    const sourceOutputs = [0, 1, 2].map((n) => ({ lockingBytecode: lock, valueSatoshis: 1000n, ...(n === 2 ? { token: { category: new Uint8Array(CATEGORY_DISPLAY), amount: 1000n, nft: { capability: 'mutable', commitment: new Uint8Array(scenario.stateCommit) } } } : {}) }));
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

console.log(`\nhook price (r2:statement → r2:slices, fixture 0, same proof both builds):`);
for (const mode of ['standard', 'consensus']) {
    const t = rangeCost(hooked, Th.unlockings, mode, 'r2:statement', 'r2:slices');
    const p = rangeCost(plain, Tp.unlockings, mode, 'r2:statement', 'r2:slices');
    console.log(`  ${mode.padEnd(9)}: hook costs ${t.op - p.op} op (${t.bytes - p.bytes} B of role-2 code) — range totals: hooked ${t.op}, plain ${p.op}`);
}

/* also: total input-2 cost + margin for both builds, both modes, for the record */
const evalIn = (prog, unlockings, mode) => {
    const lock = p2sh32(prog.R);
    const scenario = prog === hooked ? Th.scenario : poolScenario(scenarioArgs);
    const inputs = unlockings.map((u, n) => ({ outpointIndex: n, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array(u) }));
    const sourceOutputs = [0, 1, 2].map((n) => ({ lockingBytecode: lock, valueSatoshis: 1000n, ...(n === 2 ? { token: { category: new Uint8Array(CATEGORY_DISPLAY), amount: 1000n, nft: { capability: 'mutable', commitment: new Uint8Array(scenario.stateCommit) } } } : {}) }));
    const outputs = poolOutputs(prog, scenario, scenarioArgs);
    const st = VMS[mode].evaluate({ inputIndex: 2, sourceOutputs, transaction: { version: 2, locktime: 0, inputs, outputs } });
    const budget = (41 + unlockings[2].length) * 800;
    return { op: st.metrics.operationCost, budget, err: st.error };
};
console.log(`\ntotal input-2 cost (fixture 0):`);
for (const mode of ['standard', 'consensus']) {
    const h = evalIn(hooked, Th.unlockings, mode), p = evalIn(plain, Tp.unlockings, mode);
    console.log(`  ${mode.padEnd(9)}: hooked ${h.op} of ${h.budget} (${(100 * h.op / h.budget).toFixed(1)}%)${h.err ? ' ERR' : ''} · plain ${p.op} of ${p.budget} (${(100 * p.op / p.budget).toFixed(1)}%)${p.err ? ' ERR' : ''}`);
}
