// pool-sweep.mjs — liveness sweep of the HOOKED program (the role-2 pool hook) under OUR VK,
// with the same REAL snarkjs-minted proofs as sweep-ours.mjs.
//
// The plain sweep answers "does every random real proof fit the bare verifier?"; THIS one
// answers the deployment question: does every random real POOL TRANSITION fit the program
// the pool will actually deploy — the sound verifier with the pool hook inside role 2?
// For every minted scenario (and the 5 committed fixtures as controls):
//   - fills are sized against the honest POOL shape (pool-tx.mjs poolTransactionFor — the
//     stock sizer builds tokenless source outputs and the hook rejects that shape at check 2),
//     targeting the standard-mode MARGIN (6%);
//   - all three inputs are evaluated in consensus AND standard mode against the pool shape:
//     source output 2 carries the state NFT (funded per case: balance = 1000n + pv), the
//     outputs are the honest carrier / new state / payout — every input must be ACCEPTED;
//   - every case is ALSO run with all three unlockings padded (zero filler) to exactly
//     UNLOCK_CAP = 10,000 B, and every input must meet the CAP RULE there:
//       op <= 0.94 x (41 + 10,000) x 800 = 7,550,832
//     (the same rule the stock sweep applies at the cap).
//
// The same trapdoor limitation as sweep-ours.mjs applies: no forced-extreme statements under
// this VK; this measures the worst case reachable by real proofs (all three action classes,
// payout branch included). The hook's cost (33,156 op standard, pool-cost.mjs) is inside
// input 2's numbers below.
//
// Usage: BN_VK_FIXTURES=/home/apecs/cov/our.fixtures.json \
//        [SWEEP_SHARD=k/n] node pool-sweep.mjs <out.json> [<minted-proofs.json...>]
// (no minted files = the 5 committed fixtures only)
import assert from 'node:assert/strict';
import {readFileSync, writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {FIXTURES} from '../sound-si-gls/math.mjs';
import {buildProgram, setCovenant} from './script.mjs';
import {unlockingsFor, UNLOCK_CAP} from './transaction.mjs';
import {VMS, p2sh32, budgetOf} from './vm.mjs';
import {covenantHook, covenantParams, actionHashOf} from './pool-hook.mjs';
import {poolTransactionFor, poolOutputs, fuelSourceOutputs} from './pool-tx.mjs';

const [shard, shards] = (process.env.SWEEP_SHARD ?? '0/1').split('/').map(Number);
const outPath = process.argv[2];
const inPaths = process.argv.slice(3);
assert.ok(outPath, 'usage: node pool-sweep.mjs <out.json> [<minted-proofs.json...>]');
const CAP_BUDGET = budgetOf(new Uint8Array(10000)), CAP_RULE = Math.floor(0.94 * CAP_BUDGET);
/* every case funds its pool: balance = 1000n + pv. An unshield must satisfy the hook's check 8
   (newBalance = balance + pv - 2·sign·pv >= 0), so the state NFT must carry at least pv — the
   first pool-sweep run REJECTED every big-pv minted unshield with balance 1000, which is check 8
   working correctly on an underfunded scenario, not a hook defect. */

const CATEGORY_DISPLAY = Buffer.from('2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544', 'hex');
const OUTS = process.env.POOL_3OUT === '1' ? 3 : 2;
setCovenant(covenantHook(covenantParams({categoryOnChain: Buffer.from(CATEGORY_DISPLAY).reverse().toString('hex')}), OUTS));
const prog = buildProgram();
const lock = p2sh32(prog.R); const LOCKS = [lock, lock, lock];
/* drift guard: the HOOKED program's own code hash. build.json holds the PLAIN build's hash
   (5fd6a4be…) and is asserted by sweep-ours.mjs; the hooked build has no build.json of its own.
   Pinned here so any silent change to the hook (or the plain program underneath it) fails
   loudly. History: 89a8ac14… = the pre-tagging hook (checks 1–11, 7,737 B, 2026-11-24);
   d71851a1… = the deposit-tagging revision (adds 4c fuel-category + 4g tag checks,
   7,834 B, 2026-11-24 PM) — re-derived live, red team + sweeps re-run for this pin. */
const CODE_PIN = OUTS === 3
    ? '628207b197ae2cea8b069198f9b454d12fa7e50a19bb1ffa5822cfe5ab533f73'
    : 'd71851a1ce6d795c0aa40ab055faac1000755d474313f16e6cd34855ffbfff41';
assert.equal(createHash('sha256').update(prog.code).digest('hex'), CODE_PIN, 'the HOOKED program code changed — re-derive code/R/locking, re-run the red team, and update this pin + the docs');

const leToBig = (hex) => BigInt('0x' + Buffer.from(hex, 'hex').reverse().toString('hex') || '0');
const scenarioArgsOf = (rec) => {
    const c = rec.covenant;
    const sc = { nf0: leToBig(c.nf0), nf1: leToBig(c.nf1), cm0: leToBig(c.cm0), cm1: leToBig(c.cm1), ...(OUTS === 3 ? { cm2: leToBig(c.cm2) } : {}), newRoot: leToBig(c.newMerkleRoot), pv: BigInt(c.publicValueAbs), sign: BigInt(c.isUnshield) };
    const n0 = BigInt(rec.publicSignals[0]);
    assert.equal(actionHashOf({ ...sc, categoryDisplay: CATEGORY_DISPLAY.toString('hex') }, OUTS).toString(), BigInt(rec.publicSignals[1]).toString(), 'actionHash mismatch — fixture is not self-consistent');
    return { sc, n0, categoryDisplay: CATEGORY_DISPLAY, balance: 1000n + sc.pv, outs: OUTS };
};

/* pool-aware spendAll: input 2 spends the pool lock, its source output carries the state NFT
   and the transaction outputs are the honest pool shape for the scenario being spent.
   Every byte a PLAIN Uint8Array (Node Buffers alias via slice(); the VM's REVERSEBYTES
   writes through views — STATUS.md finding 1). */
function poolSpendAll(unlockings, mode, scenario, args) {
    return unlockings.map((u, i) => {
        const inputs = unlockings.map((q, n) => ({ outpointIndex: n, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array(q) }));
        /*  inputs 0/1 = tagged fuel (hook 4c/4g); input 2 = the state NFT. */
        const fuel = fuelSourceOutputs(LOCKS[0], scenario, args);
        const sourceOutputs = [...fuel, { lockingBytecode: new Uint8Array(LOCKS[2]), valueSatoshis: 1000n, token: { category: new Uint8Array(CATEGORY_DISPLAY), amount: args.balance, nft: { capability: 'mutable', commitment: new Uint8Array(scenario.stateCommit) } } }];
        const outputs = poolOutputs(prog, scenario, args);
        const st = VMS[mode].evaluate({ inputIndex: i, sourceOutputs, transaction: { version: 2, locktime: 0, inputs, outputs } });
        const top = st.stack?.[st.stack.length - 1];
        const ok = st.error === undefined && st.stack.length === 1 && top?.length === 1 && top[0] === 1;
        return { accepted: ok, error: st.error ?? (ok ? null : 'final stack ' + st.stack.length), opCost: st.metrics.operationCost, budget: (41 + u.length) * 800, length: u.length };
    });
}

/* fillers that pad every unlocking to exactly UNLOCK_CAP (filler push header 3 B at these sizes) */
const capFills = (core) => unlockingsFor(core, prog, [0, 0, 0]).unlockings.map((u) => { const f = UNLOCK_CAP - u.length + 1 - 3; assert.ok(f >= 256, `cap filler ${f} too small`); return f; });

/* the committed fixtures' covenant args live in /home/apecs/cov/our-proofs.json (the same
   self-consistent shape the minter writes); index order matches FIXTURES.fixtures. */
const committedCovenant = JSON.parse(readFileSync(OUTS === 3 ? '/home/apecs/cov/our-3out-proofs.json' : '/home/apecs/cov/our-proofs.json', 'utf8')).map((p) => p.covenant);

/* cases: the 5 committed fixtures (controls) + every minted random scenario.
   Minted records carry the snarkjs proof shape; convert like mkfixtures.mjs. */
const g1 = ([x, y]) => ({x: BigInt(x).toString(), y: BigInt(y).toString()});
const g2 = ([[x0, x1], [y0, y1]]) => ({x: {c0: BigInt(x0).toString(), c1: BigInt(x1).toString()}, y: {c0: BigInt(y0).toString(), c1: BigInt(y1).toString()}});
const toFx = (rec) => ({publicInputs: rec.publicSignals.map((s) => BigInt(s).toString()), proof: {a: g1(rec.proof.pi_a), b: g2(rec.proof.pi_b), c: g1(rec.proof.pi_c)}});

const cases = [];
FIXTURES.fixtures.forEach((f, i) => cases.push({label: `fixture ${i}`, fx: f, args: scenarioArgsOf({covenant: committedCovenant[i], publicSignals: FIXTURES.fixtures[i].publicInputs})}));
for (const p of inPaths) { const m = JSON.parse(readFileSync(p, 'utf8'));
  for (const rec of m.proofs) cases.push({label: rec.label, fx: toFx(rec), args: scenarioArgsOf(rec)}); }

const results = [];
const meta = () => ({inputs: inPaths, shard: `${shard}/${shards}`, capBudget: CAP_BUDGET, capRule: CAP_RULE, balanceRule: 'per case: balance = 1000n + pv (an unshield must be funded; hook check 8 requires newBalance >= 0)', results});
for (const [k, c] of cases.entries()) {
  if (k % shards !== shard) continue;
  const T = poolTransactionFor(c.fx, prog, c.args);
  const row = {label: c.label, pv: c.args.sc.pv.toString(), sign: c.args.sc.sign.toString(), publicInputs: c.fx.publicInputs, nq: T.core.nq, fills: T.fills, unlocking: T.unlockings.map((u) => u.length)};
  for (const mode of ['consensus', 'standard']) {
    const xs = poolSpendAll(T.unlockings, mode, T.scenario, c.args);
    row[mode] = {accepted: xs.every((x) => x.accepted), inputs: xs.map((x) => ({op: x.opCost, budget: x.budget, margin: +(1 - x.opCost / x.budget).toFixed(5), capMargin: +(1 - x.opCost / CAP_BUDGET).toFixed(5), error: x.error}))};
  }
  { const {unlockings} = unlockingsFor(T.core, prog, capFills(T.core)); assert.ok(unlockings.every((u) => u.length === UNLOCK_CAP), 'cap padding');
    row.cap = {}; for (const mode of ['consensus', 'standard']) { const xs = poolSpendAll(unlockings, mode, T.scenario, c.args);
      row.cap[mode] = {accepted: xs.every((x) => x.accepted), inputs: xs.map((x) => ({op: x.opCost, capMargin: +(1 - x.opCost / CAP_BUDGET).toFixed(5), error: x.error}))}; } }
  row.capRule = ['consensus', 'standard'].every((m) => row.cap[m].accepted && row.cap[m].inputs.every((x) => x.op <= CAP_RULE));
  results.push(row);
  const f = (m) => row[m].inputs.map((x) => `${(x.op / 1e6).toFixed(3)}M ${(100 * x.margin).toFixed(2)}%`).join(' | ');
  console.log(`${c.label.slice(0, 52).padEnd(52)} nq=${String(row.nq).padStart(3)} U=${row.unlocking.join('/')} cons ${row.consensus.accepted} [${f('consensus')}] std ${row.standard.accepted} [${f('standard')}] at-cap std ${row.cap.standard.inputs.map((x) => (x.op / 1e6).toFixed(3) + 'M').join('/')} cap ${row.capRule}`);
  writeFileSync(outPath, JSON.stringify(meta(), null, 1) + '\n');
}
const failed = results.filter((x) => !x.consensus.accepted || !x.standard.accepted || !x.capRule);
console.log(`cases ${results.length}, failed ${failed.length}`);
for (const mode of ['consensus', 'standard']) for (let i = 0; i < 3; i++) {
  const m = results.reduce((a, x) => (x[mode].inputs[i].margin < a[mode].inputs[i].margin ? x : a)); const M = results.reduce((a, x) => (x[mode].inputs[i].op > a[mode].inputs[i].op ? x : a));
  const K = results.reduce((a, x) => (x.cap[mode].inputs[i].op > a.cap[mode].inputs[i].op ? x : a));
  console.log(`${mode} input ${i}: min margin ${(100 * m[mode].inputs[i].margin).toFixed(2)}% at ${m.label}; max op (pool fill) ${M[mode].inputs[i].op} at ${M.label}; max op AT THE CAP ${K.cap[mode].inputs[i].op} (cap margin ${(100 * K.cap[mode].inputs[i].capMargin).toFixed(2)}%) at ${K.label}`);
}
writeFileSync(outPath, JSON.stringify(meta(), null, 1) + '\n');
assert.equal(failed.length, 0, `failed: ${failed.map((x) => x.label).join(', ')}`);
