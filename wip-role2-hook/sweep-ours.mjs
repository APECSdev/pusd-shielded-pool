// sweep-ours.mjs — the liveness sweep under OUR VK, with REAL snarkjs-minted proofs.
//
// This is stock sweep.mjs with the mint source replaced: the stock file forges proofs for
// chosen public inputs from the densless-fixtures trapdoor (sound-si-gls/mint.mjs), which
// does not exist for our ceremony VK. The cases here are therefore the ones REAL proofs can
// reach: the 5 committed fixtures, the lattice-shifted (non-Babai) valid witness of fixture 0,
// and every proof minted by gen-sweep-proofs.mjs (random circuit witnesses, proved against
// build/pool_final.zkey; proveCore re-validates the full Groth16 equation under the
// FIXTURES VK before anything is sized, so a wrong-VK or malformed proof aborts the sweep).
//
// LIMITATION vs the stock sweep (stated honestly): the forced extremes (every nibble 15 / 0 /
// thin-dense / the review's worst case), the special public inputs (n = 0, 1, r-1, …) and the
// sparse-n_q search all REQUIRE minting a proof for chosen public inputs — trapdoor-only.
// Under our VK those statements are unreachable by real witnesses (n0 is a Poseidon root and
// n1 a SHA256 output; the forced shapes are measure-zero). The stock sweep measured them
// under the reference VK; op cost for a given (statement, witness, fill) is VK-independent
// (identical code size/layout, fixed-size baked constants), so those bounds carry over
// structurally. What THIS sweep measures is the worst case achievable by proofs that can
// actually be produced for this pool — the liveness question that matters for redeployment.
//
// Every case must be ACCEPTED with prover-sized fillers in consensus AND standard mode, and
// every input must meet the CAP RULE at the 10,000-byte unlock cap:
//   op <= 0.94 x (41 + 10,000) x 800 = 7,550,832.
//
// Usage: BN_VK_FIXTURES=/home/apecs/cov/our.fixtures.json \
//        [SWEEP_SHARD=k/n] node sweep-ours.mjs <out.json> <minted-proofs.json...>
import assert from 'node:assert/strict';
import {readFileSync, writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {FIXTURES, glsDecompose, GLS_OFFSET, LATTICE} from '../sound-si-gls/math.mjs';
import {buildProgram} from './script.mjs';
import {transactionFor, unlockingsFor, UNLOCK_CAP} from './transaction.mjs';
import {spendAll, budgetOf} from './vm.mjs';

const [shard, shards] = (process.env.SWEEP_SHARD ?? '0/1').split('/').map(Number);
const outPath = process.argv[2];
const inPaths = process.argv.slice(3);
assert.ok(outPath && inPaths.length >= 1, 'usage: node sweep-ours.mjs <out.json> <minted-proofs.json...>');
const CAP_BUDGET = budgetOf(new Uint8Array(10000)), CAP_RULE = Math.floor(0.94 * CAP_BUDGET);
const prog = buildProgram();
const built = JSON.parse(readFileSync(new URL('./build.json', import.meta.url), 'utf8'));
assert.equal(createHash('sha256').update(prog.code).digest('hex'), built.codeSha256, 'build.json is stale: run build.mjs');

/* snarkjs -> bench fixture shape (the mkfixtures.mjs mapping) */
const g1 = ([x, y]) => ({x: BigInt(x).toString(), y: BigInt(y).toString()});
const g2 = ([[x0, x1], [y0, y1]]) => ({x: {c0: BigInt(x0).toString(), c1: BigInt(x1).toString()}, y: {c0: BigInt(y0).toString(), c1: BigInt(y1).toString()}});
const toFx = (rec) => ({publicInputs: rec.publicSignals.map((s) => BigInt(s).toString()), proof: {a: g1(rec.proof.pi_a), b: g2(rec.proof.pi_b), c: g1(rec.proof.pi_c)}});

const cases = [];
FIXTURES.fixtures.forEach((f, i) => cases.push({label: `fixture ${i}`, fx: f}));
{ const es = FIXTURES.fixtures[0].publicInputs.map((n) => glsDecompose(BigInt(n))); let done = false;
  for (const v of LATTICE) for (const sg of [1n, -1n]) { const e2 = es[0].map((x, i) => x + sg * v[i]); if (!done && e2.every((x) => x >= -GLS_OFFSET && x < GLS_OFFSET)) { done = true; cases.push({label: 'fixture 0, lattice-shifted GLS witness', fx: FIXTURES.fixtures[0], opts: {es: [e2, es[1]]}}); } } }
const seeds = [];
for (const p of inPaths) { const m = JSON.parse(readFileSync(p, 'utf8')); seeds.push(`${p}: ${m.seed ?? '?'}`);
  for (const rec of m.proofs) cases.push({label: rec.label, fx: toFx(rec)}); }

/* fillers that pad every unlocking to exactly UNLOCK_CAP bytes (the filler push header is 3 bytes at these sizes) */
const capFills = (core) => unlockingsFor(core, prog, [0, 0, 0]).unlockings.map((u) => { const f = UNLOCK_CAP - u.length + 1 - 3; assert.ok(f >= 256); return f; });

const results = [];
const meta = () => ({inputs: inPaths, seeds, forcedCases: 'unavailable under this VK — no trapdoor; see header', shard: `${shard}/${shards}`, capBudget: CAP_BUDGET, capRule: CAP_RULE, results});
for (const [k, c] of cases.entries()) {
  if (k % shards !== shard) continue;
  const t = transactionFor(c.fx, prog, c.opts ?? {});
  const row = {label: c.label, publicInputs: c.fx.publicInputs, nq: t.core.nq, fills: t.fills, unlocking: t.unlockings.map((u) => u.length)};
  for (const mode of ['consensus', 'standard']) {
    const xs = spendAll(t.unlockings.map(() => t.locking), t.unlockings, mode);
    row[mode] = {accepted: xs.every((x) => x.accepted), inputs: xs.map((x) => ({op: x.opCost, budget: x.budget, margin: +(1 - x.opCost / x.budget).toFixed(5), capMargin: +(1 - x.opCost / CAP_BUDGET).toFixed(5), error: x.error}))};
  }
  { const {unlockings} = unlockingsFor(t.core, prog, capFills(t.core)); assert.ok(unlockings.every((u) => u.length === UNLOCK_CAP), 'cap padding');
    row.cap = {}; for (const mode of ['consensus', 'standard']) { const xs = spendAll(unlockings.map(() => t.locking), unlockings, mode);
      row.cap[mode] = {accepted: xs.every((x) => x.accepted), inputs: xs.map((x) => ({op: x.opCost, capMargin: +(1 - x.opCost / CAP_BUDGET).toFixed(5), error: x.error}))}; } }
  row.capRule = ['consensus', 'standard'].every((m) => row.cap[m].accepted && row.cap[m].inputs.every((x) => x.op <= CAP_RULE));
  results.push(row);
  const f = (m) => row[m].inputs.map((x) => `${(x.op / 1e6).toFixed(3)}M ${(100 * x.margin).toFixed(2)}%`).join(' | ');
  console.log(`${c.label.slice(0, 60).padEnd(60)} nq=${String(row.nq).padStart(3)} U=${row.unlocking.join('/')} cons ${row.consensus.accepted} [${f('consensus')}] std ${row.standard.accepted} [${f('standard')}] at-cap std ${row.cap.standard.inputs.map((x) => (x.op / 1e6).toFixed(3) + 'M').join('/')} cap ${row.capRule}`);
  writeFileSync(outPath, JSON.stringify(meta(), null, 1) + '\n');
}
const failed = results.filter((x) => !x.consensus.accepted || !x.standard.accepted || !x.capRule);
console.log(`cases ${results.length}, failed ${failed.length}`);
for (const mode of ['consensus', 'standard']) for (let i = 0; i < 3; i++) {
  const m = results.reduce((a, x) => (x[mode].inputs[i].margin < a[mode].inputs[i].margin ? x : a)); const M = results.reduce((a, x) => (x[mode].inputs[i].op > a[mode].inputs[i].op ? x : a));
  const K = results.reduce((a, x) => (x.cap[mode].inputs[i].op > a.cap[mode].inputs[i].op ? x : a));
  console.log(`${mode} input ${i}: min margin ${(100 * m[mode].inputs[i].margin).toFixed(2)}% at ${m.label}; max op (prover fill) ${M[mode].inputs[i].op} at ${M.label}; max op AT THE CAP ${K.cap[mode].inputs[i].op} (cap margin ${(100 * K.cap[mode].inputs[i].capMargin).toFixed(2)}%) at ${K.label}`);
}
writeFileSync(outPath, JSON.stringify(meta(), null, 1) + '\n');
assert.equal(failed.length, 0, `failed: ${failed.map((x) => x.label).join(', ')}`);
