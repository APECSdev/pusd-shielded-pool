// pool-sweep-v3.mjs — liveness sweep of the V3 program (the 5-input nullifier-set
// shape: the sound verifier + the v3 hook + the walk inputs) under the pool4 VK,
// with the same REAL snarkjs-minted proofs as gen-sweep-proofs-v3.mjs.
//
// The deployment question this answers: does every random real POOL TRANSITION fit
// the program the v3 pool will actually deploy — in the FULL 5-input shape, where
// the two walk inputs (~8.2-KB unlockings, self-funded budgets) evaluate their own
// 254-level SHA256 SMT walks on every action?
// For every minted scenario (and the 5 committed fixtures as controls):
//   - fills are sized against the honest v3 POOL shape (pool-tx-v3.mjs
//     poolTransactionForV3 — inputs 0-2 sized, the walks fixed), targeting the
//     standard-mode MARGIN (6%);
//   - all FIVE inputs are evaluated in consensus AND standard mode: source outputs
//     = tagged fuel + state NFT + the raw walk lockings, outputs = the honest
//     carrier / new state / payout — every input must be ACCEPTED;
//   - every case is ALSO run with the verifier unlockings padded (zero filler) to
//     exactly UNLOCK_CAP = 10,000 B (inputs 3/4 CANNOT be padded — their witness is
//     length-pinned at 254×32 siblings, so the walk inputs' cap run IS their fixed
//     run) and every input must meet the CAP RULE there:
//       op <= 0.94 x (41 + unlockingLen) x 800
//     (the stock rule applied per-input: the padded inputs at the 10,000-B budget,
//     the walks at their own self-funded budgets).
//
// The same trapdoor limitation as the stock sweeps applies: no forced-extreme
// statements under this VK; this measures the worst case reachable by real proofs
// (transfer / shield / unshield / DEPOSIT — the onboarding path included).
//
// Usage: BN_VK_FIXTURES=/home/apecs/cov/our-v3-proofs.json \
//        [SWEEP_SHARD=k/n] node pool-sweep-v3.mjs <out.json> [<minted-proofs.json...>]
// (no minted files = the 5 committed fixtures only)
import assert from 'node:assert/strict';
import {readFileSync, writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {FIXTURES} from '../sound-si-gls/math.mjs';
import {buildProgram, setCovenant} from './script.mjs';
import {unlockingsFor, UNLOCK_CAP} from './transaction.mjs';
import {VMS, p2sh32} from './vm.mjs';
import {covenantHook, covenantParams, actionHashOf} from './pool-hook.mjs';
import {poolOutputs} from './pool-tx.mjs';
import {scenarioV3, poolTransactionForV3, walkWitnesses} from './pool-tx-v3.mjs';
import {buildWalkScripts} from './walk-scripts.mjs';

const [shard, shards] = (process.env.SWEEP_SHARD ?? '0/1').split('/').map(Number);
const outPath = process.argv[2];
const inPaths = process.argv.slice(3);
assert.ok(outPath, 'usage: node pool-sweep-v3.mjs <out.json> [<minted-proofs.json...>]');
/* every case funds its pool: balance = 1000n + pv. An unshield must satisfy the hook's check 8
   (newBalance = balance + pv - 2·sign·pv >= 0), so the state NFT must carry at least pv — the
   first pool-sweep run REJECTED every big-pv minted unshield with balance 1000, which is check 8
   working correctly on an underfunded scenario, not a hook defect. */

const CATEGORY_DISPLAY = Buffer.from('2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544', 'hex');
const CATEGORY_ONCHAIN = Buffer.from(CATEGORY_DISPLAY).reverse().toString('hex');

/* the v3 program: walk scripts + the graph pin + the v3 hook */
const { walkA, walkB, walkAHash, walkBHash, sizes } = buildWalkScripts(CATEGORY_ONCHAIN);
process.env.POOL_NULLDATA_HASHES = JSON.stringify([walkAHash.toString('hex'), walkBHash.toString('hex')]);
setCovenant(covenantHook(covenantParams({ categoryOnChain: CATEGORY_ONCHAIN }), 3, { walkAHash, walkBHash }));
const prog = buildProgram();
const lock = p2sh32(prog.R); const LOCKS = [lock, lock, lock];
const WALK_LOCKS = [walkA, walkB];
/* drift guard: the committed v3 program (7,998 B, build.v3.json hooked-v3,
   commit 1528993) — any silent change to the hook, the walk scripts or the graph
   pin fails loudly here. */
const CODE_PIN = 'd98c1d2ac828a909ba71bc94b719e2e21afcccc2d7565b8268ed8221d097b429';
assert.equal(createHash('sha256').update(prog.code).digest('hex'), CODE_PIN, 'the v3 program code changed — re-derive code/R/locking, re-run the red team, and update this pin + the docs');
console.log(`v3 program built · walkA ${sizes.walkA} B · walkB ${sizes.walkB} B · program ${prog.code.length} B · pin ok`);

const proofs = JSON.parse(readFileSync('/home/apecs/cov/our-v3-proofs.json', 'utf8'));
const leToBig = (hex) => BigInt('0x' + Buffer.from(hex, 'hex').reverse().toString('hex') || '0');
const scenarioArgsOf = (rec) => {
    const c = rec.covenant;
    const sc = { nf0: leToBig(c.nf0), nf1: leToBig(c.nf1), cm0: leToBig(c.cm0), cm1: leToBig(c.cm1), cm2: leToBig(c.cm2), newRoot: leToBig(c.newMerkleRoot), pv: BigInt(c.publicValueAbs), sign: BigInt(c.isUnshield) };
    const n0 = BigInt(rec.publicSignals[0]);
    assert.equal(actionHashOf({ ...sc, categoryDisplay: CATEGORY_DISPLAY.toString('hex') }, 3).toString(), BigInt(rec.publicSignals[1]).toString(), 'actionHash mismatch — record is not self-consistent');
    assert.ok(rec.nullSet && rec.nullSet.sibsA?.length === 254 && rec.nullSet.sibsB?.length === 254, 'record carries no v3 nullSet walk data');
    return { sc, n0, nullSet: rec.nullSet, categoryDisplay: CATEGORY_DISPLAY, balance: 1000n + sc.pv, outs: 3 };
};

/* v3 pool-aware spendAll: FIVE inputs — [fuel0, fuel1, state, walkA, walkB]; source
   outputs = the fuel pair + the state NFT + the raw walk lockings; outputs = the
   honest carrier / new state / payout. Every byte a PLAIN Uint8Array. */
function poolSpendAllV3(unlockings, walkW, mode, scenario, args) {
    const inputs = [...unlockings.map((u, n) => ({ outpointIndex: n, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array(u) })),
        ...walkW.map((w, k) => ({ outpointIndex: unlockings.length + k, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array(w) }))];
    const fuel = [
        { lockingBytecode: new Uint8Array(lock), valueSatoshis: 1000n, token: { category: new Uint8Array(CATEGORY_DISPLAY), amount: args.sc.sign === 0n ? args.sc.pv : 0n, nft: { capability: 'mutable', commitment: new Uint8Array(scenario.tag) } } },
        { lockingBytecode: new Uint8Array(lock), valueSatoshis: 1000n, token: { category: new Uint8Array(CATEGORY_DISPLAY), amount: 0n, nft: { capability: 'mutable', commitment: new Uint8Array(scenario.tag) } } },
    ];
    const sourceOutputs = [...fuel,
        { lockingBytecode: new Uint8Array(lock), valueSatoshis: 1000n, token: { category: new Uint8Array(CATEGORY_DISPLAY), amount: args.balance, nft: { capability: 'mutable', commitment: new Uint8Array(scenario.stateCommit) } } },
        { lockingBytecode: new Uint8Array(walkA), valueSatoshis: 300n },
        { lockingBytecode: new Uint8Array(walkB), valueSatoshis: 300n }];
    const outputs = poolOutputs(prog, scenario, args);
    const all = [...unlockings, ...walkW];
    return all.map((u, i) => {
        const st = VMS[mode].evaluate({ inputIndex: i, sourceOutputs, transaction: { version: 2, locktime: 0, inputs, outputs } });
        const top = st.stack?.[st.stack.length - 1];
        const ok = st.error === undefined && st.stack.length === 1 && top?.length === 1 && top[0] === 1;
        return { accepted: ok, error: st.error ?? (ok ? null : 'final stack ' + st.stack.length), opCost: st.metrics.operationCost, budget: (41 + u.length) * 800, length: u.length };
    });
}

/* fillers that pad the VERIFIER unlockings to exactly UNLOCK_CAP (filler push header 3 B at these sizes);
   the walk unlockings are fixed — they ride along unchanged */
const capFills = (core) => unlockingsFor(core, prog, [0, 0, 0]).unlockings.map((u) => { const f = UNLOCK_CAP - u.length + 1 - 3; assert.ok(f >= 256, `cap filler ${f} too small`); return f; });

/* cases: the 5 committed fixtures (controls) + every minted random scenario.
   Minted records carry the snarkjs proof shape; convert like mkfixtures.mjs. */
const g1 = ([x, y]) => ({x: BigInt(x).toString(), y: BigInt(y).toString()});
const g2 = ([[x0, x1], [y0, y1]]) => ({x: {c0: BigInt(x0).toString(), c1: BigInt(x1).toString()}, y: {c0: BigInt(y0).toString(), c1: BigInt(y1).toString()}});
const toFx = (rec) => ({publicInputs: rec.publicSignals.map((s) => BigInt(s).toString()), proof: {a: g1(rec.proof.pi_a), b: g2(rec.proof.pi_b), c: g1(rec.proof.pi_c)}});

const cases = [];
proofs.forEach((p, i) => cases.push({label: `fixture ${i} (${p.label})`, fx: FIXTURES.fixtures[i], args: scenarioArgsOf(p)}));
for (const p of inPaths) { const m = JSON.parse(readFileSync(p, 'utf8'));
  for (const rec of m.proofs) cases.push({label: rec.label, fx: toFx(rec), args: scenarioArgsOf(rec)}); }

const results = [];
const meta = () => ({inputs: inPaths, shard: `${shard}/${shards}`, shape: 'v3 5-input (fuel0, fuel1, state, walkA, walkB)', balanceRule: 'per case: balance = 1000n + pv (an unshield must be funded; hook check 8 requires newBalance >= 0)', results});
for (const [k, c] of cases.entries()) {
  if (k % shards !== shard) continue;
  const T = poolTransactionForV3(c.fx, prog, c.args, WALK_LOCKS);
  const row = {label: c.label, pv: c.args.sc.pv.toString(), sign: c.args.sc.sign.toString(), publicInputs: c.fx.publicInputs, nq: T.core.nq, fills: T.fills, unlocking: [...T.unlockings.map((u) => u.length), ...T.walkW.map((w) => w.length)]};
  for (const mode of ['consensus', 'standard']) {
    const xs = poolSpendAllV3(T.unlockings, T.walkW, mode, T.scenario, c.args);
    row[mode] = {accepted: xs.every((x) => x.accepted), inputs: xs.map((x) => ({op: x.opCost, budget: x.budget, margin: +(1 - x.opCost / x.budget).toFixed(5), error: x.error}))};
  }
  { const {unlockings} = unlockingsFor(T.core, prog, capFills(T.core)); assert.ok(unlockings.every((u) => u.length === UNLOCK_CAP), 'cap padding');
    row.cap = {}; for (const mode of ['consensus', 'standard']) { const xs = poolSpendAllV3(unlockings, T.walkW, mode, T.scenario, c.args);
      row.cap[mode] = {accepted: xs.every((x) => x.accepted), inputs: xs.map((x) => ({op: x.opCost, budget: x.budget, capMargin: +(1 - x.opCost / x.budget).toFixed(5), error: x.error}))}; } }
  row.capRule = ['consensus', 'standard'].every((m) => row.cap[m].accepted && row.cap[m].inputs.every((x) => x.op <= Math.floor(0.94 * x.budget)));
  results.push(row);
  const f = (m) => row[m].inputs.map((x) => `${(x.op / 1e6).toFixed(3)}M ${(100 * x.margin).toFixed(2)}%`).join(' | ');
  console.log(`${c.label.slice(0, 52).padEnd(52)} nq=${String(row.nq).padStart(3)} U=${row.unlocking.join('/')} cons ${row.consensus.accepted} [${f('consensus')}] std ${row.standard.accepted} [${f('standard')}] at-cap std ${row.cap.standard.inputs.map((x) => (x.op / 1e6).toFixed(3) + 'M').join('/')} cap ${row.capRule}`);
  writeFileSync(outPath, JSON.stringify(meta(), null, 1) + '\n');
}
const failed = results.filter((x) => !x.consensus.accepted || !x.standard.accepted || !x.capRule);
console.log(`cases ${results.length}, failed ${failed.length}`);
for (const mode of ['consensus', 'standard']) for (let i = 0; i < 5; i++) {
  const m = results.reduce((a, x) => (x[mode].inputs[i].margin < a[mode].inputs[i].margin ? x : a)); const M = results.reduce((a, x) => (x[mode].inputs[i].op > a[mode].inputs[i].op ? x : a));
  const K = results.reduce((a, x) => (x.cap[mode].inputs[i].op > a.cap[mode].inputs[i].op ? x : a));
  console.log(`${mode} input ${i}: min margin ${(100 * m[mode].inputs[i].margin).toFixed(2)}% at ${m.label}; max op (pool fill) ${M[mode].inputs[i].op} at ${M.label}; max op AT THE CAP ${K.cap[mode].inputs[i].op} (cap margin ${(100 * K.cap[mode].inputs[i].capMargin).toFixed(2)}%) at ${K.label}`);
}
writeFileSync(outPath, JSON.stringify(meta(), null, 1) + '\n');
assert.equal(failed.length, 0, `failed: ${failed.map((x) => x.label).join(', ')}`);
