// export-our.mjs — bench-vectors file for the red team, under OUR VK.
// Same shape export.mjs writes. worstCaseProof was originally omitted (it needs the
// densless-fixtures trapdoor mint; our VK has no trapdoor — we have the real ceremony zkey
// instead). Since 2026-11-24 the liveness sweep (sweep-ours.mjs) measures the worst case
// reachable by REAL proofs, so worstCaseProof can be exported from the sweep's worst-margin
// case (smallest input-0 STANDARD margin — the bench's definition, cf.
// chunked/bls12-381/bls-native-sound/README.md). Pass the sweep report and the minted files
// it consumed to include it; without those args the export omits the key (the original
// behavior, byte-compatible with the pre-2026-11-24 our-vectors.json).
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { FIXTURES } from '../sound-si-gls/math.mjs';
import { buildProgram } from './script.mjs';
import { transactionFor } from './transaction.mjs';
import { spendAll } from './vm.mjs';

const prog = buildProgram();
const built = JSON.parse(readFileSync(new URL('./build.json', import.meta.url), 'utf8'));
assert.equal(createHash('sha256').update(prog.code).digest('hex'), built.codeSha256, 'build.json is stale: run build.mjs');

const LABELS = ['input 0: events 0-24', 'input 1: events 24-48', 'input 2: events 48-65, terminal, binding, quotient'];
const CHECKPOINTS = ['miller-events-24', 'miller-events-48', 'pairing-close'];
const stepsOf = (unlockings, locking) => unlockings.map((u, i) => ({
    label: LABELS[i], locking: locking.toString('hex'),
    unlocking: Buffer.from(u).toString('hex'), checkpoint: CHECKPOINTS[i],
}));
const run = (fx, opts = {}) => {
    const t = transactionFor(fx, prog, opts);
    const r = spendAll(t.unlockings.map(() => t.locking), t.unlockings, 'standard');
    assert.ok(r.every((x) => x.accepted), 'valid run rejected');
    return stepsOf(t.unlockings, t.locking);
};

/* the sweep's worst case -> the bench fixture shape (mkfixtures.mjs mapping for minted records) */
const g1 = ([x, y]) => ({x: BigInt(x).toString(), y: BigInt(y).toString()});
const g2 = ([[x0, x1], [y0, y1]]) => ({x: {c0: BigInt(x0).toString(), c1: BigInt(x1).toString()}, y: {c0: BigInt(y0).toString(), c1: BigInt(y1).toString()}});
const toFx = (rec) => ({publicInputs: rec.publicSignals.map((s) => BigInt(s).toString()), proof: {a: g1(rec.proof.pi_a), b: g2(rec.proof.pi_b), c: g1(rec.proof.pi_c)}});
const worstOf = async (reportPath, mintedPaths) => {
    const rep = JSON.parse(readFileSync(reportPath, 'utf8'));
    assert.ok(rep.results.length, 'empty sweep report');
    const worst = rep.results.reduce((a, x) => (x.standard.inputs[0].margin < a.standard.inputs[0].margin ? x : a));
    const m = /^fixture (\d+)$/.exec(worst.label);
    if (m) return {label: worst.label, fixture: Number(m[1]), fx: FIXTURES.fixtures[Number(m[1])]};
    if (worst.label === 'fixture 0, lattice-shifted GLS witness') {
        /* the shifted witness is part of the case: re-derive it exactly as sweep-ours.mjs does */
        const {glsDecompose, GLS_OFFSET, LATTICE} = await import('../sound-si-gls/math.mjs');
        const es = FIXTURES.fixtures[0].publicInputs.map((n) => glsDecompose(BigInt(n)));
        for (const v of LATTICE) for (const sg of [1n, -1n]) {
            const e2 = es[0].map((x, i) => x + sg * v[i]);
            if (e2.every((x) => x >= -GLS_OFFSET && x < GLS_OFFSET)) return {label: worst.label, fixture: 0, fx: FIXTURES.fixtures[0], opts: {es: [e2, es[1]]}};
        }
        throw new Error('lattice shift not found');
    }
    for (const p of mintedPaths) for (const rec of JSON.parse(readFileSync(p, 'utf8')).proofs)
        if (rec.label === worst.label) return {label: worst.label, fixture: -1, fx: toFx(rec)};
    throw new Error(`worst case ${JSON.stringify(worst.label)} not found in the minted files`);
};

const [primary, ...rest] = FIXTURES.fixtures;
const out = { steps: run(primary), invalid: [], extraValidProofs: rest.map(run) };
if (process.argv[4]) {
    const w = await worstOf(process.argv[3], process.argv.slice(4));
    out.worstCaseProof = run(w.fx, w.opts);
    console.log(`worstCaseProof = sweep case ${JSON.stringify(w.label)} (fixture ${w.fixture})`);
} else if (process.argv[3]) {
    throw new Error('usage: node export-our.mjs <out> [sweep-report.json minted1.json ...] — report without minted files');
}
writeFileSync(process.argv[2], JSON.stringify(out, null, 1) + '\n');
console.log('wrote', process.argv[2], '| steps 3, extraValidProofs', rest.length, out.worstCaseProof ? '+ worstCaseProof' : '(no worstCaseProof — pass the sweep report + minted files)');
