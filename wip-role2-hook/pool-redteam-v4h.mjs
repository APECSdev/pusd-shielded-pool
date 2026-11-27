// pool-redteam-v4h.mjs — the stock red team, re-pointed at the C-ARCHITECTURE program
// (the 7-input holdings shape) under the pool4 VK. Ported from pool-redteam-v3.mjs:
// the same 151-scenario list + section 10, with the C shapes (96-B state commitment,
// NFT-only state, the H pair at 5/6, out2 holdings, out3 payout).
//
// pool-redteam.mjs (the 2-out/3-out port) extended to the v3 action shape: every
// scenario's transaction now carries the TWO nullifier-data inputs (inputs 3/4, the
// raw walkA/walkB lockings at dust value) so the tampered verifier unlockings are
// tested against the honest rest of the FIVE-input pool tx — exactly the composition
// this suite exists to test:
//   adversarial proof + honest pool shape  → the graph must reject (the hook passes),
//   honest proof + adversarial pool shape → the hook must reject (pool-test-v3's classes),
//   adversarial WALK data + honest rest   → the walk scripts must reject (NEW — the
//   two-layer state pin: role 2 pins the note root + the walk lockings by hash, the
//   walks pin the nullifier set; the replay and free-newroot classes die at the walks).
//
// The stock 151-scenario list is kept VERBATIM (sections 0–9); graph-shape scenarios
// whose verifier-input count is not 3 now also trip the v3 GRAPH's TXINPUTCOUNT==5
// pin — the report records where each run dies. Section 10 adds the v3 walk-input
// tamper surface (witness, locking, shape, replay and cross-class scenarios).
//
// Usage (VM, from the bench dir):
//   BN_VK_FIXTURES=/home/apecs/cov/our-v3-proofs.json node pool-redteam-v3.mjs [report.json]
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync, writeFileSync} from 'node:fs';
import {encodeDataPush, decodeAuthenticationInstructions, encodeAuthenticationInstruction} from '@bitauth/libauth';
import {bn254} from '@noble/curves/bn254.js';
import {FIXTURES, p, r, PI, GLS_OFFSET, LATTICE, mod, F2, f2, Fp} from '../sound-si-gls/math.mjs';
import {BOUNDS, proveCore, factorSchedule, runRange, startState, encodeHand, zOf, zTail, sha, le32, rdle, STMT_LAYOUT, CUTS, ROLES, NQ_MAX, TAG, toFp} from './protocol.mjs';
import {buildProgram, setCovenant} from './script.mjs';
import {unlockingsFor, MARGIN} from './transaction.mjs';
import {encodeUnlocking, VMS, p2sh32} from './vm.mjs';
import {pushData} from './asm.mjs';
import {covenantHook, covenantParams} from './pool-hook.mjs';
import {buildHoldingsCovenant} from './holdings-covenant.mjs';
import {poolOutputs, fuelSourceOutputs} from './pool-tx.mjs';
import {scenarioV3H, poolTransactionForC, walkWitnesses, walkV3, v7SourceOutputs, poolOutputsC} from './pool-tx-v3.mjs';
import {buildWalkScripts} from './walk-scripts.mjs';

const reportPath = process.argv[2] ?? 'pool-redteam-v3-report.json';
const CATEGORY_DISPLAY = Buffer.from('2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544', 'hex');
const CATEGORY_ONCHAIN = Buffer.from(CATEGORY_DISPLAY).reverse().toString('hex');

/* the C-architecture program: commit96 walk scripts + the 7-input graph pin +
   the holdings-mode hook; H built after the program. The ASSET category is the
   real PUSD — the circuit witness + the FT rider; the POOL category is the synthetic
   gate category (both parameterized below). */
const ASSET_CATEGORY = process.env.ASSET_CATEGORY ?? '2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544';
const ASSET_DISPLAY = Buffer.from(ASSET_CATEGORY, 'hex');
const ASSET_ONCHAIN = Buffer.from(ASSET_DISPLAY).reverse().toString('hex');
const { walkA, walkB, sizes } = buildWalkScripts(CATEGORY_ONCHAIN, { commit96: true });
const { lockings: WALK_LOCKS, hashes: [walkAHash, walkBHash] } = walkV3(walkA, walkB);
process.env.POOL_NULLDATA_HASHES = JSON.stringify([walkAHash.toString('hex'), walkBHash.toString('hex')]);
process.env.POOL_HOLDINGS = '1';
setCovenant(covenantHook(covenantParams({ categoryOnChain: CATEGORY_ONCHAIN, assetCategoryOnChain: ASSET_ONCHAIN }), 3, { walkAHash, walkBHash, holdings: {} }));
const prog = buildProgram();
const lock = p2sh32(prog.R); const LOCKS = [lock, lock, lock];
const HC = buildHoldingsCovenant({ progLockingHashHex: createHash('sha256').update(Buffer.from(lock)).digest('hex'), walkAHashHex: walkAHash.toString('hex'), walkBHashHex: walkBHash.toString('hex') });
const H_LOCKS = [HC.locking, HC.locking];
/* drift guard: the v3.1 program (the P2SH32-wrapped walk pins — re-derived when the
   wrap landed). Any silent change to the hook, the walk scripts or the graph pin
   fails loudly here. */
/* the v4h program pin is per-build (VK-specific): pass PIN=<sha256> to assert, or
   the run records the hash for the docs. */
const CODE_PIN = process.env.PIN ?? null;
const codeHash = createHash('sha256').update(prog.code).digest('hex');
if (CODE_PIN) assert.equal(codeHash, CODE_PIN, 'the v4h program code changed — re-derive and re-run the gates');
console.log(`v4h program built · walks ${sizes.walkA}/${sizes.walkB} B (commit96) · H ${HC.redeemBytes} B · program ${prog.code.length} B sha256 ${codeHash.slice(0, 16)}…${CODE_PIN ? ' · pin ok' : ''}`);

const proofs = JSON.parse(readFileSync('/home/apecs/cov/our-v3-proofs.json', 'utf8'));
const leToBig = (hex) => BigInt('0x' + Buffer.from(hex, 'hex').reverse().toString('hex') || '0');
const scenarioArgsOf = (i) => {
    const c = proofs[i].covenant;
    return { sc: { nf0: leToBig(c.nf0), nf1: leToBig(c.nf1), cm0: leToBig(c.cm0), cm1: leToBig(c.cm1), cm2: leToBig(c.cm2), newRoot: leToBig(c.newMerkleRoot), pv: BigInt(c.publicValueAbs), sign: BigInt(c.isUnshield) }, n0: BigInt(proofs[i].publicSignals[0]), nullSet: proofs[i].nullSet, categoryDisplay: CATEGORY_DISPLAY, assetCategoryDisplay: ASSET_DISPLAY, balance: 1000n, outs: 3 };
};

const fx0 = FIXTURES.fixtures[0], fx1 = FIXTURES.fixtures[1];
const T0 = poolTransactionForC(fx0, prog, scenarioArgsOf(0), [walkA, walkB], HC.script, HC.locking);
const T1 = poolTransactionForC(fx1, prog, scenarioArgsOf(1), [walkA, walkB], HC.script, HC.locking);
const scenario0 = T0.scenario;
const fills = T0.fills;
/* the honest walk witnesses of the tx's OWN carrier/state (fixture 0's nullSet data
   — the walks key off OUTPUT 0's nf slices and the state commitment, both honest
   fixture-0 values in every run; T1-based staples are adversarial by construction) */
const WALK_W = T0.walkW.map((w) => Buffer.from(w));

/* pool-aware v3 spendAll: like the 3-out port, but the tx carries the two walk
   inputs. For verifier inputs 0/1 the 3-out precedent holds (tokenless shape,
   junk outputs — roles 0/1 read neither; the graph's walk-hash pins still see the
   walk lockings, appended at the tail); input 2 gets the pool shape; inputs 3/4
   get the pool shape (the walks read the carrier, the state NFT and each other). */
function poolSpendAllV3(locks, unlockings, walkWIn, walkLocks, mode, scenario = scenario0, args = scenarioArgsOf(0)) {
    /* the C shape: the walkW array carries the two walk witnesses AND the two H redeem
       pushes (inputs 5/6) — the fill-sized verifier inputs 0/1/2 come first, walks 3/4,
       H 5/6 — poolTransactionForC returns only the 2 walk witnesses; the callers that
       pass WALK_W get the full 4-tail via the H_PUSHES below. */
    const H_PUSHES = [HC.script, HC.script].map((h) => Uint8Array.from(pushData(Uint8Array.from(h))));
    const walkW = [...walkWIn.map((w) => Buffer.from(w)), ...H_PUSHES.map((h) => Buffer.from(h))];
    const nV = unlockings.length;
    const evalOne = (i) => {
        const walkInputs = walkW.map((w, k) => ({ outpointIndex: nV + k, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array(w) }));
        const inputs = [...unlockings.map((q, n) => ({ outpointIndex: n, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array(q) })), ...walkInputs];
        const isPool2 = i === 2 && nV > 2 && Buffer.from(locks[2]).equals(Buffer.from(lock));
        const isWalk = i >= nV;
        const fuel = fuelSourceOutputs(lock, scenario, args);
        const sourceOutputs = [
            ...locks.map((l, n) => {
                if (isPool2 && n === 2) return { lockingBytecode: new Uint8Array(l), valueSatoshis: 1000n, token: { category: new Uint8Array(CATEGORY_DISPLAY), amount: 0n, nft: { capability: 'mutable', commitment: new Uint8Array(scenario.stateCommit) } } };
                if ((isPool2 || isWalk) && n < 2 && Buffer.from(l).equals(Buffer.from(lock))) return fuel[n];
                if (isWalk && n === 2 && Buffer.from(l).equals(Buffer.from(lock))) return { lockingBytecode: new Uint8Array(l), valueSatoshis: 1000n, token: { category: new Uint8Array(CATEGORY_DISPLAY), amount: 0n, nft: { capability: 'mutable', commitment: new Uint8Array(scenario.stateCommit) } } };
                return { lockingBytecode: new Uint8Array(l), valueSatoshis: 1000n };
            }),
            /* the walk + H source outputs follow the WITNESS count (the shape scenarios
               drop/duplicate inputs — the source list must match the input list
               or libauth throws instead of cleanly rejecting) */
            ...walkW.map((w, k) => k < 2
                ? { lockingBytecode: new Uint8Array(walkLocks[Math.min(k, walkLocks.length - 1)]), valueSatoshis: 300n }
                : { lockingBytecode: new Uint8Array(HC.locking), valueSatoshis: 600n, ...(k === 2 && BigInt(args.balance) > 0n ? { token: { category: new Uint8Array(ASSET_DISPLAY), amount: BigInt(args.balance) } } : {}) }),
        ];
        const outputs = (isPool2 || isWalk) ? poolOutputsC(prog, HC.locking, scenario, args) : [{ lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 1000n }];
        const st = VMS[mode].evaluate({ inputIndex: i, sourceOutputs, transaction: { version: 2, locktime: 0, inputs, outputs } });
        const top = st.stack?.[st.stack.length - 1];
        const ok = st.error === undefined && st.stack.length === 1 && top?.length === 1 && top[0] === 1;
        const u = i < nV ? unlockings[i] : walkW[i - nV];
        return { accepted: ok, error: st.error ?? (ok ? null : 'final stack ' + st.stack.length), opCost: st.metrics.operationCost, budget: (41 + u.length) * 800, length: u.length };
    };
    return unlockings.map((_, i) => evalOne(i)).concat(walkW.map((_, k) => evalOne(nV + k)));
}

const PUSH = {S0: [0, 0], DS0: [0, 1], C0: [0, 2], F0: [0, 3], R0: [0, 4], S1: [1, 0], H1: [1, 1], DS1: [1, 2], C1: [1, 3], F1: [1, 4], R1: [1, 5],
  DG: [2, 0], STMT: [2, 1], S2: [2, 2], H2: [2, 3], DS2: [2, 4], F2: [2, 5], WQ: [2, 6], R2: [2, 7]};

const runs = [];
const add = (label, kind, unlockings, {locks = LOCKS, expect = null, walkW = WALK_W, walkLocks = WALK_LOCKS, scenarioOverride = null} = {}) => runs.push({label, kind, unlockings: unlockings.map((u) => Buffer.from(u)), locks, walkW: walkW.map((w) => Buffer.from(w)), walkLocks, expect, scenarioOverride});
const clonePushes = (T) => T.pushes.map((ps) => ps.map((b) => Buffer.from(b)));
const enc = (P) => P.map((ps) => Buffer.from(encodeUnlocking(ps)));
const setWord = (b, off, v) => { const c = Buffer.from(b); le32(v).copy(c, off); return c; };
const flipAt = (b, i, m = 1) => { const c = Buffer.from(b); c[i] ^= m; return c; };
const raw = (label, kind, f, T = T0) => { const P = clonePushes(T); f(P); add(label, kind, enc(P)); };
const at = (P, k) => P[PUSH[k][0]][PUSH[k][1]];
const put = (P, k, v) => { P[PUSH[k][0]][PUSH[k][1]] = Buffer.from(v); };
// recommitted: change committed items (STMT, S, WQ), recompute DG, rho, z and the handovers the honest roles compute
function recommitted(label, kind, {STMT, S, WQ, fill2, core, expect} = {}, base = T0) {
  const c = {...(core ?? base.core), STMT: STMT ?? base.core.STMT, S: S ?? base.core.S, WQ: WQ ?? base.core.WQ};
  c.D = Buffer.concat([sha(c.S[0]), sha(c.S[1]), sha(c.STMT, c.S[2])]);
  c.h0 = sha(TAG, c.D); c.rhoRaw = sha(c.h0, Buffer.from('rho')); c.rho = toFp(c.rhoRaw);
  const f = [...fills]; if (fill2 !== undefined) f[2] = fill2;
  const z = zOf(c, zTail(f[2], c.WQ)); let s = startState(c, z); const H = [null];
  for (let i = 0; i < 2; i++) { s = runRange(c, z, CUTS[i], CUTS[i + 1], s); H.push(encodeHand(s)); }
  const P = clonePushes(base); put(P, 'DG', c.D); put(P, 'STMT', c.STMT); put(P, 'S0', c.S[0]); put(P, 'S1', c.S[1]); put(P, 'S2', c.S[2]); put(P, 'WQ', c.WQ);
  put(P, 'H1', H[1]); put(P, 'H2', H[2]); put(P, 'F2', Buffer.alloc(f[2]));
  add(label, kind, enc(P));
}
const W = T0.core; const word = (b, o) => rdle(b, o);
const stmtWith = (off, v) => setWord(W.STMT, off, v);

// ---------------- 0. sanity: the recommit path reproduces the valid transaction ----------------
{ recommitted('(control)', 'control'); const u = runs.pop().unlockings;
  u.forEach((x, i) => assert.ok(x.equals(T0.unlockings[i]), 'recommit path reproduces the valid run')); }

// ---------------- 1. statement: public inputs ----------------
{ const n0 = BigInt(fx0.publicInputs[0]), n1 = BigInt(fx0.publicInputs[1]);
  for (const [label, a, b] of [['n0 + 1', n0 + 1n, n1], ['n0 - 1', n0 - 1n, n1], ['n1 + 1', n0, n1 + 1n], ['n0 = 0', 0n, n1], ['n0, n1 swapped', n1, n0], ['n0 := fixture 1 n0', BigInt(fx1.publicInputs[0]), n1]])
    recommitted(`claim ${label} (honest witness otherwise; DG recommitted)`, 'public-input-binding', {STMT: setWord(stmtWith(STMT_LAYOUT.n0, a), STMT_LAYOUT.n1, b)});
  recommitted('n0 + r (non-canonical alias of n0)', 'public-input-encoding', {STMT: stmtWith(STMT_LAYOUT.n0, n0 + r)});
  recommitted('n1 + r (non-canonical alias of n1)', 'public-input-encoding', {STMT: stmtWith(STMT_LAYOUT.n1, n1 + r)});
  recommitted('n0 with the top bit set', 'public-input-encoding', {STMT: flipAt(W.STMT, STMT_LAYOUT.n0 + 31, 0x80)});
  recommitted('n0 = 2^256 - 1', 'public-input-encoding', {STMT: stmtWith(STMT_LAYOUT.n0, (1n << 256n) - 1n)});
  raw('n0 + 1 without recommitting DG', 'public-input-binding', (P) => put(P, 'STMT', stmtWith(STMT_LAYOUT.n0, n0 + 1n)));
}
// ---------------- 2. statement: proof points ----------------
{ for (const [label, off] of [['A.x + 1 (off curve)', 0], ['A.y + 1', 32], ['B.x.c0 + 1 (off twist)', 64], ['B.y.c1 + 1', 160], ['C.x + 1', 192], ['C.y + 1', 224]])
    recommitted(label, 'invalid-proof-point', {STMT: stmtWith(off, word(W.STMT, off) + 1n)});
  for (const [label, off] of [['A.x + p', 0], ['A.y + p', 32], ['B.x.c1 + p', 96], ['B.y.c0 + p', 128], ['C.x + p', 192], ['C.y + p', 224]])
    recommitted(label + ' (non-canonical alias of the same point)', 'non-canonical-coordinate', {STMT: stmtWith(off, word(W.STMT, off) + p)});
  recommitted('A = (0, 0)', 'invalid-proof-point', {STMT: setWord(stmtWith(0, 0n), 32, 0n)});
  recommitted('C = (0, 0)', 'invalid-proof-point', {STMT: setWord(stmtWith(192, 0n), 224, 0n)});
  recommitted('B = (0, 0)', 'invalid-proof-point', {STMT: [64, 96, 128, 160].reduce((b, o) => setWord(b, o, 0n), W.STMT)});
  recommitted('-A (y negated, on the curve)', 'invalid-proof-point', {STMT: stmtWith(32, mod(-word(W.STMT, 32)))});
  recommitted('-C (y negated)', 'invalid-proof-point', {STMT: stmtWith(224, mod(-word(W.STMT, 224)))});
  recommitted('-B (y negated, on the twist)', 'invalid-proof-point', {STMT: setWord(stmtWith(128, mod(-word(W.STMT, 128))), 160, mod(-word(W.STMT, 160)))});
  recommitted('A from proof 1', 'invalid-proof-point', {STMT: Buffer.concat([T1.core.STMT.subarray(0, 64), W.STMT.subarray(64)])});
  recommitted('B from proof 1 (in G2; the inverse-norm witnesses no longer match)', 'invalid-proof-point', {STMT: Buffer.concat([W.STMT.subarray(0, 64), T1.core.STMT.subarray(64, 192), W.STMT.subarray(192)])});
}
// ---------------- 2b. B on the twist but outside G2 (the endpoint guard) ----------------
{ const bT = F2.div(f2(3n, 0n), f2(9n, 1n)); let Bq = null;
  for (let k = 1n; !Bq; k++) { const x = f2(k, 1n); let y; try { y = F2.sqrt(F2.add(F2.mul(F2.sqr(x), x), bT)); } catch { continue; } if (!y) continue;
    let inG2 = true; try { bn254.G2.Point.fromAffine({x, y}).assertValidity(); } catch { inG2 = false; } if (!inG2) Bq = {x, y}; }
  const st2 = {...W.st, xB: Bq.x, yB: Bq.y}; const sched2 = factorSchedule(st2);
  assert.ok(!sched2.endpoint, 'non-G2 B: the walk must not end at -psi^3(B)');
  const S2 = ROLES.map(({chunks, i}) => { const out = [];
    for (let k of chunks) { for (let e = (k ? BOUNDS[k - 1] : 0); e < BOUNDS[k]; e++) out.push(...sched2.events[e].ts.map((t) => le32(mod(t)))); out.push(...W.states[k].slice(0, 6).map((v) => le32(mod(v)))); }
    if (i === ROLES.length - 1) out.push(...sched2.tts.map((t) => le32(mod(t))));
    const b = Buffer.concat(out); assert.equal(b.length, ROLES[i].streamSize); return b; });
  const STMT2 = [Bq.x.c0, Bq.x.c1, Bq.y.c0, Bq.y.c1].reduce((b, v, j) => setWord(b, 64 + 32 * j, v), W.STMT);
  recommitted('B on the twist but outside G2 (t, DG, rho, z, handovers recomputed; states, quotient honest)', 'g2-subgroup',
    {STMT: STMT2, S: S2, core: {...W, st: st2, sched: sched2}});
}
// ---------------- 3. statement: GT-GLS nibbles, residue root ----------------
{ const L = STMT_LAYOUT;
  recommitted('nibble N0[30] = 0x10 (out of range)', 'gls-digit', {STMT: ((b) => { b[L.N0 + 30] = 0x10; return b; })(Buffer.from(W.STMT))});
  recommitted('nibble N1[64] = 0x80 (negative zero)', 'gls-digit', {STMT: ((b) => { b[L.N1 + 64] = 0x80; return b; })(Buffer.from(W.STMT))});
  recommitted('nibble N0[0] = 0xff', 'gls-digit', {STMT: ((b) => { b[L.N0] = 0xff; return b; })(Buffer.from(W.STMT))});
  recommitted('nibble N1[10] bit flip (in range, binding broken)', 'gls-digit', {STMT: flipAt(W.STMT, L.N1 + 10)});
  recommitted('nibble N0[50] bit flip (role 2 range)', 'gls-digit', {STMT: flipAt(W.STMT, L.N0 + 50, 2)});
  { const es = W.es.map((e) => e.slice()); let ok = false;
    for (const v of LATTICE) for (const sg of [1n, -1n]) { if (ok) continue; const e2 = es[0].map((x, i) => x + sg * v[i]); if (e2.every((x) => x >= -GLS_OFFSET && x < GLS_OFFSET)) { es[0] = e2; ok = true; } }
    assert.ok(ok); assert.equal(mod(es[0].reduce((a, x, i) => a + x * PI[i], 0n), r), BigInt(fx0.publicInputs[0]));
    const alt = proveCore(fx0, {es});
    const b = Buffer.from(W.STMT); alt.STMT.copy(b, L.N0, L.N0, L.N0 + 130);
    recommitted('lattice-shifted GLS digits (binding holds) with stale states and quotient', 'gls-digit', {STMT: b});
  }
  recommitted('residue root s^c word 0 + 1', 'tamper-residue', {STMT: stmtWith(L.sc, word(W.STMT, L.sc) + 1n)});
  recommitted('residue root s^c word 3 + p (alias)', 'non-canonical-state', {STMT: stmtWith(L.sc + 96, word(W.STMT, L.sc + 96) + p)});
  recommitted('residue root from proof 1', 'tamper-residue', {STMT: Buffer.concat([W.STMT.subarray(0, L.sc), T1.core.STMT.subarray(L.sc)])});
}
// ---------------- 4. streams: states and inverse-norm witnesses ----------------
{ const S = (i, f) => W.S.map((x, j) => (j === i ? f(Buffer.from(x)) : x));
  const recOff = (i, k) => ROLES[i].records.slice(0, k).reduce((a, b) => a + b, 0);
  const stateOff = (i, k) => recOff(i, k) + ROLES[i].records[k] - 192;
  for (const [i, k, j] of [[0, 0, 0], [0, 11, 5], [1, 0, 2], [1, 6, 0], [2, 0, 1], [2, 8, 5]]) {
    const o = stateOff(i, k) + 32 * j;
    recommitted(`role ${i} state ${k + 1} of its range, word ${j} + 1`, 'tamper-state', {S: S(i, (b) => setWord(b, o, word(b, o) + 1n))});
  }
  recommitted('role 1 state 3 word 2 + p (alias)', 'non-canonical-state', {S: S(1, (b) => { const o = stateOff(1, 2) + 64; return setWord(b, o, word(b, o) + p); })});
  recommitted('role 2 last state word 5 = p', 'non-canonical-state', {S: S(2, (b) => setWord(b, stateOff(2, 8) + 160, p))});
  recommitted('role 0 states 2 and 3 swapped', 'tamper-state', {S: S(0, (b) => { const x = Buffer.from(b.subarray(stateOff(0, 1), stateOff(0, 1) + 192)), y = Buffer.from(b.subarray(stateOff(0, 2), stateOff(0, 2) + 192)); y.copy(b, stateOff(0, 1)); x.copy(b, stateOff(0, 2)); return b; })});
  const tOffs = [['role 0 first doubling t', 0, 0], ['role 1 first t (doubling)', 1, 0], ['role 0 an addition t (event 1)', 0, 64], ['role 2 terminal t_psi', 2, ROLES[2].streamSize - 64], ['role 2 terminal t_{-psi^2}', 2, ROLES[2].streamSize - 32]];
  for (const [what, i, o] of tOffs) {
    recommitted(`${what} + p (non-canonical)`, 'inverse-norm', {S: S(i, (b) => setWord(b, o, word(b, o) + p))});
    recommitted(`${what} = 0`, 'inverse-norm', {S: S(i, (b) => setWord(b, o, 0n))});
    recommitted(`${what} + 1 (wrong inverse)`, 'inverse-norm', {S: S(i, (b) => setWord(b, o, mod(word(b, o) + 1n)))});
  }
  recommitted('role 0 stream from proof 1', 'staple', {S: [T1.core.S[0], W.S[1], W.S[2]]});
  recommitted('role 1 stream from proof 1', 'staple', {S: [W.S[0], T1.core.S[1], W.S[2]]});
  recommitted('role 2 stream from proof 1', 'staple', {S: [W.S[0], W.S[1], T1.core.S[2]]});
  raw('role 0 stream byte flipped (DG not recommitted)', 'tamper-transcript', (P) => put(P, 'S0', flipAt(at(P, 'S0'), 300)));
  raw('role 2 stream byte flipped (DG not recommitted)', 'tamper-transcript', (P) => put(P, 'S2', flipAt(at(P, 'S2'), 300)));
}
// ---------------- 5. quotient ----------------
{ const Q = W.WQ, n = Q.length / 32;
  for (const i of [0, 1, n >> 1, n - 1]) recommitted(`Q word ${i} + 1`, 'tamper-quotient', {WQ: setWord(Q, 32 * i, word(Q, 32 * i) + 1n)});
  recommitted('Q word 3 + p (alias)', 'non-canonical-quotient', {WQ: setWord(Q, 96, word(Q, 96) + p)});
  recommitted('Q word 7 top bit set', 'non-canonical-quotient', {WQ: flipAt(Q, 7 * 32 + 31, 0x80)});
  recommitted('Q with a leading zero word (non-canonical n_q)', 'non-canonical-quotient', {WQ: Buffer.concat([Buffer.alloc(32), Q])});
  recommitted('Q missing the leading word', 'tamper-quotient', {WQ: Q.subarray(32)});
  recommitted('Q missing the last word', 'tamper-quotient', {WQ: Q.subarray(0, -32)});
  recommitted('Q padded to 133 words (over the cap)', 'quotient-cap', {WQ: Buffer.concat([Buffer.alloc(32 * (NQ_MAX + 1 - n)).fill(1, 0, 1), Q])});
  recommitted('Q length not a multiple of 32', 'quotient-cap', {WQ: Q.subarray(1)});
  recommitted('Q all zero (same length)', 'tamper-quotient', {WQ: Buffer.alloc(Q.length).fill(1, 0, 1)});
  recommitted('Q from proof 1', 'tamper-quotient', {WQ: T1.core.WQ});
  raw('Q word flipped (z not recomputed: stale handovers)', 'tamper-quotient', (P) => put(P, 'WQ', flipAt(at(P, 'WQ'), 40)));
  raw('Q empty', 'quotient-cap', (P) => put(P, 'WQ', Buffer.alloc(0)));
}
// ---------------- 6. handovers ----------------
{ for (const [k, nm] of [['H1', 'HAND_1'], ['H2', 'HAND_2']]) {
    for (const [w, wn] of [[0, 'x_T.c0'], [3, 'y_T.c1'], [4, 'F+'], [6, 'R']]) {
      raw(`${nm} ${wn} + 1`, 'handover', (P) => put(P, k, setWord(at(P, k), 32 * w, word(at(P, k), 32 * w) + 1n)));
      raw(`${nm} ${wn} + p (alias)`, 'handover', (P) => put(P, k, setWord(at(P, k), 32 * w, word(at(P, k), 32 * w) + p)));
    }
    raw(`${nm} single bit flipped`, 'handover', (P) => put(P, k, flipAt(at(P, k), 100, 0x10)));
    raw(`${nm} words shifted by one (off-by-one word)`, 'handover', (P) => { const h = at(P, k); put(P, k, Buffer.concat([h.subarray(32), h.subarray(0, 32)])); });
    raw(`${nm} from proof 1`, 'staple', (P) => put(P, k, at(clonePushes(T1), k)));
  }
}
// ---------------- 7. staples: whole inputs from another proof ----------------
for (const [label, mix] of [['input 0 from proof 1', [1, 0, 0]], ['input 1 from proof 1', [0, 1, 0]], ['input 2 from proof 1', [0, 0, 1]], ['inputs 0, 1 from proof 1', [1, 1, 0]], ['inputs 1, 2 from proof 1', [0, 1, 1]]])
  add(label, 'staple', mix.map((m, i) => (m ? T1 : T0).unlockings[i]));
// ---------------- 8. layout ----------------
{ const U = (P) => enc(P);
  for (const i of [0, 1, 2]) {
    add(`input ${i}: extra push at the bottom`, 'layout', U(clonePushes(T0).map((ps, j) => (j === i ? [Buffer.from([1]), ...ps] : ps))));
    add(`input ${i}: filler push missing`, 'layout', U(clonePushes(T0).map((ps, j) => (j === i ? ps.filter((_, k) => k !== PUSH['F' + i][1]) : ps))));
    add(`input ${i}: first two pushes swapped`, 'layout', U(clonePushes(T0).map((ps, j) => (j === i ? [ps[1], ps[0], ...ps.slice(2)] : ps))));
    /*  filler tamper only where the filler is non-empty: in the HOOKED build inputs 0/1 have
        empty fillers (the hook's code pieces make their unlockings longer, so their budgets
        already cover the graph), and flipping a byte of an empty push is a no-op that would
        accept. Input 2's filler is always sized (fills [0,0,171] in the 3-out port; the v3
        sizer re-derives it). */
    if (at(clonePushes(T0), 'F' + i).length > 0) {
      raw(`input ${i}: filler with a nonzero byte`, 'filler', (P) => { const f = at(P, 'F' + i); assert.ok(f.length > 0); put(P, 'F' + i, flipAt(f, f.length - 1)); });
      raw(`input ${i}: filler of 0x80 bytes (BIN2NUM zero)`, 'filler', (P) => put(P, 'F' + i, Buffer.alloc(at(P, 'F' + i).length).fill(0x80)));
    }
    raw(`input ${i}: redeem byte flipped`, 'layout', (P) => put(P, 'R' + i, flipAt(at(P, 'R' + i), 20)));
  }
  raw('input 2: filler grown so the unlocking exceeds 10,000 B', 'filler', (P) => put(P, 'F2', Buffer.alloc(at(P, 'F2').length + 10000 - T0.unlockings[2].length + 1)));
  raw('input 0: code piece byte flipped (K_code)', 'code', (P) => put(P, 'C0', flipAt(at(P, 'C0'), 123)));
  raw('input 1: code piece byte flipped (K_code)', 'code', (P) => put(P, 'C1', flipAt(at(P, 'C1'), 1234)));
  raw('input 0: delta slice byte flipped (K_DS)', 'constants', (P) => put(P, 'DS0', flipAt(at(P, 'DS0'), 999)));
  raw('input 2: delta slice byte flipped (K_DS)', 'constants', (P) => put(P, 'DS2', flipAt(at(P, 'DS2'), 64)));
  raw('input 2: DG byte flipped', 'tamper-transcript', (P) => put(P, 'DG', flipAt(at(P, 'DG'), 70)));
  const nonMinimal = (P, i, k, op) => { const pre = P[i].slice(0, k).map((b) => Buffer.from(encodeDataPush(b))); const x = P[i][k];
    const h = op === 0x4e ? Buffer.from([0x4e, ...(() => { const l = Buffer.alloc(4); l.writeUInt32LE(x.length); return l; })()]) : Buffer.from([0x4d, x.length & 255, x.length >> 8]);
    const post = P[i].slice(k + 1).map((b) => Buffer.from(encodeDataPush(b))); return Buffer.concat([...pre, h, x, ...post]); };
  { const P = clonePushes(T0); const u = enc(P); u[1] = nonMinimal(P, 1, 1, 0x4d); add('input 1: HAND_1 pushed with a non-minimal PUSHDATA2 (remote offset shift)', 'layout', u); }
  { const P = clonePushes(T0); const u = enc(P); u[2] = nonMinimal(P, 2, 1, 0x4e); add('input 2: STMT pushed with a non-minimal PUSHDATA4 (remote offset shift)', 'layout', u); }
  { const P = clonePushes(T0); const u = enc(P); u[2] = nonMinimal(P, 2, 6, 0x4e); add('input 2: WQ pushed with a non-minimal PUSHDATA4', 'layout', u); }
  { const P = clonePushes(T0); const u = enc(P); u[0] = Buffer.concat([Buffer.from(encodeDataPush(P[0][0])), Buffer.from([0x61]), ...P[0].slice(1).map((b) => Buffer.from(encodeDataPush(b)))]); add('input 0: OP_NOP in the unlocking', 'layout', u); }
  add('inputs 0 and 1 swapped (unlockings)', 'graph', [T0.unlockings[1], T0.unlockings[0], T0.unlockings[2]]);
  add('inputs 1 and 2 swapped (unlockings)', 'graph', [T0.unlockings[0], T0.unlockings[2], T0.unlockings[1]]);
}
// ---------------- 9. graph (transaction shape) ----------------
{ add('2 inputs (input 2 missing)', 'graph', T0.unlockings.slice(0, 2), {locks: [lock, lock]});
  add('4 inputs (input 2 duplicated)', 'graph', [...T0.unlockings, T0.unlockings[2]], {locks: [lock, lock, lock, lock]});
  const foreign = Buffer.from(p2sh32(Uint8Array.of(0x51))); // P2SH32(OP_TRUE)
  add('input 2 replaced by a foreign P2SH32(OP_TRUE) input', 'graph', [T0.unlockings[0], T0.unlockings[1], Buffer.from(encodeUnlocking([Uint8Array.of(0x51)]))], {locks: [lock, lock, foreign]});
  add('a foreign P2SH32(OP_TRUE) input appended', 'graph', [...T0.unlockings, Buffer.from(encodeUnlocking([Uint8Array.of(0x51)]))], {locks: [lock, lock, lock, foreign]});
  add('input 0 replaced by a foreign P2SH32(OP_TRUE) input', 'graph', [Buffer.from(encodeUnlocking([Uint8Array.of(0x51)])), T0.unlockings[1], T0.unlockings[2]], {locks: [foreign, lock, lock]});
  for (const j of [0, 1, 2]) {
    const n = T0.pushes[j].length - 1; const fr = Uint8Array.from([...Array(n >> 1).fill(0x6d), ...(n & 1 ? [0x75] : []), 0x51]);
    const U = T0.unlockings.slice(); U[j] = Buffer.from(encodeUnlocking([...T0.pushes[j].slice(0, -1), fr]));
    const locks = LOCKS.slice(); locks[j] = Buffer.from(p2sh32(fr));
    add(`foreign P2SH32 input at index ${j} carrying the honest pushes`, 'graph', U, {locks});
  }
}
// ---------------- 10. the v3 walk inputs (the nullifier-data tamper surface) ----------------
{ const ns0 = proofs[0].nullSet, ns1 = proofs[1].nullSet;
  const sibsA0 = ns0.sibsA.map((h) => Buffer.from(h, 'hex')), sibsB0 = ns0.sibsB.map((h) => Buffer.from(h, 'hex'));
  const midRoot0 = Buffer.from(ns0.midRoot, 'hex');
  const wA = T0.walkW[0], wB = T0.walkW[1];
  /* witness tampering — the walks' own scripts must reject */
  { const w = Buffer.from(wA); w[100] ^= 1; add('walkA witness byte flipped (sibling blob)', 'walk-witness', T0.unlockings, {walkW: [w, wB]}); }
  { const w = Buffer.from(wB); w[w.length - 5] ^= 1; add('walkB witness byte flipped (sibling blob)', 'walk-witness', T0.unlockings, {walkW: [wA, w]}); }
  { const w = Buffer.from(wA); w[0] ^= 1; add('walkA declared midRoot tampered (its own pin)', 'walk-witness', T0.unlockings, {walkW: [w, wB]}); }
  { const w = Buffer.from(wA); add('walkA witness truncated (blob length pin)', 'walk-witness', T0.unlockings, {walkW: [w.subarray(0, w.length - 40), wB]}); }
  { const w = Buffer.from(wB); add('walkB witness truncated (blob length pin)', 'walk-witness', T0.unlockings, {walkW: [wA, w.subarray(0, w.length - 40)]}); }
  add('walk witnesses swapped between inputs 3 and 4', 'walk-witness', T0.unlockings, {walkW: [wB, wA]});
  add('walkA unlocking replaced by an OP_TRUE-sized junk push', 'walk-witness', T0.unlockings, {walkW: [Buffer.from([0x51]), wB]});
  { const w1 = walkWitnesses(ns1, walkA, walkB); add('walk witnesses from ANOTHER action (fixture 1 null-set data)', 'walk-staple', T0.unlockings, {walkW: w1.map((x) => Buffer.from(x))}); }
  /* locking tampering — the hook 4w hash pins + the graph pins must reject
     (the lockings are the P2SH32 forms, v3.1) */
  add('walk lockings swapped between inputs 3 and 4 (4w/graph pins)', 'walk-locking', T0.unlockings, {walkLocks: [WALK_LOCKS[1], WALK_LOCKS[0]]});
  add('input 3 locked to junk (4w/graph pins)', 'walk-locking', T0.unlockings, {walkLocks: [Uint8Array.from([0x51]), WALK_LOCKS[1]]});
  add('input 4 locked to junk (4w/graph pins)', 'walk-locking', T0.unlockings, {walkLocks: [WALK_LOCKS[0], Uint8Array.from([0x51])]});
  add('both walk lockings junk (4w/graph pins)', 'walk-locking', T0.unlockings, {walkLocks: [Uint8Array.from([0x51]), Uint8Array.from([0x51])]});
  /* shape tampering — the GRAPH's TXINPUTCOUNT==5 pin (the walk source outputs
     follow the witness count so the harness rejects at the pins, not by throwing) */
  add('walk input 4 dropped (4-input tx — graph pin)', 'walk-shape', T0.unlockings, {walkW: [wA], walkLocks: [WALK_LOCKS[0]]});
  add('walk input 3 dropped (4-input tx — graph pin)', 'walk-shape', T0.unlockings, {walkW: [wB], walkLocks: [WALK_LOCKS[1]]});
  add('walkB duplicated as a 6th input (6-input tx — graph pin)', 'walk-shape', T0.unlockings, {walkW: [wA, wB, wB], walkLocks: [WALK_LOCKS[0], WALK_LOCKS[1], WALK_LOCKS[1]]});
  /* the R2 mechanism, stopped at consensus level: nf0 already in the set — the state's
     stored nullSetRoot is planted at the post-nf0 root (midRoot), so walkA's 0-walk of
     nf0 against a non-empty slot must fail the anchor pin */
  { const sc = scenarioV3H(scenarioArgsOf(0));
    sc.stateCommit = Buffer.concat([sc.stateCommit.subarray(0, 32), midRoot0]);
    add('REPLAY: nf0 already in the null set (walkA 0-walk must reject)', 'walk-replay', T0.unlockings, {scenarioOverride: sc});
  }
  /* the state commitment's nullSetRoot half tampered — walkA rejects */
  { const sc = scenarioV3H(scenarioArgsOf(0));
    const t = Buffer.from(sc.stateCommit); t[40] ^= 0x20; sc.stateCommit = t;
    add('state nullSetRoot half tampered (walkA must reject)', 'walk-state', T0.unlockings, {scenarioOverride: sc});
  }
  /* the new commitment's finalNullRoot half tampered — walkB rejects (role 2 accepts
     by design: the two-script pin) */
  { const sc = scenarioV3H(scenarioArgsOf(0));
    const t = Buffer.from(sc.newCommit); t[40] ^= 0x40; sc.newCommit = t;
    add('new commitment finalNullRoot half tampered (walkB must reject)', 'walk-state', T0.unlockings, {scenarioOverride: sc});
  }
}

// ---------------- locate the first rejecting guard ----------------
const roleIns = [0, 1, 2].map((i) => { const c = prog.funcCodes['role' + i]; const d = decodeAuthenticationInstructions(c); const o = []; let x = 0; for (const t of d) { o.push(x); x += encodeAuthenticationInstruction(t).length; } return {n: d.length, offs: o}; });
const fnOf = new Map(); for (const [n, c] of Object.entries(prog.funcCodes)) { if (n.startsWith('role')) continue; const L = decodeAuthenticationInstructions(c).length; fnOf.set(L, fnOf.has(L) ? fnOf.get(L) + '|' + n : n); }
const marks = prog.marks.slice().sort((a, b) => a.roff - b.roff);
const guardOf = (locks, unl, walkW, walkLocks, input, scenario) => {
  const nV = unl.length;
  const walkInputs = walkW.map((w, k) => ({ outpointIndex: nV + k, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array(w) }));
  const inputs = [...unl.map((q, n) => ({ outpointIndex: n, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array(q) })), ...walkInputs];
  const isPool2 = input === 2 && nV > 2 && Buffer.from(locks[2]).equals(Buffer.from(lock));
  const isWalk = input >= nV;
  const fuel = fuelSourceOutputs(lock, scenario, scenarioArgsOf(0));
  const sourceOutputs = [
    ...locks.map((l, n) => {
      if (isPool2 && n === 2) return { lockingBytecode: new Uint8Array(l), valueSatoshis: 1000n, token: { category: new Uint8Array(CATEGORY_DISPLAY), amount: 1000n, nft: { capability: 'mutable', commitment: new Uint8Array(scenario.stateCommit) } } };
      if ((isPool2 || isWalk) && n < 2 && Buffer.from(l).equals(Buffer.from(lock))) return fuel[n];
      if (isWalk && n === 2 && Buffer.from(l).equals(Buffer.from(lock))) return { lockingBytecode: new Uint8Array(l), valueSatoshis: 1000n, token: { category: new Uint8Array(CATEGORY_DISPLAY), amount: 1000n, nft: { capability: 'mutable', commitment: new Uint8Array(scenario.stateCommit) } } };
      return { lockingBytecode: new Uint8Array(l), valueSatoshis: 1000n };
    }),
    ...walkW.map((w, k) => ({ lockingBytecode: new Uint8Array(walkLocks[Math.min(k, walkLocks.length - 1)]), valueSatoshis: 300n })),
  ];
  const outputs = (isPool2 || isWalk) ? poolOutputs(prog, scenario, scenarioArgsOf(0)) : [{ lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 1000n }];
  if (isWalk) {
    const tr = VMS.consensus.debug({ inputIndex: input, sourceOutputs, transaction: { version: 2, locktime: 0, inputs, outputs } });
    const bad = tr.find((s) => s.error);
    return `walk${input - nV === 0 ? 'A' : 'B'} script (ip ${bad?.ip})`;
  }
  const tr = VMS.consensus.debug({ inputIndex: input, sourceOutputs, transaction: { version: 2, locktime: 0, inputs, outputs } });
  let sec = 'unlocking/redeem', fn = '';
  for (const s of tr) { const ri = roleIns.findIndex((x) => x.n === s.instructions?.length);
    if (ri >= 0) { fn = ''; let n = 'r' + ri + ':start'; for (const m of marks) if (m.role === ri && m.roff <= roleIns[ri].offs[Math.max(0, s.ip - 1)]) n = m.name; sec = n; }
    else if (fnOf.has(s.instructions?.length)) fn = fnOf.get(s.instructions.length) + '@' + (s.ip - 1);
    if (s.error) break; }
  return sec + (fn ? ' > ' + fn : ''); };

// ---------------- evaluate ----------------
const report = []; let acceptedAny = 0;
for (const x of runs) {
  const scenario = x.scenarioOverride ?? scenario0;
  const c = poolSpendAllV3(x.locks, x.unlockings, x.walkW, x.walkLocks, 'consensus', scenario), s = poolSpendAllV3(x.locks, x.unlockings, x.walkW, x.walkLocks, 'standard', scenario);
  const accC = c.every((y) => y.accepted), accS = s.every((y) => y.accepted);
  const first = c.findIndex((y) => !y.accepted);
  const rejecting = c.map((y, i) => (y.accepted ? null : i)).filter((i) => i !== null);
  const nV = x.unlockings.length;
  let at = null;
  if (first >= 0) {
    if (first >= nV) at = `input ${first}: ${Buffer.from(x.walkLocks[first - nV]).equals(Buffer.from(WALK_LOCKS[0])) ? 'walkA' : Buffer.from(x.walkLocks[first - nV]).equals(Buffer.from(WALK_LOCKS[1])) ? 'walkB' : 'walk'} script`;
    else if (Buffer.from(x.locks[first]).equals(Buffer.from(lock))) at = `input ${first}: ${guardOf(x.locks, x.unlockings, x.walkW, x.walkLocks, first, scenario)}`;
    else at = `input ${first} (foreign)`;
  }
  report.push({label: x.label, kind: x.kind, consensus: accC, standard: accS, rejectingInputs: rejecting,
    reason: first >= 0 ? String(c[first].error).replace(/^.*?: /, '').slice(0, 100) : null, at});
  if (accC || accS) { acceptedAny++; console.log('ACCEPTED:', x.label); }
}
// positive controls: the honest sized 5-input witness and a valid lattice-shifted alternative witness
const controls = [['fixture 0 (v3 pool-sized witness, 5 inputs)', LOCKS, T0.unlockings, T0.walkW, WALK_LOCKS]];
{ const es = W.es.map((e) => e.slice()); let done = false; for (const v of LATTICE) for (const sg of [1n, -1n]) { const e2 = W.es[0].map((x, i) => x + sg * v[i]); if (!done && e2.every((x) => x >= -GLS_OFFSET && x < GLS_OFFSET)) { es[0] = e2; done = true; } }
  assert.ok(done);
  const t = poolTransactionForC(fx0, prog, scenarioArgsOf(0), [walkA, walkB], HC.script, HC.locking, {es}); controls.push(['fixture 0, lattice-shifted GLS decomposition', LOCKS, t.unlockings, t.walkW, WALK_LOCKS]); }
for (const [label, locks, u, walkW, walkLocks] of controls) for (const m of ['consensus', 'standard']) assert.ok(poolSpendAllV3(locks, u, walkW, walkLocks, m).every((y) => y.accepted), 'control rejected: ' + label + ' ' + m);
const kinds = [...new Set(runs.map((x) => x.kind))];
console.log(`runs ${runs.length}, accepted ${acceptedAny}; kinds: ${kinds.join(', ')}; positive controls accepted: ${controls.map((c) => c[0]).join('; ')}`);
assert.equal(acceptedAny, 0);
writeFileSync(reportPath, JSON.stringify({runs: report, controls: controls.map((c) => c[0])}, null, 1) + '\n');
console.log(`report: ${reportPath}`);
