// pool-tx-v3.mjs — v3 (5-input) pool-shaped witness sizing + the honest v3 scenario.
//
// Extends pool-tx.mjs to the v3 action shape (docs/V3-BUILD-2026-11-27.md §4):
//   inputs  [fuel0-tagged, fuel1-tagged, state-NFT (role 2), walkA-data, walkB-data]
//   source  outputs 0/1 = the tagged fuel pair (UNCHANGED — pool-tx.mjs fuelSourceOutputs),
//           output 2 = the state NFT, commitment = noteRoot ‖ nullSetRoot (the second
//           half is the SHA256-SMT root, NOT the old fold), outputs 3/4 = the walk
//           scripts in P2SH32 form at dust value.
//   out1's  commitment = newRoot ‖ finalNullRoot — role 2 pins the first half, walkB
//           pins the second. The old fold check 7 is GONE; the SMT replaces it.
//
// v3.1 (measured 2026-11-27): the walk UTXOs are P2SH32-WRAPPED. The committed raw
// form (locking = the script) is a NON-STANDARD scriptPubKey — relay refuses the
// creating tx ("scriptpubkey (code 64)", minimal-tx A/B confirmed on chipnet).
// The wrap keeps the walk SCRIPTS byte-identical (they ride the unlocking as the
// redeem push, exactly like the program's own inputs): the unlockings grow to
// ~8,445 / ~8,425 B — still ~1.5 KB under the 10,000-B cap, which only the spike's
// 11.6-KB unrolled form ever threatened. The hook 4w/graph pins hash the P2SH32
// lockings (SHA256(UTXOBYTECODE(3)) — the source locking, whatever its form).
//
// The walk unlockings are FIXED SIZE (no filler field), so the fill sizing covers
// inputs 0–2 exactly as pool-tx.mjs does; the walks ride along at their
// witness-supplied sizes with self-funded budgets (41 + len) × 800.
//
// Every byte passed to the VM is a PLAIN Uint8Array — Node Buffers alias via
// slice() and the VM's REVERSEBYTES writes through the views (STATUS.md finding 1).
import { createHash } from 'node:crypto';
import { VMS, p2sh32 } from './vm.mjs';
import { proveCore } from './protocol.mjs';
import { unlockingsFor, MARGIN, UNLOCK_CAP } from './transaction.mjs';
import { carrierOf } from './pool-hook.mjs';
import { fuelSourceOutputs, poolOutputs } from './pool-tx.mjs';
import { walkAWitness, walkBWitness } from './walk-scripts.mjs';
import { pushData } from './asm.mjs';

/* the walk pins/lockings for the v3.1 wrap, derived from the raw scripts */
export const walkV3 = (walkA, walkB) => {
    const lockings = [Uint8Array.from(p2sh32(Uint8Array.from(walkA))), Uint8Array.from(p2sh32(Uint8Array.from(walkB)))];
    const sha = (b) => createHash('sha256').update(Buffer.from(b)).digest();
    return { lockings, hashes: [sha(lockings[0]), sha(lockings[1])] };
};

const sha = (b) => createHash('sha256').update(b).digest();
const be32 = (v) => { const b = Buffer.alloc(32); let x = BigInt(v); for (let i = 31; i >= 0 && x > 0n; i--) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; };
const to32LE = (v) => Buffer.from(be32(v)).reverse();

/* the honest v3 scenario for one record (a committed fixture or a minted sweep
   proof): both commitments use the v3 64-B layout; the tag is unchanged
   (SHA256 of the carrier's first 64 bytes). fuelSourceOutputs/poolOutputs
   consume {tag, newCommit, newBal, carr} — this supplies them unchanged. */
export const scenarioV3 = ({ sc, n0, nullSet, balance = 1000n, categoryDisplay }) => {
    const carr = carrierOf(sc, 3);
    const tag = sha(carr.subarray(0, 64));
    const newBal = balance + sc.pv - 2n * sc.sign * sc.pv;
    const stateCommit = Buffer.concat([to32LE(n0), Buffer.from(nullSet.nullSetRootBefore, 'hex')]);
    const newCommit = Buffer.concat([to32LE(sc.newRoot), Buffer.from(nullSet.finalNullRoot, 'hex')]);
    return { carr, newBal, tag, stateCommit, newCommit };
};

/* the walk unlockings for one record's nullSet data (sibsA/midRoot, sibsB) — the
   redeem push (the walk script itself) rides the unlocking exactly like the
   program inputs' R push: P2SH32 form, v3.1 */
export const walkWitnesses = (nullSet, walkA, walkB) => [
    Uint8Array.from([...walkAWitness(Buffer.from(nullSet.midRoot, 'hex'), nullSet.sibsA.map((h) => Buffer.from(h, 'hex'))), ...pushData(Uint8Array.from(walkA))]),
    Uint8Array.from([...walkBWitness(nullSet.sibsB.map((h) => Buffer.from(h, 'hex'))), ...pushData(Uint8Array.from(walkB))]),
];

/* the 5-input source outputs for the honest pool shape. walkLocks = the walk
   lockings in their ON-CHAIN form (P2SH32, v3.1); pass tampered values to express
   the 4w/GRAPH pin scenarios. */
export const v5SourceOutputs = (lock, walkLocks, scenario, { sc, balance = 1000n, categoryDisplay }) => [
    ...fuelSourceOutputs(lock, scenario, { sc, categoryDisplay }),
    { lockingBytecode: new Uint8Array(lock), valueSatoshis: 1000n, token: { category: new Uint8Array(categoryDisplay), amount: balance, nft: { capability: 'mutable', commitment: new Uint8Array(scenario.stateCommit) } } },
    { lockingBytecode: new Uint8Array(walkLocks[0]), valueSatoshis: 300n },
    { lockingBytecode: new Uint8Array(walkLocks[1]), valueSatoshis: 300n },
];

/* the 5-input transaction inputs: the verifier unlockings (any count — the graph
   scenarios mutate it) followed by the walk witnesses */
export const v5Inputs = (unlockings, walkW) => [
    ...unlockings.map((u, n) => ({ outpointIndex: n, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array(u) })),
    ...walkW.map((w, n) => ({ outpointIndex: unlockings.length + n, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array(w) })),
];

/* evaluate one input of the 5-input pool-shaped transaction (standard mode, like
   stock sizeFills) — inputs 3/4 evaluate the walk scripts themselves */
const evalInput = (prog, unlockings, walkW, walkLocks, i, scenario, { sc, balance = 1000n, categoryDisplay }) => {
    const lock = p2sh32(prog.R);
    const inputs = v5Inputs(unlockings, walkW);
    const sourceOutputs = v5SourceOutputs(lock, walkLocks, scenario, { sc, balance, categoryDisplay });
    const outputs = poolOutputs(prog, scenario, { sc, balance, categoryDisplay });
    const st = VMS.standard.evaluate({ inputIndex: i, sourceOutputs, transaction: { version: 2, locktime: 0, inputs, outputs } });
    const top = st.stack?.[st.stack.length - 1];
    const ok = st.error === undefined && st.stack.length === 1 && top?.length === 1 && top[0] === 1;
    return { accepted: ok, error: st.error, opCost: st.metrics.operationCost, budget: (41 + unlockings[i].length) * 800, length: unlockings[i].length };
};

/* stock sizeFills's growth formula, replicated verbatim from pool-tx.mjs */
const nextFills = (runs, fills, unlockings, margin) => runs.map((x, i) => {
    const base = unlockings[i].length - fills[i] - (fills[i] >= 256 ? 3 : fills[i] >= 76 ? 2 : 1) + 1;
    let need = Math.ceil(x.opCost / ((1 - margin) * 800)) - 41;
    let f = Math.max(0, need - base);
    f = Math.max(0, need - (base - 1) - (f >= 256 ? 3 : f >= 76 ? 2 : 1));
    return Math.min(f, Math.max(0, UNLOCK_CAP - base - 2));
});

/* pool-aware v3 replacement for transactionFor: sizes fills for inputs 0–2 against
   the FIVE-input pool shape (the walks are fixed and ride along). walkScripts =
   [walkA, walkB] — the RAW scripts; the source lockings derive via the v3.1 wrap. */
export function poolTransactionForV3(fx, prog, scenarioArgs, walkScripts, { margin = MARGIN, fills0 = [0, 0, 0], maxIter = 40, es } = {}) {
    const core = proveCore(fx, es !== undefined ? { es } : {});
    const scenario = scenarioV3(scenarioArgs);
    const walkW = walkWitnesses(scenarioArgs.nullSet, walkScripts[0], walkScripts[1]);
    const walkLocks = walkV3(walkScripts[0], walkScripts[1]).lockings;
    let fills = fills0.slice();
    for (let it = 0; it < maxIter; it++) {
        const { unlockings, pushes, z, H } = unlockingsFor(core, prog, fills);
        const runs = [0, 1, 2].map((i) => evalInput(prog, unlockings, walkW, walkLocks, i, scenario, scenarioArgs));
        const ok = runs.map((x, i) => x.opCost <= (1 - margin) * x.budget || x.length >= UNLOCK_CAP - 3);
        if (ok.every(Boolean)) return { core, fills, pushes, unlockings, walkW, z, H, scenario, runs, locking: p2sh32(prog.R) };
        const next = nextFills(runs, fills, unlockings, margin);
        fills = next.map((f, i) => (ok[i] ? fills[i] : Math.max(f, fills[i] + 1)));
    }
    throw new Error('v3 pool fill sizing did not converge');
}
