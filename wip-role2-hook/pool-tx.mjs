// pool-tx.mjs — pool-shaped witness sizing for the hooked program.
//
// WHY THIS EXISTS (open item 1): the stock sizeFills evaluates every input via programOf, which
// builds TOKENLESS source outputs and uses the module-global transaction outputs (one bare
// OP_RETURN). The hook rejects that shape at check 2 (state category) and check 3 (carrier), so
// the stock sizer sees a tiny op-cost, declares victory, and leaves fills [0,0,0] — the real
// evaluation then runs at ~96% of budget with NO margin. vm.mjs's setOutputs only swaps the
// transaction outputs; the source outputs are hardcoded tokenless, which is why setOutputs alone
// could not fix this.
//
// This module runs the SAME fill-growth loop as stock sizeFills (transaction.mjs), but evaluates
// input 2 against the pool's real shape: source output 2 carries the state NFT (category, amount
// = balance, commitment = storedRoot‖oldNull) and the transaction outputs are the honest
// carrier / new-state / payout for the fixture being sized. Growth formula and margin are the
// stock ones, replicated verbatim.
//
// Every byte passed to the VM is a PLAIN Uint8Array — Node Buffers alias via slice() and the
// VM's REVERSEBYTES writes through the views (see wip-role2-hook/STATUS.md finding 1).
import { createHash } from 'node:crypto';
import { VMS, p2sh32 } from './vm.mjs';
import { proveCore } from './protocol.mjs';
import { unlockingsFor, MARGIN, UNLOCK_CAP } from './transaction.mjs';
import { carrierOf, carrierOutput } from './pool-hook.mjs';

const sha = (b) => createHash('sha256').update(b).digest();
const be32 = (v) => { const b = Buffer.alloc(32); let x = BigInt(v); for (let i = 31; i >= 0 && x > 0n; i--) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; };
const to32LE = (v) => Buffer.from(be32(v)).reverse();

/* the honest pool scenario for one fixture: carrier, state commitment, new commitment, outputs */
export const poolScenario = ({ sc, n0, balance = 1000n, oldNull = Buffer.alloc(32), categoryDisplay, outs = 2 }) => {
    const carr = carrierOf(sc, outs);
    /* deployed covenant folds the RAW LE covenant args: sha256(old ‖ nf0 ‖ nf1) (asset-pool.cash:148) */
    const newNull = sha(Buffer.concat([oldNull, carr.subarray(0, 32), carr.subarray(32, 64)]));
    /* deposit tag (hook check 4g): SHA256 of the carrier's first 64 bytes = the intended
       action's nullifiers — stored by the lock tx as both fuel outputs' NFT commitments */
    const tag = sha(carr.subarray(0, 64));
    const newBal = balance + sc.pv - 2n * sc.sign * sc.pv;
    const stateCommit = Buffer.concat([to32LE(n0), oldNull]);
    const newCommit = Buffer.concat([to32LE(sc.newRoot), newNull]);
    return { carr, newNull, newBal, stateCommit, newCommit, tag };
};

/* the honest fuel/deposit source outputs for inputs 0/1 (hook checks 4c/4g): both carry
   the pool category as a MUTABLE NFT tagged with the action's nullifier-hash; in0 carries
   the FT deposit on a shield (chain shape: lock out0 = deposit, out1 = plain fuel). */
export const fuelSourceOutputs = (lock, scenario, { sc, categoryDisplay }) => [
    { lockingBytecode: new Uint8Array(lock), valueSatoshis: 1000n, token: { category: new Uint8Array(categoryDisplay), amount: sc.sign === 0n ? sc.pv : 0n, nft: { capability: 'mutable', commitment: new Uint8Array(scenario.tag) } } },
    { lockingBytecode: new Uint8Array(lock), valueSatoshis: 1000n, token: { category: new Uint8Array(categoryDisplay), amount: 0n, nft: { capability: 'mutable', commitment: new Uint8Array(scenario.tag) } } },
];

export const poolOutputs = (prog, scenario, { sc, balance = 1000n, categoryDisplay }) => [
    { lockingBytecode: new Uint8Array(carrierOutput(scenario.carr)), valueSatoshis: 0n },
    { lockingBytecode: p2sh32(prog.R), valueSatoshis: 1000n, token: { category: new Uint8Array(categoryDisplay), amount: scenario.newBal, nft: { capability: 'mutable', commitment: new Uint8Array(scenario.newCommit) } } },
    ...(sc.sign === 1n ? [{ lockingBytecode: new Uint8Array([0x76, 0xa9, 0x14, ...new Uint8Array(20), 0x88, 0xac]), valueSatoshis: 546n, token: { category: new Uint8Array(categoryDisplay), amount: sc.pv } }] : []),
];

/* evaluate one input of the pool-shaped transaction (standard mode, like stock sizeFills) */
const evalInput = (prog, unlockings, i, scenario, { sc, balance = 1000n, categoryDisplay }) => {
    const lock = p2sh32(prog.R);
    const inputs = unlockings.map((u, n) => ({ outpointIndex: n, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array(u) }));
    const fuel = fuelSourceOutputs(lock, scenario, { sc, categoryDisplay });
    const sourceOutputs = [...fuel, { lockingBytecode: lock, valueSatoshis: 1000n, token: { category: new Uint8Array(categoryDisplay), amount: balance, nft: { capability: 'mutable', commitment: new Uint8Array(scenario.stateCommit) } } }];
    const outputs = poolOutputs(prog, scenario, { sc, balance, categoryDisplay });
    const st = VMS.standard.evaluate({ inputIndex: i, sourceOutputs, transaction: { version: 2, locktime: 0, inputs, outputs } });
    const top = st.stack?.[st.stack.length - 1];
    const ok = st.error === undefined && st.stack.length === 1 && top?.length === 1 && top[0] === 1;
    return { accepted: ok, error: st.error, opCost: st.metrics.operationCost, budget: (41 + unlockings[i].length) * 800, length: unlockings[i].length };
};

/* stock sizeFills's growth formula, replicated verbatim */
const nextFills = (runs, fills, unlockings, margin) => runs.map((x, i) => {
    const base = unlockings[i].length - fills[i] - (fills[i] >= 256 ? 3 : fills[i] >= 76 ? 2 : 1) + 1;
    let need = Math.ceil(x.opCost / ((1 - margin) * 800)) - 41;
    let f = Math.max(0, need - base);
    f = Math.max(0, need - (base - 1) - (f >= 256 ? 3 : f >= 76 ? 2 : 1));
    return Math.min(f, Math.max(0, UNLOCK_CAP - base - 2));
});

/* pool-aware replacement for transactionFor: sizes fills against the pool shape */
export function poolTransactionFor(fx, prog, scenarioArgs, { margin = MARGIN, fills0 = [0, 0, 0], maxIter = 40, es } = {}) {
    const core = proveCore(fx, es !== undefined ? { es } : {});
    const scenario = poolScenario(scenarioArgs);
    let fills = fills0.slice();
    for (let it = 0; it < maxIter; it++) {
        const { unlockings, pushes, z, H } = unlockingsFor(core, prog, fills);
        const runs = [0, 1, 2].map((i) => evalInput(prog, unlockings, i, scenario, scenarioArgs));
        const ok = runs.map((x, i) => x.opCost <= (1 - margin) * x.budget || x.length >= UNLOCK_CAP - 3);
        if (ok.every(Boolean)) return { core, fills, pushes, unlockings, z, H, scenario, runs, locking: p2sh32(prog.R) };
        const next = nextFills(runs, fills, unlockings, margin);
        fills = next.map((f, i) => (ok[i] ? fills[i] : Math.max(f, fills[i] + 1)));
    }
    throw new Error('pool fill sizing did not converge');
}
