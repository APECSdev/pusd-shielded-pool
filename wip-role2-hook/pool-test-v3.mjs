// pool-test-v3.mjs — the v3 acceptance suite: the pool hook WITH the nullifier-SMT
// walk inputs, on the BCH-2026 VM, under the pool4 VK.
//
// Composition (identical to pool-build-v3.mjs): walkA/walkB built for the category,
// POOL_NULLDATA_HASHES exported (script.mjs's GRAPH: TXINPUTCOUNT == 5, inputs 3/4
// hash-pinned), covenantHook(params, 3, { walkAHash, walkBHash }) — the v3 role-2 hook.
//
// The action shape is FIVE inputs: [fuel0-tagged, fuel1-tagged, state-NFT (role 2),
// walkA data, walkB data] and THREE outputs (carrier, new state, payout-if-unshield).
// Input 2 is evaluated for the hook's own checks; inputs 3/4 are evaluated for the
// walk-side pins (the null-set classes live THERE, not in role 2).
//
// New classes vs the 3-out suite (which had 21):
//   - a DEPOSIT control (fixture 4: onboarding at the empty genesis tree);
//   - shape: a 4-input tx (input 4 dropped) — the GRAPH's TXINPUTCOUNT pin;
//   - shape: input 3/4 locked to the WRONG raw script — the 4w hash pins;
//   - the REPLAY: the state's nullSetRoot already contains nf0 — walkA's 0-walk
//     must reject (the R2 mechanism, now actually stopped);
//   - the state commitment's nullSetRoot half tampered — walkA rejects;
//   - the new state commitment's finalNullRoot half tampered — role 2 ACCEPTS (it
//     only pins the first half by design) and walkB rejects — the two-script pin.
//
// Usage (VM, from the bench dir):
//   BN_VK_FIXTURES=/home/apecs/cov/our-v3.fixtures.json node pool-test-v3.mjs
//   (the fixtures file — the {vk, fixtures} shape; our-v3-proofs.json is the raw proofs list)
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { VMS, p2sh32 } from './vm.mjs';
import { decodeAuthenticationInstructions, encodeAuthenticationInstruction } from '@bitauth/libauth';
import { buildProgram, setCovenant } from './script.mjs';
import { transactionFor } from './transaction.mjs';
import { FIXTURES } from '../sound-si-gls/math.mjs';
import { covenantHook, covenantParams, carrierOf, carrierOutput, actionHashOf } from './pool-hook.mjs';
import { buildWalkScripts } from './walk-scripts.mjs';
import { walkWitnesses, walkV3 } from './pool-tx-v3.mjs';

const sha = (b) => createHash('sha256').update(b).digest();
const CATEGORY_DISPLAY = Buffer.from('2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544', 'hex');
const CATEGORY_ONCHAIN = Buffer.from(CATEGORY_DISPLAY).reverse();

/* the v3.1 program: walk scripts (P2SH32-wrapped on chain — the raw form is
   relay-nonstandard, measured on chipnet 2026-11-27: "scriptpubkey (code 64)")
   + the graph pin + the v3 hook. The 4w/graph pins hash the ON-CHAIN lockings. */
const { walkA, walkB, sizes } = buildWalkScripts(CATEGORY_ONCHAIN.toString('hex'));
const { lockings: WALK_LOCKS, hashes: [walkAHash, walkBHash] } = walkV3(walkA, walkB);
process.env.POOL_NULLDATA_HASHES = JSON.stringify([walkAHash.toString('hex'), walkBHash.toString('hex')]);
setCovenant(covenantHook(covenantParams({ categoryOnChain: CATEGORY_ONCHAIN.toString('hex') }), 3, { walkAHash, walkBHash }));
const prog = buildProgram();
const lock = p2sh32(prog.R);
console.log(`v3.1 program built · walkA ${sizes.walkA} B / walkB ${sizes.walkB} B scripts (P2SH32 on chain) · program ${prog.code?.length ?? '?'} B`);

const proofs = JSON.parse(readFileSync('/home/apecs/cov/our-v3-proofs.json', 'utf8'));
const leToBig = (hex) => BigInt('0x' + Buffer.from(hex, 'hex').reverse().toString('hex') || '0');
const be32 = (v) => { const b = Buffer.alloc(32); let x = BigInt(v); for (let i = 31; i >= 0 && x > 0n; i--) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; };
const to32LE = (v) => Buffer.from(be32(v)).reverse();
const catDisplay = Buffer.from(CATEGORY_ONCHAIN).reverse().toString('hex');

const scenarioOf = (p) => {
    const c = p.covenant;
    const s = {
        nf0: leToBig(c.nf0), nf1: leToBig(c.nf1), cm0: leToBig(c.cm0), cm1: leToBig(c.cm1), cm2: leToBig(c.cm2),
        newRoot: leToBig(c.newMerkleRoot), pv: BigInt(c.publicValueAbs), sign: BigInt(c.isUnshield),
    };
    const n0 = BigInt(p.publicSignals[0]);
    assert.equal(actionHashOf({ ...s, categoryDisplay: catDisplay }, 3).toString(), BigInt(p.publicSignals[1]).toString(), 'actionHash mismatch — fixture is not self-consistent');
    return { s, n0 };
};
const foreignTag = (idx) => new Uint8Array(sha(carrierOf(scenarioOf(proofs[idx]).s, 3).subarray(0, 64)));

/* run(label, expect, {proofIdx, mutate, txMutate, evalInput, dropWalkB, swapLock3, junkLock4, replayNf0})
   — the tx knobs beyond the 3-out suite:
     evalInput: which input to evaluate (default 2 = role 2 / the hook);
     dropWalkB: build a 4-input tx (input 4 + its source output omitted) — the GRAPH pin;
     lock3/lock4: substitute the raw lockings of inputs 3/4 — the 4w hash pins;
     replayNf0: the state's nullSetRoot half := the fixture's midRoot (nf0 already
       spent) — walkA's 0-walk must reject. */
const run = (label, expect, { proofIdx, mutate = {}, txMutate = {}, evalInput = 2, dropWalkB = false, lock3 = null, lock4 = null, replayNf0 = false, tamperStateNull = false, tamperNewNull = false }) => {
    const { s, n0 } = scenarioOf(proofs[proofIdx]);
    const sc = { ...s, ...mutate };
    const balance = 1000n;
    const fx = proofs[proofIdx].nullSet;                       // the fixture's SMT walk data
    const nullSetRoot = Buffer.from(fx.nullSetRootBefore, 'hex');
    const midRoot = Buffer.from(fx.midRoot, 'hex');
    const finalNullRoot = Buffer.from(fx.finalNullRoot, 'hex');
    /* the stored nullSetRoot: honest = the empty root; the REPLAY plants nf0's
       post-insert root (midRoot) so nf0 is already spent */
    const storedNull = replayNf0 ? midRoot : (tamperStateNull ? Buffer.from([...nullSetRoot.slice(0, 3), nullSetRoot[3] ^ 0x20, ...nullSetRoot.slice(4)]) : nullSetRoot);
    const stateCommit = Buffer.concat([to32LE(n0), storedNull]);
    const newCommitTail = tamperNewNull ? Buffer.from([...finalNullRoot.slice(0, 2), finalNullRoot[2] ^ 0x40, ...finalNullRoot.slice(3)]) : finalNullRoot;
    const newCommit = Buffer.concat([to32LE(sc.newRoot), newCommitTail]);
    const carr = carrierOf(sc, 3);
    const newBal = balance + sc.pv - 2n * sc.sign * sc.pv;
    const tag = sha(carr.subarray(0, 64));
    const tx = {
        sourceCategory: new Uint8Array(CATEGORY_DISPLAY),
        stateCommit: new Uint8Array(stateCommit),
        out1Category: new Uint8Array(CATEGORY_DISPLAY),
        newCommit: new Uint8Array(newCommit),
        out1Amount: newBal,
        payout: sc.sign === 1n,
        fuelCat0: new Uint8Array(CATEGORY_DISPLAY),
        fuelCat1: new Uint8Array(CATEGORY_DISPLAY),
        fuelTag0: new Uint8Array(tag),
        fuelTag1: new Uint8Array(tag),
        fuelNaked0: false,
        fuelNaked1: false,
        ...txMutate,
    };

    const T = transactionFor(FIXTURES.fixtures[proofIdx], prog);
    const inputs = T.unlockings.map((u, n) => ({ outpointIndex: n, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array(u) }));
    inputs.push({ outpointIndex: 0, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array(walkWitnesses(fx, walkA, walkB)[0]) });
    if (!dropWalkB) inputs.push({ outpointIndex: 1, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array(walkWitnesses(fx, walkA, walkB)[1]) });
    const fuelOut = (n) => (tx['fuelNaked' + n]
        ? { lockingBytecode: lock, valueSatoshis: 1000n }
        : { lockingBytecode: lock, valueSatoshis: 1000n, token: { category: tx['fuelCat' + n], amount: n === 0 && sc.sign === 0n ? sc.pv : 0n, nft: { capability: 'mutable', commitment: tx['fuelTag' + n] } } });
    const sourceOutputs = [
        fuelOut(0),
        fuelOut(1),
        { lockingBytecode: lock, valueSatoshis: 1000n, token: { category: tx.sourceCategory, amount: balance, nft: { capability: 'mutable', commitment: tx.stateCommit } } },
        { lockingBytecode: new Uint8Array(lock3 ?? WALK_LOCKS[0]), valueSatoshis: 300n },
    ];
    if (!dropWalkB) sourceOutputs.push({ lockingBytecode: new Uint8Array(lock4 ?? WALK_LOCKS[1]), valueSatoshis: 300n });
    const outputs = [
        { lockingBytecode: new Uint8Array(carrierOutput(carrierOf(sc, 3))), valueSatoshis: 0n },
        { lockingBytecode: lock, valueSatoshis: 1000n, token: { category: tx.out1Category, amount: tx.out1Amount, nft: { capability: 'mutable', commitment: tx.newCommit } } },
    ];
    if (tx.payout) outputs.push({ lockingBytecode: Buffer.from([0x76, 0xa9, 0x14, ...Buffer.alloc(20), 0x88, 0xac]), valueSatoshis: 546n, token: { category: new Uint8Array(CATEGORY_DISPLAY), amount: sc.pv } });

    const res = {};
    for (const mode of ['consensus', 'standard']) {
        const st = VMS[mode].evaluate({ inputIndex: evalInput, sourceOutputs, transaction: { version: 2, locktime: 0, inputs, outputs } });
        const top = st.stack[st.stack.length - 1];
        res[mode] = { ok: st.error === undefined && st.stack.length === 1 && top && top.length === 1 && top[0] === 1, err: st.error, op: st.metrics?.operationCost ?? 0 };
    }
    const acc = res.consensus.ok && res.standard.ok;
    let where = '';
    if (!acc && evalInput === 2) {
        const d = decodeAuthenticationInstructions(prog.funcCodes.role2); const offs = []; let x = 0;
        for (const t of d) { offs.push(x); x += encodeAuthenticationInstruction(t).length; }
        const trace = VMS.consensus.debug({ inputIndex: 2, sourceOutputs, transaction: { version: 2, locktime: 0, inputs, outputs } });
        const bad = trace.find((st) => st.error);
        const off = bad ? bad.ip : Infinity;
        let di = 0; while (di + 1 < offs.length && offs[di + 1] <= off) di++;
        const mk = prog.marks.filter((m) => m.role === 2).sort((a, b) => a.roff - b.roff).filter((m) => m.roff <= off);
        where = ` · at ${mk.at(-1)?.name ?? '?'} (ip ${bad?.ip})`;
    }
    const pass = acc === expect;
    console.log(`${pass ? 'ok  ' : 'FAIL'} ${acc ? 'ACCEPT' : 'REJECT'} (want ${expect ? 'ACCEPT' : 'REJECT'})  [in ${evalInput}] ${label}`);
    console.log(`       ${res.consensus.err ? String(res.consensus.err).slice(0, 96) : 'no error'} · op ${res.standard.op}${where}`);
    return pass;
};

const R = [];
console.log('--- controls: real pool transitions (5-input shape) ---');
R.push(run('fixture 0 transfer (pv=0)', true, { proofIdx: 0 }));
R.push(run('fixture 1 shield (pv=250)', true, { proofIdx: 1 }));
R.push(run('fixture 2 unshield (pv=400)', true, { proofIdx: 2 }));
R.push(run('fixture 4 DEPOSIT (onboarding, pv=125)', true, { proofIdx: 4 }));

console.log('\n--- the walk inputs themselves (their own script evaluations) ---');
R.push(run('walkA honest (input 3 evaluates the walk)', true, { proofIdx: 0, evalInput: 3 }));
R.push(run('walkB honest (input 4 evaluates the walk)', true, { proofIdx: 0, evalInput: 4 }));

console.log('\n--- rejections: carrier tampering ---');
R.push(run('carrier newRoot changed (actionHash mismatch)', false, { proofIdx: 0, mutate: { newRoot: 0x1234n } }));
R.push(run('carrier pv changed', false, { proofIdx: 0, mutate: { pv: 1n } }));
R.push(run('carrier sign flipped', false, { proofIdx: 0, mutate: { sign: 1n } }));
R.push(run('carrier nf0 changed', false, { proofIdx: 0, mutate: { nf0: 7n } }));
R.push(run('carrier cm2 changed', false, { proofIdx: 0, mutate: { cm2: 0x1234n } }));

console.log('\n--- rejections: state input + out1 ---');
R.push(run('state input wrong category', false, { proofIdx: 0, txMutate: { sourceCategory: new Uint8Array(32) } }));
R.push(run('state input wrong stored root', false, { proofIdx: 0, txMutate: { stateCommit: new Uint8Array(64) } }));
R.push(run('out1 wrong category', false, { proofIdx: 0, txMutate: { out1Category: new Uint8Array(32) } }));
R.push(run('out1 wrong commitment (forged newRoot)', false, { proofIdx: 0, txMutate: { newCommit: new Uint8Array(64) } }));
R.push(run('out1 wrong amount (balance not conserved)', false, { proofIdx: 0, txMutate: { out1Amount: 1001n } }));

console.log('\n--- rejections: payout rules ---');
R.push(run('unshield missing its payout', false, { proofIdx: 2, txMutate: { payout: false } }));
R.push(run('shield minting a payout', false, { proofIdx: 0, txMutate: { payout: true } }));

console.log('\n--- rejections: deposit tagging (hook 4c/4g) ---');
R.push(run('fuel in0 tokenless', false, { proofIdx: 0, txMutate: { fuelNaked0: true } }));
R.push(run('fuel in1 tokenless', false, { proofIdx: 0, txMutate: { fuelNaked1: true } }));
R.push(run('fuel tags wrong (foreign nullifier-hash)', false, { proofIdx: 0, txMutate: { fuelTag0: new Uint8Array(sha(Buffer.alloc(64))), fuelTag1: new Uint8Array(sha(Buffer.alloc(64))) } }));
R.push(run('THEFT replay: fuel locked for ANOTHER action', false, { proofIdx: 0, txMutate: { fuelTag0: foreignTag(1), fuelTag1: foreignTag(1) } }));
R.push(run('fuel tags asymmetric', false, { proofIdx: 0, txMutate: { fuelTag1: foreignTag(1) } }));

console.log('\n--- rejections: the v3 nullifier-set classes ---');
R.push(run('REPLAY: nf0 already in the null set (walkA must reject)', false, { proofIdx: 0, evalInput: 3, replayNf0: true }));
R.push(run('state nullSetRoot half tampered (walkA must reject)', false, { proofIdx: 0, evalInput: 3, tamperStateNull: true }));
R.push(run('new commitment finalNullRoot half tampered (walkB must reject; role 2 accepts by design)', false, { proofIdx: 0, evalInput: 4, tamperNewNull: true }));
R.push(run('shape: input 4 dropped (4-input tx — GRAPH TXINPUTCOUNT pin)', false, { proofIdx: 0, dropWalkB: true }));
R.push(run('shape: input 3 locked to walkB (4w hash pin)', false, { proofIdx: 0, lock3: WALK_LOCKS[1] }));
R.push(run('shape: input 4 locked to junk (4w hash pin)', false, { proofIdx: 0, lock4: Uint8Array.from([0x51]) }));

console.log(`\n${R.filter(Boolean).length}/${R.length} match expectation`);
process.exit(R.every(Boolean) ? 0 : 1);
