// pool-test.mjs — acceptance test for the pool hook, on the BCH-2026 VM.
// The stock harness (vm.mjs programOf) gives every source output NO token, so a pool-aware
// program is built here instead. Only input 2 is evaluated: role 2 is the role that runs the hook.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { VMS, p2sh32 } from './vm.mjs';
import { decodeAuthenticationInstructions, encodeAuthenticationInstruction } from '@bitauth/libauth';
import { buildProgram, setCovenant } from './script.mjs';
import { transactionFor } from './transaction.mjs';
import { FIXTURES } from '../sound-si-gls/math.mjs';
import { covenantHook, covenantParams, carrierOf, carrierOutput, actionHashOf, CARRIER_LEN } from './pool-hook.mjs';

/* libauth's Output.token.category is in DISPLAY order; OP_UTXOTOKENCATEGORY returns the
   ON-CHAIN (reversed) order followed by the capability byte. The hook's ctor arg is the
   reversed form; the source outputs must carry the display form. */
const CATEGORY_DISPLAY = Buffer.from('2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544', 'hex');
const CATEGORY_ONCHAIN = Buffer.from(CATEGORY_DISPLAY).reverse();
setCovenant(covenantHook(covenantParams({ categoryOnChain: CATEGORY_ONCHAIN.toString('hex') })));
const prog = buildProgram();
const lock = p2sh32(prog.R);
const LOCKS = [lock, lock, lock];

/* our real proofs carry the covenant args (LE VM-number hex) that hash to their own n1 */
const proofs = JSON.parse(readFileSync('/home/apecs/cov/our-proofs.json', 'utf8'));
const sha = (b) => createHash('sha256').update(b).digest();
const leToBig = (hex) => BigInt('0x' + Buffer.from(hex, 'hex').reverse().toString('hex') || '0');
const be32 = (v) => { const b = Buffer.alloc(32); let x = BigInt(v); for (let i = 31; i >= 0 && x > 0n; i--) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; };
/* the pool stores its merkle root as the 32-byte LE VM-number form (asset-pool.cash: "stored as the
   32-byte LE VM-number byte form"), while the actionHash preimage uses big-endian fields. */
const to32LE = (v) => Buffer.from(be32(v)).reverse();
const catDisplay = Buffer.from(CATEGORY_ONCHAIN).reverse().toString('hex');

const scenarioOf = (p) => {
    const c = p.covenant;
    const s = {
        nf0: leToBig(c.nf0), nf1: leToBig(c.nf1), cm0: leToBig(c.cm0), cm1: leToBig(c.cm1),
        newRoot: leToBig(c.newMerkleRoot), pv: BigInt(c.publicValueAbs), sign: BigInt(c.isUnshield),
    };
    const n0 = BigInt(p.publicSignals[0]);
    assert.equal(actionHashOf({ ...s, categoryDisplay: catDisplay }).toString(), BigInt(p.publicSignals[1]).toString(), 'actionHash mismatch — fixture is not self-consistent');
    return { s, n0 };
};

const run = (label, expect, { proofIdx, mutate = {}, txMutate = {} }) => {
    const { s, n0 } = scenarioOf(proofs[proofIdx]);
    const sc = { ...s, ...mutate };
    const balance = 1000n;
    const oldNull = Buffer.alloc(32);
    /*  the deployed covenant folds the RAW covenant args: sha256(old ‖ nf0 ‖ nf1) with the
        32-byte LE VM-number forms (asset-pool.cash line 148) — NOT the BE preimage forms. */
    const carr = carrierOf(sc);
    const newNull = sha(Buffer.concat([oldNull, carr.subarray(0, 32), carr.subarray(32, 64)]));
    const newBal = balance + sc.pv - 2n * sc.sign * sc.pv;
    const stateCommit = Buffer.concat([to32LE(n0), oldNull]);
    const newCommit = Buffer.concat([to32LE(sc.newRoot), newNull]);
    /*  tx-level tamper knobs — every field a plain Uint8Array (Node Buffers alias via slice()
        and the VM's REVERSEBYTES writes through the views). */
    const tx = {
        sourceCategory: new Uint8Array(CATEGORY_DISPLAY),
        stateCommit: new Uint8Array(stateCommit),
        out1Category: new Uint8Array(CATEGORY_DISPLAY),
        newCommit: new Uint8Array(newCommit),
        out1Amount: newBal,
        payout: sc.sign === 1n,
        ...txMutate,
    };

    const T = transactionFor(FIXTURES.fixtures[proofIdx], prog);
    const inputs = T.unlockings.map((u, n) => ({ outpointIndex: n, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array(u) }));
    const sourceOutputs = [
        { lockingBytecode: lock, valueSatoshis: 1000n },
        { lockingBytecode: lock, valueSatoshis: 1000n },
        { lockingBytecode: lock, valueSatoshis: 1000n, token: { category: tx.sourceCategory, amount: balance, nft: { capability: 'mutable', commitment: tx.stateCommit } } },
    ];
    const outputs = [
        { lockingBytecode: new Uint8Array(carrierOutput(carrierOf(sc))), valueSatoshis: 0n },
        { lockingBytecode: lock, valueSatoshis: 1000n, token: { category: tx.out1Category, amount: tx.out1Amount, nft: { capability: 'mutable', commitment: tx.newCommit } } },
    ];
    if (tx.payout) outputs.push({ lockingBytecode: Buffer.from([0x76, 0xa9, 0x14, ...Buffer.alloc(20), 0x88, 0xac]), valueSatoshis: 546n, token: { category: new Uint8Array(CATEGORY_DISPLAY)  /* plain Uint8Array: Buffer.slice() returns a VIEW and REVERSEBYTES writes through it */, amount: sc.pv } });

    const res = {};
    for (const mode of ['consensus', 'standard']) {
        const st = VMS[mode].evaluate({ inputIndex: 2, sourceOutputs, transaction: { version: 2, locktime: 0, inputs, outputs } });
        const top = st.stack[st.stack.length - 1];
        res[mode] = { ok: st.error === undefined && st.stack.length === 1 && top && top.length === 1 && top[0] === 1, err: st.error, op: st.metrics?.operationCost ?? 0 };
    }
    const acc = res.consensus.ok && res.standard.ok;
    let where = '';
    if (!acc) {
        const d = decodeAuthenticationInstructions(prog.funcCodes.role2); const offs = []; let x = 0;
        for (const t of d) { offs.push(x); x += encodeAuthenticationInstruction(t).length; }
        const trace = VMS.consensus.debug({ inputIndex: 2, sourceOutputs, transaction: { version: 2, locktime: 0, inputs, outputs } });
        const bad = trace.find((s) => s.error);
        /*  libauth's debug ip is a BYTE OFFSET into the executing bytecode — not an instruction
            index. Map it to the containing instruction, then show that window. */
        const off = bad ? bad.ip : Infinity;
        let di = 0; while (di + 1 < offs.length && offs[di + 1] <= off) di++;
        const mk = prog.marks.filter((m) => m.role === 2).sort((a, b) => a.roff - b.roff).filter((m) => m.roff <= off);
        const instr = bad ? d.slice(Math.max(0, di - 4), di + 2).map((t) => (t.data ? `PUSH(${Buffer.from(t.data).toString('hex').slice(0, 12)})` : `0x${t.opcode.toString(16)}`)).join(' ') : '';
        const stk = (bad?.stack ?? []).slice(-8).map((x) => { const b = Buffer.from(x); return b.length > 8 ? `[${b.length}]${b.toString('hex').slice(0, 10)}` : `${b.toString('hex')}`; }).reverse().join(' | ');
        where = ` · at ${mk.at(-1)?.name ?? '?'} (ip ${bad?.ip}) · instr: ${instr}\n       runtime stack (top first): ${stk}`;
    }
    const pass = acc === expect;
    console.log(`${pass ? 'ok  ' : 'FAIL'} ${acc ? 'ACCEPT' : 'REJECT'} (want ${expect ? 'ACCEPT' : 'REJECT'})  ${label}`);
    console.log(`       ${res.consensus.err ? String(res.consensus.err).slice(0, 90) : 'no error'} · op ${res.standard.op}${where}`);
    return pass;
};

const R = [];
console.log('--- control: a real pool transition ---');
for (const i of [0, 1]) R.push(run(`fixture ${i} (pv=${proofs[i].covenant.publicValueAbs}, sign=${proofs[i].covenant.isUnshield})`, true, { proofIdx: i }));
R.push(run('fixture 2 (unshield, pv=400)', true, { proofIdx: 2 }));

console.log('\n--- rejections: carrier tampering ---');
R.push(run('carrier newRoot changed (actionHash no longer matches n1)', false, { proofIdx: 0, mutate: { newRoot: 0x1234n } }));
R.push(run('carrier pv changed', false, { proofIdx: 0, mutate: { pv: 1n } }));
R.push(run('carrier sign flipped', false, { proofIdx: 0, mutate: { sign: 1n } }));
R.push(run('carrier nf0 changed', false, { proofIdx: 0, mutate: { nf0: 7n } }));

console.log('\n--- rejections: state input tampering ---');
R.push(run('state input wrong category', false, { proofIdx: 0, txMutate: { sourceCategory: new Uint8Array(32) } }));
R.push(run('state input wrong stored root', false, { proofIdx: 0, txMutate: { stateCommit: new Uint8Array(64) } }));

console.log('\n--- rejections: out1 tampering ---');
R.push(run('out1 wrong category', false, { proofIdx: 0, txMutate: { out1Category: new Uint8Array(32) } }));
R.push(run('out1 wrong commitment (forged newRoot)', false, { proofIdx: 0, txMutate: { newCommit: new Uint8Array(64) } }));
R.push(run('out1 wrong amount (balance not conserved)', false, { proofIdx: 0, txMutate: { out1Amount: 1001n } }));

console.log('\n--- rejections: payout rules ---');
R.push(run('unshield missing its payout', false, { proofIdx: 2, txMutate: { payout: false } }));
R.push(run('shield minting a payout', false, { proofIdx: 0, txMutate: { payout: true } }));

console.log(`\n${R.filter(Boolean).length}/${R.length} match expectation`);
process.exit(R.every(Boolean) ? 0 : 1);
