// probe-np01-extra-output.mjs — the NP01 measurement (Nito ask, VENDING-NITO-REQUEST-2026-11-27 §4.1):
// does the v4h program tolerate an EXTRA chain output carrying the encrypted-note packet
// (~174-B OP_RETURN-class) on a TRANSFER action? This is pool-test-v4h.mjs with ONE line
// changed — the extraOut scenario output is the LITERAL packet shape (a 176-B OP_RETURN,
// 0 sats) instead of a value-carrying output. Answer, MEASURED 2026-11-28 on the BCH-2026
// VM under the deployed mainnet category 324b1dbf… + the three-contribution fixtures
// (BN_VK_FIXTURES=our-v3-user3.fixtures.json): REJECT — "transfer appends an extra output
// (TXOUTPUTCOUNT == 3 + sign)" fails at r2:p4c (ip 321), identical to the value-carrying
// variant; the full suite still 42/42. The count pin is type-independent: an OP_RETURN
// output is still a TXOUTPUT. CONSEQUENCE: the packet CANNOT ride the chain on any v4h
// action; off-chain delivery (the Nostr mailbox) is the only note-delivery path.
//
// pool-test-v4h.mjs — the C-architecture acceptance suite: the holdings-mode hook with
// the nullifier-SMT walk inputs AND the asset-side holdings/deposit pair, on the
// BCH-2026 VM, under the pool4 MPC VK.
//
// Composition (identical to pool-build-v4h.mjs): commit96 walks + POOL_NULLDATA_HASHES +
// POOL_HOLDINGS=1 + covenantHook(params, 3, { walkAHash, walkBHash, holdings: {} }) +
// buildHoldingsCovenant (H). The action shape is SEVEN inputs / 3-4 outputs:
//   [fuel0-tagged, fuel1-tagged, state-NFT (96-B commitment, NFT-only), walkA, walkB,
//    holdings (Y-bare FT at H), deposit slot (Y-bare FT == pv on deposits; tokenless
//    otherwise)] → [carrier, state (96-B), holdings out2 (Y-bare == newBal), payout out3].
//
// Classes beyond the v3.1 suite's 29:
//   - the balance chain: the state commitment's THIRD field (96-B) is the authenticated
//     balance — tamper it, tamper out1's third field, put FT back on the state;
//   - out2 holdings: wrong locking / wrong category (pool cat instead of the ASSET) /
//     wrong amount;
//   - the payout at out3 (moved from out2), still in the ASSET's bare category;
//   - TXOUTPUTCOUNT == 3 + sign (the C output shape);
//   - the shape pin: inputs 5/6 pinned to each other (the graph's byte-compare);
//   - the H covenant's own mini-suite (evalInput 5/6): honest ACCEPT; TXINPUTCOUNT tamper;
//     program/walk locking substitutions; the sibling-mismatch class.
//
// Documented NON-classes (conservation-domain — the per-input script eval cannot see
// global token conservation; the real network enforces it, and the op tool asserts it
// off-chain before broadcast — same treatment as the v3.1 suite):
//   - a deposit whose in6 tokenless (out2 would need FT from nowhere);
//   - an in5 carrying MORE than the committed balance (the excess cannot vanish).
// The hook accepts both BY DESIGN (its checks are conservation-blind); the chain kills
// them at the consensus token rules. The unforgeability itself is check 5 + 9h: the
// balance comes from the state commitment, so an action cannot move a holdings line it
// did not carry in full.
//
// Usage (VM, from the bench dir):
//   BN_VK_FIXTURES=/home/apecs/cov/our-v3-mpc.fixtures.json node pool-test-v4h.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { VMS, p2sh32 } from './vm.mjs';
import { decodeAuthenticationInstructions, encodeAuthenticationInstruction } from '@bitauth/libauth';
import { pushData } from './asm.mjs';
import { buildProgram, setCovenant } from './script.mjs';
import { transactionFor } from './transaction.mjs';
import { FIXTURES } from '../sound-si-gls/math.mjs';
import { covenantHook, covenantParams, carrierOf, carrierOutput, actionHashOf } from './pool-hook.mjs';
import { buildWalkScripts } from './walk-scripts.mjs';
import { buildHoldingsCovenant } from './holdings-covenant.mjs';
import { walkV3, walkWitnesses } from './pool-tx-v3.mjs';

const sha = (b) => createHash('sha256').update(b).digest();
const POOL_CATEGORY = process.env.POOL_CATEGORY ?? 'aa11aa22aa33aa44aa55aa66aa77aa88aa99aa00bb11bb22bb33bb44bb55bb66';
const ASSET_CATEGORY = process.env.ASSET_CATEGORY ?? '2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544';
const CATEGORY_DISPLAY = Buffer.from(POOL_CATEGORY, 'hex');
const ASSET_DISPLAY = Buffer.from(ASSET_CATEGORY, 'hex');
const CATEGORY_ONCHAIN = Buffer.from(CATEGORY_DISPLAY).reverse().toString('hex');
const ASSET_ONCHAIN = Buffer.from(ASSET_DISPLAY).reverse().toString('hex');

/* the C program: commit96 walks + the graph pin (7-input, 5==6 byte-pin) + the holdings hook */
const { walkA, walkB, sizes } = buildWalkScripts(CATEGORY_ONCHAIN, { commit96: true });
const { lockings: WALK_LOCKS, hashes: [walkAHash, walkBHash] } = walkV3(walkA, walkB);
process.env.POOL_NULLDATA_HASHES = JSON.stringify([walkAHash.toString('hex'), walkBHash.toString('hex')]);
process.env.POOL_HOLDINGS = '1';
setCovenant(covenantHook(covenantParams({ categoryOnChain: CATEGORY_ONCHAIN, assetCategoryOnChain: ASSET_ONCHAIN }), 3, { walkAHash, walkBHash, holdings: {} }));
const prog = buildProgram();
const lock = p2sh32(prog.R);
const HC = buildHoldingsCovenant({ progLockingHashHex: sha(lock).toString('hex'), walkAHashHex: walkAHash.toString('hex'), walkBHashHex: walkBHash.toString('hex') });
console.log(`v4h program built · ${prog.code?.length} B · walks A ${sizes.walkA} B / B ${sizes.walkB} B (commit96) · H ${HC.redeemBytes} B`);

const proofs = JSON.parse(readFileSync(process.env.PROOFS ?? '/home/apecs/cov/our-v3-mpc-proofs.json', 'utf8'));
const leToBig = (hex) => BigInt('0x' + Buffer.from(hex, 'hex').reverse().toString('hex') || '0');
const be32 = (v) => { const b = Buffer.alloc(32); let x = BigInt(v); for (let i = 31; i >= 0 && x > 0n; i--) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; };
const to32LE = (v) => Buffer.from(be32(v)).reverse();
const catDisplay = POOL_CATEGORY;      /* already display-order hex — Buffer.from(str) without 'hex' would UTF-8 it */
const assetDisplay = ASSET_CATEGORY; /* ditto */

const scenarioOf = (p) => {
    const c = p.covenant;
    const s = {
        nf0: leToBig(c.nf0), nf1: leToBig(c.nf1), cm0: leToBig(c.cm0), cm1: leToBig(c.cm1), cm2: leToBig(c.cm2),
        newRoot: leToBig(c.newMerkleRoot), pv: BigInt(c.publicValueAbs), sign: BigInt(c.isUnshield),
    };
    const n0 = BigInt(p.publicSignals[0]);
    /*  C architecture: the actionHash's category field is the ASSET (the circuit's
        witness — the fixtures/sweeps were minted with 2469acc5… as that witness, which
        is exactly right here: the asset IS PUSD). The POOL category never enters the
        circuit — only the on-chain hook/walks pin it. */
    assert.equal(actionHashOf({ ...s, categoryDisplay: assetDisplay }, 3).toString(), BigInt(p.publicSignals[1]).toString(), 'actionHash mismatch — fixture is not self-consistent');
    return { s, n0 };
};
const foreignTag = (idx) => new Uint8Array(sha(carrierOf(scenarioOf(proofs[idx]).s, 3).subarray(0, 64)));

/* run(label, expect, {proofIdx, mutate, txMutate, evalInput, dropInput, lock3, lock4,
   replayNf0, tamperStateNull, tamperNewNull, stateBal, out1Bal, out2Locking, out2Category,
   out2Amount, payoutMissing, payoutCategory, extraOut})
   — the C knobs:
     stateBal: plant the state commitment's THIRD field (the committed balance) — the honest
       value is the funded balance; a mismatch must die at 8/9h (the unforgeable line);
     out1Bal: plant out1's third field — must equal to32LE(newBal) (check 9);
     out2Locking/out2Category/out2Amount: the holdings output's pins (check 9h);
     payoutMissing: drop out3 on an unshield; payoutCategory: the payout in the WRONG
       category; extraOut: append a 4th output to a transfer (check 8b: 3 + sign);
     dropInput: omit input 6 (the 6-input shape — the GRAPH pin);
     lock0: substitute input 0's source locking (the H program-hash pin class);
     h6Locking: substitute input 6's locking — the graph's 5==6 byte-pin. */
const run = (label, expect, { proofIdx, mutate = {}, txMutate = {}, evalInput = 2, dropInput = false, lock3 = null, lock4 = null, lock0 = null, replayNf0 = false, tamperStateNull = false, tamperNewNull = false, stateBal = null, out1Bal = null, out2Locking = null, out2Category = null, out2Amount = null, payoutMissing = false, payoutCategory = null, extraOut = false, h6Locking = null }) => {
    const { s, n0 } = scenarioOf(proofs[proofIdx]);
    const sc = { ...s, ...mutate };
    const balance = proofIdx === 4 ? 0n : 1000n;                    /* fixture 4 = the genesis deposit */
    const fx = proofs[proofIdx].nullSet;
    const nullSetRoot = Buffer.from(fx.nullSetRootBefore, 'hex');
    const midRoot = Buffer.from(fx.midRoot, 'hex');
    const finalNullRoot = Buffer.from(fx.finalNullRoot, 'hex');
    const storedNull = replayNf0 ? midRoot : (tamperStateNull ? Buffer.from([...nullSetRoot.slice(0, 3), nullSetRoot[3] ^ 0x20, ...nullSetRoot.slice(4)]) : nullSetRoot);
    const newBal = balance + sc.pv - 2n * sc.sign * sc.pv;
    const carr = carrierOf(sc, 3);
    const tag = sha(carr.subarray(0, 64));
    const stateCommit = Buffer.concat([to32LE(n0), storedNull, to32LE(stateBal ?? balance)]);
    const newCommitTail = tamperNewNull ? Buffer.from([...finalNullRoot.slice(0, 2), finalNullRoot[2] ^ 0x40, ...finalNullRoot.slice(3)]) : finalNullRoot;
    const newCommit = Buffer.concat([to32LE(sc.newRoot), newCommitTail, to32LE(out1Bal ?? newBal)]);
    const assetCat = new Uint8Array(ASSET_DISPLAY);
    const poolCat = new Uint8Array(CATEGORY_DISPLAY);
    const tx = {
        sourceCategory: poolCat,
        stateCommit: new Uint8Array(stateCommit),
        out1Category: poolCat,
        newCommit: new Uint8Array(newCommit),
        out1Amount: 0n,                                              /* the state is NFT-only */
        out2Locking: new Uint8Array(out2Locking ?? HC.locking),
        out2Category: out2Category ?? assetCat,
        out2Amount: out2Amount ?? newBal,
        payout: sc.sign === 1n && !payoutMissing,
        payoutCategory: new Uint8Array(payoutCategory ?? ASSET_DISPLAY),
        fuelCat0: poolCat, fuelCat1: poolCat,
        fuelTag0: new Uint8Array(tag), fuelTag1: new Uint8Array(tag),
        fuelNaked0: false, fuelNaked1: false,
        extraOut,
        ...txMutate,
    };

    const T = transactionFor(FIXTURES.fixtures[proofIdx], prog);
    const inputs = T.unlockings.map((u, n) => ({ outpointIndex: n, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array(u) }));
    const wW = walkWitnesses(fx, walkA, walkB);
    inputs.push({ outpointIndex: 0, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array(wW[0]) });
    inputs.push({ outpointIndex: 1, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array(wW[1]) });
    /* in5 = the holdings (Y-bare balance; tokenless at genesis), in6 = the deposit slot —
       both spend by the H redeem push alone (witness-free) */
    const mkH = () => ({ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0xfffffffe, unlockingBytecode: Uint8Array.from(pushData(HC.script)) });
    inputs.push(mkH());
    if (!dropInput) inputs.push(mkH());

    const fuelOut = (n) => (tx['fuelNaked' + n]
        ? { lockingBytecode: lock, valueSatoshis: 1000n }
        : { lockingBytecode: n === 0 && lock0 ? new Uint8Array(lock0) : lock, valueSatoshis: 1000n, token: { category: tx['fuelCat' + n], amount: 0n, nft: { capability: 'mutable', commitment: tx['fuelTag' + n] } } });
    const in5 = balance > 0n
        ? { lockingBytecode: new Uint8Array(HC.locking), valueSatoshis: 600n, token: { category: assetCat, amount: balance } }
        : { lockingBytecode: new Uint8Array(HC.locking), valueSatoshis: 600n };
    const in6Honest = (sc.sign === 0n && sc.pv > 0n)
        ? { lockingBytecode: new Uint8Array(HC.locking), valueSatoshis: 600n, token: { category: assetCat, amount: sc.pv } }
        : { lockingBytecode: new Uint8Array(HC.locking), valueSatoshis: 600n };
    const in6 = h6Locking ? { ...in6Honest, lockingBytecode: new Uint8Array(h6Locking) } : in6Honest;
    const sourceOutputs = [
        fuelOut(0), fuelOut(1),
        { lockingBytecode: lock, valueSatoshis: 1000n, token: { category: tx.sourceCategory, amount: 0n, nft: { capability: 'mutable', commitment: tx.stateCommit } } },
        { lockingBytecode: new Uint8Array(lock3 ?? WALK_LOCKS[0]), valueSatoshis: 300n },
        { lockingBytecode: new Uint8Array(lock4 ?? WALK_LOCKS[1]), valueSatoshis: 300n },
        in5,
        ...(dropInput ? [] : [in6]),
    ];
    const outputs = [
        { lockingBytecode: new Uint8Array(carrierOutput(carrierOf(sc, 3))), valueSatoshis: 0n },
        { lockingBytecode: lock, valueSatoshis: 1000n, token: { category: tx.out1Category, amount: tx.out1Amount, nft: { capability: 'mutable', commitment: tx.newCommit } } },
        { lockingBytecode: new Uint8Array(tx.out2Locking), valueSatoshis: 1000n, token: { category: tx.out2Category, amount: tx.out2Amount } },
    ];
    if (tx.payout) outputs.push({ lockingBytecode: Buffer.from([0x76, 0xa9, 0x14, ...Buffer.alloc(20), 0x88, 0xac]), valueSatoshis: 546n, token: { category: tx.payoutCategory, amount: sc.pv } });
    if (tx.extraOut) outputs.push({ lockingBytecode: Buffer.concat([Buffer.from([0x6a, 0x4c, 0xad]), Buffer.alloc(173)]), valueSatoshis: 0n }); /* NP01 probe: a 176-B OP_RETURN-class 0-value output (the encrypted-note packet shape) */

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
console.log('--- controls: real pool transitions (7-input shape) ---');
R.push(run('fixture 0 transfer (pv=0)', true, { proofIdx: 0 }));
R.push(run('fixture 1 shield (pv=250, deposit slot)', true, { proofIdx: 1 }));
R.push(run('fixture 2 unshield (pv=400, payout out3)', true, { proofIdx: 2 }));
R.push(run('fixture 4 DEPOSIT (genesis, pv=125, in5 tokenless)', true, { proofIdx: 4 }));

console.log('\n--- the walk + H inputs themselves ---');
R.push(run('walkA honest (input 3)', true, { proofIdx: 0, evalInput: 3 }));
R.push(run('walkB honest (input 4)', true, { proofIdx: 0, evalInput: 4 }));
R.push(run('H honest at input 5', true, { proofIdx: 0, evalInput: 5 }));
R.push(run('H honest at input 6', true, { proofIdx: 0, evalInput: 6 }));

console.log('\n--- rejections: carrier tampering ---');
R.push(run('carrier newRoot changed', false, { proofIdx: 0, mutate: { newRoot: 0x1234n } }));
R.push(run('carrier pv changed', false, { proofIdx: 0, mutate: { pv: 1n } }));
R.push(run('carrier sign flipped', false, { proofIdx: 0, mutate: { sign: 1n } }));
R.push(run('carrier nf0 changed', false, { proofIdx: 0, mutate: { nf0: 7n } }));
R.push(run('carrier cm2 changed', false, { proofIdx: 0, mutate: { cm2: 0x1234n } }));

console.log('\n--- rejections: the state input + out1 (96-B commitment) ---');
R.push(run('state input wrong category', false, { proofIdx: 0, txMutate: { sourceCategory: new Uint8Array(32) } }));
R.push(run('state input wrong stored root', false, { proofIdx: 0, txMutate: { stateCommit: new Uint8Array(96) } }));
R.push(run('state commitment BALANCE field tampered (the unforgeable line)', false, { proofIdx: 0, stateBal: 4000n }));
R.push(run('out1 wrong category', false, { proofIdx: 0, txMutate: { out1Category: new Uint8Array(32) } }));
R.push(run('out1 wrong commitment (forged newRoot)', false, { proofIdx: 0, txMutate: { newCommit: new Uint8Array(96) } }));
R.push(run("out1's BALANCE field tampered (must equal to32LE(newBal))", false, { proofIdx: 0, out1Bal: 1001n }));
R.push(run('out1 carries FT (state must be NFT-only)', false, { proofIdx: 0, txMutate: { out1Amount: 1000n } }));

console.log('\n--- rejections: the holdings output (check 9h) ---');
R.push(run('out2 wrong locking (the program instead of H)', false, { proofIdx: 0, out2Locking: lock }));
R.push(run('out2 wrong category (pool cat instead of the ASSET)', false, { proofIdx: 0, out2Category: new Uint8Array(CATEGORY_DISPLAY) }));
R.push(run('out2 wrong amount (balance not conserved)', false, { proofIdx: 0, out2Amount: 1001n }));

console.log('\n--- rejections: payout rules (out3) ---');
R.push(run('unshield missing its payout', false, { proofIdx: 2, payoutMissing: true }));
R.push(run('unshield payout in the WRONG category', false, { proofIdx: 2, payoutCategory: new Uint8Array(CATEGORY_DISPLAY) }));
R.push(run('transfer mints a payout', false, { proofIdx: 0, txMutate: { payout: true } }));
R.push(run('transfer appends an extra output (TXOUTPUTCOUNT == 3 + sign)', false, { proofIdx: 0, extraOut: true }));

console.log('\n--- rejections: deposit tagging (hook 4c/4g) ---');
R.push(run('fuel in0 tokenless', false, { proofIdx: 0, txMutate: { fuelNaked0: true } }));
R.push(run('fuel in1 tokenless', false, { proofIdx: 0, txMutate: { fuelNaked1: true } }));
R.push(run('fuel tags wrong', false, { proofIdx: 0, txMutate: { fuelTag0: new Uint8Array(sha(Buffer.alloc(64))), fuelTag1: new Uint8Array(sha(Buffer.alloc(64))) } }));
R.push(run('THEFT replay: fuel locked for ANOTHER action', false, { proofIdx: 0, txMutate: { fuelTag0: foreignTag(1), fuelTag1: foreignTag(1) } }));
R.push(run('fuel tags asymmetric', false, { proofIdx: 0, txMutate: { fuelTag1: foreignTag(1) } }));

console.log('\n--- rejections: the v3 nullifier-set classes ---');
R.push(run('REPLAY: nf0 already in the null set (walkA rejects)', false, { proofIdx: 0, evalInput: 3, replayNf0: true }));
R.push(run('state nullSetRoot half tampered (walkA rejects)', false, { proofIdx: 0, evalInput: 3, tamperStateNull: true }));
R.push(run('new commitment finalNullRoot half tampered (walkB rejects; role 2 accepts by design)', false, { proofIdx: 0, evalInput: 4, tamperNewNull: true }));

console.log('\n--- rejections: shape pins ---');
R.push(run('input 6 dropped (6-input tx — GRAPH pin)', false, { proofIdx: 0, dropInput: true }));
R.push(run('input 3 locked to walkB (4w hash pin)', false, { proofIdx: 0, lock3: WALK_LOCKS[1] }));
R.push(run('input 4 locked to junk (4w hash pin)', false, { proofIdx: 0, lock4: Uint8Array.from([0x51]) }));
R.push(run('input 6 locked away from H (GRAPH 5==6 byte-pin)', false, { proofIdx: 0, h6Locking: lock }));

console.log('\n--- the H covenant mini-suite (its own theft classes) ---');
R.push(run('H at input 5 of a 6-input tx (TXINPUTCOUNT pin)', false, { proofIdx: 0, evalInput: 5, dropInput: true }));
R.push(run('H with input 0 locked to junk (program-hash pin)', false, { proofIdx: 0, evalInput: 5, lock0: Uint8Array.from([0x51]) }));
R.push(run('H with the sibling locked away (self byte-pin)', false, { proofIdx: 0, evalInput: 5, h6Locking: lock }));

console.log(`\n${R.filter(Boolean).length}/${R.length} match expectation`);
process.exit(R.every(Boolean) ? 0 : 1);
