// walk-test.mjs — the walk-script acceptance battery (the v3 nullifier SMT, script side).
//
// Builds walkA/walkB (walk-scripts.mjs), assembles a 5-input pool-shaped test
// transaction, and evaluates inputs 3/4 on the real BCH-2026 VM (consensus AND
// standard) — the same evidence bar as the spike's probe-walk-cost.mjs, now in
// the production loop form:
//
//   honest accepts:
//     walkA — the zeros-fold == the state's nullSetRoot; the marker-fold == the
//              declared midRoot (the witness item).
//     walkB — the zeros-fold == midRoot (read back from walkA's unlocking);
//              the marker-fold == the new state commitment's second half.
//   rejections:
//     a tampered sibling (walkA + walkB), a wrong declared midRoot, a REPLAYED
//     nullifier (already in the set — the zeros-fold must miss), a tampered
//     carrier key slice, a wrong-length sibling blob, and a swapped walk
//     locking (walkA's witness under walkB's script and vice versa).
//
// Every byte passed to the VM is a PLAIN Uint8Array (the Buffer-aliasing rule).

import { buildWalkScripts, walkAWitness, walkBWitness, smtWalk, smtBitOf, SPENT_MARKER, EMPTY_NULL_ROOT, SIB_BLOB_LEN } from './walk-scripts.mjs';
import { VMS, budgetOf } from './vm.mjs';
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';

const sha = (b) => createHash('sha256').update(Buffer.from(b)).digest();
const NULL_D = 254;

/* ── a tiny SMT mirror (the spike's gen-spike-inputs recursion, SHA256 form) ── */
const szh = [Buffer.alloc(32)];
for (let i = 1; i <= NULL_D; i++) szh.push(sha(Buffer.concat([szh[i - 1], szh[i - 1]])));
function makeSmt(keysHex) {
    const S = keysHex.map((h) => Buffer.from(h, 'hex'));
    const memo = new Map();
    const agrees = (k, mk, from) => { for (let b = from; b < NULL_D; b++) if (smtBitOf(k, b) !== smtBitOf(mk, b)) return false; return true; };
    function subtree(mk, h) {
        const id = mk.toString('hex') + '|' + h;
        if (memo.has(id)) return memo.get(id);
        let any = false;
        for (const k of S) { let ok = true; for (let b = h; b < NULL_D; b++) if (smtBitOf(k, b) !== smtBitOf(mk, b)) { ok = false; break; } if (ok) { any = true; break; } }
        let r;
        if (!any) r = szh[h];
        else if (h === 0) r = SPENT_MARKER;
        else {
            const mk0 = Buffer.from(mk); mk0[(h - 1) >> 3] &= ~(1 << ((h - 1) & 7)) & 0xff;
            const mk1 = Buffer.from(mk); mk1[(h - 1) >> 3] |= 1 << ((h - 1) & 7);
            r = sha(Buffer.concat([subtree(mk0, h - 1), subtree(mk1, h - 1)]));
        }
        memo.set(id, r);
        return r;
    }
    return {
        root: () => subtree(Buffer.alloc(32), NULL_D),
        siblingsFor: (k) => Array.from({ length: NULL_D }, (_, i) => {
            const mk = Buffer.from(k); mk[i >> 3] ^= 1 << (i & 7);
            return subtree(mk, i);
        }),
    };
}

/* ── the scenario: a fresh category, three already-spent nullifiers, two fresh ones ── */
const CATEGORY_DISPLAY = Buffer.from(createHash('sha256').update('walk-test-category').digest());
const CATEGORY_ONCHAIN = Buffer.from(CATEGORY_DISPLAY).reverse();
const categoryOnChainHex = CATEGORY_ONCHAIN.toString('hex');

const spentKeys = [sha('spent-0'), sha('spent-1'), sha('spent-2')];
const nf0 = sha('nf0-fresh'), nf1 = sha('nf1-fresh');         // the carrier slices (32-B, LE-form stand-ins)
const smt0 = makeSmt(spentKeys.map((k) => k.toString('hex')));
const nullSetRoot = smt0.root();
/* the empty-tree root must match walk-scripts' exported constant; the populated root must differ */
assert.deepEqual(makeSmt([]).root(), EMPTY_NULL_ROOT, 'empty SMT root != EMPTY_NULL_ROOT');
assert.ok(!nullSetRoot.equals(EMPTY_NULL_ROOT), 'the populated SMT root must differ from the empty root');

const sibsA = smt0.siblingsFor(nf0);
const midRoot = smtWalk(SPENT_MARKER, nf0, sibsA);
const smt1 = makeSmt([...spentKeys.map((k) => k.toString('hex')), nf0.toString('hex')]);
assert.deepEqual(smt1.root(), midRoot, 'mirror: midRoot');
const sibsB = smt1.siblingsFor(nf1);
const finalNullRoot = smtWalk(SPENT_MARKER, nf1, sibsB);
const smt2 = makeSmt([...spentKeys.map((k) => k.toString('hex')), nf0.toString('hex'), nf1.toString('hex')]);
assert.deepEqual(smt2.root(), finalNullRoot, 'mirror: finalNullRoot');

/* ── the tx shape (the pool's 5-input action, walk-inputs under test) ── */
const { walkA, walkB, sizes, walkAHash, walkBHash } = buildWalkScripts(categoryOnChainHex);
console.log(`walk scripts: walkA ${sizes.walkA} B (sha256 ${walkAHash.toString('hex').slice(0, 16)}…) · walkB ${sizes.walkB} B (sha256 ${walkBHash.toString('hex').slice(0, 16)}…)`);
assert.ok(sizes.walkA <= 10000 && sizes.walkB <= 10000, 'walk lockings exceed the 10,000-B cap');

const catMutable = Uint8Array.from([...CATEGORY_ONCHAIN, 0x01]);   // what the VM's UTXOTOKCAT pushes (reverse(stored)+cap)
const catBare = Uint8Array.from(CATEGORY_DISPLAY);                  // libauth token.category fields carry DISPLAY bytes (pool-tx.mjs convention)
const carrierPayload = Buffer.alloc(201);
nf0.copy(carrierPayload, 0); nf1.copy(carrierPayload, 32);
const carrierOut = Uint8Array.from([0x6a, 0x4c, 201, ...carrierPayload]);
const noteRoot = sha('note-root');
const stateCommit = Uint8Array.from([...sha('nr-le-standin'), ...nullSetRoot]);
const newNoteRoot = sha('new-note-root');
const newCommit = Uint8Array.from([...newNoteRoot, ...finalNullRoot]);
const P2SH_DUMMY = Uint8Array.from([0x76, 0xa9, 0x14, ...Buffer.alloc(20), 0x88, 0xac]); // a plausible non-walk locking

const mkTx = ({ walkAUnlock, walkBUnlock, carrier = carrierOut, newCommitment = newCommit }) => ({   /* the STATE commitment is per-CASE: it rides sourceOutputs, not this tx */
    version: 2, locktime: 0,
    inputs: [
        { outpointIndex: 0, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array() },
        { outpointIndex: 1, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array() },
        { outpointIndex: 2, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array() },
        { outpointIndex: 0, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array(walkAUnlock) },
        { outpointIndex: 1, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array(walkBUnlock) },
    ],
    outputs: [
        { lockingBytecode: carrier, valueSatoshis: 0n },
        { lockingBytecode: P2SH_DUMMY, valueSatoshis: 1000n, token: { category: catBare, amount: 700n, nft: { capability: 'mutable', commitment: new Uint8Array(newCommitment) } } },
    ],
});
const sourceOutputs = (walkALocking, walkBLocking, stateCommitment = stateCommit) => [
    { lockingBytecode: P2SH_DUMMY, valueSatoshis: 15000n },
    { lockingBytecode: P2SH_DUMMY, valueSatoshis: 15000n },
    { lockingBytecode: P2SH_DUMMY, valueSatoshis: 1000n, token: { category: catBare, amount: 700n, nft: { capability: 'mutable', commitment: new Uint8Array(stateCommitment) } } },
    { lockingBytecode: new Uint8Array(walkALocking), valueSatoshis: 300n },
    { lockingBytecode: new Uint8Array(walkBLocking), valueSatoshis: 300n },
];

const honestA = walkAWitness(midRoot, sibsA);
const honestB = walkBWitness(sibsB);

/* the source outputs must be built PER CASE: input 2's NFT commitment is the
   scenario's stored nullSetRoot (the replay case pins a DIFFERENT root). */
const run = (name, walk, inputIndex, unlock, tx, stateCommitment = stateCommit) => {
    const srcs = sourceOutputs(walkA, walkB, stateCommitment);
    const res = {};
    for (const mode of ['consensus', 'standard']) {
        const st = VMS[mode].evaluate({ inputIndex, sourceOutputs: srcs, transaction: tx });
        res[mode] = { err: st.error ? String(st.error).split('\n')[0].slice(0, 90) : null, op: st.metrics?.operationCost, budget: budgetOf(Uint8Array.from(unlock)) };
    }
    const ok = !res.consensus.err && !res.standard.err;
    console.log(`  ${name}: ${ok ? 'ACCEPTED' : 'REJECTED'} · op ${res.consensus.op}/${res.standard.op} of budget ${res.consensus.budget}` +
        (ok ? '' : ` · ${res.consensus.err ?? res.standard.err}`));
    return ok;
};

console.log('== honest accepts ==');
const tx1 = mkTx({ walkAUnlock: honestA, walkBUnlock: honestB });
const okA = run('walkA honest', walkA, 3, honestA, tx1);
const okB = run('walkB honest', walkB, 4, honestB, tx1);
assert.ok(okA && okB, 'the honest walks must be ACCEPTED');

console.log('== rejections ==');
let n = 0, allRejected = true;
const reject = (name, ...build) => { const tx = build[0], unlock = build[1], walk = build[2], ix = build[3], sc = build[4]; const ok = run(name, walk, ix, unlock, tx, sc); if (ok) { allRejected = false; console.log(`  !!! ${name} was ACCEPTED — SOUNDNESS FAILURE`); } else n++; };

/* a tampered sibling in walkA's blob */
{
    const badSibs = sibsA.map((s, i) => (i === 100 ? Buffer.from([...s.slice(0, 5), s[5] ^ 0x40, ...s.slice(6)]) : s));
    const unlock = walkAWitness(midRoot, badSibs);
    reject('walkA tampered sibling', mkTx({ walkAUnlock: unlock, walkBUnlock: honestB }), unlock, walkA, 3);
}
/* a tampered sibling in walkB's blob */
{
    const badSibs = sibsB.map((s, i) => (i === 200 ? Buffer.from([...s.slice(0, 1), s[1] ^ 0x10, ...s.slice(2)]) : s));
    const unlock = walkBWitness(badSibs);
    reject('walkB tampered sibling', mkTx({ walkAUnlock: honestA, walkBUnlock: unlock }), unlock, walkB, 4);
}
/* a wrong declared midRoot (walkA's own pin + walkB's anchor) */
{
    const badMid = Buffer.from([...midRoot.slice(0, 3), midRoot[3] ^ 0x20, ...midRoot.slice(4)]);
    const unlockA = walkAWitness(badMid, sibsA);
    reject('walkA wrong declared midRoot', mkTx({ walkAUnlock: unlockA, walkBUnlock: honestB }), unlockA, walkA, 3);
    reject('walkB anchored to the tampered midRoot', mkTx({ walkAUnlock: unlockA, walkBUnlock: honestB }), honestB, walkB, 4);
}
/* a REPLAYED nullifier: nf0 already in the set — the zeros-fold must miss */
{
    const smtR = makeSmt([...spentKeys.map((k) => k.toString('hex')), nf0.toString('hex')]);
    const rootR = smtR.root();
    const sibsR = smtR.siblingsFor(nf0);        // siblings FOR the replayed key
    const midR = smtWalk(SPENT_MARKER, nf0, sibsR);
    const unlockA = walkAWitness(midR, sibsR);
    const stateR = Uint8Array.from([...sha('nr-le-standin'), ...rootR]);
    reject('walkA replayed nf0 (already spent)', mkTx({ walkAUnlock: unlockA, walkBUnlock: honestB }), unlockA, walkA, 3, stateR);
}
/* a tampered carrier key slice: byte 7 is inside nf0's slice [0..32] (walkA's
   key); byte 39 is inside nf1's slice [32..64] (walkB's key) */
{
    const badPayload = Buffer.from(carrierPayload); badPayload[7] ^= 0x08;
    const badCarrier = Uint8Array.from([0x6a, 0x4c, 201, ...badPayload]);
    reject('walkA tampered carrier key (nf0 slice)', mkTx({ walkAUnlock: honestA, walkBUnlock: honestB, carrier: badCarrier }), honestA, walkA, 3);
    const badPayload2 = Buffer.from(carrierPayload); badPayload2[39] ^= 0x40;
    const badCarrier2 = Uint8Array.from([0x6a, 0x4c, 201, ...badPayload2]);
    reject('walkB tampered carrier key (nf1 slice)', mkTx({ walkAUnlock: honestA, walkBUnlock: honestB, carrier: badCarrier2 }), honestB, walkB, 4);
}
/* a wrong-length sibling blob (the length pin) */
{
    const shortBlob = sibsA.slice(0, 200);
    const unlock = walkAWitness(midRoot, shortBlob);
    reject('walkA short sibling blob', mkTx({ walkAUnlock: unlock, walkBUnlock: honestB }), unlock, walkA, 3);
}
/* swapped lockings: walkA's witness under walkB's script (and vice versa) */
{
    const srcsSwapped = sourceOutputs(walkB, walkA, stateCommit);
    const st = VMS.consensus.evaluate({ inputIndex: 3, sourceOutputs: srcsSwapped, transaction: tx1 });
    const st2 = VMS.consensus.evaluate({ inputIndex: 4, sourceOutputs: srcsSwapped, transaction: tx1 });
    const okSw = !st.error && !st2.error;
    console.log(`  swapped walk lockings: ${okSw ? '!!! ACCEPTED — SHAPE FAILURE' : 'REJECTED (both)'}`);
    if (okSw) allRejected = false; else n += 2;
}
/* the honest budget check: the self-funded budget must cover the walk */
console.log(`\nwalkA unlocking ${honestA.length} B · walkB unlocking ${honestB.length} B (caps: 10,000 B)`);
assert.ok(honestA.length <= 10000 && honestB.length <= 10000, 'unlocking exceeds the 10,000-B cap');
assert.ok(allRejected && n >= 8, 'every rejection class must reject');
console.log(`\nWALK BATTERY PASS — honest accepts on both VMs, ${n} rejections all rejected.`);
