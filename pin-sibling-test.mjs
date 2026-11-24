// pin-sibling-test.mjs
//
// REGRESSION TEST for the verifier-sibling pin in asset-pool.cash (step −1).
//
// WHY THIS EXISTS
//   spend() reads the proven public inputs (n0 = merkleRoot, n1 = actionHash) out of
//   the GENESIS step's unlocking bytecode at fixed offsets (1825 / 1792). That read
//   authenticates nothing by itself: the stored root is public (it is the pool's own
//   NFT commitment) and the actionHash is recomputed by the covenant from values the
//   spender supplies. Without a locking check, a spender can put ANY script at the
//   genesis index whose unlocking carries those two byte ranges — no proof, no
//   verifier — and drain the pool.
//
//   This test proves both halves on the BCH-2026 VM:
//     · the UNPINNED covenant (1 ctor arg) ACCEPTS a foreign OP_1 script at the
//       genesis index and at an executor index — i.e. the hole was real;
//     · the PINNED covenant (5 ctor args) ACCEPTS the honest transaction and
//       REJECTS both substitutions.
//
// WHAT IT DOES
//   Builds a synthetic 6-input transaction: five "verifier" inputs (0..4) plus the
//   covenant at index 5, and evaluates ONLY the covenant input. The verifier's
//   arithmetic is irrelevant to the property under test, so the sibling inputs carry
//   no meaningful scripts — only their LOCKINGS matter, and those are what the test
//   varies.
//
// RUN (needs @bitauth/libauth + cashscript resolvable from the CWD, and the two
// compiled artifacts; see the header of eval-pool.mjs for the same dependency note):
//
//   cashc -o orig.artifact.json   asset-pool.cash        # at the pre-pin commit
//   cashc -o pinned.artifact.json asset-pool.cash        # this tree
//   node pin-sibling-test.mjs orig.artifact.json pinned.artifact.json
//
// Exit code 0 iff every case matches its expectation.

import { readFileSync } from 'node:fs';
import { createVirtualMachineBch2026, sha256, hexToBin } from '@bitauth/libauth';
const { Contract } = await import('cashscript');

const [, , origPath, pinnedPath] = process.argv;
if (!origPath || !pinnedPath) {
    console.error('usage: node pin-sibling-test.mjs <orig.artifact.json> <pinned.artifact.json>');
    process.exit(2);
}

/* ── the pool's fixed data ─────────────────────────────────────────────────── */
const CATEGORY = '2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544';
const CAT_ONCHAIN = Buffer.from(CATEGORY, 'hex').reverse().toString('hex');

/* Real step lockings (gate3 / mainnet program, from nito.cash verifier-program.js).
   Any 35-byte P2SH32 would do for the property under test; these are the real ones
   so the ctor args look like a deployment. */
const EXEC = 'aa2043098e3bd650d5eb8aebd6091cd4436895ac99a211624246ea3f2284c59457b287';
const GENESIS = 'aa20372ab5b94351c3576d917497eb2f877539deed5a5b6e683d1e7a4ff5ed38d47d87';
const TERMINAL = 'aa203190c338a765f9cac3def9c25194cfc8d214796df04d89dd474e47f31f7f3f0c87';

/* The attacker's script: one byte, OP_1. Satisfies anything that only pushes. */
const FOREIGN = '51';

const GEN_INDEX = 3;

/* ── the transition the covenant is asked to apply ─────────────────────────── */
const H = (b) => Buffer.alloc(32, b);
const storedRoot = H(0x11);        // == the pool's current NFT commitment root
const newRoot = H(0x22);
const nf0 = H(0x33), nf1 = H(0x44), cm0 = H(0x55), cm1 = H(0x66);
const pv = 0n, isUnshield = 0n;

/* actionHash, computed exactly as the covenant computes it: args arrive as LE VM
   numbers, the preimage is big-endian, the digest's top 3 bits are cleared, and the
   result is reversed back to the LE form the verifier pushes as n1. */
const pre = Buffer.concat([
    Buffer.from(nf0).reverse(), Buffer.from(nf1).reverse(),
    Buffer.from(cm0).reverse(), Buffer.from(cm1).reverse(),
    Buffer.alloc(32), Buffer.alloc(32),                      // toPaddedBytes(pv, 32), toPaddedBytes(sign, 32)
    Buffer.from(CATEGORY, 'hex'), Buffer.from(newRoot).reverse(),
]);
const be = Buffer.from(sha256.hash(pre));
be[0] &= 0x1f;                                               // clear the top 3 bits
const actionHashLE = Buffer.from(be).reverse();

/* The genesis unlocking, fabricated so that the two fixed-offset reads land on the
   values above: byte 1791 = 0x20 then actionHash at [1792,1824); byte 1824 = 0x20
   then storedRoot at [1825,1857). The 1791 filler bytes are OP_0 pushes. */
const genUnlocking = Buffer.concat([
    Buffer.alloc(1791, 0x00),
    Buffer.from([0x20]), actionHashLE,
    Buffer.from([0x20]), storedRoot,
]);

/* ── one scenario ──────────────────────────────────────────────────────────── */
const run = async ({ label, expect, artifact, ctor, genesisLocking, execLocking }) => {
    const contract = new Contract(artifact, ctor, { provider: { network: 'chipnet' }, contractType: 'p2s' });
    const redeem = hexToBin(contract.bytecode);
    const unlocker = contract.unlock.spend(nf0, nf1, cm0, cm1, newRoot, pv, isUnshield);
    const unlocking = unlocker.generateUnlockingBytecode
        ? unlocker.generateUnlockingBytecode({ transaction: { version: 2, inputs: [], outputs: [], locktime: 0 }, sourceOutputs: [], inputIndex: 5 })
        : unlocker;

    const mkTok = (cap, commitment, amount) => ({ amount, category: hexToBin(CATEGORY), nft: { capability: cap, commitment } });
    const inputs = [0, 1, 2, 3, 4].map((n) => ({
        outpointTransactionHash: new Uint8Array(32), outpointIndex: n, sequenceNumber: 0,
        unlockingBytecode: n === GEN_INDEX ? genUnlocking : new Uint8Array(0),
    }));
    inputs.push({ outpointTransactionHash: new Uint8Array(32), outpointIndex: 5, sequenceNumber: 0, unlockingBytecode: unlocking });

    const lockOf = (n) => hexToBin(n === GEN_INDEX ? genesisLocking : n === 4 ? TERMINAL : execLocking);
    const sourceOutputs = [
        ...inputs.slice(0, 5).map((_, n) => ({ lockingBytecode: lockOf(n), valueSatoshis: 1000n })),
        { lockingBytecode: redeem, valueSatoshis: 1000n, token: mkTok('mutable', Buffer.concat([storedRoot, Buffer.alloc(32)]), 1000n) },
    ];
    const newNull = Buffer.from(sha256.hash(Buffer.concat([Buffer.alloc(32), nf0, nf1])));
    const outputs = [{ lockingBytecode: redeem, valueSatoshis: 1000n, token: mkTok('mutable', Buffer.concat([newRoot, newNull]), 1000n) }];

    const vm = createVirtualMachineBch2026(true);
    const st = vm.evaluate({ inputIndex: 5, sourceOutputs, transaction: { version: 2, inputs, outputs, locktime: 0 } });
    const top = st.stack[st.stack.length - 1];
    const accepted = st.error === undefined && st.stack.length === 1 && top && top.length === 1 && top[0] === 1;

    const budget = (41 + unlocking.length) * 800;
    const cost = st.metrics?.operationCost ?? 0;
    const pass = accepted === expect;
    console.log(`${pass ? 'ok  ' : 'FAIL'} ${accepted ? 'ACCEPT' : 'REJECT'} (expected ${expect ? 'ACCEPT' : 'REJECT'})  ${label}`);
    console.log(`       ${st.error ? 'error: ' + String(st.error).slice(0, 100) : 'no error'} · redeem ${redeem.length} B · unlock ${unlocking.length} B · op ${cost}/${budget} (${(100 * cost / budget).toFixed(1)}%)`);
    return pass;
};

/* ── the matrix ────────────────────────────────────────────────────────────── */
const orig = JSON.parse(readFileSync(origPath, 'utf8'));
const pinned = JSON.parse(readFileSync(pinnedPath, 'utf8'));
const ctorOrig = [CAT_ONCHAIN];
const ctorPinned = (g, e, t) => [CAT_ONCHAIN, hexToBin(g), hexToBin(e), hexToBin(t), BigInt(GEN_INDEX)];

const results = [];
console.log('--- control: the real verifier siblings are in place ---');
results.push(await run({ label: 'orig   · real siblings', expect: true, artifact: orig, ctor: ctorOrig, genesisLocking: GENESIS, execLocking: EXEC }));
results.push(await run({ label: 'pinned · real siblings', expect: true, artifact: pinned, ctor: ctorPinned(GENESIS, EXEC, TERMINAL), genesisLocking: GENESIS, execLocking: EXEC }));

console.log('\n--- attack: the genesis sibling carries a foreign script (OP_1) ---');
results.push(await run({ label: 'orig   · FOREIGN genesis', expect: true, artifact: orig, ctor: ctorOrig, genesisLocking: FOREIGN, execLocking: EXEC }));
results.push(await run({ label: 'pinned · FOREIGN genesis', expect: false, artifact: pinned, ctor: ctorPinned(GENESIS, EXEC, TERMINAL), genesisLocking: FOREIGN, execLocking: EXEC }));

console.log('\n--- attack: an executor sibling carries a foreign script (OP_1) ---');
results.push(await run({ label: 'orig   · FOREIGN exec', expect: true, artifact: orig, ctor: ctorOrig, genesisLocking: GENESIS, execLocking: FOREIGN }));
results.push(await run({ label: 'pinned · FOREIGN exec', expect: false, artifact: pinned, ctor: ctorPinned(GENESIS, EXEC, TERMINAL), genesisLocking: GENESIS, execLocking: FOREIGN }));

console.log(`\n${results.filter(Boolean).length}/${results.length} cases match expectation`);
process.exit(results.every(Boolean) ? 0 : 1);
