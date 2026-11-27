// pool-build-v3.mjs — the v3 program BUILD RECORD (plain + v3-hooked, pool-cost pattern).
//
// NOT build.mjs's own smoke: its bench transaction is tokenless and the pool hook
// rejects that shape at check 2 by design (the same reason pool-tx.mjs exists);
// the hooked builds of record were always produced via the pool-shaped harnesses
// (pool-cost.mjs / pool-test.mjs / pool-redteam.mjs / pool-sweep.mjs). This script
// emits the same record fields build.mjs writes, from setCovenant + buildProgram:
//   - the PLAIN program under the pool4 VK (no hook);
//   - the v3 HOOKED program (walk scripts + the graph pin + the v3 role-2 hook);
//   - the walk scripts' bytes + hashes (the raw lockings of inputs 3/4);
//   - a pool-shaped accept smoke on fixture 0 (the 5-input shape, all inputs).
//
// Usage (VM, from the bench dir):
//   BN_VK_FIXTURES=/home/apecs/cov/our-v3.fixtures.json node pool-build-v3.mjs
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { buildProgram, setCovenant } from './script.mjs';
import { transactionFor } from './transaction.mjs';
import { FIXTURES } from '../sound-si-gls/math.mjs';
import { VMS, p2sh32, spendAll } from './vm.mjs';
import { covenantHook, covenantParams, carrierOf, carrierOutput } from './pool-hook.mjs';
import { buildWalkScripts, walkAWitness, walkBWitness } from './walk-scripts.mjs';
import { walkV3, walkWitnesses } from './pool-tx-v3.mjs';

const sha = (b) => createHash('sha256').update(Buffer.from(b)).digest('hex');
const hex = (b) => Buffer.from(b).toString('hex');
const CATEGORY_DISPLAY = Buffer.from('2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544', 'hex');
const CATEGORY_ONCHAIN = Buffer.from(CATEGORY_DISPLAY).reverse().toString('hex');

/* the walk scripts + the graph pin env — v3.1: the pins hash the P2SH32
   WRAP lockings (the raw form is relay-nonstandard, measured on chain) */
const { walkA, walkB, sizes } = buildWalkScripts(CATEGORY_ONCHAIN);
const { lockings: WALK_LOCKS, hashes: [walkAHash, walkBHash] } = walkV3(walkA, walkB);
process.env.POOL_NULLDATA_HASHES = JSON.stringify([walkAHash.toString('hex'), walkBHash.toString('hex')]);

/* the PLAIN program under the pool4 VK (module-level COVENANT empty until setCovenant) */
const plain = buildProgram();
/* the v3 HOOKED program */
setCovenant(covenantHook(covenantParams({ categoryOnChain: CATEGORY_ONCHAIN }), 3, { walkAHash, walkBHash }));
const hooked = buildProgram();

const proofs = JSON.parse(readFileSync('/home/apecs/cov/our-v3-proofs.json', 'utf8'));
const leToBig = (h) => BigInt('0x' + Buffer.from(h, 'hex').reverse().toString('hex') || '0');
const c = proofs[0].covenant;
const sc = { nf0: leToBig(c.nf0), nf1: leToBig(c.nf1), cm0: leToBig(c.cm0), cm1: leToBig(c.cm1), cm2: leToBig(c.cm2), newRoot: leToBig(c.newMerkleRoot), pv: BigInt(c.publicValueAbs), sign: BigInt(c.isUnshield) };
const n0 = BigInt(proofs[0].publicSignals[0]);
const fx = proofs[0].nullSet;

/* the pool-shaped 5-input smoke on fixture 0: all FIVE inputs must spend (the
   walk scripts evaluate their own unlockings; the program inputs 0/1/2 spend
   under the plain program's stock sizing — no hook on the plain build, and the
   hooked build's inputs 0/1/2 need pool-shaped fills, so the smoke here uses
   the PLAIN unlockings for the program inputs and evaluates the hooked program
   only where its checks are meaningful: inputs 3/4 (the walks) + input 2 via
   pool-test-v3.mjs, which is the full hooked acceptance of record). */
const T = transactionFor(FIXTURES.fixtures[0], plain);
const unlockings = [...T.unlockings,
    walkWitnesses(fx, walkA, walkB)[0],
    walkWitnesses(fx, walkA, walkB)[1]];
const carr = carrierOf(sc, 3);
const stateCommit = Buffer.concat([Buffer.from(be32le(n0)), Buffer.from(fx.nullSetRootBefore, 'hex')]);
const newCommit = Buffer.concat([Buffer.from(be32le(sc.newRoot)), Buffer.from(fx.finalNullRoot, 'hex')]);
const fuel = (n) => ({ lockingBytecode: p2sh32(hooked.R), valueSatoshis: 1000n, token: { category: new Uint8Array(CATEGORY_DISPLAY), amount: n === 0 && sc.sign === 0n ? sc.pv : 0n, nft: { capability: 'mutable', commitment: new Uint8Array(createHash('sha256').update(carr.subarray(0, 64)).digest()) } } });
const sourceOutputs = [
    fuel(0), fuel(1),
    { lockingBytecode: p2sh32(hooked.R), valueSatoshis: 1000n, token: { category: new Uint8Array(CATEGORY_DISPLAY), amount: 1000n, nft: { capability: 'mutable', commitment: new Uint8Array(stateCommit) } } },
    { lockingBytecode: new Uint8Array(WALK_LOCKS[0]), valueSatoshis: 300n },
    { lockingBytecode: new Uint8Array(WALK_LOCKS[1]), valueSatoshis: 300n },
];
const outputs = [
    { lockingBytecode: new Uint8Array(carrierOutput(carr)), valueSatoshis: 0n },
    { lockingBytecode: p2sh32(hooked.R), valueSatoshis: 1000n, token: { category: new Uint8Array(CATEGORY_DISPLAY), amount: 1000n, nft: { capability: 'mutable', commitment: new Uint8Array(newCommit) } } },
];
/* evaluate the WALK inputs (3/4) of the hooked program's action shape */
const inputs = unlockings.map((u, n) => ({ outpointIndex: n, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array(u) }));
for (const ix of [3, 4]) {
    const st = VMS.consensus.evaluate({ inputIndex: ix, sourceOutputs, transaction: { version: 2, locktime: 0, inputs, outputs } });
    const top = st.stack?.[st.stack.length - 1];
    const ok = st.error === undefined && st.stack.length === 1 && top?.length === 1 && top[0] === 1;
    if (!ok) throw new Error(`walk input ${ix} smoke failed: ${st.error}`);
    console.log(`walk input ${ix} smoke: ACCEPT · op ${st.metrics.operationCost}`);
}

function be32le(v) { const b = Buffer.alloc(32); let x = BigInt(v); for (let i = 31; i >= 0 && x > 0n; i--) { b[i] = Number(x & 0xffn); x >>= 8n; } return Buffer.from(b).reverse(); }

const record = (name, prog) => ({
    name,
    codeBytes: prog.code.length, codeSha256: sha(prog.code),
    redeemBytes: prog.R.length, redeemSha256: sha(prog.R),
    lockingHex: hex(p2sh32(prog.R)), lockingSha256: sha(p2sh32(prog.R)),
    codePieces: prog.pieces.map((x) => x.length),
    roleCodeBytes: Object.fromEntries(Object.entries(prog.funcCodes).map(([k, v]) => [k, v.length])),
});
const out = {
    vk: { fixturesFile: '/home/apecs/cov/our-v3.fixtures.json', nPublic: 2, icLength: 3 },
    plain: record('plain', plain),
    hooked: record('hooked-v3', hooked),
    walk: { walkABytes: sizes.walkA, walkASha256: walkAHash.toString('hex'), walkBBytes: sizes.walkB, walkBSha256: walkBHash.toString('hex'),
        walkALocking32: hex(WALK_LOCKS[0]), walkBLocking32: hex(WALK_LOCKS[1]),
        walkAUnlocking: walkWitnesses(fx, walkA, walkB)[0].length,
        walkBUnlocking: walkWitnesses(fx, walkA, walkB)[1].length },
    shape: { inputs: 5, walkInputs: [3, 4], carrierBytes: 204, stateCommitmentBytes: 64 },
};
writeFileSync(process.env.OUT ?? 'build.v3.json', JSON.stringify(out, null, 2));
console.log(`plain  ${out.plain.codeBytes} B sha256 ${out.plain.codeSha256.slice(0, 16)}… locking ${out.plain.lockingSha256.slice(0, 16)}…`);
console.log(`hooked ${out.hooked.codeBytes} B sha256 ${out.hooked.codeSha256.slice(0, 16)}… locking ${out.hooked.lockingSha256.slice(0, 16)}…`);
console.log(`walkA  ${out.walk.walkABytes} B (unlocking ${out.walk.walkAUnlocking} B) · walkB ${out.walk.walkBBytes} B (unlocking ${out.walk.walkBUnlocking} B)`);
console.log('wrote', process.env.OUT ?? 'build.v3.json');
