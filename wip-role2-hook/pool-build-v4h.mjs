// pool-build-v4h.mjs — the C-architecture program BUILD RECORD (plain + holdings-hooked).
//
// The C architecture (2026-11-27, the "no issuer" fix): the pool keeps its OWN fresh
// category (state NFT + blanks — our key, no third party), and the ASSET — a category we
// do NOT own and can never mint (e.g. real ParyonUSD 2469acc5…) — rides a dedicated
// holdings input (5) / deposit slot (6) pair locked to the H covenant. The state NFT
// commitment grows to 96 B — [noteRoot ‖ nullSetRoot ‖ balance32] — the authenticated
// balance chain (hook check 5's third field + check 9's write-back), which makes the
// holdings line unforgeable: an action that does not carry the full committed balance
// dies on consensus token conservation. out2 recreates the holdings; the unshield
// payout is out3, in the ASSET's bare category.
//
// Deltas vs pool-build-v3.mjs:
//   - buildWalkScripts(categoryOnChain, { commit96: true }) — the walks split the
//     96-B commitments' balance tails off their anchor/target reads;
//   - POOL_HOLDINGS=1 — the graph pins TXINPUTCOUNT == 7 and inputs 5/6 to each other
//     (byte-compare; H pins the program by hash — no circular hash);
//   - covenantHook(covenantParams({ categoryOnChain, assetCategoryOnChain }), 3,
//     { walkAHash, walkBHash, holdings: {} }) — the holdings-mode hook;
//   - buildHoldingsCovenant — H, built AFTER the program (embeds the program locking
//     hash + the walk hashes);
//   - the smoke evaluates the walk inputs (3/4) AND the H inputs (5/6) — H must ACCEPT
//     inside the honest 7-input shape. The full hook acceptance is pool-test-v4h.mjs.
//
// The category pair is parameterized: the GATES run under a synthetic pool category
// with the REAL asset category; the live deploy re-runs this build with the anchor
// txid as the pool category (the program is per-category; the VK is not — the MPC
// zkey/fixtures are category-agnostic, probe-verified 2026-11-27 via the
// role2-op4-CHECK-2469 deposit proof under pool4_0002_hush.zkey, snarkjs verify OK).
//
// Usage (VM, from the bench dir):
//   POOL_CATEGORY=<hex32> ASSET_CATEGORY=2469acc5… \
//   BN_VK_FIXTURES=/home/apecs/cov/our-v3-mpc.fixtures.json node pool-build-v4h.mjs
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { buildProgram, setCovenant } from './script.mjs';
import { transactionFor } from './transaction.mjs';
import { FIXTURES } from '../sound-si-gls/math.mjs';
import { VMS, p2sh32, spendAll } from './vm.mjs';
import { covenantHook, covenantParams, carrierOf, carrierOutput } from './pool-hook.mjs';
import { buildWalkScripts } from './walk-scripts.mjs';
import { buildHoldingsCovenant } from './holdings-covenant.mjs';
import { walkV3, walkWitnesses, v7Inputs, v7SourceOutputs, poolOutputsC, scenarioV3H } from './pool-tx-v3.mjs';

const sha = (b) => createHash('sha256').update(Buffer.from(b)).digest('hex');
const hex = (b) => Buffer.from(b).toString('hex');
const POOL_CATEGORY = process.env.POOL_CATEGORY ?? 'aa11aa22aa33aa44aa55aa66aa77aa88aa99aa00bb11bb22bb33bb44bb55bb66';
const ASSET_CATEGORY = process.env.ASSET_CATEGORY ?? '2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544';
if (POOL_CATEGORY.length !== 64 || ASSET_CATEGORY.length !== 64) throw new Error('categories must be 32-B hex (display order)');
const CATEGORY_DISPLAY = Buffer.from(POOL_CATEGORY, 'hex');
const ASSET_DISPLAY = Buffer.from(ASSET_CATEGORY, 'hex');
const CATEGORY_ONCHAIN = Buffer.from(CATEGORY_DISPLAY).reverse().toString('hex');
const ASSET_ONCHAIN = Buffer.from(ASSET_DISPLAY).reverse().toString('hex');

/* the commit96 walk scripts + the graph pin env (walk hashes + the holdings shape) */
const { walkA, walkB, sizes } = buildWalkScripts(CATEGORY_ONCHAIN, { commit96: true });
const { lockings: WALK_LOCKS, hashes: [walkAHash, walkBHash] } = walkV3(walkA, walkB);
process.env.POOL_NULLDATA_HASHES = JSON.stringify([walkAHash.toString('hex'), walkBHash.toString('hex')]);
process.env.POOL_HOLDINGS = '1';

/* the PLAIN program under the pool4 VK */
const plain = buildProgram();
/* the C-HOOKED program */
setCovenant(covenantHook(covenantParams({ categoryOnChain: CATEGORY_ONCHAIN, assetCategoryOnChain: ASSET_ONCHAIN }), 3, { walkAHash, walkBHash, holdings: {} }));
const hooked = buildProgram();
const progLocking = p2sh32(hooked.R);
const progLockingHashHex = sha(progLocking);

/* H — after the program (embeds the program locking hash + the walk hashes) */
const HC = buildHoldingsCovenant({ progLockingHashHex, walkAHashHex: walkAHash.toString('hex'), walkBHashHex: walkBHash.toString('hex') });

/* the smoke: fixture 0 (transfer) through the honest C shape — walk inputs 3/4 and
   the H inputs 5/6 must ACCEPT. The scenario record comes from the post-MPC fixture
   proofs (VK-independent witness data). */
const proofs = JSON.parse(readFileSync(process.env.PROOFS ?? '/home/apecs/cov/our-v3-mpc-proofs.json', 'utf8'));
const leToBig = (h) => BigInt('0x' + Buffer.from(h, 'hex').reverse().toString('hex') || '0');
const c = proofs[0].covenant;
const sc = { nf0: leToBig(c.nf0), nf1: leToBig(c.nf1), cm0: leToBig(c.cm0), cm1: leToBig(c.cm1), cm2: leToBig(c.cm2), newRoot: leToBig(c.newMerkleRoot), pv: BigInt(c.publicValueAbs), sign: BigInt(c.isUnshield) };
const n0 = BigInt(proofs[0].publicSignals[0]);
const fx = proofs[0].nullSet;
const balance = 1000n;
const scenario = scenarioV3H({ sc, n0, nullSet: fx, balance });
const T = transactionFor(FIXTURES.fixtures[0], plain);
const walkW = walkWitnesses(fx, walkA, walkB);
const inputs = v7Inputs(T.unlockings, walkW, HC.script);
/* the honest 7-input shape: sources + outputs per the C builders */
const args = { sc, balance, categoryDisplay: CATEGORY_DISPLAY, assetCategoryDisplay: ASSET_DISPLAY };
const sourceOutputs = v7SourceOutputs(progLocking, WALK_LOCKS, HC.locking, scenario, args);
const outputs = poolOutputsC(hooked, HC.locking, scenario, args);
for (const ix of [3, 4, 5, 6]) {
    const st = VMS.consensus.evaluate({ inputIndex: ix, sourceOutputs, transaction: { version: 2, locktime: 0, inputs, outputs } });
    const top = st.stack?.[st.stack.length - 1];
    const ok = st.error === undefined && st.stack.length === 1 && top?.length === 1 && top[0] === 1;
    if (!ok) throw new Error(`input ${ix} smoke failed: ${st.error}`);
    console.log(`input ${ix} smoke: ACCEPT · op ${st.metrics.operationCost}`);
}

const record = (name, prog) => ({
    name,
    codeBytes: prog.code.length, codeSha256: sha(prog.code),
    redeemBytes: prog.R.length, redeemSha256: sha(prog.R),
    lockingHex: hex(p2sh32(prog.R)), lockingSha256: sha(p2sh32(prog.R)),
    codePieces: prog.pieces.map((x) => x.length),
    roleCodeBytes: Object.fromEntries(Object.entries(prog.funcCodes).map(([k, v]) => [k, v.length])),
});
const out = {
    vk: { fixturesFile: process.env.BN_VK_FIXTURES ?? '/home/apecs/cov/our-v3-mpc.fixtures.json', nPublic: 2, icLength: 3 },
    categories: { pool: POOL_CATEGORY, asset: ASSET_CATEGORY },
    plain: record('plain', plain),
    hooked: record('hooked-v4h', hooked),
    walk: { walkABytes: sizes.walkA, walkASha256: walkAHash.toString('hex'), walkBBytes: sizes.walkB, walkBSha256: walkBHash.toString('hex'),
        walkALocking32: hex(WALK_LOCKS[0]), walkBLocking32: hex(WALK_LOCKS[1]),
        walkAUnlocking: walkW[0].length, walkBUnlocking: walkW[1].length, commit96: true },
    holdingsCovenant: { redeemBytes: HC.redeemBytes, lockingHex: HC.lockingHex, lockingHashHex: HC.lockingHashHex,
        progLockingHashHex, pins: { walkAHash: walkAHash.toString('hex'), walkBHash: walkBHash.toString('hex') } },
    shape: { inputs: 7, walkInputs: [3, 4], holdingsInputs: [5, 6], carrierBytes: 204, stateCommitmentBytes: 96, payoutOutput: 3, holdingsOutput: 2 },
};
writeFileSync(process.env.OUT ?? 'build.v4h.json', JSON.stringify(out, null, 2));
console.log(`plain   ${out.plain.codeBytes} B sha256 ${out.plain.codeSha256.slice(0, 16)}…`);
console.log(`hooked  ${out.hooked.codeBytes} B sha256 ${out.hooked.codeSha256.slice(0, 16)}… locking ${out.hooked.lockingHex.slice(0, 22)}…`);
console.log(`walks   A ${sizes.walkA} B / B ${sizes.walkB} B (commit96) · unlockings ${walkW[0].length}/${walkW[1].length} B`);
console.log(`H       ${HC.redeemBytes} B redeem · locking ${HC.lockingHex.slice(0, 22)}…`);
console.log('wrote', process.env.OUT ?? 'build.v4h.json');
