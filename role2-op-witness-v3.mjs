// role2-op-witness-v3.mjs — generate + prove the REAL pool-action witness for the
// v4-circuit role-2 pool (the v3 revision: deposit path + append proof + nf0!=nf1,
// with the hook-level SHA256 nullifier SMT data).
//
// Path: pusd-shielded-pool/role2-op-witness-v3.mjs
//
// role2-op-witness-3out.mjs adapted to circuits/pool4.circom (build4/):
//   - isDeposit: the onboarding path — phantom in-notes (value 0, fresh secrets),
//     membership gated off in-circuit; no bootstrap seeds needed, genesis tree EMPTY;
//   - the append witness: appendIndex (the fill count) + three frontier sibling
//     paths; newMerkleRoot is now CIRCUIT-CONSTRAINED (R3-FREE-NEWROOT fix);
//   - nf0 != nf1 is enforced in-circuit (R2 fix) — the generator refuses duplicates;
//   - the 9-field actionHash and the 201-B carrier are UNCHANGED;
//   - the hook-level nullifier SMT (script-side, SHA256, D=254): this generator
//     emits the walk data the action builder embeds in the two nullifier-data
//     inputs — sibsA/midRoot (walk nf0 from the stored nullSetRoot), sibsB/
//     finalNullRoot (walk nf1 from midRoot) — with 4/4 JS-mirror walk checks.
//
// The dense-shape rule is asserted in JS before proving: every append sibling
// must equal the zero-hash zh[d] exactly when the slot's bit d is 0 (the
// frontier pin — noteappend.circom enforces the same in-circuit).
//
// Usage (VM, from ~/zkb/pusd-shielded-pool):
//   ~/bin/node role2-op-witness-v3.mjs --action deposit   --amount N
//   ~/bin/node role2-op-witness-v3.mjs --action transfer  --in 14,15
//   ~/bin/node role2-op-witness-v3.mjs --action unshield --amount N --in 14,15
//   add --no-prove to stop after the witness (wtns check only),
//       --wasm build4/pool4_js/pool4.wasm --zkey build4/pool4_final.zkey to override.
// State file defaults to /home/apecs/cov/role2-pool4-state.json; op JSON to
// /home/apecs/cov/role2-op4.json. The state file gains `nullSet` (spent SMT keys,
// 32-B LE hex) alongside the pool fields; genesis is an EMPTY note tree.
import { buildPoseidon, buildBabyjub } from "circomlibjs";
import * as snarkjs from "snarkjs";
import { readFileSync, writeFileSync } from "fs";
import { createHash } from "node:crypto";

const argOf = (n, d) => { const i = process.argv.indexOf(n); return i >= 0 ? process.argv[i + 1] : d; };
const ACTION = argOf("--action", "transfer");
const AMOUNT = BigInt(argOf("--amount", "1000"));
const IN_IDX = ACTION === "deposit" ? [] : (argOf("--in", "0,1")).split(",").map(Number);
const OUTS = argOf("--outs", "");
const SEED = argOf("--seed", "");
const STATE = argOf("--state", "/home/apecs/cov/role2-pool4-state.json");
const OUT = argOf("--out", "/home/apecs/cov/role2-op4.json");
const WASM = argOf("--wasm", "build4/pool4_js/pool4.wasm");
const ZKEY = argOf("--zkey", "build4/pool4_final.zkey");
const NO_PROVE = process.argv.includes("--no-prove");

const be32 = (bi) => { const b = Buffer.alloc(32, 0); let x = BigInt(bi); for (let i = 31; i >= 0 && x > 0n; i--) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; };
const le32 = (bi) => Buffer.from(be32(bi).reverse());           // the carrier's 32-B LE VM-number form
function actionHashSHA256(nf0, nf1, cm0, cm1, cm2, pvAbs, pvSign, category, newRoot) {
    const pre = Buffer.concat([be32(nf0), be32(nf1), be32(cm0), be32(cm1), be32(cm2), be32(pvAbs), be32(pvSign), be32(category), be32(newRoot)]);
    const h = createHash("sha256").update(pre).digest(); h[0] &= 0x1f; return BigInt("0x" + h.toString("hex"));
}
function bigIntToVmNumber(value) { let v = BigInt(value); if (v === 0n) return new Uint8Array(0); const neg = v < 0n; if (neg) v = -v; const b = []; while (v > 0n) { b.push(Number(v & 0xffn)); v >>= 8n; } if (b[b.length - 1] & 0x80) b.push(neg ? 0x80 : 0); else if (neg) b[b.length - 1] |= 0x80; return Uint8Array.from(b); }

const TREE_DEPTH = 20;
const poseidon = await buildPoseidon(); const F = poseidon.F;
const H = (...xs) => F.toObject(poseidon(xs));
const commit = (v, o, rho, r) => H(v, o, rho, r), nullifier = (nk, rho) => H(nk, rho);
const zeros = [0n]; for (let d = 1; d <= TREE_DEPTH; d++) zeros.push(H(zeros[d - 1], zeros[d - 1]));
function merklePath(leaves, index) { const pe = [], pb = []; let idx = index, cur = new Map(leaves.map((v, i) => [i, v]));
    for (let d = 0; d < TREE_DEPTH; d++) { const s = idx % 2 === 0 ? idx + 1 : idx - 1; pe.push(cur.get(s) ?? zeros[d]); pb.push(idx % 2);
        const nx = new Map(), ks = new Set([...cur.keys()].map((k) => k >> 1)); ks.add(idx >> 1);
        for (const k of ks) nx.set(k, H(cur.get(2 * k) ?? zeros[d], cur.get(2 * k + 1) ?? zeros[d])); cur = nx; idx >>= 1; }
    return { pathElements: pe, pathBits: pb, root: cur.get(0) ?? zeros[TREE_DEPTH] }; }
/* self-check: the JS zero ladder MUST equal noteappend.circom's hardcoded ZeroLadder20 */
const CIRCUIT_ZH = ["0", "14744269619966411208579211824598458697587494354926760081771325075741142829156", "7423237065226347324353380772367382631490014989348495481811164164159255474657", "11286972368698509976183087595462810875513684078608517520839298933882497716792", "3607627140608796879659380071776844901612302623152076817094415224584923813162", "19712377064642672829441595136074946683621277828620209496774504837737984048981", "20775607673010627194014556968476266066927294572720319469184847051418138353016", "3396914609616007258851405644437304192397291162432396347162513310381425243293", "21551820661461729022865262380882070649935529853313286572328683688269863701601", "6573136701248752079028194407151022595060682063033565181951145966236778420039", "12413880268183407374852357075976609371175688755676981206018884971008854919922", "14271763308400718165336499097156975241954733520325982997864342600795471836726", "20066985985293572387227381049700832219069292839614107140851619262827735677018", "9394776414966240069580838672673694685292165040808226440647796406499139370960", "11331146992410411304059858900317123658895005918277453009197229807340014528524", "15819538789928229930262697811477882737253464456578333862691129291651619515538", "19217088683336594659449020493828377907203207941212636669271704950158751593251", "21035245323335827719745544373081896983162834604456827698288649288827293579666", "6939770416153240137322503476966641397417391950902474480970945462551409848591", "10941962436777715901943463195175331263348098796018438960955633645115732864202", "15019797232609675441998260052101280400536945603062888308240081994073687793470"].map(BigInt);
CIRCUIT_ZH.forEach((v, i) => { if (v !== zeros[i]) throw new Error(`zero-ladder mismatch at zh[${i}] — noteappend.circom's hardcoded ladder does not match the JS mirror`); });

/* ── the hook-level nullifier SMT (SHA256, D=254) — JS mirror + walk data ── */
const NULL_D = 254;
const sha = (b) => createHash("sha256").update(b).digest();
const szh = [Buffer.alloc(32)];
for (let i = 1; i <= NULL_D; i++) szh.push(sha(Buffer.concat([szh[i - 1], szh[i - 1]])));
const EMPTY_NULL_ROOT = szh[NULL_D];
const MARKER = Buffer.from([1, ...Array(31).fill(0)]);           // the spent leaf (32 B, NOT a 1-B OP_0)
const bitOf = (key, i) => (key[i >> 3] >> (i & 7)) & 1;
/* subtree(mk, mask, h): the SMT node covering keys agreeing with mk on the masked
   bits (mask = a high-bit mask), at height h — same recursion as the spike's
   gen-spike-inputs.mjs, hashing SHA256(left‖right) over Buffers. */
function makeSmt(keyHexes) {
    const S = keyHexes.map((h) => Buffer.from(h, "hex"));
    const memo = new Map();
    /* subtree(mk, h): the SMT node at height h covering keys that agree with mk on
       bits h..NULL_D-1 (empty -> szh[h]; h=0 -> the leaf: MARKER if spent, else the
       32-zero-byte empty leaf). Same address convention as the spike's Poseidon
       mirror, hashing SHA256(left||right) over Buffers. */
    function subtree(mk, h) {
        const id = mk.toString("hex") + "|" + h;
        if (memo.has(id)) return memo.get(id);
        let any = false;
        for (const k of S) {
            let agree = true;
            for (let b = h; b < NULL_D; b++) if (bitOf(k, b) !== bitOf(mk, b)) { agree = false; break; }
            if (agree) { any = true; break; }
        }
        let r;
        if (!any) r = szh[h];
        else if (h === 0) r = MARKER;
        else {
            const mk0 = Buffer.from(mk); mk0[(h - 1) >> 3] &= ~(1 << ((h - 1) & 7)) & 0xff;
            const mk1 = Buffer.from(mk); mk1[(h - 1) >> 3] |= 1 << ((h - 1) & 7);
            r = sha(Buffer.concat([subtree(mk0, h - 1), subtree(mk1, h - 1)]));
        }
        memo.set(id, r);
        return r;
    }
    const rootOf = () => subtree(Buffer.alloc(32), NULL_D);
    /* sibling at height i: the off-path node — keys agreeing with k on bits i+1..NULL_D-1,
       bit i flipped (the same highMask(i) convention the probe verified). */
    function siblingsFor(k) {
        const sib = [];
        for (let i = 0; i < NULL_D; i++) {
            const mk = Buffer.from(k); mk[i >> 3] ^= 1 << (i & 7);
            sib.push(subtree(mk, i));
        }
        return sib;
    }
    /* the dual walk (probe-walk-cost.mjs's exact fold) */
    function walk(leaf, key, sibs) {
        let cur = leaf;
        for (let i = 0; i < NULL_D; i++) {
            const bit = bitOf(key, i);
            const left = bit ? sibs[i] : cur;
            const right = bit ? cur : sibs[i];
            cur = sha(Buffer.concat([left, right]));
        }
        return cur;
    }
    return { rootOf, siblingsFor, walk, keys: S };
}

/* ── the deployed pool state ── */
const state = JSON.parse(readFileSync(STATE, "utf8"));
/* v4h (the C architecture): the circuit's category witness is the ASSET (real PUSD
   2469acc5…) — the category the actionHash binds and the one every fixture/sweep proof
   was minted under (the whichcat probe, 2026-11-27). v3.1 states carry no assetCategory
   and fall back to the pool category, which equals the asset there — byte-identical
   behavior for every existing state file. */
const assetCategory = BigInt("0x" + (state.assetCategory ?? state.category));
const catHi = assetCategory >> 128n, catLo = assetCategory & ((1n << 128n) - 1n);
const oldRoot = BigInt(state.pool.root);
const leaves = state.pool.leaves.map(BigInt);
const balance = BigInt(state.pool.balance);
const spentKeys = state.nullSet ?? [];
const smt = makeSmt(spentKeys);
const nullSetRoot = smt.rootOf();

/* ── the in-notes ── */
const bbj = await buildBabyjub();
const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const modr = (x) => ((x % R) + R) % R;
const pubOf = (nk) => { const p = bbj.mulPointEscalar(bbj.Base8, nk); const x = BigInt(F.toObject(p[0])); if (x >= R) throw new Error("babyjub x >= field prime"); return x; };
const rng = (seed) => { let c = 0; return () => BigInt("0x" + createHash("sha256").update(`${seed}:${c++}`).digest("hex")); };
const rnd = rng(`role2-op4-${state.deployTxid ?? "genesis"}-${ACTION}-${AMOUNT}${SEED ? "-" + SEED : ""}`);

let inNotes, nks, inPathEls, inPathBits, isDeposit;
if (ACTION === "deposit") {
    /* the onboarding path: phantom in-notes (value 0, fresh secrets); the circuit
       gates membership off (isDeposit=1) and pins both values to zero. */
    isDeposit = 1n;
    inNotes = [0, 1].map(() => { const nk = modr(rnd()); return { value: 0n, ownerPub: pubOf(nk), rho: modr(rnd()), r: modr(rnd()), nk }; });
    nks = inNotes.map((n) => n.nk);
    inPathEls = [Array(TREE_DEPTH).fill(0n), Array(TREE_DEPTH).fill(0n)];   // unused, boolean-safe
    inPathBits = [Array(TREE_DEPTH).fill(0), Array(TREE_DEPTH).fill(0)];
} else {
    isDeposit = 0n;
    const inRecs = IN_IDX.map((ix) => state.pool.notes.find((n) => Number(n.index) === ix));
    if (inRecs.some((r) => !r)) throw new Error("no recorded note at tree index " + IN_IDX.join("/") + " — indices are TREE positions");
    if (inRecs.length !== 2) throw new Error("the circuit spends exactly 2 in-notes");
    inNotes = inRecs.map((rec) => ({ value: BigInt(rec.note.value), ownerPub: BigInt(rec.note.ownerPub), rho: BigInt(rec.note.rho), r: BigInt(rec.note.r) }));
    nks = inRecs.map((rec) => BigInt(rec.nk));
    const inCms = inNotes.map((n) => commit(n.value, n.ownerPub, n.rho, n.r));
    inCms.forEach((cm, i) => { if (cm !== leaves[IN_IDX[i]]) throw new Error(`in-note ${i} commitment mismatch vs recorded leaf`); });
    if (merklePath(leaves, IN_IDX[0]).root !== oldRoot) throw new Error("recorded leaves do not fold to the recorded pool root");
    const p0 = merklePath(leaves, IN_IDX[0]), p1 = merklePath(leaves, IN_IDX[1]);
    inPathEls = [p0.pathElements, p1.pathElements];
    inPathBits = [p0.pathBits, p1.pathBits];
}

/* action: pv/sign + out-note values under the conservation law */
let pv, sign;
if (ACTION === "deposit" || ACTION === "shield") { pv = AMOUNT; sign = 0n; }
else if (ACTION === "transfer") { pv = 0n; sign = 0n; }
else if (ACTION === "unshield") { pv = AMOUNT; sign = 1n; }
else throw new Error("unknown action " + ACTION);
const inSum = inNotes.reduce((a, n) => a + n.value, 0n);
const outSum = inSum + (sign ? -pv : pv);
if (outSum < 0n) throw new Error(`underfunded unshield: notes hold ${inSum}, requested ${pv}`);

const out0v = outSum * 2n / 5n, out1v = outSum * 3n / 10n, out2v = outSum - out0v - out1v;
const split = OUTS ? OUTS.split(",").map((x) => BigInt(x.trim())) : [out0v, out1v, out2v];
if (split.length !== 3) throw new Error("--outs needs exactly three comma-separated values");
if (split.some((v) => v < 0n)) throw new Error("--outs values must be non-negative");
if (split.reduce((a, v) => a + v, 0n) !== outSum) throw new Error(`--outs must sum to the conservation outSum ${outSum}, got ${split.reduce((a, v) => a + v, 0n)}`);

/* fresh out-note secrets (seeded — recorded in the op JSON so follow-up ops can spend them) */
const outNotes = [0, 1, 2].map((i) => { const nk = modr(rnd()); const v = split[i];
    return { value: v, ownerPub: pubOf(nk), rho: modr(rnd()), r: modr(rnd()), nk }; });
const cm = outNotes.map((n) => commit(n.value, n.ownerPub, n.rho, n.r));
cm.forEach((c, i) => { if (leaves.includes(c)) throw new Error(`out-note ${i} commitment is already a leaf — pass --seed to derive fresh secrets`); });

/* ── the append witness (pool4): three sequential frontier inserts ── */
const appendIndex = leaves.length;
const appendSiblings = [];
let treeLeaves = [...leaves];
for (let k = 0; k < 3; k++) {
    const slot = appendIndex + k;
    const p = merklePath(treeLeaves, slot);       // the off-path siblings of the empty frontier slot
    appendSiblings.push(p.pathElements);
    /* the old-walk fold: the zero leaf at the frontier slot must reconstruct the
       CURRENT tree's root (with cm[0..k-1] already appended) */
    const curRoot = merklePath(treeLeaves, 0).root;
    if (p.root !== curRoot) throw new Error(`append ${k} old-walk does not fold to the current tree root`);
    if (k === 0 && curRoot !== oldRoot) throw new Error("append 0 fold != the stored pool root");
    /* dense-shape rule assert (the circuit enforces the same): sibling[d] == zh[d] <=> bit d == 0 */
    for (let d = 0; d < TREE_DEPTH; d++) {
        const bit = (slot >> d) & 1;
        const isZh = p.pathElements[d] === zeros[d];
        if (bit === 0 && !isZh) throw new Error(`append ${k} level ${d}: bit=0 but sibling != zh — the slot is not the frontier`);
        if (bit === 1 && isZh) throw new Error(`append ${k} level ${d}: bit=1 but sibling == zh — the left neighbor is empty (hole)`);
    }
    treeLeaves.push(cm[k]);
}
/* the chain: oldRoot -(cm0)-> r1 -(cm1)-> r2 -(cm2)-> newMerkleRoot */
const newLeaves = [...leaves, ...cm];
const newMerkleRoot = merklePath(newLeaves, 0).root;

/* ── the nullifiers + the R2 fix ── */
const nf0 = nullifier(nks[0], inNotes[0].rho), nf1 = nullifier(nks[1], inNotes[1].rho);
if (nf0 === nf1) throw new Error("nf0 == nf1 — the v3 circuit forbids nullifier doubling");
const kA = le32(nf0), kB = le32(nf1);           // the carrier's 32-B LE slices = the SMT keys
if (Buffer.compare(kA, kB) === 0) throw new Error("SMT key collision (nf0 == nf1)");

/* ── the SMT walk data for the hook's nullifier-data inputs ── */
const sibsA = smt.siblingsFor(kA);
if (Buffer.compare(smt.walk(Buffer.alloc(32), kA, sibsA), nullSetRoot) !== 0) throw new Error("SMT old-walk A does not fold to the stored nullSetRoot (key already spent?)");
const midRoot = smt.walk(MARKER, kA, sibsA);
const smtAfterA = makeSmt([...spentKeys, kA.toString("hex")]);
if (Buffer.compare(smtAfterA.rootOf(), midRoot) !== 0) throw new Error("midRoot mismatch (walk vs tree)");
const sibsB = smtAfterA.siblingsFor(kB);
if (Buffer.compare(smtAfterA.walk(Buffer.alloc(32), kB, sibsB), midRoot) !== 0) throw new Error("SMT old-walk B does not fold to midRoot (key already spent?)");
const finalNullRoot = smtAfterA.walk(MARKER, kB, sibsB);
const smtAfterB = makeSmt([...spentKeys, kA.toString("hex"), kB.toString("hex")]);
if (Buffer.compare(smtAfterB.rootOf(), finalNullRoot) !== 0) throw new Error("finalNullRoot mismatch (walk vs tree)");

/* ── the witness ── */
const actionHash = actionHashSHA256(nf0, nf1, cm[0], cm[1], cm[2], pv, sign, assetCategory, newMerkleRoot);
const input = { merkleRoot: oldRoot.toString(), actionHash: actionHash.toString(),
    nf: [nf0.toString(), nf1.toString()], cm: cm.map(String),
    publicValueAbs: pv.toString(), publicValueSign: sign.toString(), assetCategoryHi: catHi.toString(), assetCategoryLo: catLo.toString(),
    newMerkleRoot: newMerkleRoot.toString(),
    isDeposit: isDeposit.toString(), appendIndex: appendIndex.toString(),
    appendSiblings: appendSiblings.map((s) => s.map(String)),
    inValue: inNotes.map((n) => n.value.toString()), inOwnerPub: inNotes.map((n) => n.ownerPub.toString()),
    inRho: inNotes.map((n) => n.rho.toString()), inR: inNotes.map((n) => n.r.toString()), nk: nks.map(String),
    inPathElements: inPathEls.map((p) => p.map(String)), inPathBits: inPathBits.map((p) => p.map(String)),
    outValue: outNotes.map((n) => n.value.toString()), outOwnerPub: outNotes.map((n) => n.ownerPub.toString()),
    outRho: outNotes.map((n) => n.rho.toString()), outR: outNotes.map((n) => n.r.toString()) };

console.log(`${ACTION} pv=${pv} sign=${sign} isDeposit=${isDeposit} · inSum=${inSum} → out ${split[0]}+${split[1]}+${split[2]}`);
console.log(`append: index ${appendIndex} → ${appendIndex + 2} · newRoot ${newMerkleRoot.toString().slice(0, 18)}…`);
console.log(`null set: root ${nullSetRoot.toString("hex").slice(0, 16)}… → mid ${midRoot.toString("hex").slice(0, 16)}… → final ${finalNullRoot.toString("hex").slice(0, 16)}… (4/4 walks verified)`);

if (NO_PROVE) {
    /* OUT = the raw circuit input (snarkjs wtns calculate consumes it directly);
       OUT.full = the same record the proving path writes, minus the proof. */
    const jsonStringify = (o) => JSON.stringify(o, (k, v) => (typeof v === "bigint" ? v.toString() : v), 2);
    writeFileSync(OUT, JSON.stringify(input, null, 1));
    writeFileSync(OUT + ".full", jsonStringify({ action: ACTION, pv: pv.toString(), sign: sign.toString(), isDeposit: isDeposit.toString(), outNotes,
        newRoot: newMerkleRoot.toString(), newLeaves: newLeaves.map(String), appendIndex, inIdx: IN_IDX, balanceBefore: balance.toString(),
        nullSet: { sibsA: sibsA.map((s) => s.toString("hex")), midRoot: midRoot.toString("hex"), sibsB: sibsB.map((s) => s.toString("hex")), finalNullRoot: finalNullRoot.toString("hex"),
            keysAdded: [kA.toString("hex"), kB.toString("hex")], nullSetRootBefore: nullSetRoot.toString("hex") } }));
    console.log(`wrote witness-only ${OUT} (+ .full) — no prove`);
    process.exit(0);
}

const t0 = Date.now();
const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
console.log(`proved in ${((Date.now() - t0) / 1000).toFixed(1)}s · n0 ${publicSignals[0].slice(0, 18)}… · n1 ${publicSignals[1].slice(0, 18)}…`);
if (BigInt(publicSignals[0]) !== oldRoot) throw new Error("PROOF n0 != pool root");

/* covenant args (LE VM-number byte forms) that hash to the proof's own n1 */
const cov = { nf0: Buffer.from(bigIntToVmNumber(nf0)).toString("hex"), nf1: Buffer.from(bigIntToVmNumber(nf1)).toString("hex"),
    cm0: Buffer.from(bigIntToVmNumber(cm[0])).toString("hex"), cm1: Buffer.from(bigIntToVmNumber(cm[1])).toString("hex"),
    cm2: Buffer.from(bigIntToVmNumber(cm[2])).toString("hex"),
    newMerkleRoot: Buffer.from(bigIntToVmNumber(newMerkleRoot)).toString("hex"), publicValueAbs: pv.toString(), isUnshield: sign.toString() };

const op = { action: ACTION, pv: pv.toString(), sign: sign.toString(), isDeposit: isDeposit.toString(), proof, publicSignals, covenant: cov,
    outNotes: outNotes.map((n, i) => ({ value: n.value.toString(), ownerPub: n.ownerPub.toString(), rho: n.rho.toString(), r: n.r.toString(), nk: n.nk.toString(), index: leaves.length + i })),
    newRoot: newMerkleRoot.toString(), newLeaves: newLeaves.map(String), appendIndex, inIdx: IN_IDX, balanceBefore: balance.toString(),
    nullSet: { sibsA: sibsA.map((s) => s.toString("hex")), midRoot: midRoot.toString("hex"), sibsB: sibsB.map((s) => s.toString("hex")), finalNullRoot: finalNullRoot.toString("hex"),
        keysAdded: [kA.toString("hex"), kB.toString("hex")], nullSetRootBefore: nullSetRoot.toString("hex") } };
writeFileSync(OUT, JSON.stringify(op, null, 2));
console.log(`wrote ${OUT} · out notes at tree indices ${leaves.length}..${leaves.length + 2}`);
process.exit(0);
