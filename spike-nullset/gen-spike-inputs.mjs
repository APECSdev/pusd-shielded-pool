// gen-spike-inputs.mjs — SPIKE (nullifier-set depth measurement, 2026-11-26).
//
// Builds TWO circuit inputs from the live 3-out pool state
// (/home/apecs/cov/role2-pool3-state.json), prove-free (witness only):
//
//   build/spike-input-pool3.json     — a valid input for the CURRENT
//                                      circuits/pool3.circom (9-field actionHash)
//                                      — the wtns timing anchor.
//   build/spike-input-v3null-<D>.json — a valid input for pool3_v3null.circom
//                                      (11-field actionHash + the nullifier-set
//                                      signals: empty genesis tree, two
//                                      sequential inserts at depth D).
//
// The note/tree/nullifier/commitment logic is copied from the PROVEN
// role2-op-witness-3out.mjs (same state file, same merklePath, same
// commitment/nullifier derivations, same be32+SHA256 actionHash packing);
// only the out-note secrets are re-seeded (fixed spike seed) and the
// actionHash gains the two nullifier-root fields for the v3 variant.
//
// Self-checks before writing: every JS-mirrored walk must land exactly on the
// tree roots; `snarkjs wtns check` against the compiled r1cs is the final gate.
//
// Usage: node gen-spike-inputs.mjs [D=254]

import { buildPoseidon, buildBabyjub } from "circomlibjs";
import { readFileSync, writeFileSync, unlinkSync } from "fs";
import { createHash } from "node:crypto";

const D = parseInt(process.argv[2] ?? "254", 10);
const STATE = "/home/apecs/cov/role2-pool3-state.json";

const poseidon = await buildPoseidon();
const F = poseidon.F;
const H = (...xs) => F.toObject(poseidon(xs));
const commit = (v, o, rho, r) => H(v, o, rho, r);
const nullifier = (nk, rho) => H(nk, rho);

// ---- the proven actionHash packing (role2-op-witness-3out.mjs) ----
const be32 = (bi) => { const b = Buffer.alloc(32, 0); let x = BigInt(bi); for (let i = 31; i >= 0 && x > 0n; i--) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; };
const shaAction = (...fields) => {
    const h = createHash("sha256").update(Buffer.concat(fields.map(be32))).digest();
    h[0] &= 0x1f;
    return BigInt("0x" + h.toString("hex"));
};

// ---- the proven note-tree path walker (role2-op-witness-3out.mjs) ----
const TREE_DEPTH = 20;
const zeros = [0n];
for (let d = 1; d <= TREE_DEPTH; d++) zeros.push(H(zeros[d - 1], zeros[d - 1]));
function merklePath(leaves, index) {
    const pe = [], pb = [];
    let idx = index, cur = new Map(leaves.map((v, i) => [i, v]));
    for (let d = 0; d < TREE_DEPTH; d++) {
        const s = idx % 2 === 0 ? idx + 1 : idx - 1;
        pe.push(cur.get(s) ?? zeros[d]); pb.push(idx % 2);
        const nx = new Map(), ks = new Set([...cur.keys()].map((k) => k >> 1)); ks.add(idx >> 1);
        for (const k of ks) nx.set(k, H(cur.get(2 * k) ?? zeros[d], cur.get(2 * k + 1) ?? zeros[d]));
        cur = nx; idx >>= 1;
    }
    return { pathElements: pe, pathBits: pb, root: cur.get(0) ?? zeros[TREE_DEPTH] };
}

// ---- the live pool state ----
const state = JSON.parse(readFileSync(STATE, "utf8"));
const assetCategory = BigInt("0x" + state.category);
const catHi = assetCategory >> 128n, catLo = assetCategory & ((1n << 128n) - 1n);
const oldRoot = BigInt(state.pool.root);
const leaves = state.pool.leaves.map(BigInt);

// the two in-notes: the two lowest-index RECORDED notes (a transfer, pv=0)
const IN_IDX = state.pool.notes.map((n) => Number(n.index)).sort((a, b) => a - b).slice(0, 2);
const inRecs = IN_IDX.map((ix) => state.pool.notes.find((n) => Number(n.index) === ix));
if (inRecs.some((r) => !r)) throw new Error("no recorded note at " + IN_IDX.join("/"));
const inNotes = inRecs.map((rec) => ({ value: BigInt(rec.note.value), ownerPub: BigInt(rec.note.ownerPub), rho: BigInt(rec.note.rho), r: BigInt(rec.note.r) }));
const nks = inRecs.map((rec) => BigInt(rec.nk));
const inCms = inNotes.map((n) => commit(n.value, n.ownerPub, n.rho, n.r));
inCms.forEach((cm, i) => { if (cm !== leaves[IN_IDX[i]]) throw new Error(`in-note ${i} commitment mismatch vs recorded leaf`); });
if (merklePath(leaves, IN_IDX[0]).root !== oldRoot) throw new Error("recorded leaves do not fold to the recorded pool root");

// transfer: pv=0, sign=0, outSum = inSum, 40/30/30 split
const pv = 0n, sign = 0n;
const inSum = inNotes.reduce((a, n) => a + n.value, 0n);
const outSum = inSum;
const split = [outSum * 2n / 5n, outSum * 3n / 10n, outSum - outSum * 2n / 5n - outSum * 3n / 10n];

// fresh out-note secrets (fixed spike seed, recorded in the emitted inputs)
const bbj = await buildBabyjub();
const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const modr = (x) => ((x % R) + R) % R;
const pubOf = (nk) => { const p = bbj.mulPointEscalar(bbj.Base8, nk); const x = BigInt(F.toObject(p[0])); if (x >= R) throw new Error("babyjub x >= field prime"); return x; };
const rng = (seed) => { let c = 0; return () => BigInt("0x" + createHash("sha256").update(`${seed}:${c++}`).digest("hex")); };
const rnd = rng("spike-nullset-2026-11-26");
const outNotes = [0, 1, 2].map((i) => { const nk = modr(rnd()); const v = split[i];
    return { value: v, ownerPub: pubOf(nk), rho: modr(rnd()), r: modr(rnd()), nk }; });
const cm = outNotes.map((n) => commit(n.value, n.ownerPub, n.rho, n.r));
cm.forEach((c, i) => { if (leaves.includes(c)) throw new Error(`out-note ${i} commitment is already a leaf`); });

// witness values
const p0 = merklePath(leaves, IN_IDX[0]), p1 = merklePath(leaves, IN_IDX[1]);
const nf0 = nullifier(nks[0], inNotes[0].rho), nf1 = nullifier(nks[1], inNotes[1].rho);
const newLeaves = [...leaves, ...cm];
const newMerkleRoot = merklePath(newLeaves, 0).root;

const common = {
    merkleRoot: oldRoot.toString(),
    nf: [nf0.toString(), nf1.toString()],
    cm: cm.map(String),
    publicValueAbs: pv.toString(), publicValueSign: sign.toString(),
    assetCategoryHi: catHi.toString(), assetCategoryLo: catLo.toString(),
    newMerkleRoot: newMerkleRoot.toString(),
    inValue: inNotes.map((n) => n.value.toString()), inOwnerPub: inNotes.map((n) => n.ownerPub.toString()),
    inRho: inNotes.map((n) => n.rho.toString()), inR: inNotes.map((n) => n.r.toString()), nk: nks.map(String),
    inPathElements: [p0.pathElements.map(String), p1.pathElements.map(String)],
    inPathBits: [p0.pathBits.map(String), p1.pathBits.map(String)],
    outValue: outNotes.map((n) => n.value.toString()), outOwnerPub: outNotes.map((n) => n.ownerPub.toString()),
    outRho: outNotes.map((n) => n.rho.toString()), outR: outNotes.map((n) => n.r.toString()),
};

// input 1: the CURRENT pool3 circuit (9-field actionHash) — the anchor
const actionHash9 = shaAction(nf0, nf1, cm[0], cm[1], cm[2], pv, sign, assetCategory, newMerkleRoot);
const pool3Input = { ...common, actionHash: actionHash9.toString() };
writeFileSync("build/spike-input-pool3.json", JSON.stringify(pool3Input, null, 1));

// ---- input 2: pool3_v3null (11-field actionHash + the nullifier set) ----
// empty genesis nullifier tree at depth D; two sequential inserts.
const zh = [0n];
for (let i = 1; i <= D; i++) zh.push(H(zh[i - 1], zh[i - 1]));
const keyOf = (nf) => nf & ((1n << BigInt(D)) - 1n);

const S = new Set();
const memo = new Map();
function subtree(mk, mask, h) {
    const id = `${mk & mask}|${mask}|${h}`;
    if (memo.has(id)) return memo.get(id);
    let any = false;
    for (const k of S) if ((k & mask) === (mk & mask)) { any = true; break; }
    let r;
    if (!any) r = zh[h];
    else if (h === 0) r = 1n;
    else {
        const bitMask = 1n << BigInt(h - 1);
        const mask2 = mask | bitMask;
        const L = subtree(mk & ~bitMask, mask2, h - 1);
        const R2 = subtree(mk | bitMask, mask2, h - 1);
        r = H(L, R2);
    }
    memo.set(id, r);
    return r;
}
const rootOf = () => subtree(0n, 0n, D);
const highMask = (from) => ((1n << BigInt(D - from)) - 1n) << BigInt(from);
function siblingsFor(k) {
    const sib = [];
    // the step-i sibling is the height-i node on the other side of bit i:
    // keys agreeing with k on bits i..D-1 (mask INCLUDES bit i — the node
    // address is bits i..D-1 from the root down), bit i flipped. The subtree
    // recursion accumulates the lower bits into the mask as it descends, so
    // at h=0 the mask is the full key (the exact leaf slot).
    for (let i = 0; i < D; i++) sib.push(subtree(k ^ (1n << BigInt(i)), highMask(i), i));
    return sib;
}
// JS mirror of the circuit's dual-walk — the cross-check of both wire sides
function walk(leafVal, key, sibs) {
    let cur = leafVal;
    for (let i = 0; i < D; i++) {
        const bit = (key >> BigInt(i)) & 1n;
        const left = bit ? sibs[i] : cur;
        const right = bit ? cur : sibs[i];
        cur = H(left, right);
    }
    return cur;
}

const k0 = keyOf(nf0), k1 = keyOf(nf1);
if (k0 === k1) throw new Error("nullifier keys collide at D=" + D);

const oldNullRoot = rootOf();
const sib0 = siblingsFor(k0);
if (walk(0n, k0, sib0) !== oldNullRoot) throw new Error("old walk 0 mismatch");
const rootA_walk = walk(1n, k0, sib0);
S.add(k0);
memo.clear();
const rootA = rootOf();
if (rootA !== rootA_walk) throw new Error("rootA mismatch (walk vs tree)");

const sib1 = siblingsFor(k1);
if (walk(0n, k1, sib1) !== rootA) throw new Error("old walk 1 mismatch");
const newNullRoot_walk = walk(1n, k1, sib1);
S.add(k1);
memo.clear();
const newNullRoot = rootOf();
if (newNullRoot !== newNullRoot_walk) throw new Error("newNullRoot mismatch (walk vs tree)");

const actionHash11 = shaAction(nf0, nf1, cm[0], cm[1], cm[2], pv, sign, assetCategory, newMerkleRoot, oldNullRoot, newNullRoot);
const v3Input = {
    ...common,
    actionHash: actionHash11.toString(),
    oldNullRoot: oldNullRoot.toString(),
    newNullRoot: newNullRoot.toString(),
    nfSiblings: [sib0.map(String), sib1.map(String)],
};
const out = `build/spike-input-v3null-${D}.json`;
writeFileSync(out, JSON.stringify(v3Input, null, 1));

console.log(`D=${D}: in-notes at tree ${IN_IDX.join(",")} (values ${inNotes.map((n) => n.value).join("+")} → out ${split.join("+")})`);
console.log(`null tree: oldNullRoot=${oldNullRoot.toString().slice(0, 16)}… rootA=${rootA.toString().slice(0, 16)}… newNullRoot=${newNullRoot.toString().slice(0, 16)}… (4/4 walks verified)`);
console.log(`wrote build/spike-input-pool3.json and ${out}`);
try { unlinkSync("build/v3null-input-" + D + ".json"); } catch {}
