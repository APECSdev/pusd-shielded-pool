// probe-v3-negatives.mjs — SPIKE (v3 build session, 2026-11-27).
//
// The pool4 circuit-revision gate: the two demonstrated drains MUST now die at
// the witness level (snarkjs wtns check against build4/pool4.r1cs):
//
//   1. R3-FREE-NEWROOT (probe-freeroot-drain.mjs): a "plant" witness — honest
//      in-notes, honest out-notes, but newMerkleRoot set to the root of a FAKE
//      tree (real leaves + this action's cms + two fabricated notes), with the
//      actionHash recomputed over the fake root so ONLY the append-proof chain
//      can reject it. pool3 ACCEPTED this witness (the drain proofs verified);
//      pool4 must REJECT.
//
//   2. R2-NULLIFIER-DOUBLING (handoff §12): the same recorded note loaded as
//      BOTH in-notes (identical value/ownerPub/rho/r/nk/paths) — a valid pool3
//      witness (the drain proofs verified); pool4 must REJECT via nf0 != nf1.
//
// Also re-asserts the honest control: the UNMUTATED witness must still pass.
//
// Usage (VM, from ~/zkb/pusd-shielded-pool):
//   ~/bin/node spike-nullset/probe-v3-negatives.mjs /tmp/w-transfer.json
// (the argument is the honest witness JSON emitted by role2-op-witness-v3.mjs
//  --no-prove; it must be a TRANSFER on the 3-out state file.)

import { buildPoseidon } from "circomlibjs";
import { readFileSync, writeFileSync, unlinkSync } from "fs";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";

const WIT = process.argv[2];
const SN = "node_modules/snarkjs/cli.js";
const WASM = "build4/pool4_js/pool4.wasm";
const R1CS = "build4/pool4.r1cs";

const poseidon = await buildPoseidon(); const F = poseidon.F;
const H = (...xs) => F.toObject(poseidon(xs));
const be32 = (bi) => { const b = Buffer.alloc(32, 0); let x = BigInt(bi); for (let i = 31; i >= 0 && x > 0n; i--) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; };
function actionHashSHA256(nf0, nf1, cm0, cm1, cm2, pvAbs, pvSign, category, newRoot) {
    const pre = Buffer.concat([be32(nf0), be32(nf1), be32(cm0), be32(cm1), be32(cm2), be32(pvAbs), be32(pvSign), be32(category), be32(newRoot)]);
    const h = createHash("sha256").update(pre).digest(); h[0] &= 0x1f; return BigInt("0x" + h.toString("hex"));
}

const TREE_DEPTH = 20;
const zeros = [0n]; for (let d = 1; d <= TREE_DEPTH; d++) zeros.push(H(zeros[d - 1], zeros[d - 1]));
function merklePath(leaves, index) { const pe = [], pb = []; let idx = index, cur = new Map(leaves.map((v, i) => [i, v]));
    for (let d = 0; d < TREE_DEPTH; d++) { const s = idx % 2 === 0 ? idx + 1 : idx - 1; pe.push(cur.get(s) ?? zeros[d]); pb.push(idx % 2);
        const nx = new Map(), ks = new Set([...cur.keys()].map((k) => k >> 1)); ks.add(idx >> 1);
        for (const k of ks) nx.set(k, H(cur.get(2 * k) ?? zeros[d], cur.get(2 * k + 1) ?? zeros[d])); cur = nx; idx >>= 1; }
    return { pathElements: pe, pathBits: pb, root: cur.get(0) ?? zeros[TREE_DEPTH] }; }

/* wtns calculate + check via the snarkjs CLI; returns true iff the witness is VALID */
function wtnsCheck(name, input, tmp) {
    writeFileSync(tmp, JSON.stringify(input));
    try { unlinkSync(tmp + ".wtns"); } catch {}
    try {
        execFileSync("node", [SN, "wtns", "calculate", WASM, tmp, tmp + ".wtns"], { stdio: "pipe" });
        execFileSync("node", [SN, "wtns", "check", R1CS, tmp + ".wtns"], { stdio: "pipe" });
        console.log(`  ${name}: ACCEPTED (wtns check OK)`);
        return true;
    } catch (e) {
        const msg = String(e.stderr ?? e.stdout ?? e).split("\n").filter((l) => /constraint|Assert|error|Error/i.test(l)).slice(0, 2).join(" | ");
        console.log(`  ${name}: REJECTED — ${msg.slice(0, 140)}`);
        return false;
    }
}

const honest = JSON.parse(readFileSync(WIT, "utf8"));
console.log("== pool4 negative-probe battery (build4) ==");
const okControl = wtnsCheck("honest control (unmutated)", honest, "/tmp/w-ctrl.json");
if (!okControl) throw new Error("the honest control FAILED — the battery is invalid");

/* ── 1. the R3 fake-root plant ── */
const category = (BigInt(honest.assetCategoryHi) << 128n) | BigInt(honest.assetCategoryLo);
/* Mirror the DenseAppend chain forward in JS from the witness's own pieces
   (appendSiblings + appendIndex + cms) to recover the honest new root, then plant a
   DIFFERENT root with the actionHash recomputed over it — exactly the attack of
   probe-freeroot-drain.mjs action A: the ONLY constraint that can reject the
   witness is the append-proof chain. */
const cm = honest.cm.map(BigInt);
const appSib = honest.appendSiblings.map((s) => s.map(BigInt));
const idxBits = (n) => Array.from({ length: TREE_DEPTH }, (_, d) => (Number(BigInt(n)) >> d) & 1);
function walkAppend(oldRoot, leaf, bits, sibs) {
    let oldCur = 0n, newCur = leaf;
    for (let i = 0; i < TREE_DEPTH; i++) {
        const b = bits[i], s = sibs[i];
        oldCur = b ? H(s, oldCur) : H(oldCur, s);
        newCur = b ? H(s, newCur) : H(newCur, s);
    }
    return { oldRootCheck: oldCur, newRoot: newCur };
}
let r = BigInt(honest.merkleRoot);
const bits0 = idxBits(honest.appendIndex), bits1 = idxBits(BigInt(honest.appendIndex) + 1n), bits2 = idxBits(BigInt(honest.appendIndex) + 2n);
const step0 = walkAppend(r, cm[0], bits0, appSib[0]); if (step0.oldRootCheck !== r) throw new Error("mirror walk 0 failed");
r = step0.newRoot;
const step1 = walkAppend(r, cm[1], bits1, appSib[1]); if (step1.oldRootCheck !== r) throw new Error("mirror walk 1 failed");
r = step1.newRoot;
const step2 = walkAppend(r, cm[2], bits2, appSib[2]); if (step2.oldRootCheck !== r) throw new Error("mirror walk 2 failed");
const honestNewRoot = step2.newRoot;
if (honestNewRoot !== BigInt(honest.newMerkleRoot)) throw new Error("mirror chain != witness newMerkleRoot");
console.log(`  (mirror: honest append chain reproduces newMerkleRoot ${honestNewRoot.toString().slice(0, 16)}…)`);

/* The plant: any newMerkleRoot != the chain's honest output. The attacker of
   probe-freeroot-drain.mjs built the fake root from a full leaf list (real leaves
   + fabricated notes); here H(fabLeaf, honestNewRoot) stands for that root — the
   circuit must reject ANY root the chain does not emit. The actionHash is
   recomputed over the fake root so ONLY the append chain can fire. */
const fabLeaf = H(1n, 2n, 3n, 4n);  // a fabricated commitment (value irrelevant)
const fakeRoot = H(fabLeaf, honestNewRoot);
if (fakeRoot === honestNewRoot) throw new Error("degenerate fake root");
const plant = { ...honest, newMerkleRoot: fakeRoot.toString(),
    actionHash: actionHashSHA256(BigInt(honest.nf[0]), BigInt(honest.nf[1]), cm[0], cm[1], cm[2], BigInt(honest.publicValueAbs), BigInt(honest.publicValueSign), category, fakeRoot).toString() };
const r3Rejected = !wtnsCheck("R3 plant (fake newMerkleRoot, actionHash recomputed)", plant, "/tmp/w-plant.json");
if (!r3Rejected) throw new Error("!!! R3 NOT CLOSED — the fake-root witness still passes pool4 !!!");
console.log("  R3-FREE-NEWROOT: CLOSED at the witness level (pool4 rejects the plant)");

/* ── 2. the R2 doubling witness ── */
/* same recorded note as BOTH in-notes: value/ownerPub/rho/r/nk/paths identical */
const dbl = {
    ...honest,
    inValue: [honest.inValue[0], honest.inValue[0]],
    inOwnerPub: [honest.inOwnerPub[0], honest.inOwnerPub[0]],
    inRho: [honest.inRho[0], honest.inRho[0]],
    inR: [honest.inR[0], honest.inR[0]],
    nk: [honest.nk[0], honest.nk[0]],
    inPathElements: [honest.inPathElements[0], honest.inPathElements[0]],
    inPathBits: [honest.inPathBits[0], honest.inPathBits[0]],
    nf: [honest.nf[0], honest.nf[0]],
};
/* conservation with doubled inSum: outSum must grow — scale the out-values (any
   split summing to 2*inValue works; keep the actionHash fields consistent) */
const inSum2 = BigInt(honest.inValue[0]) * 2n;
const outs = [inSum2 * 2n / 5n, inSum2 * 3n / 10n, inSum2 - inSum2 * 2n / 5n - inSum2 * 3n / 10n];
dbl.outValue = outs.map(String);
/* the cms/out-notes change with the new split — the attacker re-derives fresh notes;
   reuse honest cms and just rescale their VALUES (the NoteCommitment constraint
   would fail first if we don't). To isolate nf0!=nf1, keep the ORIGINAL out-notes
   and conservation by scaling pv? transfer has pv=0 — instead make inSum2 == outSum
   by DOUBLING the out-notes: fresh commitments would be needed... For the isolation
   to be exact we rebuild out-notes as commitments over the scaled values: */
const dblCm = outs.map((v, i) => H(v, BigInt(honest.outOwnerPub[i]), BigInt(honest.outRho[i]), BigInt(honest.outR[i])));
dbl.cm = dblCm.map(String);
/* rebuild the append chain for the new cms: same siblings work only if the frontier
   structure is unchanged — the old walks fold the ZERO leaf, so the siblings are
   slot-addressed, not cm-addressed: the chain (merkleRoot, appendIndex, siblings)
   is IDENTICAL; only the emitted roots change. */
let rr = BigInt(honest.merkleRoot);
const s0 = walkAppend(rr, dblCm[0], bits0, appSib[0]); rr = s0.newRoot;
const s1 = walkAppend(rr, dblCm[1], bits1, appSib[1]); rr = s1.newRoot;
const s2 = walkAppend(rr, dblCm[2], bits2, appSib[2]); const dblNewRoot = s2.newRoot;
dbl.newMerkleRoot = dblNewRoot.toString();
dbl.actionHash = actionHashSHA256(BigInt(dbl.nf[0]), BigInt(dbl.nf[1]), dblCm[0], dblCm[1], dblCm[2], BigInt(honest.publicValueAbs), BigInt(honest.publicValueSign), category, dblNewRoot).toString();
const r2Rejected = !wtnsCheck("R2 doubling (same note as both in-notes)", dbl, "/tmp/w-dbl.json");
if (!r2Rejected) throw new Error("!!! R2 NOT CLOSED — the doubling witness still passes pool4 !!!");
console.log("  R2-NULLIFIER-DOUBLING: CLOSED at the witness level (pool4 rejects nf0 == nf1)");
console.log("\nBATTERY PASS: honest control ACCEPTED, both drains REJECTED.");
