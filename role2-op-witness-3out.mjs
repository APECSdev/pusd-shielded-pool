// role2-op-witness-3out.mjs — generate + prove the REAL pool-action witness for the
// 3-output (v3) role-2 pool.
//
// Path: pusd-shielded-pool/role2-op-witness-3out.mjs
//
// role2-op-witness.mjs adapted to the measured 3-out circuit (build3/):
//   - three output notes (cm[3], outValue[3], outOwnerPub[3], outRho[3], outR[3]);
//   - the 9-field actionHash preimage:
//       nf0|nf1|cm0|cm1|cm2|pvAbs|pvSign|assetCategory|newMerkleRoot   (288 bytes)
//   - the new tree appends THREE commitments (leaves.length + 3).
//
// Reads the deployment state file (role2-pool3-state.json, written by
// pool-deploy-role2.mjs with POOL_3OUT=1), builds the circuit witness against the pool's
// ACTUAL state (the public bootstrap seed notes for op 1, the recorded notes thereafter),
// proves it with snarkjs against the 1-of-1 demo setup (build3/pool3_final.zkey, sha256
// b0177dbe… — VM-local, runner-free), and writes the op JSON (proof + publicSignals +
// covenant args incl. cm2 + out-notes) that pool-op-role2.mjs --3out consumes.
//
// Usage (VM, from ~/zkb/pusd-shielded-pool):
//   ~/bin/node role2-op-witness-3out.mjs --action shield   --amount 1000000
//   ~/bin/node role2-op-witness-3out.mjs --action transfer --in 2,3
//   ~/bin/node role2-op-witness-3out.mjs --action unshield --amount N --in 2,3
// State file + op out default to /home/apecs/cov/role2-pool3-state.json + role2-op3.json.
//
// --outs a,b,c overrides the default 40/30/30 split with explicit out-note values that
// MUST sum to the conservation law's outSum. A zero value is legal (pool3.circom only
// RangeChecks each outValue and constrains sumIn + signedPublic === sumOut), so
// `--outs 400,20,0` expresses a 2-out flow through the 3-out circuit — the design's
// "zero-value dummy third note". The tree still appends THREE leaves; the dummy costs a
// leaf, not a note.
//
// --seed <tag> appends a tag to the out-note secret derivation. The default seed is
// `role2-op3-<deployTxid>-<action>-<amount>`, so two actions with the same action/amount
// would derive the SAME secrets; distinct out VALUES still give distinct commitments,
// but identical values would duplicate a leaf. Pass --seed when in doubt; the duplicate
// guard below refuses to prove a commitment that is already in the tree.
import { buildPoseidon, buildBabyjub } from "circomlibjs";
import * as snarkjs from "snarkjs";
import { readFileSync, writeFileSync } from "fs";
import { createHash } from "node:crypto";

const argOf = (n, d) => { const i = process.argv.indexOf(n); return i >= 0 ? process.argv[i + 1] : d; };
const ACTION = argOf("--action", "shield");
const AMOUNT = BigInt(argOf("--amount", "1000000"));
const IN_IDX = (argOf("--in", "0,1")).split(",").map(Number);
const OUTS = argOf("--outs", "");
const SEED = argOf("--seed", "");
const STATE = argOf("--state", "/home/apecs/cov/role2-pool3-state.json");
const OUT = argOf("--out", "/home/apecs/cov/role2-op3.json");
const WASM = argOf("--wasm", "build3/pool3_js/pool3.wasm");
const ZKEY = argOf("--zkey", "build3/pool3_final.zkey");

const be32 = (bi) => { const b = Buffer.alloc(32, 0); let x = BigInt(bi); for (let i = 31; i >= 0 && x > 0n; i--) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; };
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

/* the deployed pool state */
const state = JSON.parse(readFileSync(STATE, "utf8"));
const assetCategory = BigInt("0x" + state.category);
const catHi = assetCategory >> 128n, catLo = assetCategory & ((1n << 128n) - 1n);
const oldRoot = BigInt(state.pool.root);
const leaves = state.pool.leaves.map(BigInt);
const balance = BigInt(state.pool.balance);

/* the two in-notes: the pool's recorded notes (bootstrap seeds for op 1) */
const inRecs = IN_IDX.map((ix) => state.pool.notes.find((n) => Number(n.index) === ix));
if (inRecs.some((r) => !r)) throw new Error("no recorded note at tree index " + IN_IDX.join("/") + " — indices are TREE positions (bootstrap seeds live at 0/1)");
if (inRecs.length !== 2) throw new Error("the circuit spends exactly 2 in-notes");
const inNotes = inRecs.map((rec) => ({ value: BigInt(rec.note.value), ownerPub: BigInt(rec.note.ownerPub), rho: BigInt(rec.note.rho), r: BigInt(rec.note.r) }));
const nks = inRecs.map((rec) => BigInt(rec.nk));

/* self-check: the recorded leaves are exactly these notes' commitments, and the pool root
   is the tree over them (bootstrap seeds: verified against the chain-deployed root). */
const inCms = inNotes.map((n) => commit(n.value, n.ownerPub, n.rho, n.r));
inCms.forEach((cm, i) => { if (cm !== leaves[IN_IDX[i]]) throw new Error(`in-note ${i} commitment mismatch vs recorded leaf`); });
if (merklePath(leaves, IN_IDX[0]).root !== oldRoot) throw new Error("recorded leaves do not fold to the recorded pool root");

/* action: pv/sign + out-note values under the conservation law
   in0+in1+(sign?-pv:+pv) == out0+out1+out2 */
let pv, sign;
if (ACTION === "shield") { pv = AMOUNT; sign = 0n; }
else if (ACTION === "transfer") { pv = 0n; sign = 0n; }
else if (ACTION === "unshield") { pv = AMOUNT; sign = 1n; }
else throw new Error("unknown action " + ACTION);
const inSum = inNotes.reduce((a, n) => a + n.value, 0n);
const outSum = inSum + (sign ? -pv : pv);
if (outSum < 0n) throw new Error(`underfunded unshield: notes hold ${inSum}, requested ${pv}`);
/* the 3-out split: 40/30/30 (deterministic, recorded) — the note-management shape.
   --outs a,b,c overrides it; the values must still satisfy the conservation law, and a
   zero is legal (RangeCheck(0) passes) — that is the zero-value dummy third note. */
const out0v = outSum * 2n / 5n, out1v = outSum * 3n / 10n, out2v = outSum - out0v - out1v;
const split = OUTS ? OUTS.split(",").map((x) => BigInt(x.trim())) : [out0v, out1v, out2v];
if (split.length !== 3) throw new Error("--outs needs exactly three comma-separated values");
if (split.some((v) => v < 0n)) throw new Error("--outs values must be non-negative");
const splitSum = split.reduce((a, v) => a + v, 0n);
if (splitSum !== outSum) throw new Error(`--outs must sum to the conservation outSum ${outSum}, got ${splitSum}`);

/* fresh out-note secrets (seeded — recorded in the op JSON so follow-up ops can spend them).
   Each note carries its own nullifier key nk with ownerPub = x(nk · G) on BabyJubJub — the
   bootstrap-note convention — WITHOUT this, a randomly-chosen ownerPub has no known nk and
   the note could never be spent again. */
const bbj = await buildBabyjub();
const rng = (seed) => { let c = 0; return () => BigInt("0x" + createHash("sha256").update(`${seed}:${c++}`).digest("hex")); };
const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const modr = (x) => ((x % R) + R) % R;
const pubOf = (nk) => { const p = bbj.mulPointEscalar(bbj.Base8, nk); const x = BigInt(F.toObject(p[0])); if (x >= R) throw new Error("babyjub x >= field prime"); return x; };
const rnd = rng(`role2-op3-${state.deployTxid}-${ACTION}-${AMOUNT}${SEED ? "-" + SEED : ""}`);
const outNotes = [0, 1, 2].map((i) => { const nk = modr(rnd()); const v = split[i];
    return { value: v, ownerPub: pubOf(nk), rho: modr(rnd()), r: modr(rnd()), nk }; });
const cm = outNotes.map((n) => commit(n.value, n.ownerPub, n.rho, n.r));
/* a duplicate leaf would be unspendable-by-index ambiguity; refuse before proving */
cm.forEach((c, i) => { if (leaves.includes(c)) throw new Error(`out-note ${i} commitment is already a leaf — pass --seed to derive fresh secrets`); });

/* the witness */
const p0 = merklePath(leaves, IN_IDX[0]), p1 = merklePath(leaves, IN_IDX[1]);
const nf0 = nullifier(nks[0], inNotes[0].rho), nf1 = nullifier(nks[1], inNotes[1].rho);
const newLeaves = [...leaves, ...cm];
const newMerkleRoot = merklePath(newLeaves, 0).root;
const actionHash = actionHashSHA256(nf0, nf1, cm[0], cm[1], cm[2], pv, sign, assetCategory, newMerkleRoot);
const input = { merkleRoot: oldRoot.toString(), actionHash: actionHash.toString(),
    nf: [nf0.toString(), nf1.toString()], cm: cm.map(String),
    publicValueAbs: pv.toString(), publicValueSign: sign.toString(), assetCategoryHi: catHi.toString(), assetCategoryLo: catLo.toString(),
    newMerkleRoot: newMerkleRoot.toString(),
    inValue: inNotes.map((n) => n.value.toString()), inOwnerPub: inNotes.map((n) => n.ownerPub.toString()),
    inRho: inNotes.map((n) => n.rho.toString()), inR: inNotes.map((n) => n.r.toString()), nk: nks.map(String),
    inPathElements: [p0.pathElements.map(String), p1.pathElements.map(String)], inPathBits: [p0.pathBits.map(String), p1.pathBits.map(String)],
    outValue: outNotes.map((n) => n.value.toString()), outOwnerPub: outNotes.map((n) => n.ownerPub.toString()),
    outRho: outNotes.map((n) => n.rho.toString()), outR: outNotes.map((n) => n.r.toString()) };

console.log(`${ACTION} pv=${pv} sign=${sign} · inSum=${inSum} → out ${split[0]}+${split[1]}+${split[2]}${split.some((v) => v === 0n) ? " (zero-value dummy: a 2-out flow)" : ""}`);
const t0 = Date.now();
const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
console.log(`proved in ${((Date.now() - t0) / 1000).toFixed(1)}s · n0 ${publicSignals[0].slice(0, 18)}… · n1 ${publicSignals[1].slice(0, 18)}…`);
if (BigInt(publicSignals[0]) !== oldRoot) throw new Error("PROOF n0 != pool root");

/* covenant args (LE VM-number byte forms) that hash to the proof's own n1 */
const cov = { nf0: Buffer.from(bigIntToVmNumber(nf0)).toString("hex"), nf1: Buffer.from(bigIntToVmNumber(nf1)).toString("hex"),
    cm0: Buffer.from(bigIntToVmNumber(cm[0])).toString("hex"), cm1: Buffer.from(bigIntToVmNumber(cm[1])).toString("hex"),
    cm2: Buffer.from(bigIntToVmNumber(cm[2])).toString("hex"),
    newMerkleRoot: Buffer.from(bigIntToVmNumber(newMerkleRoot)).toString("hex"), publicValueAbs: pv.toString(), isUnshield: sign.toString() };

const op = { action: ACTION, pv: pv.toString(), sign: sign.toString(), proof, publicSignals, covenant: cov,
    outNotes: outNotes.map((n, i) => ({ value: n.value.toString(), ownerPub: n.ownerPub.toString(), rho: n.rho.toString(), r: n.r.toString(), nk: n.nk.toString(), index: leaves.length + i })),
    newRoot: newMerkleRoot.toString(), newLeaves: newLeaves.map(String), inIdx: IN_IDX, balanceBefore: balance.toString() };
writeFileSync(OUT, JSON.stringify(op, null, 2));
console.log(`wrote ${OUT} · out notes at tree indices ${leaves.length}..${leaves.length + 2}`);
process.exit(0);
