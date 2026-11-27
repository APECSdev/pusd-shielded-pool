// gen-pool5-vectors.mjs — the pool5 seed vector + the SHIELD (pv=4) and UNSHIELD (pv=2) proofs
// under the UNCHANGED Nov-13 solo-ceremony zkey (build/pool_final.zkey, 4a4e2543…) + byte-parity circuit.
// Honest seed: notes {1, 0} == holdings 1 FT (the deploy funds holdings with 1 of the user's 5 units;
// the SHIELD brings the remaining 4 — the pool's notes and holdings stay equal at every step).
// Modeled on gen-demo-vector.mjs (the same actionHash formula the deployed covenant recomputes).
//
// LAYOUT GATE (measured this session): the covenant reads n1/n0 from the genesis unlocking at FIXED
// offsets 1792/1825 — valid only when the unlocking is exactly the demo's 7,904 B. genesis[1] =
// bigIntToVmNumber(w.selector) and a selector of 0 encodes to ZERO bytes (a one-byte shrink, which
// shifts every later push). The actionHash push must also be a full 32-byte VM number (BE top byte
// = h[0]&0x1f ≠ 0). Both proofs are gated on this before saving.
import { buildPoseidon } from "/home/apecs/zkb/pusd-shielded-pool/node_modules/circomlibjs/main.js";
import * as snarkjs from "/home/apecs/zkb/tools/node_modules/snarkjs/main.js";
import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";

const ROOT = "/home/apecs/zkb/pusd-shielded-pool";
const WASM = `${ROOT}/build256-vm/pool_js/pool.wasm`;
const ZKEY = `${ROOT}/build/pool_final.zkey`;
const VK_JSON = `${ROOT}/build/verification_key.json`;

const be32 = (bi) => { const b = Buffer.alloc(32, 0); let x = BigInt(bi); for (let i = 31; i >= 0 && x > 0n; i--) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; };
const le32 = (bi) => Buffer.from(be32(bi).reverse());
const hex = (buf) => buf.toString("hex");
function actionHashSHA256(nf0, nf1, cm0, cm1, pvAbs, pvSign, category, newRoot) {
  const preimage = Buffer.concat([be32(nf0), be32(nf1), be32(cm0), be32(cm1), be32(pvAbs), be32(pvSign), be32(category), be32(newRoot)]);
  const h = createHash("sha256").update(preimage).digest();
  h[0] &= 0x1f; // 253-bit truncation — matches the circuit's Bits2Num(253) and the covenant's & 0x1f
  return BigInt("0x" + h.toString("hex"));
}

const TREE_DEPTH = 20;
const poseidon = await buildPoseidon();
const F = poseidon.F;
const H = (...xs) => F.toObject(poseidon(xs));
const commit = (v, o, rho, r) => H(v, o, rho, r), nullifier = (nk, rho) => H(nk, rho);
const zeros = [0n]; for (let d = 1; d <= TREE_DEPTH; d++) zeros.push(H(zeros[d - 1], zeros[d - 1]));
function merklePath(leaves, index) {
  const pe = [], pb = []; let idx = index, cur = new Map(leaves.map((v, i) => [i, v]));
  for (let d = 0; d < TREE_DEPTH; d++) {
    const s = idx % 2 === 0 ? idx + 1 : idx - 1; pe.push(cur.get(s) ?? zeros[d]); pb.push(idx % 2);
    const nx = new Map(), ks = new Set([...cur.keys()].map(k => k >> 1)); ks.add(idx >> 1);
    for (const k of ks) { nx.set(k, H(cur.get(2 * k) ?? zeros[d], cur.get(2 * k + 1) ?? zeros[d])); } cur = nx; idx >>= 1;
  }
  return { pathElements: pe, pathBits: pb, root: cur.get(0) ?? zeros[TREE_DEPTH] };
}
const assetCategory = 0x2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544n;

const vkSnark = JSON.parse(readFileSync(VK_JSON, "utf8"));
const g1 = (p) => ({ x: p[0], y: p[1] });
const g2 = (p) => ({ x: { c0: p[0][0], c1: p[0][1] }, y: { c0: p[1][0], c1: p[1][1] } });

async function prove(name, input, outFile) {
  console.log(`fullProve ${name}...`);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
  if (!(await snarkjs.groth16.verify(vkSnark, publicSignals, proof))) throw new Error(name + " self-verify failed");
  console.log(`  ${name} self-verify OK`);
  const vector = {
    description: `hym pool5 ${name}: solo-ceremony zkey + byte-parity circuit (apecsdev VM)`,
    curve: "bn254 / alt_bn128 (EIP-196/197)", oracle: "solo-ceremony (entropy published)",
    publicInputs: publicSignals,
    vk: { alpha: g1(vkSnark.vk_alpha_1), beta: g2(vkSnark.vk_beta_2), gamma: g2(vkSnark.vk_gamma_2), delta: g2(vkSnark.vk_delta_2), ic: vkSnark.IC.map(g1) },
    proof: { a: g1(proof.pi_a), b: g2(proof.pi_b), c: g1(proof.pi_c) },
  };
  writeFileSync(outFile, JSON.stringify(vector, null, 2));
  return { publicSignals };
}

function buildInput(oldRoot, leaves, inNotes, inIdxs, nks, outs, pv, sign, cmOuts, newRoot, ah, nfs) {
  const p0 = merklePath(leaves, inIdxs[0]), p1 = merklePath(leaves, inIdxs[1]);
  if (p0.root !== oldRoot || p1.root !== oldRoot) throw new Error("path/root mismatch");
  return {
    merkleRoot: oldRoot.toString(), actionHash: ah.toString(),
    nf: [nfs[0].toString(), nfs[1].toString()], cm: [cmOuts[0].toString(), cmOuts[1].toString()],
    publicValueAbs: pv.toString(), publicValueSign: sign.toString(),
    assetCategoryHi: (assetCategory >> 128n).toString(), assetCategoryLo: (assetCategory & ((1n << 128n) - 1n)).toString(),
    newMerkleRoot: newRoot.toString(),
    inValue: [inNotes[0].value.toString(), inNotes[1].value.toString()],
    inOwnerPub: [inNotes[0].ownerPub.toString(), inNotes[1].ownerPub.toString()],
    inRho: [inNotes[0].rho.toString(), inNotes[1].rho.toString()], inR: [inNotes[0].r.toString(), inNotes[1].r.toString()],
    nk: [nks[0].toString(), nks[1].toString()],
    inPathElements: [p0.pathElements.map(String), p1.pathElements.map(String)], inPathBits: [p0.pathBits.map(String), p1.pathBits.map(String)],
    outValue: [outs[0].value.toString(), outs[1].value.toString()], outOwnerPub: [outs[0].ownerPub.toString(), outs[1].ownerPub.toString()],
    outRho: [outs[0].rho.toString(), outs[1].rho.toString()], outR: [outs[0].r.toString(), outs[1].r.toString()],
  };
}

// ── the seed tree (honest: notes sum 1 == holdings 1 FT) ──
const s0 = { value: 1n, ownerPub: 111n, rho: 7001n, r: 8001n }, s1 = { value: 0n, ownerPub: 111n, rho: 7002n, r: 8002n };
const s0c = commit(s0.value, s0.ownerPub, s0.rho, s0.r), s1c = commit(s1.value, s1.ownerPub, s1.rho, s1.r);
const R0 = merklePath([s0c, s1c], 0).root;

// ── OP1: SHIELD pv=4 (the user's remaining 4 units enter; in-notes = the 2 seeds) ──
const sh_nk = [701n, 702n];
const o0 = { value: 3n, ownerPub: 444n, rho: 7101n, r: 8101n }, o1 = { value: 2n, ownerPub: 555n, rho: 7102n, r: 8102n };
const o0c = commit(o0.value, o0.ownerPub, o0.rho, o0.r), o1c = commit(o1.value, o1.ownerPub, o1.rho, o1.r);
const sh_nf = [nullifier(sh_nk[0], s0.rho), nullifier(sh_nk[1], s1.rho)];
const R1 = merklePath([s0c, s1c, o0c, o1c], 0).root;
const sh_pv = 4n, sh_sign = 0n;
const sh_ah = actionHashSHA256(sh_nf[0], sh_nf[1], o0c, o1c, sh_pv, sh_sign, assetCategory, R1);
if (s0.value + s1.value + sh_pv !== o0.value + o1.value) throw new Error("shield conservation broken");

const shInput = buildInput(R0, [s0c, s1c], [s0, s1], [0, 1], sh_nk, [o0, o1], sh_pv, sh_sign, [o0c, o1c], R1, sh_ah, sh_nf);
const shOut = await prove("SHIELD pv=4", shInput, "/home/apecs/matrix/pool5-shield.json");

// ── the layout gate ──
const { produceTransaction } = await import("/home/apecs/zkb/groth16_cashscript/chunked/bn254/densless-msm/transaction.mjs");
const genesisLen = (file) => { const vec = JSON.parse(readFileSync(file, "utf8")); const steps = produceTransaction(vec.vk, vec.proof, vec.publicInputs); return Math.round(steps[3].unlocking.length / 2) };
const shLen = genesisLen("/home/apecs/matrix/pool5-shield.json");
console.log("SHIELD genesis unlocking:", shLen, "B", shLen === 7904 ? "(layout OK)" : "(BAD LAYOUT)");
if (shLen !== 7904) throw new Error("SHIELD layout incompatible with the covenant offsets — re-roll the seed notes");

// ── OP2: UNSHIELD pv=2 (in-notes = the SHIELD's out-notes at leaves 2,3) — re-rolled until layout-compatible ──
const un_nk = [801n, 802n];
const un_pv = 2n, un_sign = 1n;
let unOut, m_un, rhoBase = 7201n;
for (let roll = 1; ; roll++, rhoBase += 7n) {
  const u0 = { value: 2n, ownerPub: 444n, rho: rhoBase, r: 8201n }, u1 = { value: 1n, ownerPub: 555n, rho: rhoBase + 1n, r: 8202n };
  const u0c = commit(u0.value, u0.ownerPub, u0.rho, u0.r), u1c = commit(u1.value, u1.ownerPub, u1.rho, u1.r);
  const un_nf = [nullifier(un_nk[0], o0.rho), nullifier(un_nk[1], o1.rho)];
  const R2 = merklePath([s0c, s1c, o0c, o1c, u0c, u1c], 0).root;
  const un_ah = actionHashSHA256(un_nf[0], un_nf[1], u0c, u1c, un_pv, un_sign, assetCategory, R2);
  if (o0.value + o1.value - un_pv !== u0.value + u1.value) throw new Error("unshield conservation broken");
  const unInput = buildInput(R1, [s0c, s1c, o0c, o1c], [o0, o1], [2, 3], un_nk, [u0, u1], un_pv, un_sign, [u0c, u1c], R2, un_ah, un_nf);
  console.log(`UNSHIELD roll ${roll} (rho ${rhoBase})...`);
  unOut = await prove(`UNSHIELD pv=2 roll ${roll}`, unInput, "/home/apecs/matrix/pool5-unshield.json");
  m_un = {
    merkleRoot: hex(le32(R1)), nf0: hex(le32(un_nf[0])), nf1: hex(le32(un_nf[1])),
    cm0: hex(le32(u0c)), cm1: hex(le32(u1c)), newMerkleRoot: hex(le32(R2)),
    actionHash: hex(le32(un_ah)), publicValueAbs: "2", publicValueSign: "1", isUnshield: "1",
  };
  if (BigInt(unOut.publicSignals[0]) !== R1 || BigInt(unOut.publicSignals[1]) !== un_ah) throw new Error("unshield publicSignals mismatch");
  const len = genesisLen("/home/apecs/matrix/pool5-unshield.json");
  const ahTop = parseInt(m_un.actionHash.slice(-2), 16);
  console.log(`  genesis unlocking: ${len} B | actionHash BE top byte: 0x${ahTop.toString(16).padStart(2, "0")}`);
  if (len === 7904 && ahTop !== 0) { console.log("  LAYOUT OK — using this roll"); break }
  console.log("  layout incompatible — re-rolling");
}

// ── the covenant-args metas (LE-hex forms, exactly like op-meta.json) ──
const metas = {
  seed: { rootLE: hex(le32(R0)), leaves: [hex(le32(s0c)), hex(le32(s1c))] },
  shield: {
    merkleRoot: hex(le32(R0)), nf0: hex(le32(sh_nf[0])), nf1: hex(le32(sh_nf[1])),
    cm0: hex(le32(o0c)), cm1: hex(le32(o1c)), newMerkleRoot: hex(le32(R1)),
    actionHash: hex(le32(sh_ah)), publicValueAbs: "4", publicValueSign: "0", isUnshield: "0",
  },
  unshield: m_un,
};
if (BigInt(shOut.publicSignals[0]) !== R0 || BigInt(shOut.publicSignals[1]) !== sh_ah) throw new Error("shield publicSignals mismatch");
writeFileSync("/home/apecs/matrix/pool5-metas.json", JSON.stringify(metas, null, 1));
console.log("wrote pool5-metas.json");
console.log("R0 LE:", metas.seed.rootLE.slice(0, 32), "…");
console.log("ALL POOL5 VECTORS DONE");
process.exit(0);
