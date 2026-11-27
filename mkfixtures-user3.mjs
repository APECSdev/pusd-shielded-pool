// mkfixtures-v3.mjs — convert the pool4 VK + the 5 v3 proofs into the bench's
// BN_VK_FIXTURES shape ({vk, fixtures}), with a self-verify of every proof.
// Same conversion as gen-fixtures.mjs (the snarkjs -> bench point mapping).
//
// Usage (VM, from ~/zkb/pusd-shielded-pool):
//   ~/bin/node mkfixtures-v3.mjs
// Reads  build4/verification_key_user3.json + /home/apecs/cov/our-v3-user3-proofs.json
// Writes /home/apecs/cov/our-v3-user3.fixtures.json
import * as snarkjs from "snarkjs";
import { readFileSync, writeFileSync } from "fs";

const vk = JSON.parse(readFileSync("build4/verification_key_user3.json", "utf8"));
const proofs = JSON.parse(readFileSync("/home/apecs/cov/our-v3-user3-proofs.json", "utf8"));
const g1 = (p) => ({ x: p[0], y: p[1] });
const g2 = (p) => ({ x: { c0: p[0][0], c1: p[0][1] }, y: { c0: p[1][0], c1: p[1][1] } }); // snarkjs G2 = [[x_c0,x_c1],[y_c0,y_c1]] (real-first)

const fixtures = [];
for (const [i, rec] of proofs.entries()) {
    if (!(await snarkjs.groth16.verify(vk, rec.publicSignals, rec.proof))) throw new Error("fixture " + i + " (" + rec.label + ") self-verify failed");
    fixtures.push({ fixture: i, publicInputs: rec.publicSignals,
        proof: { a: g1(rec.proof.pi_a), b: g2(rec.proof.pi_b), c: g1(rec.proof.pi_c) } });
    console.log("fixture", i, `(${rec.label})`, "verified, n0:", rec.publicSignals[0].slice(0, 16) + "…");
}

const out = {
    artifactSha256: "pool4-v3-07638f10",
    vk: { alpha: g1(vk.vk_alpha_1), beta: g2(vk.vk_beta_2), gamma: g2(vk.vk_gamma_2), delta: g2(vk.vk_delta_2), ic: vk.IC.map(g1) },
    fixtures,
    provenance: "pool4 v4h — the three-contribution mini-MPC (Nito -> Hush -> user); zkey pool4_0003_user.zkey sha256 de7875e3…; VK verification_key_user3.json sha256 f6b49cc0…",
    mapping: "snarkjs -> bench: G1 [x,y,1]; G2 [[x0,x1],[y0,y1],[1,0]]; publicSignals -> publicInputs",
};
writeFileSync("/home/apecs/cov/our-v3-user3.fixtures.json", JSON.stringify(out, null, 2));
console.log("wrote /home/apecs/cov/our-v3-user3.fixtures.json with", fixtures.length, "fixtures, ic.length", out.vk.ic.length);
