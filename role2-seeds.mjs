// role2-seeds.mjs — the PUBLIC bootstrap seed notes + genesis tree for the role-2 pool.
// Same published constants as the nito.cash deployments (deploy-pool.mjs BOOTSTRAP_SEED:
// value 0, nk = 1, ASCII rho/r) so any wallet can bootstrap its first action; the genesis
// root they produce must equal the chain-deployed v2/v4 genesis root LE 551108f6…510f
// (both nito pools carry it in their state NFTs), which self-checks this derivation
// against on-chain ground truth. Deterministic; run to print the constants.
import { buildPoseidon, buildBabyjub } from "circomlibjs";

const poseidon = await buildPoseidon(); const F = poseidon.F;
const H = (...xs) => BigInt(F.toObject(poseidon(xs.map((x) => BigInt(x)))));
const bb = await buildBabyjub();
const BOOTSTRAP_NK = 1n;
const BOOTSTRAP_SEED = [
    { rho: 0x626f6f7473747261702d736565642d30n, r: 0x736565642d302d6e69746f2d706f6f6cn },
    { rho: 0x626f6f7473747261702d736565642d31n, r: 0x736565642d312d6e69746f2d706f6f6cn },
];
const bootPub = BigInt(F.toObject(bb.mulPointEscalar(bb.Base8, BOOTSTRAP_NK)[0]));
const seedNotes = BOOTSTRAP_SEED.map((s) => ({ value: 0n, ownerPub: bootPub, rho: s.rho, r: s.r }));
const genesisLeaves = seedNotes.map((n) => H(n.value, n.ownerPub, n.rho, n.r));
const zeros = [0n]; for (let d = 1; d <= 20; d += 1) zeros.push(H(zeros[d - 1], zeros[d - 1]));
const fold = (leaves) => { let level = leaves.slice();
    for (let d = 0; d < 20; d += 1) { const next = []; for (let i = 0; i < level.length; i += 2) next.push(H(level[i], (i + 1 < level.length) ? level[i + 1] : zeros[d])); level = next; }
    return level[0]; };
const seededRoot = fold(genesisLeaves);
const le = (v) => { const out = new Uint8Array(32); let x = BigInt(v); for (let i = 0; i < 32; i += 1) { out[i] = Number(x & 0xffn); x >>= 8n; } return out; };
const hex = (b) => Buffer.from(b).toString("hex");
console.log(JSON.stringify({
    seededRoot: seededRoot.toString(),
    seededRootHex: seededRoot.toString(16),
    seededRootLE: hex(le(seededRoot)),
    genesisCommitment: hex(le(seededRoot)) + "00".repeat(32),
    genesisLeaves: genesisLeaves.map(String),
    bootstrapNotes: seedNotes.map((n, i) => ({ note: { value: "0", ownerPub: n.ownerPub.toString(), rho: n.rho.toString(), r: n.r.toString() }, nk: "1", index: i })),
}, null, 2));
process.exit(0);
