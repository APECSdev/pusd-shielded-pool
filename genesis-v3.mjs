// genesis-v3.mjs — the v3 pool's GENESIS CONSTANTS, computed from first principles.
//
// The v3 genesis state is EMPTY on BOTH halves of the 64-B state NFT commitment
// (docs/V3-BUILD-2026-11-27.md §3.1: the bootstrap-seed dependency is GONE — the
// first notes enter via a DEPOSIT; the nullifier set starts empty by definition):
//
//   commitment = LE32(zh[20]) ‖ EMPTY_NULL_ROOT     (64 B)
//     zh[20]           — the depth-20 Poseidon zero-hash ladder's top, the root of
//                        the EMPTY note tree (the same ladder noteappend.circom
//                        hardcodes and role2-op-witness-v3.mjs self-checks).
//     EMPTY_NULL_ROOT  — the 254-level SHA256 zero fold, the root of the EMPTY
//                        nullifier SMT (walk-scripts.mjs computes the same value).
//
// Both constants are asserted against the recorded session-verified values at
// import time (AGENTS 2026-11-27 overnight handoff; V3-BUILD §3.1) — any drift
// in the ladder implementations fails loudly.
//
// Lives in the pool repo root (not wip-role2-hook) because zh[20] needs circomlibjs,
// which resolves from THIS repo's node_modules; the bench-side v3 deploy imports
// it by relative path and its own bench deps keep resolving from the bench.
import { buildPoseidon } from 'circomlibjs';
import { createHash } from 'node:crypto';

const poseidon = await buildPoseidon(); const F = poseidon.F;
const H = (...xs) => F.toObject(poseidon(xs));

/* zh[20]: the depth-20 Poseidon zero-hash ladder */
const zeros = [0n];
for (let d = 1; d <= 20; d++) zeros.push(H(zeros[d - 1], zeros[d - 1]));
export const ZH20 = zeros[20];
if (ZH20 !== 15019797232609675441998260052101280400536945603062888308240081994073687793470n) throw new Error('zh[20] drifted from the recorded constant — the Poseidon zero ladder changed');
if (zeros[0] !== 0n) throw new Error('zero ladder base');

/* EMPTY_NULL_ROOT: the 254-level SHA256 zero fold (walk-scripts.mjs's exact fold) */
const sha = (b) => createHash('sha256').update(b).digest();
let z = Buffer.alloc(32);
for (let i = 0; i < 254; i++) z = sha(Buffer.concat([z, z]));
export const EMPTY_NULL_ROOT = z;
if (EMPTY_NULL_ROOT.toString('hex') !== 'e579b9be0b8f58daacc4f66c959ed3ec903884d1914e11e7e0c3bbf2a5627b43') throw new Error('EMPTY_NULL_ROOT drifted from the recorded constant — the SHA256 zero fold changed');

/* the 64-B genesis state NFT commitment = LE32(zh[20]) ‖ EMPTY_NULL_ROOT */
const be32 = (v) => { const b = Buffer.alloc(32); let x = BigInt(v); for (let i = 31; i >= 0 && x > 0n; i--) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; };
export const LE32_ZH20 = Buffer.from(be32(ZH20)).reverse();
export const GENESIS_COMMITMENT = Buffer.concat([LE32_ZH20, EMPTY_NULL_ROOT]);
