// pool-info.mjs — print the HOOKED program's code / R / locking under the current VK
// and carrier layout. The hooked build cannot go through stock build.mjs (its smoke
// test builds tokenless source outputs, which the pool hook rejects at check 2);
// this is the small deterministic build the deploy/acceptance/sweep tooling uses.
//
//   BN_VK_FIXTURES=/home/apecs/cov/our.fixtures.json      node pool-info.mjs        (2-out)
//   BN_VK_FIXTURES=/home/apecs/cov/our-3out.fixtures.json POOL_3OUT=1 node pool-info.mjs
import { createHash } from 'node:crypto';
import { binToHex } from '@bitauth/libauth';
import { buildProgram, setCovenant } from './script.mjs';
import { covenantHook, covenantParams } from './pool-hook.mjs';
import { p2sh32 } from './vm.mjs';

const OUTS = process.env.POOL_3OUT === '1' ? 3 : 2;
const CATEGORY_ONCHAIN = process.env.POOL_CATEGORY_ONCHAIN
    || Buffer.from('2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544', 'hex').reverse().toString('hex');
const sha = (b) => createHash('sha256').update(b).digest('hex');

setCovenant(covenantHook(covenantParams({ categoryOnChain: CATEGORY_ONCHAIN }), OUTS));
const prog = buildProgram();
const lock = p2sh32(prog.R);
console.log(JSON.stringify({
    outs: OUTS,
    codeBytes: prog.code.length,
    codeSha256: sha(prog.code),
    redeemBytes: prog.R.length,
    redeemHex: binToHex(prog.R),
    redeemSha256: sha(prog.R),
    lockingHex: binToHex(lock),
    lockingSha256: sha(lock),
    codePieces: prog.pieces.map((p) => p.length),
    roleCode: prog.info.roles,
    prologueBytes: prog.info.prologue,
}, null, 1));
