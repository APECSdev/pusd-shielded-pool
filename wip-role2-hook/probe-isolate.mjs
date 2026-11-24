// probe-isolate.mjs — hooked program + carrier, tokens present vs absent: which combination flips the carrier?
import { readFileSync } from 'node:fs';
import { VMS, p2sh32 } from './vm.mjs';
import { buildProgram, setCovenant } from './script.mjs';
import { transactionFor } from './transaction.mjs';
import { FIXTURES } from '../sound-si-gls/math.mjs';
import { covenantHook, covenantParams, carrierOf, carrierOutput } from './pool-hook.mjs';
import { createHash } from 'node:crypto';

const CATEGORY_DISPLAY = Buffer.from('2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544', 'hex');
setCovenant(covenantHook(covenantParams({ categoryOnChain: Buffer.from(CATEGORY_DISPLAY).reverse().toString('hex') })));
const prog = buildProgram();
const lock = p2sh32(prog.R);
const proofs = JSON.parse(readFileSync('/home/apecs/cov/our-proofs.json', 'utf8'));
const c = proofs[0].covenant;
const leToBig = (hex) => BigInt('0x' + Buffer.from(hex, 'hex').reverse().toString('hex') || '0');
const sc = { nf0: leToBig(c.nf0), nf1: leToBig(c.nf1), cm0: leToBig(c.cm0), cm1: leToBig(c.cm1), newRoot: leToBig(c.newMerkleRoot), pv: BigInt(c.publicValueAbs), sign: BigInt(c.isUnshield) };

const run = (label, withTokens) => {
    const T = transactionFor(FIXTURES.fixtures[0], prog);
    const inputs = T.unlockings.map((u, n) => ({ outpointIndex: n, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0xfffffffe, unlockingBytecode: Buffer.from(u) }));
    const sourceOutputs = [0, 1, 2].map((n) => ({ lockingBytecode: lock, valueSatoshis: 1000n, ...(withTokens && n === 2 ? { token: { category: Buffer.from(CATEGORY_DISPLAY), amount: 1000n, nft: { capability: 'mutable', commitment: Buffer.alloc(64, 0x11) } } } : {}) }));
    const carrier = carrierOutput(carrierOf(sc));
    const outputs = [
        { lockingBytecode: carrier, valueSatoshis: 0n },
        { lockingBytecode: lock, valueSatoshis: 1000n, ...(withTokens ? { token: { category: Buffer.from(CATEGORY_DISPLAY), amount: 1250n, nft: { capability: 'mutable', commitment: Buffer.alloc(64, 0x22) } } } : {}) },
    ];
    const before = Buffer.from(carrier).toString('hex').slice(0, 20);
    const st = process.env.USE_DEBUG ? VMS.consensus.debug({ inputIndex: 2, sourceOutputs, transaction: { version: 2, locktime: 0, inputs, outputs } }).find((x) => x.error) ?? {} : VMS.consensus.evaluate({ inputIndex: 2, sourceOutputs, transaction: { version: 2, locktime: 0, inputs, outputs } });
    const after = Buffer.from(carrier).toString('hex').slice(0, 20);
    console.log(`${label}: ${before} -> ${after}  ${before === after ? '(unchanged)' : '*** FLIPPED ***'}  err: ${st.error ? String(st.error).slice(0, 60) : 'none'}`);
};
run('hooked + carrier, NO tokens ', false);
run('hooked + carrier, WITH tokens', true);
