// carrier-hunt.mjs — where does the [172] carrier item FIRST appear on the runtime stack?
import { readFileSync } from 'node:fs';
import { VMS, p2sh32 } from './vm.mjs';
import { buildProgram, setCovenant } from './script.mjs';
import { transactionFor } from './transaction.mjs';
import { FIXTURES } from '../sound-si-gls/math.mjs';
import { covenantHook, covenantParams, carrierOf, carrierOutput } from './pool-hook.mjs';
import { createHash } from 'node:crypto';

const CATEGORY_DISPLAY = Buffer.from('2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544', 'hex');
const CATEGORY_ONCHAIN = Buffer.from(CATEGORY_DISPLAY).reverse();
setCovenant(covenantHook(covenantParams({ categoryOnChain: CATEGORY_ONCHAIN.toString('hex') })));
const prog = buildProgram();

const sha = (b) => createHash('sha256').update(b).digest();
const leToBig = (hex) => BigInt('0x' + Buffer.from(hex, 'hex').reverse().toString('hex') || '0');
const be32 = (v) => { const b = Buffer.alloc(32); let x = BigInt(v); for (let i = 31; i >= 0 && x > 0n; i--) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; };
const to32LE = (v) => Buffer.from(be32(v)).reverse();
const proofs = JSON.parse(readFileSync('/home/apecs/cov/our-proofs.json', 'utf8'));
const p = proofs[0]; const c = p.covenant;
const sc = { nf0: leToBig(c.nf0), nf1: leToBig(c.nf1), cm0: leToBig(c.cm0), cm1: leToBig(c.cm1), newRoot: leToBig(c.newMerkleRoot), pv: BigInt(c.publicValueAbs), sign: BigInt(c.isUnshield) };
const n0 = BigInt(p.publicSignals[0]);
const balance = 1000n, oldNull = Buffer.alloc(32);
const newNull = sha(Buffer.concat([oldNull, be32(sc.nf0), be32(sc.nf1)]));
const stateCommit = Buffer.concat([to32LE(n0), oldNull]);
const newCommit = Buffer.concat([to32LE(sc.newRoot), newNull]);
const T = transactionFor(FIXTURES.fixtures[0], prog);
const inputs = T.unlockings.map((u, n) => ({ outpointIndex: n, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0xfffffffe, unlockingBytecode: Buffer.from(u) }));
const sourceOutputs = [0, 1, 2].map((n) => ({ lockingBytecode: p2sh32(prog.R), valueSatoshis: 1000n, ...(n === 2 ? { token: { category: CATEGORY_DISPLAY, amount: balance, nft: { capability: 'mutable', commitment: stateCommit } } } : {}) }));
const outputs = [
    { lockingBytecode: carrierOutput(carrierOf(sc)), valueSatoshis: 0n },
    { lockingBytecode: p2sh32(prog.R), valueSatoshis: 1000n, token: { category: CATEGORY_DISPLAY, amount: balance + sc.pv - 2n * sc.sign * sc.pv, nft: { capability: 'mutable', commitment: newCommit } } },
];
const trace = VMS.consensus.debug({ inputIndex: 2, sourceOutputs, transaction: { version: 2, locktime: 0, inputs, outputs } });
const badI = trace.findIndex((s) => s.error);
console.log(`trace: ${trace.length} states, error at ${badI} (ip ${trace[badI].ip})`);
const fmt = (x) => { const b = Buffer.from(x ?? []); return b.length === 0 ? '∅' : b.length <= 8 ? b.toString('hex') : `[${b.length}]${b.toString('hex').slice(0, 6)}`; };
const isCarrier = (x) => { const b = Buffer.from(x ?? []); return b.length === 172 && b[0] === 0x6a && b[1] === 0x4c; };
let first = -1;
for (let i = 0; i < trace.length; i++) if ((trace[i].stack ?? []).some(isCarrier)) { first = i; break; }
console.log(`first carrier item on stack at state ${first} (ip ${trace[first]?.ip})`);
for (let i = Math.max(0, first - 6); i <= Math.min(trace.length - 1, first + 2); i++) {
    const s = trace[i];
    console.log(`state ${String(i).padStart(4)} ip ${String(s.ip).padStart(4)} len ${String((s.stack ?? []).length).padStart(3)} top8: ${(s.stack ?? []).slice(-8).map(fmt).join(' ')}`);
}
/* watch every state from the carrier push (ip 108) to the error, with [172]/∅ counts */
for (let i = 574; i <= badI; i++) {
    const s = trace[i];
    const stk = s.stack ?? [];
    const n172 = stk.filter((x) => Buffer.from(x ?? []).length === 172).length;
    const nEmpty = stk.filter((x) => (x ?? []).length === 0).length;
    console.log(`st ${String(i).padStart(3)} ip ${String(s.ip).padStart(3)} len ${String(stk.length).padStart(3)} 172s:${n172} ∅:${nEmpty} top6: ${stk.slice(-6).map(fmt).join(' ')}`);
}
