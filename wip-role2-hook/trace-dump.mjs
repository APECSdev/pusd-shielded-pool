// trace-dump.mjs — watch the runtime stack evolve near the failure; settle where the error really is.
import { readFileSync } from 'node:fs';
import { VMS, p2sh32 } from './vm.mjs';
import { buildProgram, setCovenant } from './script.mjs';
import { transactionFor } from './transaction.mjs';
import { FIXTURES } from '../sound-si-gls/math.mjs';
import { covenantHook, covenantParams, carrierOf, carrierOutput, actionHashOf } from './pool-hook.mjs';
import { createHash } from 'node:crypto';

const CATEGORY_DISPLAY = Buffer.from('2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544', 'hex');
const CATEGORY_ONCHAIN = Buffer.from(CATEGORY_DISPLAY).reverse();
setCovenant(covenantHook(covenantParams({ categoryOnChain: CATEGORY_ONCHAIN.toString('hex') })));
const prog = buildProgram();
const lock = p2sh32(prog.R);
const proofs = JSON.parse(readFileSync('/home/apecs/cov/our-proofs.json', 'utf8'));
const sha = (b) => createHash('sha256').update(b).digest();
const leToBig = (hex) => BigInt('0x' + Buffer.from(hex, 'hex').reverse().toString('hex') || '0');
const be32 = (v) => { const b = Buffer.alloc(32); let x = BigInt(v); for (let i = 31; i >= 0 && x > 0n; i--) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; };
const to32LE = (v) => Buffer.from(be32(v)).reverse();

const FXI = Number(process.env.FXI ?? 0); const p = proofs[FXI];
const c = p.covenant;
const sc = { nf0: leToBig(c.nf0), nf1: leToBig(c.nf1), cm0: leToBig(c.cm0), cm1: leToBig(c.cm1), newRoot: leToBig(c.newMerkleRoot), pv: BigInt(c.publicValueAbs), sign: BigInt(c.isUnshield) };
const n0 = BigInt(p.publicSignals[0]);
const balance = 1000n, oldNull = Buffer.alloc(32);
/* deployed covenant folds the RAW LE covenant args (asset-pool.cash line 148) */
const carr = carrierOf(sc);
const newNull = sha(Buffer.concat([oldNull, carr.subarray(0, 32), carr.subarray(32, 64)]));
const newBal = balance + sc.pv - 2n * sc.sign * sc.pv;
const stateCommit = Buffer.concat([to32LE(n0), oldNull]);
const newCommit = Buffer.concat([to32LE(sc.newRoot), newNull]);

const T = transactionFor(FIXTURES.fixtures[FXI], prog);
const inputs = T.unlockings.map((u, n) => ({ outpointIndex: n, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array(u) }));
const sourceOutputs = [0, 1, 2].map((n) => ({ lockingBytecode: lock, valueSatoshis: 1000n, ...(n === 2 ? { token: { category: new Uint8Array(CATEGORY_DISPLAY)  /* plain Uint8Array: Buffer.slice() returns a VIEW and REVERSEBYTES writes through it */, amount: balance, nft: { capability: 'mutable', commitment: new Uint8Array(stateCommit) } } } : {}) }));
const outputs = [
    { lockingBytecode: new Uint8Array(carrierOutput(carrierOf(sc))), valueSatoshis: 0n },
    { lockingBytecode: lock, valueSatoshis: 1000n, token: { category: new Uint8Array(CATEGORY_DISPLAY)  /* plain Uint8Array: Buffer.slice() returns a VIEW and REVERSEBYTES writes through it */, amount: newBal, nft: { capability: 'mutable', commitment: new Uint8Array(newCommit) } } },
];
const CARRIER_BUF = outputs[0].lockingBytecode;
console.log(`carrier BEFORE debug: ${Buffer.from(CARRIER_BUF).toString('hex').slice(0, 32)}`);
console.log(`c.nf0 hex           : ${c.nf0.slice(0, 32)}`);
const trace = VMS.consensus.debug({ inputIndex: 2, sourceOutputs, transaction: { version: 2, locktime: 0, inputs, outputs } });
console.log(`carrier AFTER debug : ${Buffer.from(CARRIER_BUF).toString('hex').slice(0, 32)}`);
const badI = trace.findIndex((s) => s.error);
console.log(`fixture ${FXI}: trace length: ${trace.length}, first error at state ${badI}: ${String(trace[badI]?.error).slice(0, 60)}`);
/* ip resets = function invocations; find the last reset before the error */
let resets = [];
for (let i = 1; i < trace.length; i++) if ((trace[i].ip ?? 0) < (trace[i-1].ip ?? 0)) resets.push(i);
const lastReset = [...resets].reverse().find((r) => r <= badI);
console.log(`last ip-reset before error at state ${lastReset} (error is ${badI - lastReset} instructions into that function, ip ${trace[badI].ip})`);
const fmt = (x) => { const b = Buffer.from(x ?? []); return b.length === 0 ? '∅' : b.length <= 8 ? b.toString('hex') : `[${b.length}]${b.toString('hex').slice(0, 8)}`; };
const le = (v) => Buffer.from(be32(BigInt(v))).reverse().toString('hex').slice(0, 8);
console.log('expected LE-32 of limbs (first 8 hex chars):');
console.log(`  nf0=${le(sc.nf0)} nf1=${le(sc.nf1)} cm0=${le(sc.cm0)} cm1=${le(sc.cm1)} newRoot=${le(sc.newRoot)} n0=${le(n0)} n1=${le(BigInt(p.publicSignals[1]))}`);
for (let i = Math.max(0, badI - 90); i <= badI; i++) {
    const s = trace[i];
    const stk = (s.stack ?? []).slice(-7).map(fmt).join(' ');
    console.log(`state ${String(i).padStart(4)} ip ${String(s.ip).padStart(4)} len ${String((s.stack ?? []).length).padStart(3)} top7: ${stk}${s.error ? '   ERROR: ' + String(s.error).slice(0, 50) : ''}`);
}
