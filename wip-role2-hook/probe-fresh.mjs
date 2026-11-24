// probe-fresh.mjs — pool-test's EXACT fixture-0 scenario, alone in a fresh process.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { VMS, p2sh32 } from './vm.mjs';
import { buildProgram, setCovenant } from './script.mjs';
import { transactionFor } from './transaction.mjs';
import { FIXTURES } from '../sound-si-gls/math.mjs';
import { covenantHook, covenantParams, carrierOf, carrierOutput, actionHashOf } from './pool-hook.mjs';

const CATEGORY_DISPLAY = Buffer.from('2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544', 'hex');
const CATEGORY_ONCHAIN = Buffer.from(CATEGORY_DISPLAY).reverse();
setCovenant(covenantHook(covenantParams({ categoryOnChain: CATEGORY_ONCHAIN.toString('hex') })));
const prog = buildProgram();
const lock = p2sh32(prog.R);
const sha = (b) => createHash('sha256').update(b).digest();
const leToBig = (hex) => BigInt('0x' + Buffer.from(hex, 'hex').reverse().toString('hex') || '0');
const be32 = (v) => { const b = Buffer.alloc(32); let x = BigInt(v); for (let i = 31; i >= 0 && x > 0n; i--) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; };
const to32LE = (v) => Buffer.from(be32(v)).reverse();
const proofs = JSON.parse(readFileSync('/home/apecs/cov/our-proofs.json', 'utf8'));
const p = proofs[0]; const c = p.covenant;
const sc = { nf0: leToBig(c.nf0), nf1: leToBig(c.nf1), cm0: leToBig(c.cm0), cm1: leToBig(c.cm1), newRoot: leToBig(c.newMerkleRoot), pv: BigInt(c.publicValueAbs), sign: BigInt(c.isUnshield) };
const n0 = BigInt(p.publicSignals[0]);
const balance = 1000n, oldNull = Buffer.alloc(32);
const carr = carrierOf(sc);
const newNull = sha(Buffer.concat([oldNull, carr.subarray(0, 32), carr.subarray(32, 64)]));
const stateCommit = Buffer.concat([to32LE(n0), oldNull]);
const newCommit = Buffer.concat([to32LE(sc.newRoot), newNull]);
const T = transactionFor(FIXTURES.fixtures[0], prog);
console.log(`fills: ${JSON.stringify(T.fills)}  unlocking lengths: ${T.unlockings.map((u) => u.length).join(' / ')}`);
const inputs = T.unlockings.map((u, n) => ({ outpointIndex: n, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0xfffffffe, unlockingBytecode: Buffer.from(u) }));
const sourceOutputs = [0, 1, 2].map((n) => ({ lockingBytecode: lock, valueSatoshis: 1000n, ...(n === 2 ? { token: { category: CATEGORY_DISPLAY, amount: balance, nft: { capability: 'mutable', commitment: stateCommit } } } : {}) }));
const outputs = [
    { lockingBytecode: carrierOutput(carrierOf(sc)), valueSatoshis: 0n },
    { lockingBytecode: lock, valueSatoshis: 1000n, token: { category: CATEGORY_DISPLAY, amount: balance + sc.pv - 2n * sc.sign * sc.pv, nft: { capability: 'mutable', commitment: newCommit } } },
];
const res = VMS.consensus.evaluate({ inputIndex: 2, sourceOutputs, transaction: { version: 2, locktime: 0, inputs, outputs } });
const top = res.stack?.[res.stack.length - 1];
console.log(`consensus: ${res.error ? 'REJECT — ' + String(res.error).slice(0, 80) : 'stack len ' + res.stack.length + ', top ' + Buffer.from(top ?? []).toString('hex')}`);
console.log(`opCost: ${res.metrics?.operationCost ?? '?'}`);
