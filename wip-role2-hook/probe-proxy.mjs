// probe-proxy.mjs — trap writes to the carrier buffer; log WHO reverses it, with a stack trace.
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
const p = proofs[0]; const c = p.covenant;
const leToBig = (hex) => BigInt('0x' + Buffer.from(hex, 'hex').reverse().toString('hex') || '0');
const be32 = (v) => { const b = Buffer.alloc(32); let x = BigInt(v); for (let i = 31; i >= 0 && x > 0n; i--) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; };
const to32LE = (v) => Buffer.from(be32(v)).reverse();
const sc = { nf0: leToBig(c.nf0), nf1: leToBig(c.nf1), cm0: leToBig(c.cm0), cm1: leToBig(c.cm1), newRoot: leToBig(c.newMerkleRoot), pv: BigInt(c.publicValueAbs), sign: BigInt(c.isUnshield) };
const sha = (b) => createHash('sha256').update(b).digest();
const n0 = BigInt(p.publicSignals[0]);
const oldNull = Buffer.alloc(32);
const carr = carrierOf(sc);
const newNull = sha(Buffer.concat([oldNull, carr.subarray(0, 32), carr.subarray(32, 64)]));
const stateCommit = Buffer.concat([to32LE(n0), oldNull]);
const newCommit = Buffer.concat([to32LE(sc.newRoot), newNull]);
const T = transactionFor(FIXTURES.fixtures[0], prog);
const inputs = T.unlockings.map((u, n) => ({ outpointIndex: n, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0xfffffffe, unlockingBytecode: Buffer.from(u) }));
const sourceOutputs = [0, 1, 2].map((n) => ({ lockingBytecode: lock, valueSatoshis: 1000n, ...(n === 2 ? { token: { category: Buffer.from(CATEGORY_DISPLAY), amount: 1000n, nft: { capability: 'mutable', commitment: stateCommit } } } : {}) }));

/* wrap the carrier in a logging Proxy: any get of a byte index logs; reverse() logs a stack */
const realCarrier = carrierOutput(carrierOf(sc));
const logged = new Proxy(realCarrier, {
    get(target, prop, recv) {
        if (prop === 'reverse' || prop === 'set' || prop === 'writeUInt8' || prop === 'fill' || prop === 'copy') {
            console.log(`\n*** CARRIER METHOD ${String(prop)} ACCESSED ***`);
            console.log(new Error('trace').stack.split('\n').slice(1, 8).join('\n'));
        }
        const v = Reflect.get(target, prop, recv);
        return typeof v === 'function' ? v.bind(target) : v;
    },
    set(target, prop, val) {
        console.log(`\n*** CARRIER WRITE AT ${String(prop)} = ${val} ***`);
        console.log(new Error('trace').stack.split('\n').slice(1, 8).join('\n'));
        return Reflect.set(target, prop, val);
    },
});
const outputs = [
    { lockingBytecode: logged, valueSatoshis: 0n },
    { lockingBytecode: lock, valueSatoshis: 1000n, token: { category: Buffer.from(CATEGORY_DISPLAY), amount: 1000n + sc.pv - 2n * sc.sign * sc.pv, nft: { capability: 'mutable', commitment: newCommit } } },
];
console.log(`carrier before: ${Buffer.from(realCarrier).toString('hex').slice(0, 20)}`);
const st = VMS.consensus.evaluate({ inputIndex: 2, sourceOutputs, transaction: { version: 2, locktime: 0, inputs, outputs } });
console.log(`carrier after : ${Buffer.from(realCarrier).toString('hex').slice(0, 20)}`);
console.log(`error: ${st.error ? String(st.error).slice(0, 80) : 'none'}`);
