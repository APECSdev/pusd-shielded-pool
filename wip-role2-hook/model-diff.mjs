// model-diff.mjs — align the assembler's MODEL stack with the VM's RUNTIME stack,
// state by state, and report the first divergence inside role 2.
import { readFileSync } from 'node:fs';
import { Asm } from './asm.mjs';
import { VMS, p2sh32 } from './vm.mjs';
import { buildProgram, setCovenant } from './script.mjs';
import { transactionFor } from './transaction.mjs';
import { FIXTURES } from '../sound-si-gls/math.mjs';
import { covenantHook, covenantParams, carrierOf, carrierOutput } from './pool-hook.mjs';
import { createHash } from 'node:crypto';

/* 1. record every emit call of every Asm instance */
const REC = []; let IID = 0;
const origEmit = Asm.prototype.emit;
Asm.prototype.emit = function (...b) {
    if (globalThis.__REC) REC.push({ iid: this.__id ?? (this.__id = ++IID), off: this.code.length, st: [...this.st], n: b.length });
    return origEmit.apply(this, ...[b]);
};
globalThis.__REC = true;

const CATEGORY_DISPLAY = Buffer.from('2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544', 'hex');
const CATEGORY_ONCHAIN = Buffer.from(CATEGORY_DISPLAY).reverse();
setCovenant(covenantHook(covenantParams({ categoryOnChain: CATEGORY_ONCHAIN.toString('hex') })));
const prog = buildProgram();
globalThis.__REC = false;

/* 2. find the instance whose code is role2's funcCode */
const role2 = Buffer.from(prog.funcCodes.role2);
const iid2 = [...new Set(REC.map((r) => r.iid))].find((id) => {
    const rs = REC.filter((r) => r.iid === id);
    return rs.length && rs[rs.length - 1].off + rs[rs.length - 1].n === role2.length;
});
const R2 = REC.filter((r) => r.iid === iid2);
console.log(`role2 model: ${R2.length} emit-calls, code ${role2.length} B`);

/* 3. build the fixture-0 scenario and trace */
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
const startI = badI - (trace[badI].ip);   // role-2 execution starts this many states back
console.log(`trace: ${trace.length} states, error at ${badI} (ip ${trace[badI].ip}) → role2 starts at state ${startI} (check ip0: ${trace[startI].ip})`);

/* 4. zip model ↔ runtime; baseline depth delta at i=0, report first divergence */
const fmt = (x) => { const b = Buffer.from(x ?? []); return b.length === 0 ? '∅' : b.length <= 8 ? b.toString('hex') : `[${b.length}]${b.toString('hex').slice(0, 6)}`; };
let base = null, div = null;
for (let i = 0; i <= trace[badI].ip; i++) {
    const model = R2[i], st = trace[startI + i];
    if (!model || !st) break;
    const mlen = model.st.length, rlen = (st.stack ?? []).length;
    const delta = rlen - mlen;
    if (base === null) base = delta;
    if (delta !== base && div === null) { div = i; break; }
}
console.log(`baseline runtime-model depth delta: ${base}`);
console.log(div === null ? 'no divergence found before the error' : `FIRST DIVERGENCE at model emit-call #${div} (runtime ip ${div}):`);
if (div !== null) {
    for (let i = Math.max(0, div - 6); i <= Math.min(trace[badI].ip, div + 2); i++) {
        const m = R2[i], s = trace[startI + i];
        console.log(`#${String(i).padStart(3)} off ${String(m.off).padStart(4)} model(top8): ${m.st.slice(-8).join(' ')}`);
        console.log(`     runtime len ${(s.stack ?? []).length} (top8): ${(s.stack ?? []).slice(-8).map(fmt).join(' ')}`);
    }
    const bytes = [...role2.subarray(R2[div].off, R2[div].off + 8)].map((x) => x.toString(16).padStart(2, '0')).join(' ');
    console.log(`divergence instruction bytes @off ${R2[div].off}: ${bytes}`);
}
