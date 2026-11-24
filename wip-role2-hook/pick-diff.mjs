// pick-diff.mjs — model stack at check-9's pick('newRoot') vs the runtime stack at that moment.
import { readFileSync } from 'node:fs';
import { Asm } from './asm.mjs';
import { VMS, p2sh32 } from './vm.mjs';
import { buildProgram, setCovenant } from './script.mjs';
import { transactionFor } from './transaction.mjs';
import { FIXTURES } from '../sound-si-gls/math.mjs';
import { covenantHook, covenantParams, carrierOf, carrierOutput } from './pool-hook.mjs';
import { createHash } from 'node:crypto';

const REC = []; let IID = 0;
const origEmit = Asm.prototype.emit;
Asm.prototype.emit = function (...b) {
    if (globalThis.__REC) REC.push({ iid: this.__id ?? (this.__id = ++IID), off: this.code.length, st: [...this.st], b: [...b] });
    return origEmit.apply(this, ...[b]);
};
globalThis.__REC = true;
const CATEGORY_DISPLAY = Buffer.from('2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544', 'hex');
const CATEGORY_ONCHAIN = Buffer.from(CATEGORY_DISPLAY).reverse();
setCovenant(covenantHook(covenantParams({ categoryOnChain: CATEGORY_ONCHAIN.toString('hex') })));
const prog = buildProgram();
globalThis.__REC = false;

/* the check-9 pick('newRoot') emits pushNum(depth)+OP_PICK — find ALL such records with depth 36 */
const hex = (b) => b.map((x) => x.toString(16).padStart(2, '0')).join(' ');
const cands = REC.filter((r) => r.b.length >= 2 && r.b[0] === 0x01 && r.b[1] === 0x24 && r.b[2] === 0x79);
console.log(`records emitting PUSH1(0x24)+OP_PICK: ${cands.length}`);
for (const r of cands) {
    console.log(`\niid ${r.iid} off ${r.off} bytes ${hex(r.b)} — model stack top->bottom (named):`);
    console.log('   ' + r.st.slice().reverse().join(' '));
}
/* also: which instance is the hook's? print every instance's record-count and last offset */
const byIid = {};
for (const r of REC) byIid[r.iid] = (byIid[r.iid] ?? 0) + 1;
console.log(`\ninstances: ${Object.entries(byIid).map(([k, v]) => `#${k}:${v}`).join(' ')}`);
console.log(`funcCodes: ${Object.entries(prog.funcCodes).map(([k, v]) => `${k}=${v.length}B`).join(' ')}`);
