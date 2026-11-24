// map-code.mjs — ground truth: role-2 marks (roffs), funcCode disassembly around the hook region,
// and where each mark's code actually sits.
import { readFileSync } from 'node:fs';
import { decodeAuthenticationInstructions, encodeAuthenticationInstruction } from '@bitauth/libauth';
import { buildProgram, setCovenant } from './script.mjs';
import { covenantHook, covenantParams } from './pool-hook.mjs';

const CATEGORY_DISPLAY = Buffer.from('2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544', 'hex');
setCovenant(covenantHook(covenantParams({ categoryOnChain: Buffer.from(CATEGORY_DISPLAY).reverse().toString('hex') })));
const prog = buildProgram();
const role2 = Buffer.from(prog.funcCodes.role2);
console.log(`funcCodes lengths: ${Object.fromEntries(Object.entries(prog.funcCodes).map(([k, v]) => [k, v.length]))}`);
console.log(`info: ${JSON.stringify(prog.info).slice(0, 200)}`);
const marks = prog.marks.filter((m) => m.role === 2).sort((a, b) => a.roff - b.roff);
console.log(`role-2 marks (roff = byte offset into funcCodes.role2):`);
for (const m of marks) console.log(`  ${String(m.roff).padStart(5)}  ${m.name}`);
const d = decodeAuthenticationInstructions(role2);
let x = 0; const offs = [];
for (const t of d) { offs.push(x); x += encodeAuthenticationInstruction(t).length; }
console.log(`role2 disassembly: ${d.length} instructions, ${role2.length} bytes`);
/* print the instruction window around bytes 200-420 (the hook region per the marks) */
const show = (from, to) => { for (let i = 0; i < d.length; i++) { if (offs[i] >= from && offs[i] < to) { const t = d[i]; const bytes = [...role2.subarray(offs[i], offs[i] + (t.data ? t.data.length + 1 : 1))].map((b) => b.toString(16).padStart(2, '0')).join(' '); console.log(`  off ${String(offs[i]).padStart(4)}  ${bytes}  ${t.data ? 'PUSH ' + t.data.length + 'B' : 'op 0x' + t.opcode.toString(16)}`); } } };
console.log(`\ninstructions at bytes 234±40:`);
show(200, 275);
