// probe-walk-cost.mjs — SPIKE (nullifier-set depth measurement, 2026-11-26). v2
//
// The HOOK-LEVEL option: the nullifier set as a SHA256 sparse Merkle tree
// verified entirely in BCH-2026 script. This probe MEASURES the real cost of
// the worst-case walk on the actual VM (libauth createVirtualMachineBch2026):
//
//   - unit op costs (baseline-subtracted): push, OP_CAT (32+32 -> 64),
//     OP_SHA256 over 64 B / 32 B, and the exact stack semantics of the 0x7f
//     slice opcode (probed empirically — SUBSTR-style (data,begin,count) vs
//     SPLIT-style (data,index)),
//   - ONE nullifier's DUAL walk at depth D (64 / 128 / 254): a linear
//     (unrolled) script that
//       1. walks the OLD spine from the zero leaf up the D supplied siblings
//          and requires the result to equal the state's nullifier root (the
//          non-membership proof), then
//       2. recomputes the same spine from the spent-marker leaf and requires
//          the updated root to equal the expected new root (in the real hook
//          this root is FOLDED into the new state NFT commitment).
//     The per-level key bit is EXTRACTED IN SCRIPT from the key (slice byte +
//     AND mask + IF) — the slot is bound to the nullifier, not chosen by the
//     witness. (In the real hook the key is the carrier's proof-bound nf
//     slice, read via introspection; here it is a witness push so the cost
//     can be measured in isolation.)
//   - soundness spot-checks on the real VM: a tampered sibling and a tampered
//     old root MUST error (the old-walk root check rejects).
//
// Witness layout (unlocking pushes): [sib0..sib{D-1}, expOld, expNew, key].
// Stack bookkeeping (PICK-only, no ROLL):
//   OLD walk:  sib_i PICK position D+3 (const), key PICK position i+2.
//              end: PICK 3 (expOld) + EQUALVERIFY vs curOld.
//   NEW walk:  sib_i PICK position D+3 (const, the expOld leftover offsets the
//              consumed slot), key PICK position i+2.
//              end: PICK 2 (expNew) + EQUALVERIFY vs curNew.
//   cleanup:   OP_DROP x (D+2), then OP_1 (the one-truthy-item contract).
//
// Budget math: the per-input op budget is self-funding, (41 + unlockingLen)
// x 800 — the sibling witness itself buys the budget the walk spends. The
// per-script SIZE caps (10,000 B locking / unlocking on this VM) are the real
// structural constraint; this probe records where each depth lands.

import { VMS, budgetOf } from "../groth16_cashscript/chunked/bn254/bn-native-sound/vm.mjs";
import { createHash } from "node:crypto";

const D = parseInt(process.argv[2] ?? "254", 10);

// ---- opcodes (Bitcoin opcode numbers — OP_PICK is 0x79, NOT 0x74=OP_DEPTH) ----
const OP_0 = 0x00, OP_1 = 0x51;
const OP_TOALTSTACK = 0x6b, OP_FROMALTSTACK = 0x6c;
const OP_IF = 0x63, OP_ENDIF = 0x68;
const OP_DEPTH = 0x74, OP_DROP = 0x75, OP_NIP = 0x77, OP_OVER = 0x78;
const OP_PICK = 0x79, OP_ROLL = 0x7a, OP_SWAP = 0x7c;
const OP_CAT = 0x7e, OP_SLICE = 0x7f;
const OP_AND = 0x84, OP_EQUALVERIFY = 0x88, OP_SHA256 = 0xa8;

// ---- minimal-push encoders (the 2026 VM enforces smallest-encoding) ----
const vmNum = (n) => {
    const bytes = [];
    let x = BigInt(n);
    while (x > 0n) { bytes.push(Number(x & 0xffn)); x >>= 8n; }
    if (bytes.length === 0 || (bytes[bytes.length - 1] & 0x80)) bytes.push(0);
    return bytes;
};
const pushInt = (n) => {
    if (n === 0) return [OP_0];
    if (n >= 1 && n <= 16) return [0x50 + n];
    const b = vmNum(n);
    return [b.length, ...b];
};
const pushBytes = (b) => [b.length, ...b];
// 1-byte mask push for OP_AND (equal-length operands required): 1..16 use the
// OP_n opcodes; 32/64/128 are raw 1-byte pushes (0x80 = the number −128, a
// legal minimal encoding — bitwise AND only cares about the byte pattern).
const pushMask = (m) => (m <= 16 ? [0x50 + m] : [0x01, m]);

// ---- tiny evaluator ----
const eval1 = (locking, unlocking) => VMS.consensus.evaluate({
    inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: Uint8Array.from(locking), valueSatoshis: 1000n }],
    transaction: { version: 2, locktime: 0,
        inputs: [{ outpointIndex: 0, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0, unlockingBytecode: Uint8Array.from(unlocking) }],
        outputs: [{ lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 1000n }] },
});

// ---- unit probes (all end DROP-clean + OP_1) ----
console.log("== unit probes (consensus; op deltas vs baseline) ==");
const unit = (name, prog) => {
    const st = eval1(prog, []);
    return { name, op: st.metrics.operationCost, err: st.error ? String(st.error).split("\n")[0].slice(0, 70) : null };
};
const b32 = Array.from({ length: 32 }, (_, i) => i);
const b64 = [...b32, ...Array.from({ length: 32 }, (_, i) => i + 32)];
const units = [
    unit("baseline [OP_1]", [OP_1]),
    unit("push 32B", [...pushBytes(b32), OP_DROP, OP_1]),
    unit("CAT 32+32 -> 64B", [...pushBytes(b32), ...pushBytes(Array.from({ length: 32 }, (_, i) => i + 32)), OP_CAT, OP_DROP, OP_1]),
    unit("SHA256 over 64B", [...pushBytes(b64), OP_SHA256, OP_DROP, OP_1]),
    unit("SHA256 over 32B", [...pushBytes(b32), OP_SHA256, OP_DROP, OP_1]),
];
const baseOp = units[0].op;
for (const u of units) console.log(`  ${u.name.padEnd(20)} op=${String(u.op).padStart(5)}  delta=${String(u.op - baseOp).padStart(5)}  ${u.err ?? "ok"}`);

// ---- 0x7f semantics probe ----
console.log("== 0x7f slice opcode semantics ==");
const stA = eval1([...pushBytes([0xaa, 0xbb, 0xcc, 0xdd]), ...pushInt(1), ...pushInt(2), OP_SLICE, OP_DROP, OP_1], []);
console.log(`  (data,1,2): stack=${(stA.stack ?? []).map((x) => Buffer.from(x).toString("hex")).join(" ")} ${stA.error ? "ERR " + String(stA.error).split("\n")[0].slice(0, 60) : ""}`);
const stB = eval1([...pushBytes([0xaa, 0xbb, 0xcc, 0xdd]), ...pushInt(2), OP_SLICE, OP_DROP, OP_1], []);
console.log(`  (data,2):    stack=${(stB.stack ?? []).map((x) => Buffer.from(x).toString("hex")).join(" ")} ${stB.error ? "ERR " + String(stB.error).split("\n")[0].slice(0, 60) : ""}`);
// SUBSTR-style if (data,begin,count) -> one item; SPLIT-style if (data,index) -> two items
const isSubstr = stA.error === undefined && (stA.stack ?? []).length === 1;
console.log(`  -> treating 0x7f as ${isSubstr ? "SUBSTR (data, begin, count) -> 1 slice" : "SPLIT (data, index) -> left,right"}`);

// ---- the dual walk ----
const sha = (b) => createHash("sha256").update(Buffer.from(b)).digest();
const zh = [Buffer.alloc(32)];
for (let i = 1; i <= D; i++) zh.push(sha(Buffer.concat([zh[i - 1], zh[i - 1]])));

const key = Buffer.from(Array.from({ length: 32 }, (_, i) => (i * 7 + 3) & 0xff));
const bitOf = (i) => (key[i >> 3] >> (i & 7)) & 1;

const sibs = [];
for (let i = 0; i < D; i++) sibs.push(zh[i]);        // empty tree: sibling at height i = zh[i]
const expOld = zh[D];
let cur = Buffer.alloc(32); cur[0] = 1;               // JS mirror of the NEW walk (leaf = 1)
for (let i = 0; i < D; i++) {
    const left = bitOf(i) ? sibs[i] : cur;
    const right = bitOf(i) ? cur : sibs[i];
    cur = sha(Buffer.concat([left, right]));
}
const expNew = cur;

// level bodies. Stack invariant while walking: exactly ONE cur sits on top of
// [key, expNew, expOld, sib{D-1}..sib0] (each level CAT-consumes the old cur
// and pushes the new one). Hence: sib_i is at position D+3-i (D-1-i sibs above
// it + key + expOld + expNew + cur), and the key is at position 2 (cur + the
// just-pushed sib copy) — CONSTANT.
const bodySplit = (i, sibPos) => [
    ...pushInt(sibPos), OP_PICK,
    ...pushInt(2), OP_PICK,               // the key: position 2, constant
    ...pushInt(i >> 3), OP_SLICE,        // (key[0:idx], key[idx:])
    ...pushInt(1), OP_SLICE,             // (key[idx:idx+1]=byte, key[idx+1:]) — rest lands on TOP
    OP_SWAP,                              // byte on top
    0x6b,                                 // OP_TOALTSTACK (byte aside)
    OP_DROP, OP_DROP,                   // rest, left
    0x6c,                                 // OP_FROMALTSTACK (byte back)
    ...pushMask(1 << (i & 7)), OP_AND,
    OP_IF, OP_SWAP, OP_ENDIF,
    OP_CAT, OP_SHA256,
];

// (0x7f is OP_SPLIT on this VM — the SUBSTR-style body variant is moot; the
// SPLIT body above is the measured one.)
const body = bodySplit;

const ZERO32 = Buffer.alloc(32);
const ONE32 = Buffer.from([1, ...Array(31).fill(0)]);
const script = [...pushBytes([...ZERO32])];   // the OLD-walk leaf: the zero value, a 32-B item (NOT OP_0/empty!)
for (let i = 0; i < D; i++) script.push(...body(i, D + 3 - i));
script.push(...pushInt(3), OP_PICK, OP_EQUALVERIFY);
script.push(...pushBytes([...ONE32]));      // the NEW-walk leaf: the spent marker (32-B, 0x01..0)
for (let i = 0; i < D; i++) script.push(...body(i, D + 3 - i));
script.push(...pushInt(2), OP_PICK, OP_EQUALVERIFY);
for (let k = 0; k < D + 3; k++) script.push(OP_DROP);  // key + expOld + expNew remain + D sibs
script.push(OP_1);

const witness = (keyArr, sibArr, eo, en) => [
    ...sibArr.flatMap((s) => pushBytes([...s])),
    ...pushBytes([...eo]),
    ...pushBytes([...en]),
    ...pushBytes([...keyArr]),
];
const unlocking = witness(key, sibs, expOld, expNew);

console.log(`\n== the dual walk at depth ${D} ==`);
console.log(`  script ${script.length} B · unlocking ${unlocking.length} B (key 32 + sibs ${D * 32} + roots 64)`);
if (script.length > 10000 || unlocking.length > 10000) console.log(`  !!! exceeds the 10,000-B per-script cap (script ${script.length} B / unlocking ${unlocking.length} B)`);

const ok = eval1(script, unlocking);
console.log(`  true witness   op=${String(ok.metrics.operationCost).padStart(7)}  budget=${budgetOf(Uint8Array.from(unlocking))}  ${ok.error ? "ERR " + String(ok.error).split("\n")[0].slice(0, 80) : "ACCEPTED (no error)"}`);
const okStd = VMS.standard.evaluate({
    inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: Uint8Array.from(script), valueSatoshis: 1000n }],
    transaction: { version: 2, locktime: 0, inputs: [{ outpointIndex: 0, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0, unlockingBytecode: Uint8Array.from(unlocking) }], outputs: [{ lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 1000n }] },
});
console.log(`  (standard)     op=${String(okStd.metrics.operationCost).padStart(7)}  ${okStd.error ? "ERR " + String(okStd.error).split("\n")[0].slice(0, 80) : "ACCEPTED"}`);

const TAMPER_IX = Math.min(D - 1, 100);   // a sibling that EXISTS at this depth
const badSibs = sibs.map((s, i) => (i === TAMPER_IX ? Buffer.from([...s].map((b, j) => (j === 5 ? b ^ 0x40 : b))) : s));
const bad = eval1(script, witness(key, badSibs, expOld, expNew));
console.log(`  tampered sib#${TAMPER_IX} ${bad.error ? "REJECTED (" + String(bad.error).split("\n")[0].slice(0, 50) + ")" : "!!! ACCEPTED — SOUNDNESS FAILURE !!!"}`);
const badRoot = witness(key, sibs, Buffer.from([...expOld].map((b, j) => (j === 0 ? b ^ 0x01 : b))), expNew);
const bad2 = eval1(script, badRoot);
console.log(`  tampered expOld ${bad2.error ? "REJECTED (" + String(bad2.error).split("\n")[0].slice(0, 50) + ")" : "!!! ACCEPTED — SOUNDNESS FAILURE !!!"}`);

console.log(`\n  per-action projection (2 nullifiers): script ${2 * script.length} B + witness ${2 * unlocking.length} B extra`);
console.log(`  op (2 nullifiers): ${2 * Number(ok.metrics.operationCost)} vs self-funded budget ${(41 + 2 * unlocking.length) * 800}`);
