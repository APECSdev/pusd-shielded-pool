// pool-op-role2.mjs — build, VM-eval, broadcast and confirm a REAL role-2 pool action.
//
// Consumes the deployment state (role2-pool-state.json) + a proved op (role2-op.json from
// role2-op-witness.mjs). The action transaction is the role-2 shape:
//   inputs  0/1 — program-locking UTXOs (a SHIELD's FT deposit + a plain UTXO; two plains for
//                  transfer/unshield) — NO SIGNATURES: the P2SH32(R) script satisfaction IS
//                  the spend authorization (the graph pins TXINPUTCOUNT == 3, so fees ride
//                  on the locked UTXOs' own sats).
//   input   2   — the pool state NFT.
//   outputs    — out0 the 169-byte OP_RETURN carrier, out1 the new state NFT at the program
//                locking (amount = newBalance, commitment = newRoot ‖ newNull), and for an
//                unshield out2 the public payout (pv FT to the wallet).
// Every input is VM-evaluated against the REAL source outputs in BOTH modes before
// broadcast — the same acceptance the sweeps proved, now on the assembled chipnet tx.
//
// Usage (VM, from chunked/bn254/bn-native-sound/):
//   BN_VK_FIXTURES=/home/apecs/cov/our.fixtures.json node pool-op-role2.mjs [--op /home/apecs/cov/role2-op.json] [--no-broadcast]
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import tls from 'node:tls';
import { binToHex, cashAddressToLockingBytecode, decodeTransaction, encodeTransactionBCH, hash256, hexToBin, instantiateSha256 } from '@bitauth/libauth';
import { buildProgram, setCovenant } from './script.mjs';
import { covenantHook, covenantParams, actionHashOf, carrierOf, carrierOutput } from './pool-hook.mjs';
import { poolTransactionFor, poolScenario } from './pool-tx.mjs';
import { VMS, p2sh32 } from './vm.mjs';

const argOf = (n, d) => { const i = process.argv.indexOf(n); return i >= 0 ? process.argv[i + 1] : d; };
const STATE = argOf('--state', '/home/apecs/cov/role2-pool-state.json');
const OP = argOf('--op', '/home/apecs/cov/role2-op.json');
const NO_BROADCAST = process.argv.includes('--no-broadcast');
const STATE_FLOAT = 10_000n;

/* electrum raw TLS */
const rpc = (method, params) => new Promise((res, rej) => {
    const sock = tls.connect(50002, 'chipnet.bch.ninja', { timeout: 15000 });
    let buf = '';
    sock.on('secureConnect', () => sock.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) + '\n'));
    sock.on('data', (d) => { buf += d.toString(); const line = buf.split('\n')[0];
        if (line) { try { const o = JSON.parse(line); if (o.error) rej(new Error(JSON.stringify(o.error))); else res(o.result); sock.destroy(); } catch { /* more */ } } });
    sock.on('error', rej);
    sock.on('timeout', () => { sock.destroy(); rej(new Error('electrum timeout: ' + method)); });
});

/* ---- state + op ---- */
const state = JSON.parse(readFileSync(STATE, 'utf8'));
const op = JSON.parse(readFileSync(OP, 'utf8'));
const CAT = hexToBin(state.category); /* display order */
const balance = BigInt(state.pool.balance);
const oldNull = Buffer.from(state.pool.oldNullHex, 'hex');

/* ---- rebuild the program with the deployed category; drift guards ---- */
setCovenant(covenantHook(covenantParams({ categoryOnChain: binToHex(hexToBin(state.category).slice().reverse()) })));
const prog = buildProgram();
const programLocking = p2sh32(prog.R);
assert.equal(createHash('sha256').update(prog.code).digest('hex'), state.program.codeSha256, 'program code drifted from the deployed build');
assert.equal(binToHex(programLocking), state.program.locking, 'program locking drifted from the deployed build');

/* ---- the scenario (self-checked against the proof's own public inputs) ---- */
const leToBig = (hex) => BigInt('0x' + Buffer.from(hex, 'hex').reverse().toString('hex') || '0');
const c = op.covenant;
const sc = { nf0: leToBig(c.nf0), nf1: leToBig(c.nf1), cm0: leToBig(c.cm0), cm1: leToBig(c.cm1), newRoot: leToBig(c.newMerkleRoot), pv: BigInt(c.publicValueAbs), sign: BigInt(c.isUnshield) };
const n0 = BigInt(op.publicSignals[0]);
assert.equal(n0.toString(), state.pool.root, 'proof n0 != current pool root');
assert.equal(actionHashOf({ ...sc, categoryDisplay: state.category }).toString(), BigInt(op.publicSignals[1]).toString(), 'actionHash mismatch — op is not self-consistent');
const scenarioArgs = { sc, n0, balance, oldNull, categoryDisplay: Buffer.from(state.category, 'hex') };
const scenario = poolScenario(scenarioArgs);
console.log(`${op.action} pv=${sc.pv} sign=${sc.sign} · balance ${balance} → ${scenario.newBal} · newNull ${scenario.newNull.toString('hex').slice(0, 16)}…`);

/* ---- the bench fixture + pool-shaped fills ---- */
const g1 = ([x, y]) => ({ x: BigInt(x).toString(), y: BigInt(y).toString() });
const g2 = ([[x0, x1], [y0, y1]]) => ({ x: { c0: BigInt(x0).toString(), c1: BigInt(x1).toString() }, y: { c0: BigInt(y0).toString(), c1: BigInt(y1).toString() } });
const fx = { publicInputs: op.publicSignals.map((s) => BigInt(s).toString()), proof: { a: g1(op.proof.pi_a), b: g2(op.proof.pi_b), c: g1(op.proof.pi_c) } };
const T = poolTransactionFor(fx, prog, scenarioArgs);
console.log(`fills ${T.fills.join('/')} · unlockings ${T.unlockings.map((u) => u.length).join('/')} · nq ${T.core.nq}`);

/* ---- assemble the REAL transaction ---- */
const inA = state.outpoints.actionInputs[0], inB = state.outpoints.actionInputs[1], inS = state.outpoints.state;
if (!inA || !inB) throw new Error('state.outpoints.actionInputs must hold the two non-state inputs (refill first if consumed)');
const mkIn = (spec, unlocking) => ({ outpointTransactionHash: hexToBin(spec.txid), outpointIndex: spec.vout, sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array(unlocking) });
const inputs = [mkIn(inA, T.unlockings[0]), mkIn(inB, T.unlockings[1]), mkIn(inS, T.unlockings[2])];
const walletLocking = cashAddressToLockingBytecode(state.fundingAddress).bytecode;
const outputs = [
    { lockingBytecode: new Uint8Array(carrierOutput(scenario.carr)), valueSatoshis: 0n },
    { lockingBytecode: new Uint8Array(programLocking), valueSatoshis: STATE_FLOAT, token: { category: new Uint8Array(CAT), amount: scenario.newBal, nft: { capability: 'mutable', commitment: new Uint8Array(scenario.newCommit) } } },
];
if (sc.sign === 1n) outputs.push({ lockingBytecode: new Uint8Array(walletLocking), valueSatoshis: 1000n, token: { category: new Uint8Array(CAT), amount: sc.pv } });
const tx = { version: 2, locktime: 0, inputs, outputs };

/* the REAL source outputs (for VM-eval) — tokens exactly as recorded on chain */
const srcToken = (spec) => spec.ftAmount !== undefined && spec.ftAmount !== null && BigInt(spec.ftAmount) !== 0n ? { category: new Uint8Array(CAT), amount: BigInt(spec.ftAmount) } : undefined;
const sources = [
    { lockingBytecode: new Uint8Array(programLocking), valueSatoshis: BigInt(inA.sats), ...(srcToken(inA) ? { token: srcToken(inA) } : {}) },
    { lockingBytecode: new Uint8Array(programLocking), valueSatoshis: BigInt(inB.sats), ...(srcToken(inB) ? { token: srcToken(inB) } : {}) },
    { lockingBytecode: new Uint8Array(programLocking), valueSatoshis: BigInt(inS.sats), token: { category: new Uint8Array(CAT), amount: balance, nft: { capability: 'mutable', commitment: new Uint8Array(scenario.stateCommit) } } },
];

/* ---- VM-eval every input, both modes, against the REAL shape ---- */
for (const mode of ['consensus', 'standard']) {
    const rs = [0, 1, 2].map((i) => {
        const st = VMS[mode].evaluate({ inputIndex: i, sourceOutputs: sources, transaction: { version: 2, locktime: 0, inputs: tx.inputs.map((q) => ({ ...q, unlockingBytecode: new Uint8Array(q.unlockingBytecode) })), outputs: tx.outputs } });
        const top = st.stack?.[st.stack.length - 1];
        const ok = st.error === undefined && st.stack.length === 1 && top?.length === 1 && top[0] === 1;
        return { ok, err: st.error, op: st.metrics.operationCost, budget: (41 + tx.inputs[i].unlockingBytecode.length) * 800 };
    });
    console.log(`${mode}: ${rs.map((r) => `${r.ok ? 'ACCEPT' : 'REJECT ' + r.err}`.slice(0, 40) + ` ${r.op}/${r.budget}`).join(' | ')}`);
    assert.ok(rs.every((r) => r.ok), `${mode} mode rejected the action — NOT broadcasting`);
}

/* ---- conservation + fee sanity (consensus token rules) ---- */
const ftIn = (srcToken(inA) ? BigInt(inA.ftAmount) : 0n) + (srcToken(inB) ? BigInt(inB.ftAmount) : 0n) + balance;
const ftOut = scenario.newBal + (sc.sign === 1n ? sc.pv : 0n);
assert.equal(ftIn, ftOut, 'fungible conservation violated');
const satsIn = BigInt(inA.sats) + BigInt(inB.sats) + BigInt(inS.sats);
const satsOut = outputs.reduce((a, o) => a + o.valueSatoshis, 0n);
const sha256a = await instantiateSha256();
const hex = binToHex(encodeTransactionBCH(tx));
const decoded = decodeTransaction(hexToBin(hex));
if (typeof decoded === 'string') throw new Error('op tx does not decode: ' + decoded);
const fee = satsIn - satsOut;
const txid = binToHex(new Uint8Array(hash256(hexToBin(hex), sha256a)).reverse());
console.log(`tx ${txid} · ${hex.length / 2}B · fee ${fee} sats (${Number(fee) / (hex.length / 2)} sat/B) · FT ${ftIn} → ${ftOut}`);
assert.ok(fee >= BigInt(hex.length / 2), 'fee below 1 sat/B');

/* ---- broadcast + confirm ---- */
if (NO_BROADCAST) { console.log('--no-broadcast — op assembled and VM-accepted, nothing sent.'); process.exit(0); }
console.log('broadcasting…');
console.log('RESULT: ' + await rpc('blockchain.transaction.broadcast', [hex]));

let confirmed = false;
for (let i = 0; i < 50; i += 1) { /* ~25 min */
    await new Promise((r) => setTimeout(r, 30000));
    try { await rpc('blockchain.transaction.get_merkle', [txid]); confirmed = true; break; } catch { /* not in a block yet */ }
    process.stdout.write('.');
}
console.log('');
console.log(confirmed ? 'CONFIRMED (merkle proof available)' : 'still unconfirmed after polling — chipnet mining may be stalled; check later');

/* ---- advance the pool state ---- */
const be32 = (v) => { const b = Buffer.alloc(32); let x = BigInt(v); for (let i = 31; i >= 0 && x > 0n; i--) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; };
const remaining = state.pool.notes.filter((_, i) => !op.inIdx.includes(i));
state.outpoints = { ...state.outpoints, state: { txid, vout: 1, sats: Number(STATE_FLOAT), ftAmount: scenario.newBal.toString() }, actionInputs: [] };
state.pool = { root: op.newRoot, rootLE: be32(op.newRoot).reverse().toString('hex'), oldNullHex: scenario.newNull.toString('hex'), balance: scenario.newBal.toString(), leaves: op.newLeaves,
    notes: [...remaining, ...op.outNotes.map((n) => ({ note: { value: n.value, ownerPub: n.ownerPub, rho: n.rho, r: n.r }, nk: n.nk, index: n.index }))] }; /* same wrapped shape as the bootstrap entries, tree indices preserved */
state.ops = [...(state.ops ?? []), { action: op.action, txid, pv: sc.pv.toString(), sign: sc.sign.toString(), confirmed, at: new Date().toISOString() }];
writeFileSync(STATE, JSON.stringify(state, null, 2) + '\n');
console.log('state advanced: root ' + op.newRoot.slice(0, 18) + '… · balance ' + scenario.newBal + ' · notes ' + state.pool.notes.length + ' · next op needs an actionInputs refill');
process.exit(0);
