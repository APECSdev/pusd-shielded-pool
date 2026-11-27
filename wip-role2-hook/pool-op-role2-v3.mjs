// pool-op-role2-v3.mjs — build, VM-eval (×5 inputs), broadcast and confirm a REAL v3 pool action.
//
// Consumes the v3 deployment state (role2-pool4-state.json) + a proved op (role2-op4.json
// from role2-op-witness-v3.mjs — it carries the nullSet walk data). The action is the v3
// FIVE-input shape:
//   inputs  0/1 — program-locking TAGGED fuel UTXOs (hook 4c/4g: category+mutable NFT with
//                  commitment = SHA256(carrier[0..64]) of THIS action; the deposit FT rides 0)
//   input   2   — the pool state NFT (role 2: commitment = noteRoot ‖ nullSetRoot);
//   inputs  3/4 — the walk-data UTXOs: the walk scripts in P2SH32 form (v3.1 — the
//                  raw form is relay-nonstandard), witnesses = sibBlob + walkA's
//                  declared midRoot + the redeem push (the walk script itself).
//   outputs    — out0 the 201-B carrier, out1 the new state (commitment = newRoot ‖
//                finalNullRoot), and for an unshield out2 the public payout (pv FT).
// NO SIGNATURES anywhere: the P2SH32(R) script satisfaction IS the spend authorization
// (the graph pins TXINPUTCOUNT == 5, so fees ride on the locked UTXOs' own sats).
// Every input is VM-evaluated against the REAL source outputs in BOTH modes before
// broadcast — the acceptance the 29/29 suite and the sweeps proved, now on the real tx.
//
// Usage (VM, from chunked/bn254/bn-native-sound/):
//   BN_VK_FIXTURES=/home/apecs/cov/our-v3.fixtures.json node pool-op-role2-v3.mjs [--op …] [--no-broadcast]
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import tls from 'node:tls';
import { binToHex, cashAddressToLockingBytecode, decodeTransaction, encodeTransactionBCH, hash256, hexToBin, instantiateSha256 } from '@bitauth/libauth';
import { buildProgram, setCovenant } from './script.mjs';
import { covenantHook, covenantParams, actionHashOf, carrierOutput } from './pool-hook.mjs';
import { scenarioV3, poolTransactionForV3, walkWitnesses, walkV3 } from './pool-tx-v3.mjs';
import { buildWalkScripts } from './walk-scripts.mjs';
import { VMS, p2sh32 } from './vm.mjs';

const argOf = (n, d) => { const i = process.argv.indexOf(n); return i >= 0 ? process.argv[i + 1] : d; };
const STATE = argOf('--state', '/home/apecs/cov/role2-pool4-state.json');
const OP = argOf('--op', '/home/apecs/cov/role2-op4.json');
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

/* ---- rebuild the v3 program with the deployed category; drift guards ---- */
const CATEGORY_ONCHAIN = binToHex(hexToBin(state.category).slice().reverse());
const { walkA, walkB, sizes } = buildWalkScripts(CATEGORY_ONCHAIN);
/* v3.1: the walk UTXOs are P2SH32-wrapped — the pins hash the ON-CHAIN lockings */
const { lockings: WALK_LOCKS, hashes: [walkAHash, walkBHash] } = walkV3(walkA, walkB);
assert.equal(walkAHash.toString('hex'), state.program.walkAHash, 'walkA locking drifted from the deployed build');
assert.equal(walkBHash.toString('hex'), state.program.walkBHash, 'walkB locking drifted from the deployed build');
assert.equal(binToHex(WALK_LOCKS[0]), state.program.walkALockingHex, 'walkA P2SH32 locking drifted from the deployed build');
assert.equal(binToHex(WALK_LOCKS[1]), state.program.walkBLockingHex, 'walkB P2SH32 locking drifted from the deployed build');
process.env.POOL_NULLDATA_HASHES = JSON.stringify([walkAHash.toString('hex'), walkBHash.toString('hex')]);
setCovenant(covenantHook(covenantParams({ categoryOnChain: CATEGORY_ONCHAIN }), 3, { walkAHash, walkBHash }));
const prog = buildProgram();
const programLocking = p2sh32(prog.R);
assert.equal(createHash('sha256').update(prog.code).digest('hex'), state.program.codeSha256, 'program code drifted from the deployed build');
assert.equal(binToHex(programLocking), state.program.locking, 'program locking drifted from the deployed build');

/* ---- the scenario (self-checked against the proof's own public inputs) ---- */
const leToBig = (hex) => BigInt('0x' + Buffer.from(hex, 'hex').reverse().toString('hex') || '0');
const c = op.covenant;
const sc = { nf0: leToBig(c.nf0), nf1: leToBig(c.nf1), cm0: leToBig(c.cm0), cm1: leToBig(c.cm1), cm2: leToBig(c.cm2), newRoot: leToBig(c.newMerkleRoot), pv: BigInt(c.publicValueAbs), sign: BigInt(c.isUnshield) };
const n0 = BigInt(op.publicSignals[0]);
assert.equal(n0.toString(), state.pool.root, 'proof n0 != current pool root');
assert.equal(actionHashOf({ ...sc, categoryDisplay: state.category }, 3).toString(), BigInt(op.publicSignals[1]).toString(), 'actionHash mismatch — op is not self-consistent');
/* the state commitment cross-check: the op's walk anchor must be the stored nullSetRoot,
   and the stored note root must be n0 — the two halves of the on-chain commitment */
const be32 = (v) => { const b = Buffer.alloc(32); let x = BigInt(v); for (let i = 31; i >= 0 && x > 0n; i--) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; };
const stateCommitExpected = Buffer.concat([Buffer.from(be32(n0)).reverse(), Buffer.from(op.nullSet.nullSetRootBefore, 'hex')]);
assert.equal(stateCommitExpected.toString('hex'), state.pool.commitmentHex, 'the state commitment (noteRoot ‖ nullSetRoot) does not match the op walk anchor — re-prove against the current state');
const scenarioArgs = { sc, n0, nullSet: op.nullSet, categoryDisplay: Buffer.from(state.category, 'hex'), balance, outs: 3 };
const scenario = scenarioV3(scenarioArgs);
const walkW = walkWitnesses(op.nullSet, walkA, walkB);
console.log(`${op.action} pv=${sc.pv} sign=${sc.sign} isDeposit=${op.isDeposit} · balance ${balance} → ${scenario.newBal} · nullSet ${op.nullSet.nullSetRootBefore.slice(0, 12)}… → ${op.nullSet.finalNullRoot.slice(0, 12)}…`);

/* ---- the bench fixture + v3 pool-shaped fills ---- */
const g1 = ([x, y]) => ({ x: BigInt(x).toString(), y: BigInt(y).toString() });
const g2 = ([[x0, x1], [y0, y1]]) => ({ x: { c0: BigInt(x0).toString(), c1: BigInt(x1).toString() }, y: { c0: BigInt(y0).toString(), c1: BigInt(y1).toString() } });
const fx = { publicInputs: op.publicSignals.map((s) => BigInt(s).toString()), proof: { a: g1(op.proof.pi_a), b: g2(op.proof.pi_b), c: g1(op.proof.pi_c) } };
const T = poolTransactionForV3(fx, prog, scenarioArgs, [walkA, walkB]);
console.log(`fills ${T.fills.join('/')} · verifier unlockings ${T.unlockings.map((u) => u.length).join('/')} · walk unlockings ${walkW.map((w) => w.length).join('/')} · nq ${T.core.nq}`);

/* ---- assemble the REAL transaction (5 inputs) ---- */
const inA = state.outpoints.actionInputs[0], inB = state.outpoints.actionInputs[1], inWA = state.outpoints.actionInputs[2], inWB = state.outpoints.actionInputs[3], inS = state.outpoints.state;
if (!inA || !inB || !inWA || !inWB || inWA.walk !== 'A' || inWB.walk !== 'B') throw new Error('state.outpoints.actionInputs must hold the tagged fuel pair + the walk-data pair (refill first if consumed)');
if (!inA.tag || !inB.tag) throw new Error('actionInputs lack tags — fuel from a pre-tagging build; run pool-refill-role2-v3.mjs');
/* the fuel tags MUST be this op's own nullifier-hash: running an op against a lock built for
   a DIFFERENT action is exactly the theft the tags exist to prevent (hook check 4g). */
const opTag = createHash('sha256').update(Buffer.concat([hexToBin(c.nf0), hexToBin(c.nf1)])).digest('hex');
assert.equal(inA.tag, opTag, "fuel tag != this op's nullifier-hash (locked for ANOTHER action)");
assert.equal(inB.tag, opTag, "fuel tag != this op's nullifier-hash (locked for ANOTHER action)");
const mkIn = (spec, unlocking) => ({ outpointTransactionHash: hexToBin(spec.txid), outpointIndex: spec.vout, sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array(unlocking) });
const inputs = [mkIn(inA, T.unlockings[0]), mkIn(inB, T.unlockings[1]), mkIn(inS, T.unlockings[2]), mkIn(inWA, walkW[0]), mkIn(inWB, walkW[1])];
const walletLocking = cashAddressToLockingBytecode(state.fundingAddress).bytecode;
const outputs = [
    { lockingBytecode: new Uint8Array(carrierOutput(scenario.carr)), valueSatoshis: 0n },
    { lockingBytecode: new Uint8Array(programLocking), valueSatoshis: STATE_FLOAT, token: { category: new Uint8Array(CAT), amount: scenario.newBal, nft: { capability: 'mutable', commitment: new Uint8Array(scenario.newCommit) } } },
];
if (sc.sign === 1n) outputs.push({ lockingBytecode: new Uint8Array(walletLocking), valueSatoshis: 1000n, token: { category: new Uint8Array(CAT), amount: sc.pv } });
const tx = { version: 2, locktime: 0, inputs, outputs };

/* the REAL source outputs (for VM-eval) — tokens exactly as recorded on chain: BOTH fuel
   inputs carry the tagged mutable NFT (hook 4c/4g); input 0 additionally carries the FT
   deposit on a deposit/shield; input 2 is the state NFT (noteRoot ‖ nullSetRoot); inputs
   3/4 are the RAW walk lockings (the graph + hook 4w pin their SHA256 hashes). */
const fuelToken = (spec) => ({ category: new Uint8Array(CAT), amount: spec.ftAmount !== undefined && spec.ftAmount !== null ? BigInt(spec.ftAmount) : 0n, nft: { capability: 'mutable', commitment: hexToBin(spec.tag) } });
const sources = [
    { lockingBytecode: new Uint8Array(programLocking), valueSatoshis: BigInt(inA.sats), token: fuelToken(inA) },
    { lockingBytecode: new Uint8Array(programLocking), valueSatoshis: BigInt(inB.sats), token: fuelToken(inB) },
    { lockingBytecode: new Uint8Array(programLocking), valueSatoshis: BigInt(inS.sats), token: { category: new Uint8Array(CAT), amount: balance, nft: { capability: 'mutable', commitment: new Uint8Array(scenario.stateCommit) } } },
    { lockingBytecode: new Uint8Array(WALK_LOCKS[0]), valueSatoshis: BigInt(inWA.sats) },
    { lockingBytecode: new Uint8Array(WALK_LOCKS[1]), valueSatoshis: BigInt(inWB.sats) },
];

/* ---- VM-eval every input, both modes, against the REAL shape ---- */
for (const mode of ['consensus', 'standard']) {
    const rs = [0, 1, 2, 3, 4].map((i) => {
        const st = VMS[mode].evaluate({ inputIndex: i, sourceOutputs: sources, transaction: { version: 2, locktime: 0, inputs: tx.inputs.map((q) => ({ ...q, unlockingBytecode: new Uint8Array(q.unlockingBytecode) })), outputs: tx.outputs } });
        const top = st.stack?.[st.stack.length - 1];
        const ok = st.error === undefined && st.stack.length === 1 && top?.length === 1 && top[0] === 1;
        return { ok, err: st.error, op: st.metrics.operationCost, budget: (41 + tx.inputs[i].unlockingBytecode.length) * 800 };
    });
    console.log(`${mode}: ${rs.map((r) => `${r.ok ? 'ACCEPT' : 'REJECT ' + r.err}`.slice(0, 44) + ` ${r.op}/${r.budget}`).join(' | ')}`);
    assert.ok(rs.every((r) => r.ok), `${mode} mode rejected the action — NOT broadcasting`);
}

/* ---- conservation + fee sanity (consensus token rules) ---- */
const ftIn = BigInt(inA.ftAmount ?? '0') + BigInt(inB.ftAmount ?? '0') + balance;
const ftOut = scenario.newBal + (sc.sign === 1n ? sc.pv : 0n);
assert.equal(ftIn, ftOut, 'fungible conservation violated');
const satsIn = BigInt(inA.sats) + BigInt(inB.sats) + BigInt(inWA.sats) + BigInt(inWB.sats) + BigInt(inS.sats);
const satsOut = outputs.reduce((a, o) => a + o.valueSatoshis, 0n);
const sha256a = await instantiateSha256();
const hex = binToHex(encodeTransactionBCH(tx));
const decoded = decodeTransaction(hexToBin(hex));
if (typeof decoded === 'string') throw new Error('op tx does not decode: ' + decoded);
const fee = satsIn - satsOut;
const txid = binToHex(new Uint8Array(hash256(hexToBin(hex), sha256a)).reverse());
console.log(`tx ${txid} · ${hex.length / 2}B · fee ${fee} sats (${Number(fee) / (hex.length / 2)} sat/B) · FT ${ftIn} → ${ftOut}`);
assert.ok(fee >= BigInt(hex.length / 2), `fee below 1 sat/B — underfunded lock: need ${hex.length / 2}, have ${fee} (raise --fuel-per in pool-refill-role2-v3.mjs)`);

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
const remaining = op.inIdx.length ? state.pool.notes.filter((n) => !op.inIdx.includes(Number(n.index))) : state.pool.notes; /* deposits spend no recorded notes */
state.outpoints = { ...state.outpoints, state: { txid, vout: 1, sats: Number(STATE_FLOAT), ftAmount: scenario.newBal.toString() }, actionInputs: [] };
state.pool = { root: op.newRoot, rootLE: be32(BigInt(op.newRoot)).reverse().toString('hex'), balance: scenario.newBal.toString(),
    commitmentHex: Buffer.concat([Buffer.from(be32(BigInt(op.newRoot))).reverse(), Buffer.from(op.nullSet.finalNullRoot, 'hex')]).toString('hex'),
    leaves: op.newLeaves,
    notes: [...remaining, ...op.outNotes.map((n) => ({ note: { value: n.value, ownerPub: n.ownerPub, rho: n.rho, r: n.r }, nk: n.nk, index: n.index }))] }; /* same wrapped shape as the deploy, tree indices preserved */
/* the nullifier SMT advances by the two spent keys (the R2 replay defense: the NEXT action's
   walk anchors against a set that already contains these) */
state.nullSet = [...state.nullSet, ...op.nullSet.keysAdded];
state.ops = [...(state.ops ?? []), { action: op.action, txid, pv: sc.pv.toString(), sign: sc.sign.toString(), isDeposit: op.isDeposit, confirmed, at: new Date().toISOString() }];
writeFileSync(STATE, JSON.stringify(state, null, 2) + '\n');
console.log('state advanced: root ' + op.newRoot.slice(0, 18) + '… · balance ' + scenario.newBal + ' · nullSet ' + state.nullSet.length + ' keys · notes ' + state.pool.notes.length + ' · next op needs an actionInputs refill');
process.exit(0);
