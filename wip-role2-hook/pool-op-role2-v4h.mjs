// pool-op-role2-v4h.mjs — build, VM-eval (×7 inputs), broadcast and confirm a REAL
// C-architecture pool action.
//
// The SEVEN-input shape (the H pair carries no witness — the redeem push is the whole
// unlocking; the program runs only at inputs 0/1/2, the walks at 3/4, H at 5/6):
//   inputs  0/1 — program-locking TAGGED fuel UTXOs (hook 4c/4g; NFT-only — no FT ever);
//   input   2   — the pool state NFT (96-B commitment [noteRoot ‖ nullSetRoot ‖ balance]);
//   inputs  3/4 — the walk-data UTXOs (commit96 walk scripts, P2SH32);
//   input   5   — the holdings line: the prior action's out2 (steady) or the genesis
//                 lock-funded tokenless slot (first action);
//   input   6   — the deposit slot: the ASSET FT == pv on a deposit, tokenless otherwise.
//   outputs    — out0 the 201-B carrier · out1 the new state (NFT-only, 96-B commitment)
//                · out2 the new holdings (ASSET FT == newBal, at the H locking)
//                · out3 the unshield payout (ASSET FT == pv) — unshield only.
// NO SIGNATURES anywhere. Every input is VM-evaluated against the REAL source outputs in
// BOTH modes before broadcast. Conservation is asserted off-chain (the consensus token
// rules enforce it on-chain; the hook's check 5 + 9h make the holdings line unforgeable).
//
// Usage (VM, from chunked/bn254/bn-native-sound/):
//   BN_VK_FIXTURES=/home/apecs/cov/our-v3-user3.fixtures.json node pool-op-role2-v4h.mjs --network mainnet
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import tls from 'node:tls';
import { binToHex, cashAddressToLockingBytecode, decodeTransaction, encodeTransactionBCH, hash256, hexToBin, instantiateSha256 } from '@bitauth/libauth';
import { buildProgram, setCovenant } from './script.mjs';
import { pushData } from './asm.mjs';
import { covenantHook, covenantParams, actionHashOf, carrierOutput } from './pool-hook.mjs';
import { scenarioV3H, walkWitnesses, walkV3 } from './pool-tx-v3.mjs';
import { buildWalkScripts } from './walk-scripts.mjs';
import { buildHoldingsCovenant } from './holdings-covenant.mjs';
import { VMS, p2sh32 } from './vm.mjs';

const argOf = (n, d) => { const i = process.argv.indexOf(n); return i >= 0 ? process.argv[i + 1] : d; };
const NETWORK = argOf('--network', 'chipnet');
if (NETWORK !== 'mainnet' && NETWORK !== 'chipnet') throw new Error('--network must be mainnet|chipnet');
const ELECTRUM_HOST = argOf('--electrum', NETWORK === 'mainnet' ? 'bch.soul-dev.com' : 'chipnet.bch.ninja');
const STATE = argOf('--state', NETWORK === 'mainnet' ? '/home/apecs/cov/role2-pool4-state.mainnet-v4h.json' : '/home/apecs/cov/role2-pool4-state.v4h.json');
const OP = argOf('--op', '/home/apecs/cov/role2-op4.json');
const NO_BROADCAST = process.argv.includes('--no-broadcast');
const STATE_FLOAT = 10_000n;
const HOLDINGS_SATS = 1_000n;

const rpc = (method, params) => new Promise((res, rej) => {
    const sock = tls.connect(50002, ELECTRUM_HOST, { timeout: 15000 });
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
const CAT = hexToBin(state.category);
const ASSET = hexToBin(state.assetCategory);
const balance = BigInt(state.pool.balance);

/* ---- rebuild the v4h program; drift guards (program + walks + H) ---- */
const CATEGORY_ONCHAIN = binToHex(CAT.slice().reverse());
const ASSET_ONCHAIN = binToHex(ASSET.slice().reverse());
const { walkA, walkB } = buildWalkScripts(CATEGORY_ONCHAIN, { commit96: true });
const { lockings: WALK_LOCKS, hashes: [walkAHash, walkBHash] } = walkV3(walkA, walkB);
process.env.POOL_NULLDATA_HASHES = JSON.stringify([walkAHash.toString('hex'), walkBHash.toString('hex')]);
process.env.POOL_HOLDINGS = '1';
setCovenant(covenantHook(covenantParams({ categoryOnChain: CATEGORY_ONCHAIN, assetCategoryOnChain: ASSET_ONCHAIN }), 3, { walkAHash, walkBHash, holdings: {} }));
const prog = buildProgram();
const programLocking = p2sh32(prog.R);
const progLockingHashHex = createHash('sha256').update(Buffer.from(programLocking)).digest('hex');
const HC = buildHoldingsCovenant({ progLockingHashHex, walkAHashHex: walkAHash.toString('hex'), walkBHashHex: walkBHash.toString('hex') });
assert.equal(createHash('sha256').update(prog.code).digest('hex'), state.program.codeSha256, 'program code drifted from the deployed build');
assert.equal(binToHex(programLocking), state.program.locking, 'program locking drifted from the deployed build');
assert.equal(walkAHash.toString('hex'), state.program.walkAHash, 'walkA locking drifted from the deployed build');
assert.equal(walkBHash.toString('hex'), state.program.walkBHash, 'walkB locking drifted from the deployed build');
assert.equal(HC.lockingHex, state.program.hLockingHex, 'H locking drifted from the deployed build');

/* ---- the scenario (self-checked against the proof's own public inputs) ---- */
const leToBig = (hex) => BigInt('0x' + Buffer.from(hex, 'hex').reverse().toString('hex') || '0');
const c = op.covenant;
const sc = { nf0: leToBig(c.nf0), nf1: leToBig(c.nf1), cm0: leToBig(c.cm0), cm1: leToBig(c.cm1), cm2: leToBig(c.cm2), newRoot: leToBig(c.newMerkleRoot), pv: BigInt(c.publicValueAbs), sign: BigInt(c.isUnshield) };
const n0 = BigInt(op.publicSignals[0]);
assert.equal(n0.toString(), state.pool.root, 'proof n0 != current pool root');
/* the actionHash's category field is the ASSET — the circuit witness (the Nito-review fix) */
assert.equal(actionHashOf({ ...sc, categoryDisplay: state.assetCategory }, 3).toString(), BigInt(op.publicSignals[1]).toString(), 'actionHash mismatch — op is not self-consistent');
const be32 = (v) => { const b = Buffer.alloc(32); let x = BigInt(v); for (let i = 31; i >= 0 && x > 0n; i--) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; };
const stateCommitExpected = Buffer.concat([Buffer.from(be32(n0)).reverse(), Buffer.from(op.nullSet.nullSetRootBefore, 'hex'), Buffer.from(be32(balance)).reverse()]);
assert.equal(stateCommitExpected.toString('hex'), state.pool.commitmentHex, 'the state commitment (noteRoot ‖ nullSetRoot ‖ balance) does not match the op walk anchor — re-prove against the current state');
const scenarioArgs = { sc, n0, nullSet: op.nullSet, balance };
const scenario = scenarioV3H(scenarioArgs);
const walkW = walkWitnesses(op.nullSet, walkA, walkB);
console.log(`${op.action} pv=${sc.pv} sign=${sc.sign} isDeposit=${op.isDeposit} · balance ${balance} → ${scenario.newBal} · nullSet ${op.nullSet.nullSetRootBefore.slice(0, 12)}… → ${op.nullSet.finalNullRoot.slice(0, 12)}…`);

/* ---- the bench fixture + pool-shaped fills (7-input shape) ---- */
const g1 = ([x, y]) => ({ x: BigInt(x).toString(), y: BigInt(y).toString() });
const g2 = ([[x0, x1], [y0, y1]]) => ({ x: { c0: BigInt(x0).toString(), c1: BigInt(x1).toString() }, y: { c0: BigInt(y0).toString(), c1: BigInt(y1).toString() } });
const fx = { publicInputs: op.publicSignals.map((s) => BigInt(s).toString()), proof: { a: g1(op.proof.pi_a), b: g2(op.proof.pi_b), c: g1(op.proof.pi_c) } };
const T = poolTransactionForC(fx, prog, { ...scenarioArgs, categoryDisplay: Buffer.from(state.category, 'hex'), assetCategoryDisplay: Buffer.from(state.assetCategory, 'hex') }, [walkA, walkB], HC.script, HC.locking);
console.log(`fills ${T.fills.join('/')} · verifier unlockings ${T.unlockings.map((u) => u.length).join('/')} · walk unlockings ${walkW.map((w) => w.length).join('/')} · H unlockings ${HC.script.length + 2}/${HC.script.length + 2}`);

/* ---- assemble the REAL transaction (7 inputs) ---- */
const ai = state.outpoints.actionInputs;
const inA = ai[0], inB = ai[1], inWA = ai[2], inWB = ai[3], in6 = ai.find((x) => x.slot === 'in6'), in5g = ai.find((x) => x.slot === 'in5');
const inS = state.outpoints.state;
const priorHoldings = state.outpoints.holdings;
const in5 = priorHoldings ?? in5g;
if (!inA || !inB || !inWA || !inWB || !in6 || !in5) throw new Error('state.outpoints.actionInputs must hold fuel×2 + walks×2 + the in6 slot (+ in5 at genesis, or state.outpoints.holdings set) — refill first');
if (inWA.walk !== 'A' || inWB.walk !== 'B') throw new Error('actionInputs walks mislabeled');
const opTag = createHash('sha256').update(Buffer.concat([hexToBin(c.nf0), hexToBin(c.nf1)])).digest('hex');
assert.equal(inA.tag, opTag, "fuel tag != this op's nullifier-hash (locked for ANOTHER action)");
assert.equal(inB.tag, opTag, "fuel tag != this op's nullifier-hash (locked for ANOTHER action)");
const mkIn = (spec, unlocking) => ({ outpointTransactionHash: hexToBin(spec.txid), outpointIndex: spec.vout, sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array(unlocking) });
const hUnlock = Uint8Array.from(pushData(HC.script));
const inputs = [
    mkIn(inA, T.unlockings[0]), mkIn(inB, T.unlockings[1]), mkIn(inS, T.unlockings[2]),
    mkIn(inWA, walkW[0]), mkIn(inWB, walkW[1]),
    mkIn(in5, hUnlock), mkIn(in6, hUnlock),
];
const walletLocking = cashAddressToLockingBytecode(state.fundingAddress).bytecode;
const outputs = [
    { lockingBytecode: new Uint8Array(carrierOutput(scenario.carr)), valueSatoshis: 0n },
    { lockingBytecode: new Uint8Array(programLocking), valueSatoshis: STATE_FLOAT, token: { category: new Uint8Array(CAT), amount: 0n, nft: { capability: 'mutable', commitment: new Uint8Array(scenario.newCommit) } } },
    { lockingBytecode: new Uint8Array(HC.locking), valueSatoshis: HOLDINGS_SATS, token: { category: new Uint8Array(ASSET), amount: scenario.newBal } },
];
if (sc.sign === 1n) outputs.push({ lockingBytecode: new Uint8Array(walletLocking), valueSatoshis: 1000n, token: { category: new Uint8Array(ASSET), amount: sc.pv } });
const tx = { version: 2, locktime: 0, inputs, outputs };

/* the REAL source outputs (for VM-eval) */
const fuelToken = (spec) => ({ category: new Uint8Array(CAT), amount: 0n, nft: { capability: 'mutable', commitment: hexToBin(spec.tag) } });
const in5Token = priorHoldings
    ? { category: new Uint8Array(ASSET), amount: balance }
    : undefined; /* genesis: tokenless */
const in6Token = (sc.sign === 0n && sc.pv > 0n)
    ? { category: new Uint8Array(ASSET), amount: sc.pv }
    : undefined;
const sources = [
    { lockingBytecode: new Uint8Array(programLocking), valueSatoshis: BigInt(inA.sats), token: fuelToken(inA) },
    { lockingBytecode: new Uint8Array(programLocking), valueSatoshis: BigInt(inB.sats), token: fuelToken(inB) },
    { lockingBytecode: new Uint8Array(programLocking), valueSatoshis: BigInt(inS.sats), token: { category: new Uint8Array(CAT), amount: 0n, nft: { capability: 'mutable', commitment: new Uint8Array(scenario.stateCommit) } } },
    { lockingBytecode: new Uint8Array(WALK_LOCKS[0]), valueSatoshis: BigInt(inWA.sats) },
    { lockingBytecode: new Uint8Array(WALK_LOCKS[1]), valueSatoshis: BigInt(inWB.sats) },
    { lockingBytecode: new Uint8Array(HC.locking), valueSatoshis: BigInt(in5.sats), ...(in5Token ? { token: in5Token } : {}) },
    { lockingBytecode: new Uint8Array(HC.locking), valueSatoshis: BigInt(in6.sats), ...(in6Token ? { token: in6Token } : {}) },
];

/* ---- VM-eval every input, both modes, against the REAL shape ---- */
for (const mode of ['consensus', 'standard']) {
    const rs = [0, 1, 2, 3, 4, 5, 6].map((i) => {
        const st = VMS[mode].evaluate({ inputIndex: i, sourceOutputs: sources, transaction: { version: 2, locktime: 0, inputs: tx.inputs.map((q) => ({ ...q, unlockingBytecode: new Uint8Array(q.unlockingBytecode) })), outputs: tx.outputs } });
        const top = st.stack?.[st.stack.length - 1];
        const ok = st.error === undefined && st.stack.length === 1 && top?.length === 1 && top[0] === 1;
        return { ok, err: st.error, op: st.metrics.operationCost, budget: (41 + tx.inputs[i].unlockingBytecode.length) * 800 };
    });
    console.log(`${mode}: ${rs.map((r) => `${r.ok ? 'ACCEPT' : 'REJECT ' + r.err}`.slice(0, 44) + ` ${r.op}/${r.budget}`).join(' | ')}`);
    assert.ok(rs.every((r) => r.ok), `${mode} mode rejected the action — NOT broadcasting`);
}

/* ---- conservation + fee sanity ---- */
const asIn = (priorHoldings ? balance : 0n) + (sc.sign === 0n ? sc.pv : 0n);
const asOut = scenario.newBal + (sc.sign === 1n ? sc.pv : 0n);
assert.equal(asIn, asOut, 'ASSET conservation violated');
const satsIn = [inA, inB, inS, inWA, inWB, in5, in6].reduce((a, sp) => a + BigInt(sp.sats), 0n);
const satsOut = outputs.reduce((a, o) => a + o.valueSatoshis, 0n);
const sha256a = await instantiateSha256();
const hex = binToHex(encodeTransactionBCH(tx));
const decoded = decodeTransaction(hexToBin(hex));
if (typeof decoded === 'string') throw new Error('op tx does not decode: ' + decoded);
const fee = satsIn - satsOut;
const txid = binToHex(new Uint8Array(hash256(hexToBin(hex), sha256a)).reverse());
console.log(`tx ${txid} · ${hex.length / 2}B · fee ${fee} sats (${Number(fee) / (hex.length / 2)} sat/B) · ASSET ${asIn} → ${asOut}`);
assert.ok(fee >= BigInt(hex.length / 2), `fee below 1 sat/B — underfunded lock: need ${hex.length / 2}, have ${fee} (raise --fuel-per)`);

/* ---- broadcast + confirm ---- */
if (NO_BROADCAST) { console.log('--no-broadcast — op assembled and VM-accepted, nothing sent.'); process.exit(0); }
console.log('broadcasting…');
console.log('RESULT: ' + await rpc('blockchain.transaction.broadcast', [hex]));

let confirmed = false;
for (let i = 0; i < 50; i += 1) {
    await new Promise((r) => setTimeout(r, 30000));
    try { await rpc('blockchain.transaction.get_merkle', [txid]); confirmed = true; break; } catch { }
    process.stdout.write('.');
}
console.log('');
console.log(confirmed ? 'CONFIRMED (merkle proof available)' : 'still unconfirmed after polling — check later');

/* ---- advance the pool state ---- */
const remaining = op.inIdx.length ? state.pool.notes.filter((n) => !op.inIdx.includes(Number(n.index))) : state.pool.notes;
state.outpoints = {
    ...state.outpoints,
    state: { txid, vout: 1, sats: Number(STATE_FLOAT), ftAmount: '0', nft: 'mutable', commitment: scenario.newCommit.toString('hex') },
    holdings: { txid, vout: 2, sats: Number(HOLDINGS_SATS), ftAmount: scenario.newBal.toString() },
    actionInputs: [],
};
state.pool = { root: op.newRoot, rootLE: be32(BigInt(op.newRoot)).reverse().toString('hex'), balance: scenario.newBal.toString(),
    commitmentHex: Buffer.from(scenario.newCommit).toString('hex'),
    leaves: op.newLeaves,
    notes: [...remaining, ...op.outNotes.map((n) => ({ note: { value: n.value, ownerPub: n.ownerPub, rho: n.rho, r: n.r }, nk: n.nk, index: n.index }))] };
state.nullSet = [...state.nullSet, ...op.nullSet.keysAdded];
state.ops = [...(state.ops ?? []), { action: op.action, txid, pv: sc.pv.toString(), sign: sc.sign.toString(), isDeposit: op.isDeposit, confirmed, at: new Date().toISOString() }];
writeFileSync(STATE, JSON.stringify(state, null, 2) + '\n');
console.log('state advanced: root ' + op.newRoot.slice(0, 18) + '… · balance ' + scenario.newBal + ' (holdings ' + txid.slice(0, 12) + ':2) · nullSet ' + state.nullSet.length + ' keys · notes ' + state.pool.notes.length + ' · next op needs an actionInputs refill');
process.exit(0);
