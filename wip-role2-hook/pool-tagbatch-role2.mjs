// pool-tagbatch-role2.mjs — mint a batch of BLANK tag NFTs THROUGH THE MINTING GUARD.
//
// Post-adoption (pool-guard-adopt-role2.mjs) the category's minting NFT lives at the guard
// P2SH32, and THIS is the only transaction that can ever spend it (minting-guard.mjs,
// suite 14/14): the minting NFT is recreated at the guard's own locking and exactly K
// blanks are minted — category + MUTABLE NFT + EMPTY commitment + 0 FT — to the operator's
// P2PKH, plus one tokenless change output. Burning the minting NFT and minting FT are
// consensus-impossible; the operator signature below only authorizes WHEN the batch runs.
//
// Each LOCK (pool-refill-role2.mjs) spends two blanks, mutates their commitments to
// SHA256(carrier[0..64]) of the proved action, and re-locks them at the program P2SH32.
//
// Usage (VM, from chunked/bn254/bn-native-sound/):
//   node pool-tagbatch-role2.mjs [--state …] [--secrets …] [--no-broadcast]
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import tls from 'node:tls';
import {
    binToHex, cashAddressToLockingBytecode, decodeTransaction, encodeDataPush,
    encodeTransactionBCH, generateSigningSerializationBCH, hash256, hexToBin,
    instantiateSecp256k1, instantiateSha256, SigningSerializationTypeBCH,
} from '@bitauth/libauth';
import { p2sh32, VMS, budgetOf } from './vm.mjs';
import { guardRedeem } from './minting-guard.mjs';

const argOf = (n, d) => { const i = process.argv.indexOf(n); return i >= 0 ? process.argv[i + 1] : d; };
const STATE = argOf('--state', '/home/apecs/cov/role2-pool-state.json');
const SECRETS = argOf('--secrets', '/home/apecs/.secrets/faucet-hot-wallet.json');
const NO_BROADCAST = process.argv.includes('--no-broadcast');

/* electrum raw TLS JSON-RPC; chipnet.bch.ninja:50002 — Fulcrum 2.1.3, live-verified */
const rpc = (method, params) => new Promise((res, rej) => {
    const sock = tls.connect(50002, 'chipnet.bch.ninja', { timeout: 15000 });
    let buf = '';
    sock.on('secureConnect', () => sock.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) + '\n'));
    sock.on('data', (d) => { buf += d.toString(); const line = buf.split('\n')[0];
        if (line) { try { const o = JSON.parse(line); if (o.error) rej(new Error(JSON.stringify(o.error))); else res(o.result); sock.destroy(); } catch { /* more */ } } });
    sock.on('error', rej);
    sock.on('timeout', () => { sock.destroy(); rej(new Error('electrum timeout: ' + method)); });
});

const state = JSON.parse(readFileSync(STATE, 'utf8'));
const secrets = JSON.parse(readFileSync(SECRETS, 'utf8'));
const privateKey = hexToBin(String(secrets.privateKeyHex).replace(/^0x/, ''));
const address = secrets.addresses?.chipnet ?? secrets.address;
const sha256a = await instantiateSha256();
const secp = await instantiateSecp256k1();
const publicKey = secrets.publicKeyHex ? hexToBin(secrets.publicKeyHex) : secp.derivePublicKeyCompressed(privateKey);
if (typeof publicKey === 'string') throw new Error('pubkey derivation failed: ' + publicKey);
const fundLocking = cashAddressToLockingBytecode(address).bytecode;
const txidOf = (t) => binToHex(new Uint8Array(hash256(encodeTransactionBCH(t), sha256a)).reverse());
const P2PKH_SIGNED = 100;
/* EXACT signed-size fee probe: the guard input's unlocking is DETERMINISTIC (65-B sig push
   + redeem push) — a 100-B placeholder there underestimates the 5-KB redeem push by its whole
   length and the first broadcast attempt died on min-relay (code 66). Fee = BARE 1 sat/B
   per the user directive + a 600-sat buffer (exact-length probe ⇒ exact 1 sat/B would be
   borderline against ≥ 1000 sat/kB). */
const probeFeeExact = (t, unl0Len) => BigInt(encodeTransactionBCH({ ...t, inputs: t.inputs.map((i, n) => ({ ...i, unlockingBytecode: new Uint8Array(n === 0 ? unl0Len : P2PKH_SIGNED) })) }).length) * 1n + 600n;

/* rebuild the guard from the SAME parameters and pin it against the adopted locking */
if (!state.guard) throw new Error('no guard in state — run pool-guard-adopt-role2.mjs first');
const K = state.guard.K;
const redeem = guardRedeem({ categoryDisplayHex: state.category, K, operatorLocking: fundLocking, operatorPubkey: publicKey });
const guardLocking = p2sh32(redeem);
assert.equal(binToHex(guardLocking), state.guard.locking, 'the rebuilt guard does not match the adopted locking — source drift; refusing');
assert.equal(redeem.length, state.guard.redeemLength, 'guard redeem length drifted');

/* the guard UTXO (tracked in state) + a plain wallet UTXO for the batch sats */
const utxos = await rpc('blockchain.address.listunspent', [address, 'include_tokens']);
const plain = utxos.filter((u) => !u.token_data).sort((a, b) => b.value - a.value);
if (plain.length === 0) throw new Error('no plain wallet UTXO for the batch sats');
const fixed = 1000n * BigInt(K + 1);                                        /* passthrough float + K blanks */
if (BigInt(plain[0].value) + BigInt(state.guard.sats) < fixed + 2000n + 400n) throw new Error('wallet UTXOs too small for a K=' + K + ' batch');

const CAT_BYTES = hexToBin(state.category);
const tx = {
    version: 2, locktime: 0,
    inputs: [
        { outpointTransactionHash: hexToBin(state.guard.txid), outpointIndex: state.guard.vout, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) }, /* the guard (signed below, P2SH) */
        { outpointTransactionHash: hexToBin(plain[0].tx_hash), outpointIndex: plain[0].tx_pos, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) }, /* batch sats (P2PKH) */
    ],
    outputs: [
        /* the minting NFT passthrough — re-locked to the guard (the guard's own rule) */
        { lockingBytecode: new Uint8Array(guardLocking), valueSatoshis: 1000n, token: { category: new Uint8Array(CAT_BYTES), amount: 0n, nft: { capability: 'minting', commitment: new Uint8Array(0) } } },
        /* K blanks at the operator's P2PKH */
        ...Array.from({ length: K }, () => ({ lockingBytecode: new Uint8Array(fundLocking), valueSatoshis: 1000n, token: { category: new Uint8Array(CAT_BYTES), amount: 0n, nft: { capability: 'mutable', commitment: new Uint8Array(0) } } })),
        /* tokenless change (the guard's own rule) */
        { lockingBytecode: new Uint8Array(fundLocking), valueSatoshis: 0n },
    ],
};
const unl0Len = encodeDataPush(new Uint8Array(65)).length + encodeDataPush(redeem).length;
tx.outputs[K + 1].valueSatoshis = BigInt(plain[0].value) + BigInt(state.guard.sats) - fixed - probeFeeExact(tx, unl0Len);

/* sources exactly as the guard UTXO + sats UTXO sit on chain */
const sources = [
    { lockingBytecode: new Uint8Array(guardLocking), valueSatoshis: BigInt(state.guard.sats), token: { category: new Uint8Array(CAT_BYTES), amount: 0n, nft: { capability: 'minting', commitment: new Uint8Array(0) } } },
    { lockingBytecode: new Uint8Array(fundLocking), valueSatoshis: BigInt(plain[0].value) },
];

/* sign input 0 against the REDEEM (P2SH coveredBytecode) — the guard's checksig */
{
    const serialization = generateSigningSerializationBCH(
        { inputIndex: 0, sourceOutputs: sources, transaction: tx },
        { coveredBytecode: new Uint8Array(redeem), signingSerializationType: Uint8Array.of(SigningSerializationTypeBCH.allOutputs) },
        sha256a,
    );
    const digest = hash256(serialization, sha256a);
    const signature = secp.signMessageHashSchnorr(privateKey, digest);
    if (typeof signature === 'string') throw new Error('Schnorr signing failed: ' + signature);
    tx.inputs[0].unlockingBytecode = Uint8Array.from([...encodeDataPush(Uint8Array.from([...signature, SigningSerializationTypeBCH.allOutputs])), ...encodeDataPush(new Uint8Array(redeem))]);
}
/* sign input 1 (plain P2PKH) */
{
    const serialization = generateSigningSerializationBCH(
        { inputIndex: 1, sourceOutputs: sources, transaction: tx },
        { coveredBytecode: new Uint8Array(fundLocking), signingSerializationType: Uint8Array.of(SigningSerializationTypeBCH.allOutputs) },
        sha256a,
    );
    const digest = hash256(serialization, sha256a);
    const signature = secp.signMessageHashSchnorr(privateKey, digest);
    if (typeof signature === 'string') throw new Error('Schnorr signing failed: ' + signature);
    tx.inputs[1].unlockingBytecode = Uint8Array.from([...encodeDataPush(Uint8Array.from([...signature, SigningSerializationTypeBCH.allOutputs])), ...encodeDataPush(publicKey)]);
}

/* VM-eval the guard input in BOTH modes against the REAL shape — the same acceptance the
   suite proved, now on the assembled chipnet tx */
for (const mode of ['consensus', 'standard']) {
    const st = VMS[mode].evaluate({ inputIndex: 0, sourceOutputs: sources.map((s) => ({ ...s, lockingBytecode: new Uint8Array(s.lockingBytecode), ...(s.token ? { token: { ...s.token, category: new Uint8Array(s.token.category), commitment: new Uint8Array(s.token.commitment ?? new Uint8Array(0)), nft: s.token.nft ? { ...s.token.nft, commitment: new Uint8Array(s.token.nft.commitment ?? new Uint8Array(0)) } : undefined } } : {}) })), transaction: { version: 2, locktime: 0, inputs: tx.inputs.map((i) => ({ ...i, unlockingBytecode: new Uint8Array(i.unlockingBytecode) })), outputs: tx.outputs.map((o) => ({ ...o, lockingBytecode: new Uint8Array(o.lockingBytecode), token: o.token ? { ...o.token, category: new Uint8Array(o.token.category), nft: o.token.nft ? { ...o.token.nft, commitment: new Uint8Array(o.token.nft.commitment ?? new Uint8Array(0)) } : undefined } : undefined })) } });
    const top = st.stack?.[st.stack.length - 1];
    const ok = st.error === undefined && st.stack.length === 1 && top?.length === 1 && top[0] === 1;
    console.log(`${mode}: ${ok ? 'ACCEPT' : 'REJECT ' + st.error} · op ${st.metrics.operationCost}/${budgetOf(tx.inputs[0].unlockingBytecode)}`);
    assert.ok(ok, mode + ' mode rejected the guarded batch — NOT broadcasting');
}

const hex = binToHex(encodeTransactionBCH(tx));
const decoded = decodeTransaction(hexToBin(hex));
if (typeof decoded === 'string') throw new Error('guarded batch does not decode: ' + decoded);
const txid = txidOf(tx);
console.log(`guarded batch tx ${txid} · ${hex.length / 2}B · minted ${K} blanks (guard K=${K}) + minting-NFT passthrough at the guard`);

if (NO_BROADCAST) { console.log('--no-broadcast — nothing sent.'); process.exit(0); }
console.log('broadcasting…');
console.log('RESULT: ' + await rpc('blockchain.transaction.broadcast', [hex]));

let confirmed = false;
for (let i = 0; i < 60; i += 1) {
    await new Promise((r) => setTimeout(r, 30000));
    try { await rpc('blockchain.transaction.get_merkle', [txid]); confirmed = true; break; } catch { }
    process.stdout.write('.');
}
console.log('');
if (!confirmed) throw new Error('guarded batch unconfirmed after 30 min — re-check before locking on the blanks');
state.guard = { ...state.guard, txid, vout: 0, sats: 1000, confirmed, at: new Date().toISOString() };   /* the new passthrough outpoint */
state.tagBlanks = { lastBatchTxid: txid, minted: K, confirmed, at: new Date().toISOString(), guarded: true, discovery: 'locks find blanks by listunspent: category + nft.capability=mutable + empty commitment' };
writeFileSync(STATE, JSON.stringify(state, null, 2) + '\n');
console.log(`state updated: guard passthrough ${txid.slice(0, 16)}… · ${K} blanks minted THROUGH the guard`);
process.exit(0);
