// pool-refill-role2.mjs — the LOCK tx: create the next action's TAGGED fuel/deposit UTXOs.
//
// DEPOSIT TAGGING (hook checks 4c/4g): every fuel UTXO carries a mutable NFT whose commitment
// is SHA256(nf0 ‖ nf1) = SHA256(carrier[0..64]) of the action it funds — computed here from
// the PROVED op file (role2-op.json). Standing fuel can then only be consumed by the action
// whose witness spends exactly those nullifiers; producing them requires the note keys. This
// recreates, as a commitment, the author binding the old pools got from their signed funding
// input. The two blanks come from the wallet's tag pool (pool-tagbatch-role2.mjs); this lock
// mutates their commitments to the tag and re-locks them at the program P2SH32. A SHIELD's FT
// deposit rides output 0 (chain shape), taken from the wallet's supply UTXO; the action burns
// both tag NFTs (burn-by-omission, consensus-legal).
//
// Fee policy (user directive 2026-11-24): BARE — no fee-market headroom; BCH blocks are
// empty. The prove-first flow makes the action's size known at lock time; the default 15k
// sats per fuel UTXO (30k total) covers every real action (~28.1 KB) at 1.07 sat/B.
// TXINPUTCOUNT==3 still forbids a fee input — fees ride the locked UTXOs' own sats.
//
// Flow per action: role2-op-witness.mjs (prove) → THIS (tagged lock) → pool-op-role2.mjs
// (build, VM-eval, broadcast — it may spend the lock's UNCONFIRMED outputs; first-seen wins
// the state double-spend, closing the theft window to ~zero — the recorded client rule).
//
// Usage (VM, from chunked/bn254/bn-native-sound/):
//   node pool-refill-role2.mjs --op /home/apecs/cov/role2-op.json [--fuel-per 15000]
//       [--state …] [--secrets …] [--no-wait]
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import tls from 'node:tls';
import {
    binToHex, cashAddressToLockingBytecode, decodeTransaction, encodeDataPush,
    encodeTransactionBCH, generateSigningSerializationBCH, hash256, hexToBin,
    instantiateSecp256k1, instantiateSha256, SigningSerializationTypeBCH,
} from '@bitauth/libauth';

const argOf = (n, d) => { const i = process.argv.indexOf(n); return i >= 0 ? process.argv[i + 1] : d; };
const STATE = argOf('--state', '/home/apecs/cov/role2-pool-state.json');
const SECRETS = argOf('--secrets', '/home/apecs/.secrets/faucet-hot-wallet.json');
const OP = argOf('--op', '/home/apecs/cov/role2-op.json');
const TAG_OVERRIDE = argOf('--tag', null);
const FUEL_PER = BigInt(argOf('--fuel-per', '15000'));
const NO_WAIT = process.argv.includes('--no-wait');

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
const op = JSON.parse(readFileSync(OP, 'utf8'));
const secrets = JSON.parse(readFileSync(SECRETS, 'utf8'));
const privateKey = hexToBin(String(secrets.privateKeyHex).replace(/^0x/, '')); /* the file stores the key with an 0x prefix */
const address = secrets.addresses?.chipnet ?? secrets.address;
if (!address.startsWith('bchtest:')) throw new Error('expected a chipnet hot-wallet address, got ' + address);
const sha256a = await instantiateSha256();
const secp = await instantiateSecp256k1();
const publicKey = secrets.publicKeyHex ? hexToBin(secrets.publicKeyHex) : secp.derivePublicKeyCompressed(privateKey);
if (typeof publicKey === 'string') throw new Error('pubkey derivation failed: ' + publicKey);
const fundLocking = cashAddressToLockingBytecode(address).bytecode;
const programLocking = hexToBin(state.program.locking);
const txidOf = (t) => binToHex(new Uint8Array(hash256(encodeTransactionBCH(t), sha256a)).reverse());
const P2PKH_SIGNED = 100;
const probeFee = (t) => BigInt(encodeTransactionBCH({ ...t, inputs: t.inputs.map((i) => ({ ...i, unlockingBytecode: new Uint8Array(P2PKH_SIGNED) })) }).length) * 2n;

/* ---- the deposit tag: SHA256 of the carrier's first 64 bytes — the action's own nullifiers
   (the carrier stores nf0/nf1 as 32-byte LE VM-number forms; the op file's covenant fields ARE
   those LE hex strings — pool-hook.mjs check 4g recomputes the identical digest on chain). */
const c = op.covenant;
const nf0b = Buffer.from(c.nf0, 'hex'), nf1b = Buffer.from(c.nf1, 'hex');
assert.equal(nf0b.length + nf1b.length, 64, 'op covenant nullifier limbs must be 32+32 bytes');
const tagBuf = createHash('sha256').update(Buffer.concat([nf0b, nf1b])).digest();
const tag = TAG_OVERRIDE ?? tagBuf.toString('hex');
if (TAG_OVERRIDE && TAG_OVERRIDE !== tagBuf.toString('hex')) throw new Error('--tag override does not match the op file carrier — refusing');
const pv = BigInt(c.publicValueAbs), sign = BigInt(c.isUnshield);
const FT = (sign === 0n && pv > 0n) ? pv : 0n; /* a SHIELD deposits pv; transfers/unshields carry no FT */
console.log(`lock for ${op.action} pv=${pv} sign=${sign} · tag ${tag.slice(0, 16)}… · fuel ${FUEL_PER}×2 sats${FT > 0n ? ' · FT deposit ' + FT : ''}`);

/* ---- wallet UTXOs: 2 blanks (mutable NFT, empty commitment) + a plain BCH UTXO (+ supply FT for a shield) ---- */
const utxos = await rpc('blockchain.address.listunspent', [address, 'include_tokens']);
const blanks = utxos.filter((u) => u.token_data?.category === state.category && u.token_data.nft?.capability === 'mutable' && !u.token_data.nft.commitment);
if (blanks.length < 2) throw new Error(`only ${blanks.length} tag blank(s) at the wallet — run pool-tagbatch-role2.mjs`);
const plain = utxos.filter((u) => !u.token_data).sort((a, b) => b.value - a.value);
if (plain.length === 0) throw new Error('no plain wallet UTXO for the fuel sats');
let supply = null;
if (FT > 0n) {
    const tokenUtxos = utxos.filter((u) => u.token_data?.category === state.category && !u.token_data.nft && BigInt(u.token_data.amount) >= FT);
    if (tokenUtxos.length === 0) throw new Error('no FT UTXO at the wallet for the requested shield deposit');
    supply = tokenUtxos.sort((a, b) => BigInt(b.token_data.amount) - BigInt(a.token_data.amount))[0];
}

const fixed = 2n * FUEL_PER + (supply && BigInt(supply.token_data.amount) - FT > 0n ? 1000n : 0n);
const inSats = BigInt(plain[0].value) + BigInt(blanks[0].value) + BigInt(blanks[1].value) + (supply ? BigInt(supply.value) : 0n);
if (inSats < fixed + 2000n + 400n) throw new Error('wallet UTXOs too small for the lock');

const CAT_BYTES = hexToBin(state.category);
const tx = {
    version: 2,
    locktime: 0,
    inputs: [
        { outpointTransactionHash: hexToBin(plain[0].tx_hash), outpointIndex: plain[0].tx_pos, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) },
        { outpointTransactionHash: hexToBin(blanks[0].tx_hash), outpointIndex: blanks[0].tx_pos, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) },
        { outpointTransactionHash: hexToBin(blanks[1].tx_hash), outpointIndex: blanks[1].tx_pos, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) },
        ...(supply ? [{ outpointTransactionHash: hexToBin(supply.tx_hash), outpointIndex: supply.tx_pos, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) }] : []),
    ],
    outputs: [
        /* out0: the deposit/fuel UTXO — the FT deposit rides here on a shield (chain shape) */
        { lockingBytecode: programLocking, valueSatoshis: FUEL_PER, token: { category: CAT_BYTES, amount: FT, nft: { capability: 'mutable', commitment: hexToBin(tag) } } },
        /* out1: the second fuel UTXO (tagged, no FT) */
        { lockingBytecode: programLocking, valueSatoshis: FUEL_PER, token: { category: CAT_BYTES, amount: 0n, nft: { capability: 'mutable', commitment: hexToBin(tag) } } },
        /* BCH change */
        { lockingBytecode: fundLocking, valueSatoshis: 0n },
    ],
};
if (supply && BigInt(supply.token_data.amount) - FT > 0n) tx.outputs.push({ lockingBytecode: fundLocking, valueSatoshis: 1000n, token: { category: CAT_BYTES, amount: BigInt(supply.token_data.amount) - FT } }); /* a zero-amount FT change output would be invalid — skip if nothing remains */
tx.outputs[2].valueSatoshis = inSats - fixed - probeFee(tx);

const sources = [
    { lockingBytecode: fundLocking, valueSatoshis: BigInt(plain[0].value) },
    ...[blanks[0], blanks[1]].map((b) => ({ lockingBytecode: fundLocking, valueSatoshis: BigInt(b.value), token: { category: CAT_BYTES, amount: 0n, nft: { capability: 'mutable', commitment: new Uint8Array(0) } } })),
    ...(supply ? [{ lockingBytecode: fundLocking, valueSatoshis: BigInt(supply.value), token: { category: CAT_BYTES, amount: BigInt(supply.token_data.amount) } }] : []),
];
for (let i = 0; i < tx.inputs.length; i += 1) {
    const serialization = generateSigningSerializationBCH(
        { inputIndex: i, sourceOutputs: sources, transaction: tx },
        { coveredBytecode: fundLocking, signingSerializationType: Uint8Array.of(SigningSerializationTypeBCH.allOutputs) },
        sha256a,
    );
    const digest = hash256(serialization, sha256a);
    const signature = secp.signMessageHashSchnorr(privateKey, digest);
    if (typeof signature === 'string') throw new Error('Schnorr signing failed: ' + signature);
    tx.inputs[i].unlockingBytecode = Uint8Array.from([...encodeDataPush(Uint8Array.from([...signature, SigningSerializationTypeBCH.allOutputs])), ...encodeDataPush(publicKey)]);
}
const hex = binToHex(encodeTransactionBCH(tx));
const decoded = decodeTransaction(hexToBin(hex));
if (typeof decoded === 'string') throw new Error('lock does not decode: ' + decoded);
const txid = txidOf(tx);
console.log(`lock tx ${txid} · ${hex.length / 2}B · 2 tagged fuel UTXOs of ${FUEL_PER} sats at the program locking${FT > 0n ? ' (out0 carries the ' + FT + ' FT deposit)' : ''}`);

console.log('broadcasting…');
console.log('RESULT: ' + await rpc('blockchain.transaction.broadcast', [hex]));
state.outpoints.actionInputs = [
    { txid, vout: 0, sats: Number(FUEL_PER), ftAmount: FT.toString(), tag },
    { txid, vout: 1, sats: Number(FUEL_PER), tag },
];
writeFileSync(STATE, JSON.stringify(state, null, 2) + '\n');
console.log('state updated: actionInputs = 2 tagged UTXOs of ' + txid.slice(0, 16) + '…');

if (NO_WAIT) { console.log('--no-wait — broadcast the action now (pool-op-role2.mjs); it may spend the lock unconfirmed (atomic lock+act).'); process.exit(0); }
let confirmed = false;
for (let i = 0; i < 60; i += 1) {
    await new Promise((r) => setTimeout(r, 30000));
    try { await rpc('blockchain.transaction.get_merkle', [txid]); confirmed = true; break; } catch { }
    process.stdout.write('.');
}
console.log('');
if (!confirmed) throw new Error('lock unconfirmed after 30 min — the fuel is tagged for THIS op; either keep waiting, re-prove with the same notes (same nullifiers, tag stays valid), or abandon the fuel');
console.log('lock confirmed.');
process.exit(0);
