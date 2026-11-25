// pool-tagbatch-role2.mjs — mint a batch of BLANK tag NFTs for the deposit-tagging locks.
//
// Deposit tagging (hook checks 4c/4g) needs a supply of MUTABLE NFTs with EMPTY commitments
// ("blanks") at the wallet. Each LOCK (pool-refill-role2.mjs) spends two blanks, mutates
// their commitments to SHA256(carrier[0..64]) of the proved action, and re-locks them at the
// program P2SH32 — binding the fuel to exactly that action's nullifiers. Blanks are minted
// from the MINTING NFT, which the deploy now PASSES FORWARD to the wallet (out1) instead of
// destroying it: spending the minting NFT mints the blanks and recreates the minting NFT
// itself, so one batch call replenishes the supply any number of times.
//
// Token shape per blank: category = the pool category, FT amount 0, NFT capability MUTABLE,
// commitment EMPTY — spendable only by the wallet's P2PKH key, ready for one lock to tag.
//
// Usage (VM, from chunked/bn254/bn-native-sound/):
//   node pool-tagbatch-role2.mjs [--count 32] [--state …] [--secrets …] [--no-broadcast]
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import tls from 'node:tls';
import {
    binToHex, cashAddressToLockingBytecode, decodeTransaction, encodeDataPush,
    encodeTransactionBCH, generateSigningSerializationBCH, hash256, hexToBin,
    instantiateSecp256k1, instantiateSha256, SigningSerializationTypeBCH,
} from '@bitauth/libauth';

const argOf = (n, d) => { const i = process.argv.indexOf(n); return i >= 0 ? process.argv[i + 1] : d; };
const STATE = argOf('--state', '/home/apecs/cov/role2-pool-state.json');
const SECRETS = argOf('--secrets', '/home/apecs/.secrets/faucet-hot-wallet.json');
const COUNT = Number(argOf('--count', '32'));
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
const privateKey = hexToBin(String(secrets.privateKeyHex).replace(/^0x/, '')); /* the file stores the key with an 0x prefix */
const address = secrets.addresses?.chipnet ?? secrets.address;
if (!address.startsWith('bchtest:')) throw new Error('expected a chipnet hot-wallet address, got ' + address);
const sha256a = await instantiateSha256();
const secp = await instantiateSecp256k1();
const publicKey = secrets.publicKeyHex ? hexToBin(secrets.publicKeyHex) : secp.derivePublicKeyCompressed(privateKey);
if (typeof publicKey === 'string') throw new Error('pubkey derivation failed: ' + publicKey);
const fundLocking = cashAddressToLockingBytecode(address).bytecode;

/* BCH txid = double-sha256 of the FULL SIGNED tx, ONCE (live-verified 2026-11-22). */
const txidOf = (t) => binToHex(new Uint8Array(hash256(encodeTransactionBCH(t), sha256a)).reverse());
const P2PKH_SIGNED = 100;
const probeFee = (t) => BigInt(encodeTransactionBCH({ ...t, inputs: t.inputs.map((i) => ({ ...i, unlockingBytecode: new Uint8Array(P2PKH_SIGNED) })) }).length) * 2n;

/* the minting NFT (deploy out1 passthrough) + a plain wallet UTXO for the batch sats */
const utxos = await rpc('blockchain.address.listunspent', [address, 'include_tokens']);
const minting = utxos.find((u) => u.token_data?.category === state.category && u.token_data.nft?.capability === 'minting');
if (!minting) throw new Error('no MINTING NFT at the wallet — was the deploy run with the passthrough output? (state.outpoints.mintingNFT records where it should be)');
const plain = utxos.filter((u) => !u.token_data).sort((a, b) => b.value - a.value);
if (plain.length === 0) throw new Error('no plain wallet UTXO for the batch sats');

const fixed = 1000n * BigInt(COUNT + 1); /* minting-NFT passthrough + COUNT blanks */
const inSats = BigInt(plain[0].value) + BigInt(minting.value);
if (inSats < fixed + 2000n + 400n) throw new Error(`wallet UTXOs too small for a ${COUNT}-blank batch`);

const CAT_BYTES = hexToBin(state.category);
const tx = {
    version: 2,
    locktime: 0,
    inputs: [
        { outpointTransactionHash: hexToBin(minting.tx_hash), outpointIndex: minting.tx_pos, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) },
        { outpointTransactionHash: hexToBin(plain[0].tx_hash), outpointIndex: plain[0].tx_pos, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) },
    ],
    outputs: [
        /* the minting NFT, recreated — the capability passes forward for future batches */
        { lockingBytecode: fundLocking, valueSatoshis: 1000n, token: { category: CAT_BYTES, amount: 0n, nft: { capability: 'minting', commitment: new Uint8Array(0) } } },
        /* COUNT blanks: mutable NFTs with EMPTY commitments, ready for one lock each to tag */
        ...Array.from({ length: COUNT }, () => ({ lockingBytecode: fundLocking, valueSatoshis: 1000n, token: { category: CAT_BYTES, amount: 0n, nft: { capability: 'mutable', commitment: new Uint8Array(0) } } })),
        /* BCH change */
        { lockingBytecode: fundLocking, valueSatoshis: 0n },
    ],
};
tx.outputs[COUNT + 1].valueSatoshis = inSats - fixed - probeFee(tx);

const sources = [
    { lockingBytecode: fundLocking, valueSatoshis: BigInt(minting.value), token: { category: CAT_BYTES, amount: 0n, nft: { capability: 'minting', commitment: new Uint8Array(0) } } },
    { lockingBytecode: fundLocking, valueSatoshis: BigInt(plain[0].value) },
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
if (typeof decoded === 'string') throw new Error('tag-batch does not decode: ' + decoded);
const txid = txidOf(tx);
console.log(`tag-batch tx ${txid} · ${hex.length / 2}B · minted ${COUNT} blank mutable NFTs + minting-NFT passthrough`);

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
if (!confirmed) throw new Error('tag-batch unconfirmed after 30 min — do NOT lock on it; re-check later');
state.tagBlanks = { lastBatchTxid: txid, minted: COUNT, confirmed, at: new Date().toISOString(), discovery: 'locks find blanks by listunspent: category + nft.capability=mutable + empty commitment' };
writeFileSync(STATE, JSON.stringify(state, null, 2) + '\n');
console.log('state updated: tagBlanks batch ' + txid.slice(0, 16) + '… (' + COUNT + ' blanks)');
process.exit(0);
