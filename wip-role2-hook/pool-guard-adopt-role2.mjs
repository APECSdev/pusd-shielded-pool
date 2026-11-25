// pool-guard-adopt-role2.mjs — adopt the MINTING GUARD for the live pool: move the category's
// minting NFT from the operator's P2PKH into the guard P2SH32 (minting-guard.mjs).
//
// WHY: while the minting NFT sits at a plain P2PKH, the operator key IS the minting policy —
// a careless spend burns it (exactly how the v1 pool lost it), and a compromised key can
// mint unlimited FT. After adoption the GUARD is the policy: the only possible spend
// recreates the minting NFT at the guard's own locking and mints NFT-only, empty-commitment
// blanks to the operator — burn and FT-inflation become CONSENSUS-IMPOSSIBLE (suite 14/14,
// minting-guard.mjs). The key keeps only the right to decide WHEN a batch runs.
//
// This is a LIVE custody upgrade: the pool program, the state NFT, the category, and all
// notes are untouched — no redeploy.
//
// Usage (VM, from chunked/bn254/bn-native-sound/):
//   node pool-guard-adopt-role2.mjs [--count 64] [--state …] [--secrets …] [--dry]
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import tls from 'node:tls';
import {
    binToHex, cashAddressToLockingBytecode, decodeTransaction, encodeDataPush,
    encodeTransactionBCH, generateSigningSerializationBCH, hash256, hexToBin,
    instantiateSecp256k1, instantiateSha256, SigningSerializationTypeBCH,
} from '@bitauth/libauth';
import { p2sh32 } from './vm.mjs';
import { guardRedeem } from './minting-guard.mjs';

const argOf = (n, d) => { const i = process.argv.indexOf(n); return i >= 0 ? process.argv[i + 1] : d; };
const STATE = argOf('--state', '/home/apecs/cov/role2-pool-state.json');
const SECRETS = argOf('--secrets', '/home/apecs/.secrets/faucet-hot-wallet.json');
const K = Number(argOf('--count', '64'));
const DRY = process.argv.includes('--dry');

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
const fundLocking = cashAddressToLockingBytecode(address).bytecode;   /* the operator's P2PKH (25 B) */
const txidOf = (t) => binToHex(new Uint8Array(hash256(encodeTransactionBCH(t), sha256a)).reverse());
const P2PKH_SIGNED = 100;
const probeFee = (t) => BigInt(encodeTransactionBCH({ ...t, inputs: t.inputs.map((i) => ({ ...i, unlockingBytecode: new Uint8Array(P2PKH_SIGNED) })) }).length) * 2n;

/* the guard for THIS pool: the live category, K blanks per batch, operator = the hot wallet */
const redeem = guardRedeem({ categoryDisplayHex: state.category, K, operatorLocking: fundLocking, operatorPubkey: publicKey });
const guardLocking = p2sh32(redeem);
console.log(`guard: redeem ${redeem.length}B · locking ${binToHex(guardLocking)} · K=${K} · category ${state.category.slice(0, 8)}…`);

/* the minting NFT currently at the WALLET's P2PKH */
const utxos = await rpc('blockchain.address.listunspent', [address, 'include_tokens']);
const minting = utxos.find((u) => u.token_data?.category === state.category && u.token_data.nft?.capability === 'minting');
if (!minting) throw new Error('no minting NFT at the wallet — already adopted? (state.guard)');
const plain = utxos.filter((u) => !u.token_data).sort((a, b) => b.value - a.value);
if (plain.length === 0) throw new Error('no plain wallet UTXO for the adopt fees');

const CAT_BYTES = hexToBin(state.category);
const tx = {
    version: 2, locktime: 0,
    inputs: [
        { outpointTransactionHash: hexToBin(minting.tx_hash), outpointIndex: minting.tx_pos, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) },
        { outpointTransactionHash: hexToBin(plain[0].tx_hash), outpointIndex: plain[0].tx_pos, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) },
    ],
    outputs: [
        /* the minting NFT, ADOPTED: locked to the guard, carrying its sats float forward */
        { lockingBytecode: guardLocking, valueSatoshis: 1000n, token: { category: CAT_BYTES, amount: 0n, nft: { capability: 'minting', commitment: new Uint8Array(0) } } },
        /* BCH change */
        { lockingBytecode: fundLocking, valueSatoshis: 0n },
    ],
};
tx.outputs[1].valueSatoshis = BigInt(plain[0].value) + BigInt(minting.value) - 1000n - probeFee(tx);
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
if (typeof decoded === 'string') throw new Error('adopt does not decode: ' + decoded);
const txid = txidOf(tx);
console.log(`adopt tx ${txid} · ${hex.length / 2}B — minting NFT ${minting.tx_hash.slice(0, 12)}:${minting.tx_pos} → the guard`);
if (DRY) { console.log('DRY — not broadcasting.'); process.exit(0); }
console.log('broadcasting…');
console.log('RESULT: ' + await rpc('blockchain.transaction.broadcast', [hex]));

let confirmed = false;
for (let i = 0; i < 60; i += 1) {
    await new Promise((r) => setTimeout(r, 30000));
    try { await rpc('blockchain.transaction.get_merkle', [txid]); confirmed = true; break; } catch { }
    process.stdout.write('.');
}
console.log('');
if (!confirmed) throw new Error('adopt unconfirmed after 30 min — do NOT run the guarded batch until it confirms');
state.guard = { adoptTxid: txid, txid, vout: 0, sats: 1000, locking: binToHex(guardLocking), redeemLength: redeem.length, K, confirmed, at: new Date().toISOString(), policy: 'only possible spend: recreate the minting NFT at the guard + mint K NFT-only empty-commitment blanks to the operator; burn and FT-mint are consensus-impossible (minting-guard.mjs 14/14)' };
writeFileSync(STATE, JSON.stringify(state, null, 2) + '\n');
console.log('state updated: guard adopted — the minting NFT now lives at ' + binToHex(guardLocking).slice(0, 20) + '…');
process.exit(0);
