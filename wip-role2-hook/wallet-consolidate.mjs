// wallet-consolidate.mjs — fold a P2PKH wallet's plain UTXOs into one output.
//
// Needed when a bench script only spends plain[0] (pool-tagbatch-role2.mjs's K=64
// batch needs ~66,400 sats in a single plain UTXO). Same signing recipe as
// pool-deploy-role2.mjs (Schnorr, allOutputs, BCH 2026 VM).
//
// Usage (VM, from chunked/bn254/bn-native-sound/):
//   node wallet-consolidate.mjs [--secrets /home/apecs/.secrets/wallet-a-role2-demo.json] [--dry]
import { readFileSync } from 'node:fs';
import tls from 'node:tls';
import {
    binToHex, cashAddressToLockingBytecode, encodeDataPush, encodeTransactionBCH,
    generateSigningSerializationBCH, hash256, hexToBin, instantiateSecp256k1,
    instantiateSha256, SigningSerializationTypeBCH,
} from '@bitauth/libauth';

const argOf = (n, d) => { const i = process.argv.indexOf(n); return i >= 0 ? process.argv[i + 1] : d; };
const SECRETS = argOf('--secrets', '/home/apecs/.secrets/wallet-a-role2-demo.json');
const DRY = process.argv.includes('--dry');

const rpc = (method, params) => new Promise((res, rej) => {
    const sock = tls.connect(50002, 'chipnet.bch.ninja', { timeout: 15000 });
    let buf = '';
    sock.on('secureConnect', () => sock.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) + '\n'));
    sock.on('data', (d) => { buf += d.toString(); const line = buf.split('\n')[0];
        if (line) { try { const o = JSON.parse(line); if (o.error) rej(new Error(JSON.stringify(o.error))); else res(o.result); sock.destroy(); } catch { /* more */ } } });
    sock.on('error', rej);
    sock.on('timeout', () => { sock.destroy(); rej(new Error('electrum timeout: ' + method)); });
});

const secrets = JSON.parse(readFileSync(SECRETS, 'utf8'));
const privateKey = hexToBin(String(secrets.privateKeyHex).replace(/^0x/, ''));
const address = secrets.addresses?.chipnet ?? secrets.address;
const sha256a = await instantiateSha256();
const secp = await instantiateSecp256k1();
const publicKey = secrets.publicKeyHex ? hexToBin(secrets.publicKeyHex) : secp.derivePublicKeyCompressed(privateKey);
if (typeof publicKey === 'string') throw new Error('pubkey derivation failed: ' + publicKey);
const fundLocking = cashAddressToLockingBytecode(address).bytecode;
const txidOf = (t) => binToHex(new Uint8Array(hash256(encodeTransactionBCH(t), sha256a)).reverse());

const utxos = await rpc('blockchain.address.listunspent', [address, 'include_tokens']);
const plain = utxos.filter((u) => !u.token_data).sort((a, b) => b.value - a.value);
if (plain.length < 2) { console.log(`wallet ${address}: ${plain.length} plain UTXO(s) — nothing to consolidate`); process.exit(0); }
const sum = plain.reduce((a, u) => a + BigInt(u.value), 0n);
const tx = {
    version: 2, locktime: 0,
    inputs: plain.map((u) => ({ outpointTransactionHash: hexToBin(u.tx_hash), outpointIndex: u.tx_pos, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) })),
    outputs: [{ lockingBytecode: fundLocking, valueSatoshis: 0n }],
};
const probe = BigInt(encodeTransactionBCH({ ...tx, inputs: tx.inputs.map((i) => ({ ...i, unlockingBytecode: new Uint8Array(100) })) }).length) * 2n;
tx.outputs[0].valueSatoshis = sum - probe;
if (tx.outputs[0].valueSatoshis <= 0n) throw new Error('fee exceeds the wallet balance');

const sources = plain.map((u) => ({ lockingBytecode: fundLocking, valueSatoshis: BigInt(u.value) }));
for (let i = 0; i < tx.inputs.length; i += 1) {
    const serialization = generateSigningSerializationBCH(
        { inputIndex: i, sourceOutputs: sources, transaction: tx },
        { coveredBytecode: fundLocking, signingSerializationType: Uint8Array.of(SigningSerializationTypeBCH.allOutputs) },
        sha256a,
    );
    const digest = hash256(serialization, sha256a);
    const signature = secp.signMessageHashSchnorr(privateKey, digest);
    if (typeof signature === 'string') throw new Error('Schnorr signing failed: ' + signature);
    const sigWithType = Uint8Array.from([...signature, SigningSerializationTypeBCH.allOutputs]);
    tx.inputs[i].unlockingBytecode = Uint8Array.from([...encodeDataPush(sigWithType), ...encodeDataPush(publicKey)]);
}
const hex = binToHex(encodeTransactionBCH(tx));
const txid = txidOf(tx);
console.log(`consolidate ${plain.length} plain UTXOs (${sum} sats) → one ${tx.outputs[0].valueSatoshis}-sat output · fee ${probe} · ${hex.length / 2} B · tx ${txid}`);
if (DRY) { console.log('--dry — not broadcasting'); process.exit(0); }
console.log('RESULT: ' + await rpc('blockchain.transaction.broadcast', [hex]));
