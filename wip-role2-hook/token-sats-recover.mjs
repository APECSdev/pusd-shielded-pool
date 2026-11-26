// token-sats-recover.mjs — recover the BCH sats riding on DEMO token UTXOs.
//
// The role-2 demo wallets hold old test-token UTXOs (tPUSD 20,000,000 per output)
// that were funded with 60,000 sats each as fee reserves. When the pool's plain
// sats run short, spend one such UTXO with NO token output: the token is burned
// by omission (consensus-legal; these are demo/test tokens with no value) and the
// sats return as one plain UTXO. DEMO ONLY — never run this against a valued asset.
//
// Usage (VM, from chunked/bn254/bn-native-sound/):
//   node token-sats-recover.mjs --category 050b5934be… --min-value 60000 --count 1 [--secrets …] [--dry]
import { readFileSync } from 'node:fs';
import tls from 'node:tls';
import {
    binToHex, cashAddressToLockingBytecode, encodeDataPush, encodeTransactionBCH,
    generateSigningSerializationBCH, hash256, hexToBin, instantiateSecp256k1,
    instantiateSha256, SigningSerializationTypeBCH,
} from '@bitauth/libauth';

const argOf = (n, d) => { const i = process.argv.indexOf(n); return i >= 0 ? process.argv[i + 1] : d; };
const SECRETS = argOf('--secrets', '/home/apecs/.secrets/wallet-a-role2-demo.json');
const CATEGORY = argOf('--category', '');
const MIN_VALUE = BigInt(argOf('--min-value', '60000'));
const COUNT = Number(argOf('--count', '1'));
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
const candidates = utxos.filter((u) => u.token_data
    && (!CATEGORY || String(u.token_data.category).toLowerCase() === CATEGORY.toLowerCase())
    && BigInt(u.value) >= MIN_VALUE).sort((a, b) => b.value - a.value);
if (candidates.length === 0) throw new Error(`no token UTXO >= ${MIN_VALUE} sats${CATEGORY ? ' of ' + CATEGORY : ''}`);
const picked = candidates.slice(0, COUNT);
const sum = picked.reduce((a, u) => a + BigInt(u.value), 0n);
console.log(`recovering ${picked.length} token UTXO(s), ${sum} sats: ${picked.map((u) => u.tx_hash.slice(0, 12) + ':' + u.tx_pos).join(', ')}`);

const tx = {
    version: 2, locktime: 0,
    inputs: picked.map((u) => ({ outpointTransactionHash: hexToBin(u.tx_hash), outpointIndex: u.tx_pos, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) })),
    outputs: [{ lockingBytecode: fundLocking, valueSatoshis: 0n }],
};
const probe = BigInt(encodeTransactionBCH({ ...tx, inputs: tx.inputs.map((i) => ({ ...i, unlockingBytecode: new Uint8Array(100) })) }).length) * 2n;
tx.outputs[0].valueSatoshis = sum - probe;
if (tx.outputs[0].valueSatoshis <= 0n) throw new Error('fee exceeds the recovered sats');

const sources = picked.map((u) => ({
    lockingBytecode: fundLocking,
    valueSatoshis: BigInt(u.value),
    token: {
        category: hexToBin(u.token_data.category),
        amount: BigInt(u.token_data.amount),
        ...(u.token_data.nft ? { nft: { capability: u.token_data.nft.capability, commitment: hexToBin(u.token_data.nft.commitment ?? '') } } : {}),
    },
}));
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
console.log(`burn ${picked.length} demo token UTXO(s) (${sum} sats) → one ${tx.outputs[0].valueSatoshis}-sat plain output · fee ${probe} · ${hex.length / 2} B · tx ${txid}`);
if (DRY) { console.log('--dry — not broadcasting'); process.exit(0); }
console.log('RESULT: ' + await rpc('blockchain.transaction.broadcast', [hex]));
