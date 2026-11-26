// blank-sweep.mjs — recover the sats riding on unused BLANK tag NFTs.
//
// The minting guard mints K=64 blanks at the operator's P2PKH, each carrying
// 1,000 sats. A lock spends two blanks (and their sats) per action; the rest sit
// idle. When the operator's plain sats run short (the refill only counts PLAIN
// UTXOs), spend N blanks with no token outputs — the NFTs are burned by omission
// (consensus-legal, the same rule the locks use for the two they spend) and the
// sats return as one plain UTXO. Keep enough blanks for the planned actions.
//
// Usage (VM, from chunked/bn254/bn-native-sound/):
//   node blank-sweep.mjs --state /home/apecs/cov/role2-pool3-state.json --count 30 [--secrets …] [--dry]
import { readFileSync } from 'node:fs';
import tls from 'node:tls';
import {
    binToHex, cashAddressToLockingBytecode, encodeDataPush, encodeTransactionBCH,
    generateSigningSerializationBCH, hash256, hexToBin, instantiateSecp256k1,
    instantiateSha256, SigningSerializationTypeBCH,
} from '@bitauth/libauth';

const argOf = (n, d) => { const i = process.argv.indexOf(n); return i >= 0 ? process.argv[i + 1] : d; };
const STATE = argOf('--state', '/home/apecs/cov/role2-pool3-state.json');
const SECRETS = argOf('--secrets', '/home/apecs/.secrets/wallet-a-role2-demo.json');
const COUNT = Number(argOf('--count', '30'));
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

const utxos = await rpc('blockchain.address.listunspent', [address, 'include_tokens']);
const blanks = utxos.filter((u) => u.token_data
    && String(u.token_data.category).toLowerCase() === state.category.toLowerCase()
    && u.token_data.nft && u.token_data.nft.capability === 'mutable'
    && String(u.token_data.nft.commitment ?? '') === ''
    && BigInt(u.token_data.amount) === 0n);
console.log(`blanks at ${address}: ${blanks.length} (spending ${Math.min(COUNT, blanks.length)})`);
if (blanks.length === 0) throw new Error('no blanks at this address');
const picked = blanks.slice(0, Math.min(COUNT, blanks.length));
const sum = picked.reduce((a, u) => a + BigInt(u.value), 0n);

const tx = {
    version: 2, locktime: 0,
    inputs: picked.map((u) => ({ outpointTransactionHash: hexToBin(u.tx_hash), outpointIndex: u.tx_pos, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) })),
    outputs: [{ lockingBytecode: fundLocking, valueSatoshis: 0n }],
};
const probe = BigInt(encodeTransactionBCH({ ...tx, inputs: tx.inputs.map((i) => ({ ...i, unlockingBytecode: new Uint8Array(100) })) }).length) * 2n;
tx.outputs[0].valueSatoshis = sum - probe;
if (tx.outputs[0].valueSatoshis <= 0n) throw new Error('fee exceeds the recovered sats');

/* the sighash covers each source output INCLUDING its token data (BCH 2026 token prefix);
   a tokenless source here produces a signature the network rejects (code 16). */
const sources = picked.map((u) => ({
    lockingBytecode: fundLocking,
    valueSatoshis: BigInt(u.value),
    token: {
        category: hexToBin(u.token_data.category),
        amount: BigInt(u.token_data.amount),
        nft: { capability: u.token_data.nft.capability, commitment: hexToBin(u.token_data.nft.commitment ?? '') },
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
console.log(`burn ${picked.length} blanks (${sum} sats) → one ${tx.outputs[0].valueSatoshis}-sat plain output · fee ${probe} · ${hex.length / 2} B · tx ${txid}`);
if (DRY) { console.log('--dry — not broadcasting'); process.exit(0); }
console.log('RESULT: ' + await rpc('blockchain.transaction.broadcast', [hex]));
